/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.activemq.artemis.core.protocol.openwire.amq;

import java.lang.invoke.MethodHandles;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import org.apache.activemq.advisory.AdvisorySupport;
import org.apache.activemq.artemis.api.core.ICoreMessage;
import org.apache.activemq.artemis.api.core.Message;
import org.apache.activemq.artemis.api.core.QueueConfiguration;
import org.apache.activemq.artemis.api.core.RoutingType;
import org.apache.activemq.artemis.api.core.SimpleString;
import org.apache.activemq.artemis.core.client.impl.ClientConsumerImpl;
import org.apache.activemq.artemis.core.io.IOCallback;
import org.apache.activemq.artemis.core.protocol.openwire.OpenWireConnection;
import org.apache.activemq.artemis.core.protocol.openwire.OpenWireConstants;
import org.apache.activemq.artemis.core.protocol.openwire.OpenWireMessageConverter;
import org.apache.activemq.artemis.core.server.MessageReference;
import org.apache.activemq.artemis.core.server.QueueQueryResult;
import org.apache.activemq.artemis.core.server.ServerConsumer;
import org.apache.activemq.artemis.core.server.SlowConsumerDetectionListener;
import org.apache.activemq.artemis.core.server.impl.QueueImpl;
import org.apache.activemq.artemis.core.server.impl.ServerConsumerImpl;
import org.apache.activemq.artemis.core.settings.impl.AddressSettings;
import org.apache.activemq.artemis.core.transaction.Transaction;
import org.apache.activemq.artemis.core.transaction.TransactionOperationAbstract;
import org.apache.activemq.artemis.reader.MessageUtil;
import org.apache.activemq.artemis.utils.CompositeAddress;
import org.apache.activemq.artemis.utils.SelectorTranslator;
import org.apache.activemq.command.ConsumerControl;
import org.apache.activemq.command.ConsumerId;
import org.apache.activemq.command.ConsumerInfo;
import org.apache.activemq.command.MessageAck;
import org.apache.activemq.command.MessageDispatch;
import org.apache.activemq.command.MessageId;
import org.apache.activemq.command.MessagePull;
import org.apache.activemq.command.RemoveInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.activemq.artemis.core.protocol.openwire.OpenWireConstants.AMQ_MSG_MESSAGE_ID;

public class AMQConsumer {
   private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

   private final AMQSession session;
   private final org.apache.activemq.command.ActiveMQDestination openwireDestination;
   private final ConsumerInfo info;
   private final ScheduledExecutorService scheduledPool;
   private ServerConsumer serverConsumer;

   private int prefetchSize;
   private final AtomicInteger currentWindow;
   private int deliveredAcksCreditExtension = 0;
   private long messagePullSequence = 0;
   private final AtomicReference<MessagePullHandler> messagePullHandler = new AtomicReference<>(null);
   //internal means we don't expose
   //it's address/queue to management service
   private boolean internalAddress = false;
   private volatile Set<MessageReference> rolledbackMessageRefs;
   private ScheduledFuture<?> delayedDispatchPrompter;
   private AtomicLong deliveredSequenceId = new AtomicLong(0);

   public AMQConsumer(AMQSession amqSession,
                      org.apache.activemq.command.ActiveMQDestination d,
                      ConsumerInfo info,
                      ScheduledExecutorService scheduledPool,
                      boolean internalAddress) {
      this.session = amqSession;
      this.openwireDestination = d;
      this.info = info;
      this.scheduledPool = scheduledPool;
      this.prefetchSize = info.getPrefetchSize();
      this.currentWindow = new AtomicInteger(prefetchSize);
      if (prefetchSize == 0) {
         messagePullHandler.set(new MessagePullHandler());
      }
      this.internalAddress = internalAddress;
      this.rolledbackMessageRefs = null;
   }

   private Set<MessageReference> guardedInitializationOfRolledBackMessageRefs() {
      synchronized (this) {
         Set<MessageReference> rollbackedMessageRefs = this.rolledbackMessageRefs;
         if (rollbackedMessageRefs == null) {
            rollbackedMessageRefs = new ConcurrentSkipListSet<>(Comparator.comparingLong(MessageReference::getMessageID));
            this.rolledbackMessageRefs = rollbackedMessageRefs;
         }
         return rollbackedMessageRefs;
      }
   }

   private Set<MessageReference> getRolledbackMessageRefsOrCreate() {
      Set<MessageReference> rolledbackMessageRefs = this.rolledbackMessageRefs;
      if (rolledbackMessageRefs == null) {
         rolledbackMessageRefs = guardedInitializationOfRolledBackMessageRefs();
      }
      return rolledbackMessageRefs;
   }

   protected Set<MessageReference> getRolledbackMessageRefs() {
      return this.rolledbackMessageRefs;
   }


   private static String convertOpenWireToActiveMQFilterString(final String selectorString) {
      if (selectorString == null) {
         return null;
      }

      String filterString = SelectorTranslator.convertToActiveMQFilterString(selectorString);
      filterString = SelectorTranslator.parse(filterString, "AMQUserID", AMQ_MSG_MESSAGE_ID.toString());

      return filterString;
   }

   public void start() {
      if (serverConsumer == null) {
         throw new IllegalStateException("Cannot start the AMQConsumer until it has been initialized");
      }

      serverConsumer.setStarted(true);
   }

   public void init(SlowConsumerDetectionListener slowConsumerDetectionListener, long nativeId) throws Exception {

      SimpleString selector = info.getSelector() == null ? null : SimpleString.of(convertOpenWireToActiveMQFilterString(info.getSelector()));
      boolean preAck = false;
      if (info.isNoLocal()) {
         if (!AdvisorySupport.isAdvisoryTopic(openwireDestination)) {
            //tell the connection to add the property
            this.session.getConnection().setNoLocal(true);
         } else {
            preAck = true;
         }
         String id = info.getClientId() != null ? info.getClientId() : this.getId().getConnectionId();
         String noLocalSelector = MessageUtil.CONNECTION_ID_PROPERTY_NAME + "<>'" + id + "'";
         if (selector == null) {
            selector = SimpleString.of(noLocalSelector);
         } else {
            selector = SimpleString.of(info.getSelector() + " AND " + noLocalSelector);
         }
      }

      SimpleString destinationName = SimpleString.of(session.convertWildcard(openwireDestination));

      if (openwireDestination.isTopic()) {
         SimpleString queueName = createTopicSubscription(info.isDurable(), info.getClientId(), destinationName.toString(), info.getSubscriptionName(), selector, destinationName);

         serverConsumer = session.getCoreSession().createConsumer(nativeId, queueName, CompositeAddress.isFullyQualified(destinationName.toString()) ? selector : null, info.getPriority(), info.isBrowser(), false, -1);
         serverConsumer.setlowConsumerDetection(slowConsumerDetectionListener);
         //only advisory topic consumers need this.
         ((ServerConsumerImpl)serverConsumer).setPreAcknowledge(preAck);
      } else {
         serverConsumer = session.getCoreSession().createConsumer(nativeId, destinationName, selector, info.getPriority(), info.isBrowser(), false, -1);
         serverConsumer.setlowConsumerDetection(slowConsumerDetectionListener);
         AddressSettings addrSettings = session.getCoreServer().getAddressSettingsRepository().getMatch(destinationName.toString());
         if (addrSettings != null) {
            //see PolicyEntry
            if (info.getPrefetchSize() != 0 && addrSettings.getQueuePrefetch() == 0) {
               //sends back a ConsumerControl
               ConsumerControl cc = new ConsumerControl();
               cc.setConsumerId(info.getConsumerId());
               cc.setPrefetch(0);
               session.getConnection().dispatch(cc);
            }
         }
      }

      if (serverConsumer != null && serverConsumer.getQueue() != null && serverConsumer.getQueue().getQueueConfiguration() != null) {
         Long delayBeforeDispatch = serverConsumer.getQueue().getQueueConfiguration().getDelayBeforeDispatch();
         if (delayBeforeDispatch != null && delayBeforeDispatch > 0) {
            Long schedule = delayBeforeDispatch / 2;
            delayedDispatchPrompter = scheduledPool.scheduleAtFixedRate(() -> serverConsumer.promptDelivery(), schedule, schedule, TimeUnit.MILLISECONDS);
         }
      }

      serverConsumer.setProtocolData(this);
   }

   private SimpleString createTopicSubscription(boolean isDurable,
                                                String clientID,
                                                String physicalName,
                                                String subscriptionName,
                                                SimpleString selector,
                                                SimpleString address) throws Exception {

      SimpleString queueName;

      if (isDurable) {
         queueName = org.apache.activemq.artemis.jms.client.ActiveMQDestination.createQueueNameForSubscription(true, clientID, subscriptionName);
         if (info.getDestination().isComposite()) {
            queueName =  queueName.concat(physicalName);
         }
         QueueConfiguration queueConfiguration = QueueConfiguration.of(queueName).setAddress(address).setRoutingType(RoutingType.MULTICAST).setFilterString(selector).setInternal(internalAddress);
         QueueQueryResult result = session.getCoreSession().executeQueueQuery(queueName);
         if (result.isExists()) {
            // Already exists
            if (result.getConsumerCount() > 0) {
               throw new IllegalStateException("Cannot create a subscriber on the durable subscription since it already has subscriber(s)");
            }

            SimpleString oldFilterString = result.getFilterString();

            boolean selectorChanged = selector == null && oldFilterString != null || oldFilterString == null && selector != null || oldFilterString != null && selector != null && !oldFilterString.equals(selector);

            SimpleString oldTopicName = result.getAddress();

            boolean topicChanged = !oldTopicName.equals(address);

            if ((selectorChanged || topicChanged) && !result.isConfigurationManaged()) {
               // Delete the old durable sub
               session.getCoreSession().deleteQueue(queueName);

               // Create the new one
               session.getCoreSession().createQueue(queueConfiguration);
            }
         } else {
            session.getCoreSession().createQueue(queueConfiguration);
         }
      } else {
         // The consumer may be using FQQN in which case the queue might already exist.
         if (CompositeAddress.isFullyQualified(physicalName)) {
            queueName = CompositeAddress.extractQueueName(SimpleString.of(physicalName));
            if (session.getCoreServer().locateQueue(queueName) != null) {
               return queueName;
            }
         } else {
            queueName = SimpleString.of(UUID.randomUUID().toString());
         }

         session.getCoreSession().createQueue(QueueConfiguration.of(queueName).setAddress(address).setRoutingType(RoutingType.MULTICAST).setFilterString(selector).setDurable(false).setTemporary(true).setInternal(internalAddress));
      }

      return queueName;
   }

   public ConsumerId getId() {
      return info.getConsumerId();
   }

   public void replenishCredit(int n, boolean delivered) {
      if (messagePullHandler.get() != null) {
         logger.debug("replenishCredit of {} ignored, as there's no messagePullHandler", n);
         //don't replenish any credits when the pull handler controls it!!
         return;
      }

      if (delivered) {
         deliveredAcksCreditExtension += n;
      } else if (deliveredAcksCreditExtension > 0) {
         if (deliveredAcksCreditExtension < n) {
            n -= deliveredAcksCreditExtension;
            logger.debug("Requested more credits than the limit, maximizing the request as {}", n);
            deliveredAcksCreditExtension = 0;
         } else {
            deliveredAcksCreditExtension -= n;
            return;
         }
      }

      int oldwindow = currentWindow.getAndAdd(n);
      if (logger.isDebugEnabled()) {
         logger.debug("replenished {} credits, current after replenish = {}, old ={}", n, currentWindow.get(), oldwindow);
      }

      boolean promptDelivery = oldwindow < prefetchSize;

      if (promptDelivery) {
         serverConsumer.promptDelivery();
      }
   }

   public int handleDeliver(MessageReference reference, ICoreMessage message) {
      MessageDispatch dispatch;
      try {
         MessagePullHandler pullHandler = messagePullHandler.get();
         if (pullHandler != null && !pullHandler.checkForcedConsumer(message)) {
            return 0;
         }

         if (session.getConnection().isNoLocal() || (session.isInternal() && AdvisorySupport.isAdvisoryTopic(openwireDestination))) {
            message.removeProperty(MessageUtil.CONNECTION_ID_PROPERTY_NAME);
         }
         //handleDeliver is performed by an executor; any AMQConsumer can share the session.wireFormat()
         dispatch = OpenWireMessageConverter.createMessageDispatch(reference, message, session.wireFormat(), this, session.getCoreServer().getNodeManager().getUUID(), deliveredSequenceId.getAndIncrement());
         int size = dispatch.getMessage().getSize();
         reference.setProtocolData(MessageId.class, dispatch.getMessage().getMessageId());
         session.deliverMessage(dispatch);
         // Prevent races with other updates that can lead to credit going negative and starving consumers.
         currentWindow.updateAndGet(AMQConsumer::decrementWindow);
         if (logger.isDebugEnabled()) {
            logger.debug("Decremented credit, current={}", currentWindow.get());
         }
         return size;
      } catch (Throwable t) {
         logger.warn("Error during message dispatch", t);
         return 0;
      }
   }

   static int decrementWindow(int value) {
      if (value > 0) {
         return value - 1;
      } else {
         if (logger.isDebugEnabled()) {
            logger.debug("preventing the credit window from going negative, keeping value at {}", value, new Exception("trace"));
         }
         return value;
      }
   }

   public void handleDeliverNullDispatch() {
      MessageDispatch md = new MessageDispatch();
      md.setConsumerId(getId());
      md.setDestination(openwireDestination);
      session.deliverMessage(md);
   }

   /**
    * The acknowledgement in openwire is done based on intervals. We will iterate through the list of delivering
    * messages at {@link ServerConsumer#scanDeliveringReferences(boolean, Function, Function)} and add those to the
    * Transaction. Notice that we will start a new transaction on the cases where there is no transaction.
    */
   public void acknowledge(MessageAck ack) throws Exception {

      if (ack.isRedeliveredAck()) {
         // we don't mind if the client thinks it is a redelivery
         return;
      }

      logger.debug("Acking {}", ack);

      final int ackMessageCount = ack.getMessageCount();

      // this is for deliveredACK on OpenWire. Meaning the message is still being held by the client.
      // it's just to request more credits
      if (ack.isDeliveredAck()) {
         logger.debug("replinishCredit credit on {} credits, for DELIVERED_ACK_TYPE", ackMessageCount);
         replenishCredit(ackMessageCount, true);
         // our work is done
         return;
      }

      final MessageId lastID = ack.getLastMessageId();
      final MessageId startID = ack.getFirstMessageId() == null ? lastID : ack.getFirstMessageId();

      // if it's browse only, nothing to be acked
      final boolean removeReferences = !serverConsumer.isBrowseOnly() && !serverConsumer.getQueue().isNonDestructive();
      final List<MessageReference> ackList = serverConsumer.scanDeliveringReferences(removeReferences, reference -> startID.equals(reference.getProtocolData(MessageId.class)), reference -> lastID.equals(reference.getProtocolData(MessageId.class)));

      if (!ackList.isEmpty() || !removeReferences || serverConsumer.getQueue().isTemporary()) {

         if (ack.isExpiredAck()) {
            for (MessageReference ref : ackList) {
               ref.getQueue().expire(ref, serverConsumer, true);
               if (logger.isDebugEnabled()) {
                  logger.debug("Acquiring 1 credit for EXPIRED_ACK_TYPE");
               }
               replenishCredit(1, false);
            }
         } else if (removeReferences) {

            Transaction originalTX = session.getCoreSession().getCurrentTransaction();
            Transaction transaction;

            if (originalTX == null) {
               transaction = session.getCoreSession().newTransaction();
            } else {
               transaction = originalTX;
            }
            transaction.addOperation(new TransactionOperationAbstract() {
               @Override
               public void afterCommit(Transaction tx) {
                  // these credits will only be requested if the commit actually succeeds
                  logger.debug("replenishing {} credits after committed", ackMessageCount);
                  replenishCredit(ackMessageCount, false);
               }
            });

            if (ack.isIndividualAck() || ack.isStandardAck()) {
               for (MessageReference ref : ackList) {
                  ref.acknowledge(transaction, serverConsumer);
                  serverConsumer.metricsAcknowledge(ref, transaction);
                  removeRolledback(ref);
               }
            } else if (ack.isPoisonAck()) {
               for (MessageReference ref : ackList) {
                  Throwable poisonCause = ack.getPoisonCause();
                  if (poisonCause != null) {
                     ((QueueImpl) ref.getQueue()).decDelivering(ref);
                     ref.getMessage().putStringProperty(OpenWireConstants.AMQ_MSG_DLQ_DELIVERY_FAILURE_CAUSE_PROPERTY, SimpleString.of(poisonCause.toString()));
                     ((QueueImpl) ref.getQueue()).incDelivering(ref);
                  }
                  ref.getQueue().sendToDeadLetterAddress(transaction, ref);
                  removeRolledback(ref);
               }
            }

            if (originalTX == null) {
               transaction.commit(true);
            }
         } else {
            logger.debug("Replenishing {} credits without any transaction (browsing perhaps)", ackMessageCount);
            replenishCredit(ackMessageCount, false);
         }
      }
   }

   public void browseFinished() {
      MessageDispatch md = new MessageDispatch();
      md.setConsumerId(info.getConsumerId());
      md.setMessage(null);
      md.setDestination(null);

      session.deliverMessage(md);
   }

   public ConsumerInfo getInfo() {
      return info;
   }

   public boolean hasCredits() {
      return currentWindow.get() > 0;
   }

   public void processMessagePull(MessagePull messagePull) throws Exception {
      currentWindow.incrementAndGet();
      if (logger.isDebugEnabled()) {
         logger.debug("Incremented credit for processMessagePull, current = {}", currentWindow.get());
      }
      MessagePullHandler pullHandler = messagePullHandler.get();
      if (pullHandler != null) {
         pullHandler.nextSequence(messagePullSequence++, messagePull.getTimeout());
      }
   }

   public void removeConsumer() throws Exception {
      serverConsumer.close(false);
      if (delayedDispatchPrompter != null) {
         delayedDispatchPrompter.cancel(false);
      }
      OpenWireConnection openWireConnection = session.getConnection();
      if (openWireConnection != null) {
         openWireConnection.block();
         session.getCoreSession().getSessionContext().executeOnCompletion(new IOCallback() {
            @Override
            public void done() {
               session.getConnection().unblock();
            }

            @Override
            public void onError(int errorCode, String errorMessage) {
               // because response required is false on a RemoveConsumerCommand, a new consumer could miss canceled prefetched messages
               // we await the operation context completion before handling a subsequent command
               session.getConnection().unblock();
            }
         });
      }
   }

   public org.apache.activemq.command.ActiveMQDestination getOpenwireDestination() {
      return openwireDestination;
   }

   public void setPrefetchSize(int prefetchSize) {
      this.prefetchSize = prefetchSize;
      this.currentWindow.set(prefetchSize);
      if (logger.isTraceEnabled()) {
         logger.trace("Updating credits with a new prefetchSize", prefetchSize, new Exception("trace"));
      }
      this.info.setPrefetchSize(prefetchSize);
      if (this.prefetchSize == 0) {
         messagePullHandler.compareAndSet(null, new MessagePullHandler());
      } else {
         messagePullHandler.set(null);
      }
      if (this.prefetchSize > 0) {
         serverConsumer.promptDelivery();
      }
   }

   public boolean updateDeliveryCountAfterCancel(MessageReference ref) {

      if (RemoveInfo.LAST_DELIVERED_UNKNOWN == info.getLastDeliveredSequenceId()) {
         // treat as delivered
         return true;
      }
      if (ref.getProtocolData(MessageId.class).getBrokerSequenceId() <= info.getLastDeliveredSequenceId() && !isRolledBack(ref)) {
         // treat as delivered
         return true;
      }
      // default behaviour
      return false;
   }

   /**
    * The MessagePullHandler is used with slow consumer policies.
    */
   private class MessagePullHandler {

      private volatile long next = -1;
      private long timeout;
      private CountDownLatch latch = new CountDownLatch(1);
      private ScheduledFuture<?> messagePullFuture;

      public void nextSequence(long next, long timeout) throws Exception {
         this.next = next;
         this.timeout = timeout;
         latch = new CountDownLatch(1);
         serverConsumer.forceDelivery(messagePullSequence);
         //if we are 0 timeout or less we need to wait to get either the forced message or a real message.
         if (timeout <= 0) {
            latch.await(10, TimeUnit.SECONDS);
            //this means we have received no message just the forced delivery message
            if (this.next >= 0) {
               handleDeliverNullDispatch();
            }
         }
      }

      public boolean checkForcedConsumer(Message message) {
         if (message.containsProperty(ClientConsumerImpl.FORCED_DELIVERY_MESSAGE)) {
            if (next >= 0) {
               if (timeout <= 0) {
                  // Prevent races with other updates that can lead to credit going negative and starving consumers.
                  currentWindow.updateAndGet(AMQConsumer::decrementWindow);
                  if (logger.isDebugEnabled()) {
                     logger.debug("UpdateCredit down on FORCED_DELIVERY, current after decrement={}", currentWindow.get());
                  }
                  latch.countDown();
               } else {
                  messagePullFuture = scheduledPool.schedule(() -> {
                     if (next >= 0) {
                        // Timed pull did not get a message before the timeout, reduce credit. This
                        // can race with an actual message arriving so we must ensure we don't reduce
                        // credit below zero as we want credit to always be zero or on active pull it
                        // should be one (greater than one indicates a broken client implementation).
                        currentWindow.updateAndGet(AMQConsumer::decrementWindow);
                        if (logger.isDebugEnabled()) {
                           logger.debug("UpdateCredit down on FORCED_DELIVERY, current after decrement={}", currentWindow.get());
                        }
                        handleDeliverNullDispatch();
                     }
                  }, timeout, TimeUnit.MILLISECONDS);
               }
            }
            return false;
         } else {
            next = -1;
            if (messagePullFuture != null) {
               messagePullFuture.cancel(true);
            }
            latch.countDown();
            return true;
         }
      }
   }

   public void removeRolledback(MessageReference messageReference) {
      final Set<MessageReference> rolledbackMessageRefs = getRolledbackMessageRefs();
      if (rolledbackMessageRefs != null) {
         rolledbackMessageRefs.remove(messageReference);
      }
   }

   public void addRolledback(MessageReference messageReference) {
      // Note:
      // We used to call currentWindow.decrement here.
      // this is not needed any more as we won't be taking credits unless a commit happened.

      getRolledbackMessageRefsOrCreate().add(messageReference);
   }

   private boolean isRolledBack(MessageReference messageReference) {
      final Set<MessageReference> rollbackedMessageRefs = getRolledbackMessageRefs();
      if (rollbackedMessageRefs == null) {
         return false;
      }
      return rollbackedMessageRefs.contains(messageReference);
   }
}
