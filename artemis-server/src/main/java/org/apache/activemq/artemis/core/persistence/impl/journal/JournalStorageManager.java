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

package org.apache.activemq.artemis.core.persistence.impl.journal;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.activemq.artemis.api.core.ActiveMQBuffer;
import org.apache.activemq.artemis.api.core.ActiveMQException;
import org.apache.activemq.artemis.api.core.Message;
import org.apache.activemq.artemis.api.core.Pair;
import org.apache.activemq.artemis.api.core.SimpleString;
import org.apache.activemq.artemis.core.config.Configuration;
import org.apache.activemq.artemis.core.io.IOCallback;
import org.apache.activemq.artemis.core.io.IOCriticalErrorListener;
import org.apache.activemq.artemis.core.io.SequentialFile;
import org.apache.activemq.artemis.core.io.SequentialFileFactory;
import org.apache.activemq.artemis.core.io.aio.AIOSequentialFileFactory;
import org.apache.activemq.artemis.core.io.mapped.MappedSequentialFileFactory;
import org.apache.activemq.artemis.core.io.nio.NIOSequentialFileFactory;
import org.apache.activemq.artemis.core.journal.EncoderPersister;
import org.apache.activemq.artemis.core.journal.EncodingSupport;
import org.apache.activemq.artemis.core.journal.Journal;
import org.apache.activemq.artemis.core.journal.impl.JournalFile;
import org.apache.activemq.artemis.core.journal.impl.JournalImpl;
import org.apache.activemq.artemis.core.paging.PagedMessage;
import org.apache.activemq.artemis.core.paging.PagingManager;
import org.apache.activemq.artemis.core.paging.PagingStore;
import org.apache.activemq.artemis.core.persistence.OperationContext;
import org.apache.activemq.artemis.core.persistence.impl.journal.codec.LargeMessagePersister;
import org.apache.activemq.artemis.core.persistence.impl.journal.codec.RefEncoding;
import org.apache.activemq.artemis.core.protocol.core.impl.wireformat.ReplicationPrimaryIsStoppingMessage;
import org.apache.activemq.artemis.core.replication.ReplicatedJournal;
import org.apache.activemq.artemis.core.replication.ReplicationManager;
import org.apache.activemq.artemis.core.server.ActiveMQMessageBundle;
import org.apache.activemq.artemis.core.server.ActiveMQServerLogger;
import org.apache.activemq.artemis.core.server.JournalType;
import org.apache.activemq.artemis.core.server.LargeServerMessage;
import org.apache.activemq.artemis.core.server.files.FileStoreMonitor;
import org.apache.activemq.artemis.journal.ActiveMQJournalBundle;
import org.apache.activemq.artemis.spi.core.protocol.RemotingConnection;
import org.apache.activemq.artemis.utils.ArtemisCloseable;
import org.apache.activemq.artemis.utils.ExecutorFactory;
import org.apache.activemq.artemis.utils.critical.CriticalAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.lang.invoke.MethodHandles;

public class JournalStorageManager extends AbstractJournalStorageManager {

   private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
   public static final String ACTIVEMQ_DATA = "activemq-data";

   protected SequentialFileFactory journalFF;

   protected SequentialFileFactory bindingsFF;

   protected SequentialFileFactory largeMessagesFactory;

   protected Journal originalMessageJournal;

   protected Journal originalBindingsJournal;

   protected String largeMessagesDirectory;

   protected ReplicationManager replicator;

   public JournalStorageManager(final Configuration config,
                                final CriticalAnalyzer analyzer,
                                final ExecutorFactory executorFactory,
                                final ScheduledExecutorService scheduledExecutorService,
                                final ExecutorFactory ioExecutors) {
      this(config, analyzer, executorFactory, scheduledExecutorService, ioExecutors, null);
   }

   public JournalStorageManager(final Configuration config, CriticalAnalyzer analyzer, final ExecutorFactory executorFactory, final ExecutorFactory ioExecutors) {
      this(config, analyzer, executorFactory, null, ioExecutors, null);
   }

   public JournalStorageManager(final Configuration config,
                                final CriticalAnalyzer analyzer,
                                final ExecutorFactory executorFactory,
                                final ScheduledExecutorService scheduledExecutorService,
                                final ExecutorFactory ioExecutors,
                                final IOCriticalErrorListener criticalErrorListener) {
      super(config, analyzer, executorFactory, scheduledExecutorService, ioExecutors, criticalErrorListener);
   }

   public JournalStorageManager(final Configuration config,
                                final CriticalAnalyzer analyzer,
                                final ExecutorFactory executorFactory,
                                final ExecutorFactory ioExecutors,
                                final IOCriticalErrorListener criticalErrorListener) {
      super(config, analyzer, executorFactory, null, ioExecutors, criticalErrorListener);
   }

   @Override
   public Set<RemotingConnection> getUsedConnections() {
      if (replicator == null) {
         return Collections.emptySet();
      } else {
         HashSet<RemotingConnection> usedConnections = new HashSet<>();
         usedConnections.add(replicator.getBackupTransportConnection());
         return usedConnections;
      }
   }

   @Override
   public SequentialFileFactory getJournalSequentialFileFactory() {
      return journalFF;
   }

   @Override
   protected void init(Configuration config, IOCriticalErrorListener criticalErrorListener) {

      if (!EnumSet.allOf(JournalType.class).contains(config.getJournalType())) {
         throw ActiveMQMessageBundle.BUNDLE.invalidJournal();
      }

      bindingsFF = new NIOSequentialFileFactory(config.getBindingsLocation(), criticalErrorListener, config.getJournalMaxIO_NIO());
      bindingsFF.setDatasync(config.isJournalDatasync());

      Journal localBindings = new JournalImpl(ioExecutorFactory, 1024 * 1024, 2, config.getJournalPoolFiles(), config.getJournalCompactMinFiles(), config.getJournalCompactPercentage(), config.getJournalFileOpenTimeout(), bindingsFF, "activemq-bindings", "bindings", 1, 0, criticalErrorListener, config.getJournalMaxAtticFiles());

      bindingsJournal = localBindings;
      originalBindingsJournal = localBindings;

      switch (config.getJournalType()) {

         case NIO:
            if (criticalErrorListener != null) {
               ActiveMQServerLogger.LOGGER.journalUseNIO();
            }
            journalFF = new NIOSequentialFileFactory(config.getJournalLocation(), true, config.getJournalBufferSize_NIO(), config.getJournalBufferTimeout_NIO(), config.getJournalMaxIO_NIO(), config.isLogJournalWriteRate(), criticalErrorListener, getCriticalAnalyzer());
            break;
         case ASYNCIO:
            if (criticalErrorListener != null) {
               ActiveMQServerLogger.LOGGER.journalUseAIO();
            }
            journalFF = new AIOSequentialFileFactory(config.getJournalLocation(), config.getJournalBufferSize_AIO(), config.getJournalBufferTimeout_AIO(), config.getJournalMaxIO_AIO(), config.isLogJournalWriteRate(), criticalErrorListener, getCriticalAnalyzer());

            if (config.getJournalDeviceBlockSize() != null) {
               journalFF.setAlignment(config.getJournalDeviceBlockSize());
            }
            break;
         case MAPPED:
            if (criticalErrorListener != null) {
               ActiveMQServerLogger.LOGGER.journalUseMAPPED();
            }
            journalFF = new MappedSequentialFileFactory(config.getJournalLocation(), config.getJournalFileSize(), true, config.getJournalBufferSize_NIO(), config.getJournalBufferTimeout_NIO(), criticalErrorListener);
            break;
         default:
            throw ActiveMQMessageBundle.BUNDLE.invalidJournalType2(config.getJournalType());
      }

      journalFF.setDatasync(config.isJournalDatasync());


      int fileSize = fixJournalFileSize(config.getJournalFileSize(), journalFF.getAlignment());
      Journal localMessage = createMessageJournal(config, criticalErrorListener, fileSize);

      messageJournal = localMessage;
      messageJournal.replaceableRecord(JournalRecordIds.UPDATE_DELIVERY_COUNT);
      messageJournal.replaceableRecord(JournalRecordIds.SET_SCHEDULED_DELIVERY_TIME);

      originalMessageJournal = localMessage;

      largeMessagesDirectory = config.getLargeMessagesDirectory();

      largeMessagesFactory = new NIOSequentialFileFactory(config.getLargeMessagesLocation(), false, criticalErrorListener, 1);
   }

   /**
    * We need to correct the file size if its not a multiple of the alignement
    *
    * @param fileSize  : the configured file size.
    * @param alignment : the alignment.
    * @return the fixed file size
    */
   protected int fixJournalFileSize(int fileSize, int alignment) {
      int size = fileSize;
      if (fileSize <= alignment) {
         size = alignment;
      } else {
         int modulus = fileSize % alignment;
         if (modulus != 0) {
            int difference = modulus;
            int low = fileSize - difference;
            int high = low + alignment;
            size = difference < alignment / 2 ? low : high;
            ActiveMQServerLogger.LOGGER.invalidJournalFileSize(fileSize, size, alignment);
         }
      }
      return size;
   }

   protected Journal createMessageJournal(Configuration config,
                                        IOCriticalErrorListener criticalErrorListener,
                                        int fileSize) {
      return new JournalImpl(ioExecutorFactory, fileSize, config.getJournalMinFiles(), config.getJournalPoolFiles(), config.getJournalCompactMinFiles(), config.getJournalCompactPercentage(), config.getJournalFileOpenTimeout(), journalFF, ACTIVEMQ_DATA, "amq", journalFF.getMaxIO(), 0, criticalErrorListener, config.getJournalMaxAtticFiles());
   }

   // Life Cycle Handlers
   @Override
   protected void beforeStart() throws Exception {
      createDirectories();
      cleanupIncompleteFiles();
   }

   protected void createDirectories() {
      if (!config.isUsingDatabasePersistence()) {
         checkAndCreateDir(config.getBindingsLocation(), config.isCreateBindingsDir());
         checkAndCreateDir(config.getJournalLocation(), config.isCreateJournalDir());
         checkAndCreateDir(config.getLargeMessagesLocation(), config.isCreateJournalDir());
      }
   }

   @Override
   protected void beforeStop() throws Exception {
      if (replicator != null) {
         replicator.stop();
      }
   }

   @Override
   public void stop() throws Exception {
      stop(false, true);
   }

   @Override
   public boolean isReplicated() {
      return replicator != null && replicator.isStarted();
   }

   private void cleanupIncompleteFiles() throws Exception {
      if (largeMessagesFactory != null) {
         List<String> tmpFiles = largeMessagesFactory.listFiles("tmp");
         for (String tmpFile : tmpFiles) {
            SequentialFile file = largeMessagesFactory.createSequentialFile(tmpFile);
            file.delete();
         }
      }
   }

   @Override
   public void stop(boolean ioCriticalError, boolean sendFailover) throws Exception {
      try (ArtemisCloseable critical = measureCritical(CRITICAL_STOP)) {
         synchronized (this) {
            if (internalStop(ioCriticalError, sendFailover))
               return;
         }
      }
   }

   private boolean internalStop(boolean ioCriticalError, boolean sendFailover) throws Exception {
      if (!started) {
         return true;
      }

      if (!ioCriticalError) {
         performCachedLargeMessageDeletes();
         // Must call stop to make sure last id is persisted
         if (journalLoaded && idGenerator != null)
            idGenerator.stop();
      }

      final CountDownLatch latch = new CountDownLatch(1);
      try {
         executor.execute(latch::countDown);

         latch.await(30, TimeUnit.SECONDS);
      } catch (RejectedExecutionException ignored) {
         // that's ok
      }

      try (ArtemisCloseable critical = measureCritical(CRITICAL_STOP_2)) {
         storageManagerLock.writeLock().lock();
         try {

            // We cache the variable as the replicator could be changed between here and the time we call stop
            // since sendPrimaryIsStopping may issue a close back from the channel
            // and we want to ensure a stop here just in case
            ReplicationManager replicatorInUse = replicator;
            if (replicatorInUse != null) {
               if (sendFailover) {
                  final OperationContext token = replicator.sendPrimaryIsStopping(ReplicationPrimaryIsStoppingMessage.PrimaryStopping.FAIL_OVER);
                  if (token != null) {
                     try {
                        token.waitCompletion(5000);
                     } catch (Exception e) {
                        // ignore it
                     }
                  }
               }
               // we cannot clear replication tokens, otherwise clients will eventually be informed of completion during a server's shutdown
               // while the backup will never receive then
               replicatorInUse.stop(false);
            }
            bindingsJournal.stop();

            messageJournal.stop();

            journalLoaded = false;

            started = false;
         } finally {
            storageManagerLock.writeLock().unlock();
         }
      }
      return false;
   }

   /**
    * Assumption is that this is only called with a writeLock on the StorageManager.
    */
   @Override
   protected void performCachedLargeMessageDeletes() {
      storageManagerLock.writeLock().lock();
      try {
         largeMessagesToDelete.forEach((messageId, largeServerMessage) -> {
            SequentialFile msg = createFileForLargeMessage(messageId, LargeMessageExtension.DURABLE);
            try {
               msg.delete();
            } catch (Exception e) {
               ActiveMQServerLogger.LOGGER.journalErrorDeletingMessage(messageId, e);
            }
            if (replicator != null) {
               replicator.largeMessageDelete(messageId, JournalStorageManager.this);
            }
         });
         largeMessagesToDelete.clear();
      } finally {
         storageManagerLock.writeLock().unlock();
      }
   }

   @Override
   protected LargeServerMessage parseLargeMessage(final ActiveMQBuffer buff) throws Exception {
      LargeServerMessage largeMessage = createCoreLargeMessage();

      LargeMessagePersister.getInstance().decode(buff, largeMessage, null);

      largeMessage.setStorageManager(this);

      if (largeMessage.toMessage().containsProperty(Message.HDR_ORIG_MESSAGE_ID)) {
         // for compatibility: couple with old behaviour, copying the old file to avoid message loss
         long originalMessageID = largeMessage.toMessage().getLongProperty(Message.HDR_ORIG_MESSAGE_ID);

         SequentialFile currentFile = createFileForLargeMessage(largeMessage.toMessage().getMessageID(), true);

         if (!currentFile.exists()) {
            SequentialFile linkedFile = createFileForLargeMessage(originalMessageID, true);
            if (linkedFile.exists()) {
               linkedFile.copyTo(currentFile);
               linkedFile.close();
            }
         }

         currentFile.close();
      }

      return largeMessage;
   }

   @Override
   public void pageClosed(final SimpleString storeName, final long pageNumber) {
      if (isReplicated()) {
         try (ArtemisCloseable lock = closeableReadLock()) {
            if (isReplicated())
               replicator.pageClosed(storeName, pageNumber);
         }
      }
   }

   @Override
   public void pageDeleted(final SimpleString storeName, final long pageNumber) {
      if (isReplicated()) {
         try (ArtemisCloseable lock = closeableReadLock()) {
            if (isReplicated())
               replicator.pageDeleted(storeName, pageNumber);
         }
      }
   }

   @Override
   public void pageWrite(final SimpleString address, final PagedMessage message, final long pageNumber, boolean storageUp, boolean originallyReplicated) {
      if (messageJournal.isHistory()) {
         try (ArtemisCloseable lock = closeableReadLock()) {

            Message theMessage = message.getMessage();

            if (theMessage.isLargeMessage() && theMessage instanceof LargeServerMessageImpl) {
               messageJournal.appendAddEvent(theMessage.getMessageID(), JournalRecordIds.ADD_LARGE_MESSAGE, LargeMessagePersister.getInstance(), theMessage, false, getContext(false));
            } else {
               messageJournal.appendAddEvent(theMessage.getMessageID(), JournalRecordIds.ADD_MESSAGE_PROTOCOL, theMessage.getPersister(), theMessage, false, getContext(false));
            }
            for (long queueID : message.getQueueIDs()) {
               messageJournal.appendAddEvent(message.getMessage().getMessageID(), JournalRecordIds.ADD_REF, EncoderPersister.getInstance(), new RefEncoding(queueID), false, getContext(false));
            }
         } catch (Exception e) {
            logger.warn(e.getMessage(), e);
         }
      }

      if (isReplicated()) {
         try (ArtemisCloseable lock = closeableReadLock()) {
            if (isReplicated()) {
               replicator.pageWrite(address, message, pageNumber, storageUp);
            } else {
               if (originallyReplicated) {
                  // this is a case where we originally contemplated as replicated, so we have to discount it in case it is not any more
                  OperationContext context = OperationContextImpl.getContext();
                  if (context != null) {
                     context.replicationDone();
                  }
               }
            }
         }
      } else {
         if (originallyReplicated) {
            // this is a case where we originally contemplated as replicated, so we have to discount it in case it is not any more
            OperationContext context = OperationContextImpl.getContext();
            if (context != null) {
               context.replicationDone();
            }
         }
      }
   }

   @Override
   public ByteBuffer allocateDirectBuffer(int size) {
      return journalFF.allocateDirectBuffer(size);
   }

   @Override
   public void freeDirectBuffer(ByteBuffer buffer) {
      journalFF.releaseBuffer(buffer);
   }

   @Override
   public void largeMessageClosed(LargeServerMessage largeServerMessage) throws ActiveMQException {
      try (ArtemisCloseable lock = closeableReadLock()) {
         if (isReplicated()) {
            replicator.largeMessageClosed(largeServerMessage.toMessage().getMessageID(), JournalStorageManager.this);
         }
      }
   }

   @Override
   public void deleteLargeMessageBody(final LargeServerMessage largeServerMessage) throws ActiveMQException {
      final SequentialFile file = largeServerMessage.getAppendFile();
      if (file == null) {
         return;
      }

      if (largeServerMessage.toMessage().isDurable() && isReplicated()) {
         try (ArtemisCloseable lock = closeableReadLock()) {
            if (isReplicated() && replicator.isSynchronizing()) {
               largeMessagesToDelete.put(largeServerMessage.toMessage().getMessageID(), largeServerMessage);
               return;
            }
         }
      }
      Runnable deleteAction = () -> {
         try {
            try (ArtemisCloseable lock = closeableReadLock()) {
               if (replicator != null) {
                  replicator.largeMessageDelete(largeServerMessage.toMessage().getMessageID(), JournalStorageManager.this);
               }
               file.delete();
            }
         } catch (Exception e) {
            ActiveMQServerLogger.LOGGER.journalErrorDeletingMessage(largeServerMessage.toMessage().getMessageID(), e);
         }
      };

      getContext(true).executeOnCompletion(new IOCallback() {
         @Override
         public void done() {
            if (executor == null) {
               deleteAction.run();
            } else {
               executor.execute(deleteAction);
            }
         }

         @Override
         public void onError(int errorCode, String errorMessage) {

         }
      });
   }

   @Override
   public LargeServerMessage createCoreLargeMessage() {
      return new LargeServerMessageImpl(this);
   }

   @Override
   public LargeServerMessage createCoreLargeMessage(final long id, final Message message) throws Exception {
      if (logger.isTraceEnabled()) {
         logger.trace("Initializing large message {}", id, new Exception("trace"));
      }
      try (ArtemisCloseable lock = closeableReadLock()) {
         if (isReplicated()) {
            replicator.largeMessageBegin(id);
         }

         LargeServerMessageImpl largeMessage = (LargeServerMessageImpl) createCoreLargeMessage();

         largeMessage.moveHeadersAndProperties(message);

         return onLargeMessageCreate(id, largeMessage);
      }
   }

   @Override
   public LargeServerMessage onLargeMessageCreate(long id, LargeServerMessage largeMessage) throws Exception {
      largeMessage.setMessageID(id);

      // Check durable large massage size before to allocate resources if it can't be stored
      if (largeMessage.toMessage().isDurable()) {
         final long maxRecordSize = getMaxRecordSize();
         if (largeMessage instanceof LargeServerMessageImpl largeServerMessage) {
            final int messageEncodeSize = largeServerMessage.getEncodeSize();

            if (messageEncodeSize > maxRecordSize) {
               ActiveMQServerLogger.LOGGER.messageWithHeaderTooLarge(largeMessage.getMessageID(), logger.getName());

               logger.debug("Message header too large for {}", largeMessage);

               throw ActiveMQJournalBundle.BUNDLE.recordLargerThanStoreMax(messageEncodeSize, maxRecordSize);
            }
         }
      }

      return largeMessage;
   }

   @Override
   public SequentialFile createFileForLargeMessage(final long messageID, LargeMessageExtension extension) {
      return largeMessagesFactory.createSequentialFile(messageID + extension.getExtension());
   }

   /**
    * Send an entire journal file to a replicating backup server.
    */
   private void sendJournalFile(JournalFile[] journalFiles, JournalContent type) throws Exception {
      for (JournalFile jf : journalFiles) {
         if (!started)
            return;

         ReplicationManager replicatorInUse = replicator;
         if (replicatorInUse == null) {
            throw ActiveMQMessageBundle.BUNDLE.replicatorIsNull();
         }

         replicatorInUse.syncJournalFile(jf, type);
      }
   }

   private JournalFile[] prepareJournalForCopy(Journal journal,
                                               JournalContent contentType,
                                               String nodeID,
                                               boolean autoFailBack) throws Exception {
      journal.forceMoveNextFile();
      JournalFile[] datafiles = journal.getDataFiles();
      replicator.sendStartSyncMessage(datafiles, contentType, nodeID, autoFailBack);
      return datafiles;
   }

   void setReplicator(ReplicationManager replicator) {
      this.replicator = replicator;
   }

   @Override
   public void startReplication(ReplicationManager replicationManager,
                                PagingManager pagingManager,
                                String nodeID,
                                final boolean autoFailBack,
                                long initialReplicationSyncTimeout) throws Exception {
      if (!started) {
         throw new IllegalStateException("JournalStorageManager must be started...");
      }
      assert replicationManager != null;

      if (!(originalMessageJournal instanceof JournalImpl) || !(originalBindingsJournal instanceof JournalImpl)) {
         throw ActiveMQMessageBundle.BUNDLE.notJournalImpl();
      }

      // We first do a compact without any locks, to avoid copying unnecessary data over the network.
      // We do this without holding the storageManager lock, so the journal stays open while compact is being done
      originalMessageJournal.scheduleCompactAndBlock(-1);
      originalBindingsJournal.scheduleCompactAndBlock(-1);

      JournalFile[] messageFiles = null;
      JournalFile[] bindingsFiles = null;

      // We get a picture of the current situation on the large messages
      // and we send the current messages while more state is coming
      Map<Long, Pair<String, Long>> pendingLargeMessages = null;

      try {
         Map<SimpleString, Collection<Integer>> pageFilesToSync;

         // We need to get this lock here in order to
         // avoid a clash with Page.cleanup();
         // This was a fix part of https://issues.apache.org/jira/browse/ARTEMIS-3054
         pagingManager.lock();
         storageManagerLock.writeLock().lock();
         try {
            if (isReplicated()) {
               throw ActiveMQMessageBundle.BUNDLE.alreadyReplicating(replicator.isStarted());
            }
            replicator = replicationManager;

            ((JournalImpl) originalMessageJournal).flushAppendExecutor(10, TimeUnit.SECONDS);
            ((JournalImpl) originalBindingsJournal).flushAppendExecutor(10, TimeUnit.SECONDS);

            // Establishes lock
            originalMessageJournal.synchronizationLock();
            originalBindingsJournal.synchronizationLock();

            try {
               originalBindingsJournal.replicationSyncPreserveOldFiles();
               originalMessageJournal.replicationSyncPreserveOldFiles();

               pagingManager.disableCleanup();
               messageFiles = prepareJournalForCopy(originalMessageJournal, JournalContent.MESSAGES, nodeID, autoFailBack);
               bindingsFiles = prepareJournalForCopy(originalBindingsJournal, JournalContent.BINDINGS, nodeID, autoFailBack);
               pageFilesToSync = getPageInformationForSync(pagingManager);
               pendingLargeMessages = recoverPendingLargeMessages();
            } finally {
               originalMessageJournal.synchronizationUnlock();
               originalBindingsJournal.synchronizationUnlock();
            }
            bindingsJournal = new ReplicatedJournal(((byte) 0), originalBindingsJournal, replicator);
            messageJournal = new ReplicatedJournal((byte) 1, originalMessageJournal, replicator);

            // We need to send the list while locking otherwise part of the body might get sent too soon
            // it will send a list of IDs that we are allocating
            replicator.sendLargeMessageIdListMessage(pendingLargeMessages);
         } finally {
            storageManagerLock.writeLock().unlock();
            pagingManager.unlock();
         }

         sendJournalFile(messageFiles, JournalContent.MESSAGES);
         sendJournalFile(bindingsFiles, JournalContent.BINDINGS);
         sendLargeMessageFiles(pendingLargeMessages);
         sendPagesToBackup(pageFilesToSync, pagingManager);

         storageManagerLock.writeLock().lock();
         try {
            if (replicator != null) {
               replicator.sendSynchronizationDone(nodeID, initialReplicationSyncTimeout, ioCriticalErrorListener);
               performCachedLargeMessageDeletes();
            }
         } finally {
            storageManagerLock.writeLock().unlock();
         }
      } catch (Exception e) {
         ActiveMQServerLogger.LOGGER.unableToStartReplication(e);
         stopReplication();
         throw e;
      } finally {
         // Re-enable compact and reclaim of journal files
         originalBindingsJournal.replicationSyncFinished();
         originalMessageJournal.replicationSyncFinished();
         pagingManager.resumeCleanup();
      }
   }

   private void sendLargeMessageFiles(final Map<Long, Pair<String, Long>> pendingLargeMessages) throws Exception {
      Iterator<Map.Entry<Long, Pair<String, Long>>> iter = pendingLargeMessages.entrySet().iterator();
      while (started && iter.hasNext()) {
         Map.Entry<Long, Pair<String, Long>> entry = iter.next();
         String fileName = entry.getValue().getA();
         final long id = entry.getKey();
         long size = entry.getValue().getB();
         SequentialFile seqFile = largeMessagesFactory.createSequentialFile(fileName);
         if (!seqFile.exists())
            continue;

         ReplicationManager replicatorInUse = replicator;
         if (replicatorInUse == null) {
            throw ActiveMQMessageBundle.BUNDLE.replicatorIsNull();
         }

         replicatorInUse.syncLargeMessageFile(seqFile, size, id);
      }
   }

   private Map<SimpleString, Collection<Integer>> getPageInformationForSync(PagingManager pagingManager) throws Exception {
      Map<SimpleString, Collection<Integer>> info = new HashMap<>();
      for (SimpleString storeName : pagingManager.getStoreNames()) {
         PagingStore store = pagingManager.getPageStore(storeName);
         Collection<Integer> ids = store.getCurrentIds();
         info.put(storeName, ids);
         if (!ids.isEmpty()) {
            store.forceAnotherPage();
         }
      }
      return info;
   }

   private void checkAndCreateDir(final File dir, final boolean create) {
      if (!dir.exists()) {
         if (create) {
            if (!dir.mkdirs() && !dir.exists()) {
               throw new IllegalStateException("Failed to create directory " + dir);
            }
         } else {
            throw ActiveMQMessageBundle.BUNDLE.cannotCreateDir(dir.getAbsolutePath());
         }
      }
   }

   /**
    * Sets a list of large message files into the replicationManager for synchronization.
    * <p>
    * Collects a list of existing large messages and their current size, passing re.
    * <p>
    * So we know how much of a given message to sync with the backup. Further data appends to the messages will be
    * replicated normally.
    */
   private Map<Long, Pair<String, Long>> recoverPendingLargeMessages() throws Exception {

      Map<Long, Pair<String, Long>> largeMessages = new HashMap<>();
      // only send durable messages... // listFiles append a "." to anything...
      List<String> filenames = largeMessagesFactory.listFiles("msg");

      for (String filename : filenames) {
         long id = getLargeMessageIdFromFilename(filename);
         if (!largeMessagesToDelete.containsKey(id)) {
            SequentialFile seqFile = largeMessagesFactory.createSequentialFile(filename);
            long size = seqFile.size();
            largeMessages.put(id, new Pair<>(filename, size));
         }
      }

      return largeMessages;
   }

   @Override
   public void recoverLargeMessagesOnFolder(Set<Long> storedLargeMessages) throws Exception {
      List<String> filenames = largeMessagesFactory.listFiles("msg");
      filenames.forEach(f -> {
         storedLargeMessages.add(getLargeMessageIdFromFilename(f));
      });
   }

   private void sendPagesToBackup(Map<SimpleString, Collection<Integer>> pageFilesToSync,
                                  PagingManager manager) throws Exception {
      for (Map.Entry<SimpleString, Collection<Integer>> entry : pageFilesToSync.entrySet()) {
         if (!started)
            return;

         ReplicationManager replicatorInUse = replicator;
         if (replicatorInUse == null) {
            throw ActiveMQMessageBundle.BUNDLE.replicatorIsNull();
         }

         PagingStore store = manager.getPageStore(entry.getKey());
         store.sendPages(replicatorInUse, entry.getValue());
      }
   }

   private long getLargeMessageIdFromFilename(String filename) {
      return Long.parseLong(filename.split("\\.")[0]);
   }

   /**
    * Stops replication by resetting replication-related fields to their 'unreplicated' state.
    */
   @Override
   public void stopReplication() {
      logger.trace("stopReplication()");
      storageManagerLock.writeLock().lock();
      try {
         if (replicator == null)
            return;
         bindingsJournal = originalBindingsJournal;
         messageJournal = originalMessageJournal;
         try {
            replicator.stop();
         } catch (Exception e) {
            ActiveMQServerLogger.LOGGER.errorStoppingReplicationManager(e);
         }
         replicator = null;
         // delete inside the writeLock. Avoids a lot of state checking and races with
         // startReplication.
         // This method should not be called under normal circumstances
         performCachedLargeMessageDeletes();
      } finally {
         storageManagerLock.writeLock().unlock();
      }
   }

   @Override
   public void addBytesToLargeMessage(final SequentialFile file,
                                            final long messageId,
                                            final ActiveMQBuffer bytes) throws Exception {
      try (ArtemisCloseable lock = closeableReadLock()) {
         if (messageJournal.isHistory()) {
            BufferSplitter.split(bytes, 10 * 1024, (c) -> historyBody(messageId, c));
         }
         file.position(file.size());
         if (bytes.byteBuf() != null && bytes.byteBuf().nioBufferCount() == 1) {
            final ByteBuffer nioBytes = bytes.byteBuf().internalNioBuffer(bytes.readerIndex(), bytes.readableBytes());
            file.blockingWriteDirect(nioBytes, false, false);

            if (isReplicated()) {
               //copy defensively bytes
               final byte[] bytesCopy = new byte[bytes.readableBytes()];
               bytes.getBytes(bytes.readerIndex(), bytesCopy);
               replicator.largeMessageWrite(messageId, bytesCopy);
            }
         } else {
            final byte[] bytesCopy = new byte[bytes.readableBytes()];
            bytes.readBytes(bytesCopy);
            addBytesToLargeMessage(file, messageId, bytesCopy);
         }
      }
   }

   private void historyBody(long messageId, EncodingSupport partialBuffer) {

      try {
         messageJournal.appendAddEvent(messageId, JournalRecordIds.ADD_MESSAGE_BODY, EncoderPersister.getInstance(), partialBuffer, false, null);
      } catch (Exception e) {
         logger.warn("Error processing history large message body for {}", messageId, e);
      }

   }

   @Override
   public void addBytesToLargeMessage(final SequentialFile file,
                                            final long messageId,
                                            final byte[] bytes) throws Exception {
      try (ArtemisCloseable lock = closeableReadLock()) {
         if (messageJournal.isHistory()) {
            BufferSplitter.split(bytes, 10 * 1024, (c) -> historyBody(messageId, c));
         }
         file.position(file.size());
         //that's an additional precaution to avoid ByteBuffer to be pooled:
         //NIOSequentialFileFactory doesn't pool heap ByteBuffer, but better to make evident
         //the intention by calling the right method
         file.blockingWriteDirect(ByteBuffer.wrap(bytes), false, false);

         if (isReplicated()) {
            replicator.largeMessageWrite(messageId, bytes);
         }
      }
   }

   @Override
   public void injectMonitor(FileStoreMonitor monitor) throws Exception {
      if (journalFF != null) {
         monitor.addStore(journalFF.getDirectory());
      }
      if (largeMessagesFactory != null) {
         monitor.addStore(largeMessagesFactory.getDirectory());
      }
      if (bindingsFF != null) {
         monitor.addStore(bindingsFF.getDirectory());
      }
   }

   @Override
   public int getAllowedPageSize(int pageSize)  {
      if (config.getStoreConfiguration() == null) {
         return pageSize;
      }
      return config.getStoreConfiguration().getAllowedPageSize(pageSize);
   }

}
