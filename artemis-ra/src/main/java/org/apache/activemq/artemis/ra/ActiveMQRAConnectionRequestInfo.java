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
package org.apache.activemq.artemis.ra;

import javax.jms.Session;
import javax.resource.spi.ConnectionRequestInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.lang.invoke.MethodHandles;

/**
 * Connection request information
 */
public class ActiveMQRAConnectionRequestInfo implements ConnectionRequestInfo {

   private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

   /**
    * The user name
    */
   private String userName;

   /**
    * The password
    */
   private String password;

   /**
    * The client id
    */
   private String clientID;

   /**
    * The type
    */
   private final int type;

   /**
    * Use transactions
    */
   private final boolean transacted;

   /**
    * The acknowledge mode
    */
   private final int acknowledgeMode;

   /**
    * Constructor
    *
    * @param prop The resource adapter properties
    * @param type The connection type
    */
   public ActiveMQRAConnectionRequestInfo(final ActiveMQRAProperties prop, final int type) {
      logger.trace("constructor({})", prop);

      userName = prop.getUserName();
      password = prop.getPassword();
      clientID = prop.getClientID();
      this.type = type;
      transacted = true;
      acknowledgeMode = Session.AUTO_ACKNOWLEDGE;
   }

   /**
    * Constructor
    *
    * @param transacted      Use transactions
    * @param acknowledgeMode The acknowledge mode
    * @param type            The connection type
    */
   public ActiveMQRAConnectionRequestInfo(final boolean transacted, final int acknowledgeMode, final int type) {
      if (logger.isTraceEnabled()) {
         logger.trace("constructor({}, {}, {})", transacted, acknowledgeMode, type);
      }

      this.transacted = transacted;
      this.acknowledgeMode = acknowledgeMode;
      this.type = type;
   }

   /**
    * Fill in default values if they are missing
    *
    * @param prop The resource adapter properties
    */
   public void setDefaults(final ActiveMQRAProperties prop) {
      logger.trace("setDefaults({})", prop);

      if (userName == null) {
         userName = prop.getUserName();
      }
      if (password == null) {
         password = prop.getPassword();
      }
      if (clientID == null) {
         clientID = prop.getClientID();
      }
   }

   /**
    * Get the user name
    *
    * @return The value
    */
   public String getUserName() {
      logger.trace("getUserName()");

      return userName;
   }

   /**
    * Set the user name
    *
    * @param userName The value
    */
   public void setUserName(final String userName) {
      logger.trace("setUserName({})", userName);

      this.userName = userName;
   }

   /**
    * Get the password
    *
    * @return The value
    */
   public String getPassword() {
      logger.trace("getPassword()");

      return password;
   }

   /**
    * Set the password
    *
    * @param password The value
    */
   public void setPassword(final String password) {
      logger.trace("setPassword(****)");

      this.password = password;
   }

   /**
    * Get the client id
    *
    * @return The value
    */
   public String getClientID() {
      logger.trace("getClientID()");

      return clientID;
   }

   /**
    * Set the client id
    *
    * @param clientID The value
    */
   public void setClientID(final String clientID) {
      logger.trace("setClientID({})", clientID);

      this.clientID = clientID;
   }

   /**
    * Get the connection type
    *
    * @return The type
    */
   public int getType() {
      logger.trace("getType()");

      return type;
   }

   /**
    * Use transactions
    *
    * @return True if transacted; otherwise false
    */
   public boolean isTransacted() {
      if (logger.isTraceEnabled()) {
         logger.trace("isTransacted() {}", transacted);
      }

      return transacted;
   }

   /**
    * Get the acknowledge mode
    *
    * @return The mode
    */
   public int getAcknowledgeMode() {
      logger.trace("getAcknowledgeMode()");

      return acknowledgeMode;
   }

   /**
    * Indicates whether some other object is "equal to" this one.
    *
    * @param obj Object with which to compare
    * @return True if this object is the same as the obj argument; false otherwise.
    */
   @Override
   public boolean equals(final Object obj) {
      logger.trace("equals({})", obj);

      if (obj == null) {
         return false;
      }

      if (obj instanceof ActiveMQRAConnectionRequestInfo requestInfo) {
         return ActiveMQRaUtils.compare(userName, requestInfo.getUserName()) && ActiveMQRaUtils.compare(password, requestInfo.getPassword()) &&
            ActiveMQRaUtils.compare(clientID, requestInfo.getClientID()) &&
            type == requestInfo.getType() &&
            transacted == requestInfo.isTransacted() &&
            acknowledgeMode == requestInfo.getAcknowledgeMode();
      } else {
         return false;
      }
   }

   /**
    * Return the hash code for the object
    *
    * @return The hash code
    */
   @Override
   public int hashCode() {
      logger.trace("hashCode()");

      int hash = 7;

      hash += 31 * hash + (userName != null ? userName.hashCode() : 0);
      hash += 31 * hash + (password != null ? password.hashCode() : 0);
      hash += 31 * hash + Integer.valueOf(type).hashCode();
      hash += 31 * hash + (transacted ? 1 : 0);
      hash += 31 * hash + Integer.valueOf(acknowledgeMode).hashCode();

      return hash;
   }

   @Override
   public String toString() {
      return "ActiveMQRAConnectionRequestInfo[type=" + type +
         ", transacted=" + transacted + ", acknowledgeMode=" + acknowledgeMode +
         ", clientID=" + clientID + ", userName=" + userName + ", password=****]";
   }
}
