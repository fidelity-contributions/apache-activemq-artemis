/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.activemq;

import javax.jms.JMSException;
import javax.jms.Session;

import junit.framework.TestCase;

public class ConnectionCloseMultipleTimesTest extends TestCase {

   private ActiveMQConnection connection;

   @Override
   protected void setUp() throws Exception {
      ActiveMQConnectionFactory factory = new ActiveMQConnectionFactory("vm://localhost");
      connection = (ActiveMQConnection) factory.createConnection();
      connection.start();
   }

   @Override
   protected void tearDown() throws Exception {
      if (connection.isStarted()) {
         connection.stop();
      }
   }

   public void testCloseMultipleTimes() throws JMSException {
      connection.createSession(false, Session.AUTO_ACKNOWLEDGE);

      assertTrue(connection.isStarted());
      assertFalse(connection.isClosed());

      connection.close();

      assertFalse(connection.isStarted());
      assertTrue(connection.isClosed());

      // should not fail calling again
      connection.close();

      assertFalse(connection.isStarted());
      assertTrue(connection.isClosed());
   }

}
