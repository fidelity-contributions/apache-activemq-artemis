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
package org.apache.activemq.transport.failover;

import javax.jms.Connection;
import javax.net.ServerSocketFactory;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import org.apache.activemq.ActiveMQConnectionFactory;
import org.apache.activemq.util.Wait;
import org.junit.Assert;
import org.junit.Test;

public class SlowConnectionTest {

   private CountDownLatch socketReadyLatch = new CountDownLatch(1);

   @Test
   public void testSlowConnection() throws Exception {

      MockBroker broker = new MockBroker();
      broker.start();

      socketReadyLatch.await();
      int timeout = 1000;
      URI tcpUri = new URI("tcp://localhost:" + broker.ss.getLocalPort() + "?soTimeout=" + timeout + "&trace=true&connectionTimeout=" + timeout + "&wireFormat.maxInactivityDurationInitalDelay=" + timeout);

      ActiveMQConnectionFactory cf = new ActiveMQConnectionFactory("failover:(" + tcpUri + ")");
      final Connection connection = cf.createConnection();

      new Thread(() -> {
         try {
            connection.start();
         } catch (Throwable ignored) {
         }
      }).start();

      int count = 0;
      Assert.assertTrue("Transport count: " + count + ", expected <= 1", Wait.waitFor(() -> {
         int count1 = 0;
         for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (thread.getName().contains("ActiveMQ Transport")) {
               count1++;
            }
         }
         return count1 == 1;
      }));

      broker.interrupt();
      broker.join();
   }

   class MockBroker extends Thread {

      ServerSocket ss = null;

      public MockBroker() {
         super("MockBroker");
      }

      @Override
      public void run() {

         List<Socket> inProgress = new ArrayList<>();
         ServerSocketFactory factory = ServerSocketFactory.getDefault();

         try {
            ss = factory.createServerSocket(0);
            ss.setSoTimeout(5000);

            socketReadyLatch.countDown();
            while (!interrupted()) {
               inProgress.add(ss.accept());    // eat socket
            }
         } catch (java.net.SocketTimeoutException expected) {
         } catch (Exception e) {
            e.printStackTrace();
         } finally {
            try {
               ss.close();
            } catch (IOException ignored) {
            }
            for (Socket s : inProgress) {
               try {
                  s.close();
               } catch (IOException ignored) {
               }
            }
         }
      }
   }
}
