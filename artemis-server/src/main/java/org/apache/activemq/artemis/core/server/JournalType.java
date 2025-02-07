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
package org.apache.activemq.artemis.core.server;


public enum JournalType {
   NIO, ASYNCIO, MAPPED;

   public static final String validValues;

   static {
      StringBuffer stringBuffer = new StringBuffer();
      for (JournalType type : JournalType.values()) {

         if (!stringBuffer.isEmpty()) {
            stringBuffer.append(",");
         }

         stringBuffer.append(type.name());
      }

      validValues = stringBuffer.toString();
   }

   public static JournalType getType(String type) {
      switch (type) {
         case "NIO": return NIO;
         case "ASYNCIO" : return ASYNCIO;
         case "MAPPED" : return MAPPED;
         default: throw new IllegalStateException("Invalid JournalType:" + type + " valid Types: " + validValues);
      }
   }

}
