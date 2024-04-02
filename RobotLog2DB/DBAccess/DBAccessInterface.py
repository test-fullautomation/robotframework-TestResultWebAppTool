#  Copyright 2020-2024 Robert Bosch GmbH
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# ******************************************************************************
#
# File: DBAccessInterface.py
#
# Initialy created by Tran Duy Ngoan / March 2024
#
# This interface defines required methods to access TestResultWebapp' database.
#
# History:
#
# March 2024:
#  - initial version
#
# ******************************************************************************

from abc import ABCMeta, abstractmethod

class DBAccess(object):
   __metaclass__ = ABCMeta
   @abstractmethod
   def connect(self, host, user, passwd, database, charset):
      pass

   @abstractmethod
   def disconnect(self):
      pass

   # Only used for DirectDBAccess which has a transaction 
   def commit(self):
      pass

   # Methods to retrieve (GET) information from database
   @abstractmethod
   def arGetCategories(self):
      pass

   @abstractmethod
   def bExistingResultID(self):
      pass

   @abstractmethod
   def sGetLatestFileID(self):
      pass

   # Methods to create new record(s) (POST) in database
   @abstractmethod
   def sCreateNewTestResult(self):
      pass

   @abstractmethod
   def nCreateNewFile(self):
      pass

   @abstractmethod
   def vCreateNewHeader(self):
      pass

   @abstractmethod
   def nCreateNewSingleTestCase(self):
      pass

   @abstractmethod
   def nCreateNewTestCase(self):
      pass

   @abstractmethod
   def vCreateAbortReason(self):
      pass

   @abstractmethod
   def vCreateCCRdata(self):
      pass

   @abstractmethod
   def vCreateTags(self):
      pass

   # Methods to update existing record (PUT) in database
   @abstractmethod
   def vCreateReanimation(self):
      pass

   @abstractmethod
   def vSetCategory(self):
      pass

   @abstractmethod
   def vUpdateFileEndTime(self):
      pass

   @abstractmethod
   def vUpdateResultEndTime(self):
      pass

   # Methods to call Stored Procedures of database
   @abstractmethod
   def vUpdateEvtbl(self):
      pass

   @abstractmethod
   def vUpdateEvtbls(self):
      pass

   @abstractmethod
   def vFinishTestResult(self):
      pass