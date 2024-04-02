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
# This factory helps to create the appropriate DBAccess interface 
# due to given access method.
#
# History:
#
# March 2024:
#  - initial version
#
# ******************************************************************************

from .DBAccess import DirectDBAccess, RestApiDBAccess

class DBAccessFactory:
   def create(self, access_method):
      if access_method == "db":
         return DirectDBAccess()
      elif access_method == "rest":
         return RestApiDBAccess()
      else:
         raise ValueError("Invalid access_method argument")