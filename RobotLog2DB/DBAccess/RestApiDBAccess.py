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
# File: RestApiDBAccess.py
#
# Initialy created by Tran Duy Ngoan / March 2024
#
# This class provides methods to interact with TestResultWebApp's REST APIs.
#
# History:
#
# March 2024:
#  - initial version
#
# ******************************************************************************

import requests
from .DBAccessInterface import DBAccess
from requests_kerberos import HTTPKerberosAuth, OPTIONAL
import ssl
import tempfile

from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)

class RestApiDBAccess(DBAccess):
   def __init__(self):
      self.session  = requests.Session()
      self.base_url = ""
      self.session.headers = {
         "Content-Type": "application/json"
      }
      self.cookies = {}
   
   @property
   def certs_file(self):
      context = ssl.create_default_context() 
      der_certs = context.get_ca_certs(binary_form=True) 
      pem_certs = [ssl.DER_cert_to_PEM_cert(der) for der in der_certs] 
      if len(pem_certs):
         with tempfile.NamedTemporaryFile(mode='w', delete=False) as outfile: 
            path2pem = outfile.name
            for pem in pem_certs:
               outfile.write("{}\n".format(pem))

         return path2pem
      else:
         return False

   @staticmethod
   def encrypt_password(password, pubkey):
      from cryptography.hazmat.primitives import serialization, hashes
      from cryptography.hazmat.primitives.asymmetric import padding
      from cryptography.hazmat.backends import default_backend
      from base64 import b64encode

      try:
         keyPub = serialization.load_pem_public_key(pubkey.encode('utf-8'), backend=default_backend())
         encypted_Data = keyPub.encrypt(
            password.encode('utf-8'),
            padding.PKCS1v15()
         )
         return b64encode(encypted_Data).decode('utf-8', errors='ignore')
      except Exception as error:
         raise Exception("Cannot encrypt given password with public key. Reason: {}".format(error))

   # Methods to handle api request
   def __get_request(self, resource, payload=None):
      res = self.session.get("{}/{}".format(self.base_url, resource), allow_redirects=True, 
                             verify=self.certs_file)
      if res.status_code == 200 and res.json()['success']:
         return res.json()['data']
      else:
         # raise Exception(res.json()['message'])
         return None
   
   def __post_request(self, resource, payload=None):
      res = self.session.post("{}/{}".format(self.base_url, resource), json=payload, 
                              allow_redirects=True, verify=self.certs_file)
      if res.status_code == 201 and res.json()['success']:
         return res.json()['data']
      else:
         raise Exception(res.json()['message'])

   def __patch_request(self, resource, resource_id, payload=None):
      res = self.session.patch("{}/{}/{}".format(self.base_url, resource, resource_id), 
                               json=payload, allow_redirects=True, verify=self.certs_file)
      
      if res.status_code == 200 and res.json()['success']:
         return res.json()['data']
      else:
         raise Exception(res.json()['message'])

   def __get_wam_cookies(self):
      try:
         # Try with kerberos
         kerberos_auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
         res = self.session.get("{}/loggedin".format(self.base_url), auth=kerberos_auth, allow_redirects=True, 
                              verify=self.certs_file)
         if res.status_code == 200:
            # Authorized session is reused for later requests
            return
      except Exception as err:
         raise Exception("Cannot access API server. Reason: {}".format(err))

   # Implementation of interface's methods
   #
   def connect(self, host, user, passwd, database, charset):
      self.base_url = "{}/{}".format(host, database)

      self.__get_wam_cookies()
      try:
         res = self.session.get("{}/getPubKey".format(self.base_url), allow_redirects=True, 
                                verify=self.certs_file)
         # print res.status_code
         pubkey = res.json()['pubKey']

      except Exception as err:
         raise Exception("Failed to get public key. Reason: {}".format(err))

      # Reponse payload with encrypted password
      req_body = {
         'usr': user,
         'pwd': self.encrypt_password(passwd, pubkey),
         'dom': '',
      }

      res = self.session.post("{}/login".format(self.base_url), allow_redirects=True, json=req_body, 
                              verify=self.certs_file)
      if res.json()['data'] == "login_success":
         print("  > Login successfully!")
      else:
         raise Exception('Login failed!')

   def disconnect(self):
      res = self.session.get(self.base_url+'/logout', allow_redirects=True, verify=self.certs_file)
      if res.status_code == 200:
         print("  > Logout successfully!")
      else:
         raise Exception('Logout failed!')

   # Methods to retrieve (GET) information from database
   def arGetCategories(self):
      data = self.__get_request('categories')
      if data:
         return list(map(lambda item: item['category'],data))
      else:
         return []

   def bExistingResultID(self, result_id):
      data = self.__get_request('results/{}'.format(result_id))
      if data:
         return True
      return False

   def sGetLatestFileID(self, result_id=None):
      request_url = 'files/last'
      if result_id:
         request_url = 'files/last?test_result_id={}'.format(result_id)
      data = self.__get_request(request_url)
      if data and ('id' in data) and data['id']:
         return data['id']
      else:
         raise Exception("Cannot get latest file_id")
   
   def arGetProjectVersionSWByID(self, result_id):
      data = self.__get_request('results/{}'.format(result_id))
      if data:
         return (data['project'], data['version_sw_target'])
      return None

   # Methods to create new record(s) (POST) in database
   def sCreateNewTestResult(self, project, variant, branch, 
                                  result_id,
                                  result_interpretation,
                                  result_start_time,
                                  result_end_time,
                                  result_version_sw_target,
                                  result_version_sw_test,
                                  result_version_hw,
                                  result_build_url,
                                  result_report_qualitygate
                                  ):
      data_prj = self.__get_request('projects?project={}&variant={}&branch={}'.format(project, variant, branch))
      if not data_prj:
         req_prj = {
            "project": project,
            "variant": variant,
            "branch": branch
         }
         self.__post_request('projects', req_prj)
      
      req_result = {
         "test_result_id" : result_id,
         "project" : project,
         "variant" : variant,
         "branch" : branch,
         "time_start" : result_start_time,
         "time_end" : result_end_time,
         "version_sw_target" : result_version_sw_target,
         "version_sw_test" : result_version_sw_test,
         "version_hardware" : result_version_hw,
         "jenkinsurl" : result_build_url,
         "reporting_qualitygate" : result_report_qualitygate,
         "interpretation" : result_interpretation,
         "result_state" : "in progress"
      }
      data = self.__post_request('results', req_result)

      return result_id

   def nCreateNewFile(self, file_name,
                            file_tester_account,
                            file_tester_machine,
                            file_time_start,
                            file_time_end,
                            result_id,
                            file_origin="ROBFW"):
      req_file = {
         "test_result_id" : result_id,
         "name" : file_name,
         "tester_account" : file_tester_account,
         "tester_machine" : file_tester_machine,
         "time_start" : file_time_start,
         "time_end" : file_time_end,
         "origin" : file_origin
      }
      data = self.__post_request('files', req_file)
      return data['id']

   def vCreateNewHeader(self, file_id,
                              testtoolconfiguration_testtoolname,
                              testtoolconfiguration_testtoolversionstring,
                              testtoolconfiguration_projectname,
                              testtoolconfiguration_logfileencoding,
                              testtoolconfiguration_pythonversion,
                              testtoolconfiguration_testfile,
                              testtoolconfiguration_logfilepath,
                              testtoolconfiguration_logfilemode,
                              testtoolconfiguration_ctrlfilepath,
                              testtoolconfiguration_configfile,
                              testtoolconfiguration_confname,
                           
                              testfileheader_author,
                              testfileheader_project,
                              testfileheader_testfiledate,
                              testfileheader_version_major,
                              testfileheader_version_minor,
                              testfileheader_version_patch,
                              testfileheader_keyword,
                              testfileheader_shortdescription,
                              testexecution_useraccount,
                              testexecution_computername,
                           
                              testrequirements_documentmanagement,
                              testrequirements_testenvironment,
                           
                              testbenchconfig_name,
                              testbenchconfig_data,
                              preprocessor_filter,
                              preprocessor_parameters ):
      req_fileheader = {
         "file_id" : int(file_id),
         "testtoolconfiguration_testtoolname" : testtoolconfiguration_testtoolname,
         "testtoolconfiguration_testtoolversionstring" : testtoolconfiguration_testtoolversionstring,
         "testtoolconfiguration_projectname" : testtoolconfiguration_projectname,
         "testtoolconfiguration_logfileencoding" : testtoolconfiguration_logfileencoding,
         "testtoolconfiguration_pythonversion" : testtoolconfiguration_pythonversion,
         "testtoolconfiguration_testfile" : testtoolconfiguration_testfile,
         "testtoolconfiguration_logfilepath" : testtoolconfiguration_logfilepath,
         "testtoolconfiguration_logfilemode" : testtoolconfiguration_logfilemode,
         "testtoolconfiguration_ctrlfilepath" : testtoolconfiguration_ctrlfilepath,
         "testtoolconfiguration_configfile" : testtoolconfiguration_configfile,
         "testtoolconfiguration_confname" : testtoolconfiguration_confname,
         "testfileheader_author" : testfileheader_author,
         "testfileheader_project" : testfileheader_project,
         "testfileheader_testfiledate" : testfileheader_testfiledate,
         "testfileheader_version_major" : testfileheader_version_major,
         "testfileheader_version_minor" : testfileheader_version_minor,
         "testfileheader_version_patch" : testfileheader_version_patch,
         "testfileheader_keyword" : testfileheader_keyword,
         "testfileheader_shortdescription" : testfileheader_shortdescription,
         "testexecution_useraccount" : testexecution_useraccount,
         "testexecution_computername" : testexecution_computername,
         "testrequirements_documentmanagement" : testrequirements_documentmanagement,
         "testrequirements_testenvironment" : testrequirements_testenvironment,
         "testbenchconfig_name" : testbenchconfig_name,
         "testbenchconfig_data" : testbenchconfig_data,
         "preprocessor_parameters" : preprocessor_parameters,
         "preprocessor_filter" : preprocessor_filter
      }
      data = self.__post_request('fileheaders', req_fileheader)

   def nCreateNewSingleTestCase(self, case_name,
                                      case_issue,
                                      case_tcid,
                                      case_fid,
                                      case_testnumber,
                                      case_repeatcount,
                                      case_component,
                                      case_time_start,
                                      case_result_main,
                                      case_result_state,
                                      case_result_return,
                                      case_counter_resets,
                                      case_lastlog,
                                      result_id,
                                      file_id):
      req_test = {
         "name"            : case_name,
         "issue"           : case_issue,
         "tcid"            : case_tcid,
         "fid"             : case_fid,
         "component"       : case_component,
         "time_start"      : case_time_start,
         "result_main"     : case_result_main,
         "result_state"    : case_result_state,
         "result_return"   : int(case_result_return),
         "counter_resets"  : int(case_counter_resets),
         "lastlog"         : case_lastlog,
         "testnumber"      : str(case_testnumber),
         "repeatcount"     : str(case_repeatcount),
         "test_result_id"  : result_id,
         "file_id"         : int(file_id)
      }
      data = self.__post_request('testcases', req_test)
      return data['id']

   def nCreateNewTestCase(self, *args):
      return self.nCreateNewSingleTestCase(*args)

   def vCreateAbortReason(self, result_id,
                                abort_reason,
                                abort_message):
      req_abort = {
         "test_result_id"  : result_id,
         "abort_reason"    : abort_reason,
         "msg_detail"      : abort_message
      }
      self.__post_request('aborts', req_abort)

   def vCreateCCRdata(self, test_case_id, lCCRdata):
      for row in lCCRdata:
         req_ccr = {
            "test_case_id" : row[0],
            "timestamp"    : row[1],
            "MEM_RSS"      : row[2],
            "CPU"          : row[3]
         }
         self.__post_request('ccrs', req_ccr)

   def vCreateTags(self, result_id, tags):
      req_tag = {
         "test_result_id"  : result_id,
         "tags"            : tags
      }
      self.__post_request('userresults', req_tag)

   # Methods to update existing record (PATCH) in database
   def vCreateReanimation(self, result_id, num_of_reanimation):
      req_reanimation = {
         "num_of_reanimation"  : num_of_reanimation
      }
      self.__patch_request('results', result_id, req_reanimation)

   def vSetCategory(self, result_id, category_main):
      req_category = {
         "category_main"  : category_main
      }
      self.__patch_request('results', result_id, req_category)

   def vUpdateFileEndTime(self, file_id, time_end):
      req_endtime = {
         "time_end"  : time_end
      }
      self.__patch_request('files', file_id, req_endtime)

   def vUpdateResultEndTime(self, result_id, time_end):
      req_endtime = {
         "time_end"  : time_end
      }
      self.__patch_request('results', result_id, req_endtime)

   def vFinishTestResult(self, result_id):
      req_finish_result = {
         "result_state"  : "new report"
      }
      self.__patch_request('results', result_id, req_finish_result)

   # Methods to call Stored Procedures of database
   def vUpdateEvtbl(self, result_id):
      self.__patch_request('evtblresults', result_id)

   def vUpdateEvtbls(self):
      self.__post_request('evtblresults')