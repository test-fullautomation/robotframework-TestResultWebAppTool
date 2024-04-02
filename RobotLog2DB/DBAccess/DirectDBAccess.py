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
# *******************************************************************************
#
# File: DirectDBAccess.py
#
# Initialy created by Pollerspoeck Thomas (CM/PJ-CMD) / June 2016
#
# This class provides methods to interact with TestResultWebApp's database directly.
#
# History:
#
# June 2016:
#  - initial version
#
# February 2022:
#  - update sourcecode document
# 
# March 2024:
#  - rename file to DirectDBAccess due to DB interface feature of RobotLog2DB
#
# *******************************************************************************

import MySQLdb as db

class DirectDBAccess(object):
   """
DirectDBAccess class play a role as mysqlclient and provide methods to interact
with TestResultWebApp's database.
   """
   __single = None

   __NUM_BUFFERD_ELEMENTS_FOR_EXECUTEMANY=100

   #make the DirectDBAccess to singleton
   #! __new__ requires inheritance from "object" !
   def __new__(classtype, *args, **kwargs):
      """
Create object method to make singleton class ``DirectDBAccess``.
      """
      # Check to see if a __single exists already for this class
      # Compare class types instead of just looking for None so
      # that subclasses will create their own __single objects
      if classtype != type(classtype.__single):
         classtype.__single = object.__new__(classtype)
      return classtype.__single

   def __init__(self):
      """
Initializer of class ``DirectDBAccess``.
      """
      con      = None
      db       = None
      self.lTestCases = []

   def __del__(self):
      pass

   def connect(self,host        = None,
                    user        = None,
                    passwd      = None,
                    database    = None,
                    charset     = 'utf8',
                    use_unicode = True):
      """
Connect to the database with provided authentication and db info.

**Arguments:**

*  ``host``

   / *Condition*: required / *Type*: str /

   URL which is hosted the TestResultWebApp's database.

*  ``user``

   / *Condition*: required / *Type*: str /

   User name for database authentication.

*  ``passwd``

   / *Condition*: required / *Type*: str /

   User's password for database authentication.

*  ``database``

   / *Condition*: required / *Type*: str /

   Database name.

*  ``charset``

   / *Condition*: optional / *Type*: str / *Default*: 'utf8' /

   The connection character set.

*  ``use_unicode``

   / *Condition*: optional / *Type*: bool / *Default*: True /

   If True, CHAR and VARCHAR and TEXT columns are returned as Unicode strings,
   using the configured character set.

**Returns:**

(*no returns*)
      """

      if (host==None or user==None or passwd==None or database==None):
         raise Exception("host, user, passwd and database need to be provided!")

      self.db = database

      # default encoding of python is latin-1,
      # therefore we force mysql to convert to encode to utf8.
      self.con = db.connect(host,user,passwd,db=database,charset=charset,use_unicode=use_unicode)
      #for test purpose activate autocommit with (True)
      self.con.autocommit(False)
      print("Successfully connected to: %s@%s" % (self.db, host))

   def commit(self):
      """
Commit changes within transaction. 

**Arguments:**

(*no arguments*)

**Returns:**

(*no returns*)
      """
      self.con.commit()

   def disconnect(self):
      """
Disconnect from TestResultWebApp's database.

**Arguments:**

(*no arguments*)

**Returns:**

(*no returns*)
      """
      self.con.commit()
      self.con.close()

   def cleanAllTables(self):
      """
Delete all table data. Please be careful before calling this method.

**Arguments:**

(*no arguments*)

**Returns:**

(*no returns*)
      """
      print(">> Deleting all table data!")
      sql="""delete from """ + self.db + """.evtbl_result_main where test_result_id!="" """
      self.__arExec(sql)
      sql="""delete from """ + self.db + """.evtbl_failed_unknown_per_component where test_result_id!="" """
      self.__arExec(sql)
      sql="""delete from """ + self.db + """.tbl_usr_case where test_case_id>0"""
      self.__arExec(sql)
      sql="""delete from """ + self.db + """.tbl_usr_case_history where test_case_id>0"""
      self.__arExec(sql)
      sql="""delete from """ + self.db + """.tbl_usr_comments where test_case_id>0"""
      self.__arExec(sql)
      sql="""delete from """ + self.db + """.tbl_usr_links where test_case_id>0"""
      self.__arExec(sql)
      sql="""delete from """ + self.db + """.tbl_usr_result where test_result_id!="" """
      self.__arExec(sql)
      sql="""delete from """ + self.db + """.tbl_usr_result_history where test_result_id!="" """
      self.__arExec(sql)

      sql="""delete from """ + self.db + """.tbl_file_header where file_id>0"""
      self.__arExec(sql)
      sql="""delete from """ + self.db + """.tbl_case where test_case_id>0"""
      self.__arExec(sql)
      sql="""delete from """ + self.db + """.tbl_file where file_id>0"""
      self.__arExec(sql)
      sql="""delete from """ + self.db + """.tbl_result where test_result_id!="" """
      self.__arExec(sql)
      sql="""delete from """ + self.db + """.tbl_prj where project<>"a" """
      self.__arExec(sql)
      self.con.commit()

   def __arExec(self, command, values=None, bHasResponse=False, bReturnInsertedID=False):
      """
Execute a query. By default don't try to fetch a result.

**Arguments:**

*  ``command``

   / *Condition*: required / *Type*: str /

   Query need to be executed.

*  ``values``

   / *Condition*: optional / *Type*: list / *Default*: None /

   Sequence of parameters to be used with the query.

*  ``bHasResponse``

   / *Condition*: optional / *Type*: bool / *Default*: False /

   If True, respsonse is expected.

*  ``bReturnInsertedID``

   / *Condition*: optional / *Type*: bool / *Default*: False /

   If True, the lastrowid will be returned.

**Returns:**

*  ``arRes``

   / *Type*: list /

   List of reponse data (or lastrowid if bReturnInsertedID is set).
      """
      arRes = None
      c = self.con.cursor()
      c.execute(command,values)
      if bHasResponse:
         arRes = c.fetchall()
      elif bReturnInsertedID:
         arRes = c.lastrowid
      c.close()
      return arRes

   def __vExecMany(self, command, values=None):
      """
Execute a query for bulk insert of many elements. No response expected.

**Arguments:**

*  ``command``

   / *Condition*: required / *Type*: str /

   Query need to be executed.

*  ``values``

   / *Condition*: optional / *Type*: list / *Default*: None /

   Sequence of parameters to be used with the query.

**Returns:**

(*no returns*)
      """
      c = self.con.cursor()
      c.executemany(command,values)
      c.close()

   def __nGetLastInsertID(self, tbl):
      """
Return the last_insert_id of a given table.

**Arguments:**

*  ``tbl``

   / *Condition*: required / *Type*: str /

   Table name to get the last_insert_id.

**Returns:**

*  ``res``

   / *Type*: str /

   The last_insert_id.
      """
      # "select last_insert_id from table" returns as result a one column table
      # where the number of rows is the length of the full table.
      # Each row has the same value of the last_insert_id.
      # This causes dramatic performance problems.
      # Anyhow we need only one element, therefore we limit here to 1
      sql = """select last_insert_id() from """ + self.db + "." + tbl + " limit 1"
      res = self.__arExec(sql,bHasResponse=True)[0][0]
      return res

   def sCreateNewTestResult(self, _tbl_prj_project,
                                  _tbl_prj_variant,
                                  _tbl_prj_branch,
                                  _tbl_test_result_id,
                                  _tbl_result_interpretation,
                                  _tbl_result_time_start,
                                  _tbl_result_time_end,
                                  _tbl_result_version_sw_target,
                                  _tbl_result_version_sw_test,
                                  _tbl_result_version_target,
                                  _tbl_result_jenkinsurl,
                                  _tbl_result_reporting_qualitygate
                            ):
      """
Creates a new test result in ``tbl_result``. This is the main table which is
linked to all other data by means of ``test_result_id``.

**Arguments:**

*  ``_tbl_prj_project``

   / *Condition*: required / *Type*: str /

   Project information.

*  ``_tbl_prj_variant``

   / *Condition*: required / *Type*: str /

   Variant information.

*  ``_tbl_prj_branch``

   / *Condition*: required / *Type*: str /

   Branch information.

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result.

*  ``_tbl_result_interpretation``

   / *Condition*: required / *Type*: str /

   Result interpretation.

*  ``_tbl_result_time_start``

   / *Condition*: required / *Type*: str /

   Test result start time as format ``%Y-%m-%d %H:%M:%S``.

*  ``_tbl_result_time_end``

   / *Condition*: required / *Type*: str /

   Test result end time as format ``%Y-%m-%d %H:%M:%S``.

*  ``_tbl_result_version_sw_target``

   / *Condition*: required / *Type*: str /

   Software version information.

*  ``_tbl_result_version_sw_test``

   / *Condition*: required / *Type*: str /

   Test version information.

*  ``_tbl_result_version_target``

   / *Condition*: required / *Type*: str /

   Hardware version information.

*  ``_tbl_result_jenkinsurl``

   / *Condition*: required / *Type*: str /

   Jenkinsurl in case test result is executed by jenkins.

*  ``_tbl_result_reporting_qualitygate``

   / *Condition*: required / *Type*: str /

   Qualitygate information for reporting.

**Returns:**

*  ``_tbl_test_result_id``

   / *Type*: str /

   ``test_result_id`` of new test result.
      """
      sql,sqlval = """select count(*) from """ + self.db + """.tbl_prj where
               (project=%s and variant=%s and branch=%s)""", (_tbl_prj_project,
                                                              _tbl_prj_variant,
                                                              _tbl_prj_branch)
      res = self.__arExec(sql,sqlval,True)[0][0]
      if res == 0:
         sql,sqlval = """insert into """ + self.db + """.tbl_prj
         ( variant,project, branch) values (%s, %s, %s)""" , (_tbl_prj_variant,
                                                              _tbl_prj_project,
                                                              _tbl_prj_branch)
         self.__arExec(sql,sqlval)

      sql,sqlval = """insert into """ + self.db + """.tbl_result (test_result_id,
         variant,project,branch, time_start,time_end, version_sw_target,
         version_sw_test,version_hardware,jenkinsurl,reporting_qualitygate,result_state)
         values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""" , (_tbl_test_result_id,
                                                            _tbl_prj_variant,
                                                            _tbl_prj_project,
                                                            _tbl_prj_branch,
                                                            _tbl_result_time_start,
                                                            _tbl_result_time_end,
                                                            _tbl_result_version_sw_target,
                                                            _tbl_result_version_sw_test,
                                                            _tbl_result_version_target,
                                                            _tbl_result_jenkinsurl,
                                                            _tbl_result_reporting_qualitygate,
                                                            "in progress")
      self.__arExec(sql,sqlval)

      if _tbl_result_interpretation!='':
         sql,sqlval = """update """ + self.db + """.tbl_result set interpretation=%s
            where test_result_id='""" + _tbl_test_result_id + "'", (_tbl_result_interpretation,)
         self.__arExec(sql,sqlval)

      return _tbl_test_result_id

   def nCreateNewFile(self,_tbl_file_name,
                           _tbl_file_tester_account,
                           _tbl_file_tester_machine,
                           _tbl_file_time_start,
                           _tbl_file_time_end,
                           _tbl_test_result_id,
                           _tbl_file_origin="ROBFW"):
      """
Create new file entry in ``tbl_file`` table.

**Arguments:**

*  ``_tbl_file_name``

   / *Condition*: required / *Type*: str /

   File name information.

*  ``_tbl_file_tester_account``

   / *Condition*: required / *Type*: str /

   Tester account information.

*  ``_tbl_file_tester_machine``

   / *Condition*: required / *Type*: str /

   Test machine information.

*  ``_tbl_file_time_start``

   / *Condition*: required / *Type*: str /

   Test file start time as format ``%Y-%m-%d %H:%M:%S``.

*  ``_tbl_file_time_end``

   / *Condition*: required / *Type*: str /

   Test file end time as format ``%Y-%m-%d %H:%M:%S``.

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result for linking to `tbl_result` table.

*  ``_tbl_file_origin``

   / *Condition*: required / *Type*: str /

   Origin (test framework) of test file. Deafult is "ROBFW"

**Returns:**

*  ``iInsertedID``

   / *Type*: int /

   ID of new entry.
      """
      sql,sqlval ="""insert into """ + self.db + """.tbl_file (name,tester_account,
                     tester_machine,time_start,time_end,test_result_id,origin)
                     values (%s,%s,%s,%s,%s,%s,%s)""" , ( _tbl_file_name,
                                                         _tbl_file_tester_account,
                                                         _tbl_file_tester_machine,
                                                         _tbl_file_time_start,
                                                         _tbl_file_time_end,
                                                         _tbl_test_result_id,
                                                         _tbl_file_origin)
      iInsertedID = self.__arExec(sql,sqlval, bReturnInsertedID=True)
      return iInsertedID

   def vCreateNewHeader(self, _tbl_file_id,
                              _tbl_header_testtoolconfiguration_testtoolname,
                              _tbl_header_testtoolconfiguration_testtoolversionstring,
                              _tbl_header_testtoolconfiguration_projectname,
                              _tbl_header_testtoolconfiguration_logfileencoding,
                              _tbl_header_testtoolconfiguration_pythonversion,
                              _tbl_header_testtoolconfiguration_testfile,
                              _tbl_header_testtoolconfiguration_logfilepath,
                              _tbl_header_testtoolconfiguration_logfilemode,
                              _tbl_header_testtoolconfiguration_ctrlfilepath,
                              _tbl_header_testtoolconfiguration_configfile,
                              _tbl_header_testtoolconfiguration_confname,

                              _tbl_header_testfileheader_author,
                              _tbl_header_testfileheader_project,
                              _tbl_header_testfileheader_testfiledate,
                              _tbl_header_testfileheader_version_major,
                              _tbl_header_testfileheader_version_minor,
                              _tbl_header_testfileheader_version_patch,
                              _tbl_header_testfileheader_keyword,
                              _tbl_header_testfileheader_shortdescription,
                              _tbl_header_testexecution_useraccount,
                              _tbl_header_testexecution_computername,

                              _tbl_header_testrequirements_documentmanagement,
                              _tbl_header_testrequirements_testenvironment,

                              _tbl_header_testbenchconfig_name,
                              _tbl_header_testbenchconfig_data,
                              _tbl_header_preprocessor_filter,
                              _tbl_header_preprocessor_parameters ):
      """
Create a new header entry in ``tbl_file_header`` table which is linked with the file.

**Arguments:**

*  ``_tbl_file_id``

   / *Condition*: required / *Type*: int /

   File ID information.

*  ``_tbl_header_testtoolconfiguration_testtoolname``

   / *Condition*: required / *Type*: str /

   Test tool name.

*  ``_tbl_header_testtoolconfiguration_testtoolversionstring``

   / *Condition*: required / *Type*: str /

   Test tool version.

*  ``_tbl_header_testtoolconfiguration_projectname``

   / *Condition*: required / *Type*: str /

   Project name.

*  ``_tbl_header_testtoolconfiguration_logfileencoding``

   / *Condition*: required / *Type*: str /

   Encoding of logfile.

*  ``_tbl_header_testtoolconfiguration_pythonversion``

   / *Condition*: required / *Type*: str /

   Python version info.

*  ``_tbl_header_testtoolconfiguration_testfile``

   / *Condition*: required / *Type*: str /

   Test file name.

*  ``_tbl_header_testtoolconfiguration_logfilepath``

   / *Condition*: required / *Type*: str /

   Path to log file.

*  ``_tbl_header_testtoolconfiguration_logfilemode``

   / *Condition*: required / *Type*: str /

   Mode of log file.

*  ``_tbl_header_testtoolconfiguration_ctrlfilepath``

   / *Condition*: required / *Type*: str /

   Path to control file.

*  ``_tbl_header_testtoolconfiguration_configfile``

   / *Condition*: required / *Type*: str /

   Path to configuration file.

*  ``_tbl_header_testtoolconfiguration_confname``

   / *Condition*: required / *Type*: str /

   Configuration name.

*  ``_tbl_header_testfileheader_author``

   / *Condition*: required / *Type*: str /

   File author.

*  ``_tbl_header_testfileheader_project``

   / *Condition*: required / *Type*: str /

   Project information.

*  ``_tbl_header_testfileheader_testfiledate``

   / *Condition*: required / *Type*: str /

   File creation date.

*  ``_tbl_header_testfileheader_version_major``

   / *Condition*: required / *Type*: str /

   File major version.

*  ``_tbl_header_testfileheader_version_minor``

   / *Condition*: required / *Type*: str /

   File minor version.

*  ``_tbl_header_testfileheader_version_patch``

   / *Condition*: required / *Type*: str /

   File patch version.

*  ``_tbl_header_testfileheader_keyword``

   / *Condition*: required / *Type*: str /

   File keyword.

*  ``_tbl_header_testfileheader_shortdescription``

   / *Condition*: required / *Type*: str /

   File short description.

*  ``_tbl_header_testexecution_useraccount``

   / *Condition*: required / *Type*: str /

   Tester account who run the execution.

*  ``_tbl_header_testexecution_computername``

   / *Condition*: required / *Type*: str /

   Machine name which is executed on.

*  ``_tbl_header_testrequirements_documentmanagement``

   / *Condition*: required / *Type*: str /

   Requirement management information.

*  ``_tbl_header_testrequirements_testenvironment``

   / *Condition*: required / *Type*: str /

   Requirement environment information.

*  ``_tbl_header_testbenchconfig_name``

   / *Condition*: required / *Type*: str /

   Testbench configuration name.

*  ``_tbl_header_testbenchconfig_data``

   / *Condition*: required / *Type*: str /

   Testbench configuration data.

*  ``_tbl_header_preprocessor_filter``

   / *Condition*: required / *Type*: str /

   Preprocessor filter information.

*  ``_tbl_header_preprocessor_parameters``

   / *Condition*: required / *Type*: str /

   Preprocessor parameters definition.

**Returns:**

(*no returns*)
      """
      sql,sqlval ="""insert into """ + self.db + """.tbl_file_header
                        ( file_id,
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
                          preprocessor_parameters)
                  values ( %s, %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s,
                           %s, %s, %s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""" , \
                        ( _tbl_file_id,
                          _tbl_header_testtoolconfiguration_testtoolname,
                          _tbl_header_testtoolconfiguration_testtoolversionstring,
                          _tbl_header_testtoolconfiguration_projectname,
                          _tbl_header_testtoolconfiguration_logfileencoding,
                          _tbl_header_testtoolconfiguration_pythonversion,
                          _tbl_header_testtoolconfiguration_testfile,
                          _tbl_header_testtoolconfiguration_logfilepath,
                          _tbl_header_testtoolconfiguration_logfilemode,
                          _tbl_header_testtoolconfiguration_ctrlfilepath,
                          _tbl_header_testtoolconfiguration_configfile,
                          _tbl_header_testtoolconfiguration_confname,

                          _tbl_header_testfileheader_author,
                          _tbl_header_testfileheader_project,
                          _tbl_header_testfileheader_testfiledate,
                          _tbl_header_testfileheader_version_major,
                          _tbl_header_testfileheader_version_minor,
                          _tbl_header_testfileheader_version_patch,
                          _tbl_header_testfileheader_keyword,
                          _tbl_header_testfileheader_shortdescription,
                          _tbl_header_testexecution_useraccount,
                          _tbl_header_testexecution_computername,

                          _tbl_header_testrequirements_documentmanagement,
                          _tbl_header_testrequirements_testenvironment,

                          _tbl_header_testbenchconfig_name,
                          _tbl_header_testbenchconfig_data,
                          _tbl_header_preprocessor_filter,
                          _tbl_header_preprocessor_parameters)
      self.__arExec(sql,sqlval)

   def nCreateNewSingleTestCase(self,
                                _tbl_case_name,
                                _tbl_case_issue,
                                _tbl_case_tcid,
                                _tbl_case_fid,
                                _tbl_case_testnumber,
                                _tbl_case_repeatcount,
                                _tbl_case_component,
                                _tbl_case_time_start,
                                _tbl_case_result_main,
                                _tbl_case_result_state,
                                _tbl_case_result_return,
                                _tbl_case_counter_resets,
                                _tbl_case_lastlog,
                                _tbl_test_result_id,
                                _tbl_file_id
                               ):
      """
Create single testcase entry in ``tbl_case`` table immediately.

**Arguments:**

*  ``_tbl_case_name``

   / *Condition*: required / *Type*: str /

   Test case name.

*  ``_tbl_case_issue``

   / *Condition*: required / *Type*: str /

   Test case issue ID.

*  ``_tbl_case_tcid``

   / *Condition*: required / *Type*: str /

   Test case ID (used for testmanagement tool).

*  ``_tbl_case_fid``

   / *Condition*: required / *Type*: str /

   Test case requirement (function) ID.

*  ``_tbl_case_testnumber``

   / *Condition*: required / *Type*: int /

   Order of test case in file.

*  ``_tbl_case_repeatcount``

   / *Condition*: required / *Type*: int /

   Test case repeatition count.

*  ``_tbl_case_component``

   / *Condition*: required / *Type*: str /

   Component which test case is belong to.

*  ``_tbl_case_time_start``

   / *Condition*: required / *Type*: str /

   Test case start time as format ``%Y-%m-%d %H:%M:%S``.

*  ``_tbl_case_result_main``

   / *Condition*: required / *Type*: str /

   Test case main result.

*  ``_tbl_case_result_state``

   / *Condition*: required / *Type*: str /

   Test case completion state.

*  ``_tbl_case_result_return``

   / *Condition*: required / *Type*: int /

   Test case result code (as integer).

*  ``_tbl_case_counter_resets``

   / *Condition*: required / *Type*: int /

   Counter of target reset within test case execution.

*  ``_tbl_case_lastlog``

   / *Condition*: required / *Type*: str /

   Traceback information when test case is failed.

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result for linking to file in ``tbl_result`` table.

*  ``_tbl_file_id``

   / *Condition*: required / *Type*: int /

   Test file ID for linking to file in ``tbl_file`` table.

**Returns:**

*  ``iInsertedID``

   / *Type*: int /

   ID of new entry.
      """
      if _tbl_case_lastlog == "":
         _tbl_case_lastlog = None
      sql = """insert into """ + self.db + """.tbl_case (name, issue, tcid, fid,
               testnumber, repeatcount, component, time_start, result_main, result_state,
               result_return, counter_resets, lastlog, test_result_id, file_id)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
      sqlval = (_tbl_case_name,
                _tbl_case_issue,
                _tbl_case_tcid,
                _tbl_case_fid,
                _tbl_case_testnumber,
                _tbl_case_repeatcount,
                _tbl_case_component,
                _tbl_case_time_start,
                _tbl_case_result_main,
                _tbl_case_result_state,
                _tbl_case_result_return,
                _tbl_case_counter_resets,
                _tbl_case_lastlog,
                _tbl_test_result_id,
                _tbl_file_id
               )
      iInsertedTestID = self.__arExec(sql, sqlval, bReturnInsertedID=True)
      return iInsertedTestID

   #
   # create a new test case entry:
   #
   #
   def nCreateNewTestCase(self,
                          _tbl_case_name,
                          _tbl_case_issue,
                          _tbl_case_tcid,
                          _tbl_case_fid,
                          _tbl_case_testnumber,
                          _tbl_case_repeatcount,
                          _tbl_case_component,
                          _tbl_case_time_start,
                          _tbl_case_result_main,
                          _tbl_case_result_state,
                          _tbl_case_result_return,
                          _tbl_case_counter_resets,
                          _tbl_case_lastlog,
                          _tbl_test_result_id,
                          _tbl_file_id
                           ):
      """
Create bulk of test case entries: new test cases are buffered and inserted as bulk.

Once ``__NUM_BUFFERD_ELEMENTS_FOR_EXECUTEMANY`` is reached, the creation query is executed.

**Arguments:**

*  ``_tbl_case_name``

   / *Condition*: required / *Type*: str /

   Test case name.

*  ``_tbl_case_issue``

   / *Condition*: required / *Type*: str /

   Test case issue ID.

*  ``_tbl_case_tcid``

   / *Condition*: required / *Type*: str /

   Test case ID (used for testmanagement tool).

*  ``_tbl_case_fid``

   / *Condition*: required / *Type*: str /

   Test case requirement (function) ID.

*  ``_tbl_case_testnumber``

   / *Condition*: required / *Type*: int /

   Order of test case in file.

*  ``_tbl_case_repeatcount``

   / *Condition*: required / *Type*: int /

   Test case repeatition count.

*  ``_tbl_case_component``

   / *Condition*: required / *Type*: str /

   Component which test case is belong to.

*  ``_tbl_case_time_start``

   / *Condition*: required / *Type*: str /

   Test case start time as format ``%Y-%m-%d %H:%M:%S``.

*  ``_tbl_case_result_main``

   / *Condition*: required / *Type*: str /

   Test case main result.

*  ``_tbl_case_result_state``

   / *Condition*: required / *Type*: str /

   Test case completion state.

*  ``_tbl_case_result_return``

   / *Condition*: required / *Type*: int /

   Test case result code (as integer).

*  ``_tbl_case_counter_resets``

   / *Condition*: required / *Type*: int /

   Counter of target reset within test case execution.

*  ``_tbl_case_lastlog``

   / *Condition*: required / *Type*: str /

   Traceback information when test case is failed.

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result for linking to file in `tbl_result` table.

*  ``_tbl_file_id``

   / *Condition*: required / *Type*: int /

   Test file ID for linking to file in ``tbl_file`` table.

**Returns:**

(*no returns*)
      """
      if _tbl_case_lastlog == "":
         _tbl_case_lastlog = None
      sqlval = (_tbl_case_name,
                _tbl_case_issue,
                _tbl_case_tcid,
                _tbl_case_fid,
                _tbl_case_testnumber,
                _tbl_case_repeatcount,
                _tbl_case_component,
                _tbl_case_time_start,
                _tbl_case_result_main,
                _tbl_case_result_state,
                _tbl_case_result_return,
                _tbl_case_counter_resets,
                _tbl_test_result_id,
                _tbl_file_id,
                _tbl_case_lastlog,
                )
      self.lTestCases.append(sqlval)
      if len(self.lTestCases) >= DirectDBAccess.__NUM_BUFFERD_ELEMENTS_FOR_EXECUTEMANY:
         self.vEnableForeignKeyCheck(False)
         self.__vUploadTestCaseListToDb(self.lTestCases)
         self.vEnableForeignKeyCheck(True)
         # Clear test cases list
         self.lTestCases = []

   def __vUploadTestCaseListToDb(self, lTestCases):
      """
Bulk insert test case results.

**Arguments:**

*  ``lTestCases``

   / *Condition*: required / *Type*: str /

   List of test case for creation.

**Returns:**

(*no returns*)
      """
      sql = """insert into """ + self.db + """.tbl_case (name, issue, tcid, fid,
            testnumber, repeatcount, component, time_start, result_main, result_state,
            result_return, counter_resets, test_result_id, file_id, lastlog)
            values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
      self.__vExecMany(sql, lTestCases)

   def vCreateTags(self, _tbl_test_result_id, _tbl_usr_result_tags):
      """
Create tag entries.

**Arguments:**

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result.

*  ``_tbl_usr_result_tags``

   / *Condition*: required / *Type*: str /

   User tags information.

**Returns:**

(*no returns*)
      """
      sql,sqlval="""insert into """ + self.db + """.tbl_usr_result (test_result_id, tags)
                    values (%s,%s)""", (_tbl_test_result_id , _tbl_usr_result_tags)
      self.__arExec(sql,sqlval)

   def vSetCategory(self, _tbl_test_result_id, tbl_result_category_main):
      """
Create category entry.

**Arguments:**

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result.

*  ``tbl_result_category_main``

   / *Condition*: required / *Type*: str /

   Category information.

**Returns:**

(*no returns*)
      """
      sql="""update """ + self.db + """.tbl_result set category_main='""" + \
                  tbl_result_category_main + """' where test_result_id='""" + \
                  _tbl_test_result_id + "'"
      self.__arExec(sql)

   def vUpdateStartEndTime(self, _tbl_test_result_id, _tbl_result_time_start, _tbl_result_time_end):
      """
Create start-end time entry.

**Arguments:**

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result.

*  ``_tbl_result_time_start``

   / *Condition*: required / *Type*: str /

   Result start time as format ``%Y-%m-%d %H:%M:%S``.

*  ``_tbl_result_time_end``

   / *Condition*: required / *Type*: str /

   Result end time as format ``%Y-%m-%d %H:%M:%S``.

**Returns:**

(*no returns*)
      """
      sql,sqlval="""update """ + self.db + """.tbl_result set time_start=%s, time_end=%s
                  where test_result_id='""" + _tbl_test_result_id + "'" , \
                  (_tbl_result_time_start, _tbl_result_time_end)
      self.__arExec(sql,sqlval)

   def arGetCategories(self):
      """
Get existing categories.

**Arguments:**

(*no arguments*)

**Returns:**

*  ``arCategories``

   / *Type*: list /

   List of exsiting categories.
      """
      sql="""select category from """ + self.db + """.tbl_result_categories"""
      res=self.__arExec(sql, bHasResponse=True)
      arCategories=[]
      for cat in res:
         arCategories.append(cat[0])
      return arCategories

   #
   # create abort reason entry
   #
   def vCreateAbortReason(self,
                          _tbl_test_result_id,
                          _tbl_abort_reason,
                          _tbl_abort_message
                           ):
      """
Create abort reason entry.

**Arguments:**

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result.

*  ``_tbl_abort_reason``

   / *Condition*: required / *Type*: str /

   Abort reason.

*  ``_tbl_abort_message``

   / *Condition*: required / *Type*: str /

   Detail message of abort.

**Returns:**

(*no returns*)
      """
      sql,sqlval = """insert into """ + self.db + """.tbl_abort
                           (test_result_id, abort_reason, msg_detail)
                           values (%s,%s,%s)""" , (_tbl_test_result_id,
                                                   _tbl_abort_reason,
                                                   _tbl_abort_message,
                                                   )
      self.__arExec(sql,sqlval)

   def vCreateReanimation(self, _tbl_test_result_id, _tbl_num_of_reanimation):
      """
Create reanimation entry.

**Arguments:**

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result.

*  ``_tbl_num_of_reanimation``

   / *Condition*: required / *Type*: int /

   Counter of target reanimation during execution.

**Returns:**

(*no returns*)
      """
      sql, sqlval = """update """ + self.db + """.tbl_result set num_of_reanimation=%s where
                        test_result_id='""" + _tbl_test_result_id + "'", (_tbl_num_of_reanimation)
      self.__arExec(sql, sqlval)

   def vCreateCCRdata(self, _tbl_test_case_id, lCCRdata):
      """
Create CCR data per test case.

**Arguments:**

*  ``_tbl_test_case_id``

   / *Condition*: required / *Type*: int /

   test case ID.

*  ``lCCRdata``

   / *Condition*: required / *Type*: list /

   list of CCR data.

**Returns:**

(*no returns*)
      """
      sql = """insert into """ + self.db + """.tbl_ccr (test_case_id, timestamp, MEM, CPU) values(%s,%s,%s,%s)"""
      sqlVals = []
      for row in lCCRdata:
         row.insert(0, _tbl_test_case_id)
         sqlVals.append(tuple(row))
      self.__vExecMany(sql, sqlVals)

   def vFinishTestResult(self,_tbl_test_result_id):
      """
Finish upload:

* First do bulk insert of rest of test cases if buffer is not empty.
* Then set state to "new report".

**Arguments:**

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result.

**Returns:**

(*no returns*)
      """
      if len(self.lTestCases) > 0:
         self.vEnableForeignKeyCheck(False)
         self.__vUploadTestCaseListToDb(self.lTestCases)
         self.vEnableForeignKeyCheck(True)
      sql="""update """ + self.db + """.tbl_result set result_state="new report"
                  where test_result_id='""" + _tbl_test_result_id + "'"
      self.__arExec(sql)

   def vUpdateEvtbls(self):
      """
Call ``update_evtbls`` stored procedure.

**Arguments:**

(*no arguments*)

**Returns:**

(*no returns*)
      """
      sql="""call """ + self.db + """.update_evtbls();"""
      self.__arExec(sql)

   def vUpdateEvtbl(self, _tbl_test_result_id):
      """
Call ``update_evtbl`` stored procedure to update provided ``test_result_id``.

**Arguments:**

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result.

**Returns:**

(*no returns*)
      """
      sql="""call """ + self.db + """.update_evtbl('%s');"""%_tbl_test_result_id
      self.__arExec(sql)

   def vEnableForeignKeyCheck(self, enable=True):
      """
Switch ``foreign_key_checks`` flag.

**Arguments:**

*  ``enable``

   / *Condition*: optional / *Type*: bool / *Default*: True /

   If True, enable foreign key constraint.

**Returns:**

(*no returns*)
      """
      sql = "SET FOREIGN_KEY_CHECKS=%s;" %str(int(enable))
      self.__arExec(sql)

   def sGetLatestFileID(self, _tbl_test_result_id):
      """
Get latest file ID from ``tbl_file`` table.

**Arguments:**

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result.

**Returns:**

*  ``_tbl_file_id``

   / *Type*: int /

   File ID.
      """
      sql = "SELECT MAX(file_id) FROM %s.tbl_file WHERE test_result_id='%s'"%(self.db, _tbl_test_result_id)
      _tbl_file_id = self.__arExec(sql,bHasResponse=True)[0][0]
      return _tbl_file_id

   def vUpdateFileEndTime(self, _tbl_file_id, _tbl_file_time_end):
      """
Update test file end time.

**Arguments:**

*  ``_tbl_file_id``

   / *Condition*: required / *Type*: int /

   File ID to be updated.

*  ``_tbl_file_time_end``

   / *Condition*: required / *Type*: str /

   File end time as format ``%Y-%m-%d %H:%M:%S``.

**Returns:**

(*no returns*)
      """
      sql = "UPDATE %s.tbl_file SET time_end='%s' WHERE file_id=%s"%(self.db, _tbl_file_time_end, _tbl_file_id)
      self.__arExec(sql)

   def vUpdateResultEndTime(self, _tbl_test_result_id, _tbl_result_time_end):
      """
Update test result end time.

**Arguments:**

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   Result UUID to be updated.

*  ``_tbl_result_time_end``

   / *Condition*: required / *Type*: str /

   Result end time as format ``%Y-%m-%d %H:%M:%S``.

**Returns:**

(*no returns*)
      """
      sql = "UPDATE %s.tbl_result SET time_end='%s' WHERE test_result_id='%s'"%(self.db, _tbl_result_time_end, _tbl_test_result_id)
      self.__arExec(sql)

   def bExistingResultID(self, _tbl_test_result_id):
      """
Verify the given test result UUID is existing in ``tbl_result`` table or not.

**Arguments:**

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   Result UUID to be verified.

**Returns:**

*  ``bExisting``

   / *Type*: bool /

   True if test result UUID is already existing.
      """
      sql = "SELECT test_result_id FROM %s.tbl_result WHERE test_result_id='%s'"%(self.db, _tbl_test_result_id)
      res = self.__arExec(sql, bHasResponse=True)
      bExisting = False
      if res and len(res)>0:
         bExisting = True
      return bExisting

   def arGetProjectVersionSWByID(self, _tbl_test_result_id):
      """
Get the project and version_sw information of given `test_result_id`

**Arguments:**

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   Result UUID to be get the information.

**Returns:**

*  / *Type*: tuple /

   None if test result UUID is not existing, else the tuple which contains project and version_sw: (project, variant) is returned.
      """
      sql = "SELECT project, version_sw_target FROM %s.tbl_result WHERE test_result_id='%s'"%(self.db, _tbl_test_result_id)
      res = self.__arExec(sql, bHasResponse=True)
      if res and len(res)>0:
         return res[0]

      return None
