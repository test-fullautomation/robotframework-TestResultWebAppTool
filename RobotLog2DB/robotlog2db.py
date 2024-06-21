#  Copyright 2020-2023 Robert Bosch GmbH
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
# File: robotlog2db.py
#
# Initialy created by Tran Duy Ngoan(RBVH/ECM11) / November 2020
#
# This tool is used to parse the robot framework results output.xml
# then import them into TestResultWebApp's database
#
# History:
#
# 2020-11-26:
#  - initial version
#
# 2021-05-20:
#  - Correct regex for tags and testtool.
#  - Add file description information as suite.doc.
#  - Add new command line arguments:
#    + -UUID: to specify the uuid of test result.
#    + --variant: to specify project/variant of test result.
#    + --versions: to specify versions information (Software;Hardware;Test)
#    + --config: configuration(component, variant, version_sw) json file for
#                the import.
#  - Try to extract metadata from suites incase many suite levels in result.
#
# 2023-02-28:
#  - Rename key to 'components' in configuration json file (--config).
#
# ******************************************************************************

import re
import uuid
import base64
import argparse
import os
import sys
import colorama as col
import json

from lxml import etree
from robot.api import ExecutionResult
from TestResultDBAccess import DBAccessFactory
from RobotLog2DB.version import VERSION, VERSION_DATE

DRESULT_MAPPING = {
   "PASS":  "Passed",
   "FAIL":  "Failed",
   "UNKNOWN": "Unknown",
   "SKIP": "Unknown"
}

DEFAULT_METADATA = {
   "project"      :  "ROBFW",
   "version_sw"   :  "",
   "version_hw"   :  "",
   "version_test" :  "",
   "category"     :  "",

   "testtool"     :  "",
   "configfile"   :  "",
   "tester"       :  "",
   "machine"      :  "",
   "author"       :  "",

   "component"   :  "",
   "tags"         :  "",
}

CONFIG_SCHEMA = {
   "components": [str, dict],
   "variant"   : str,
   "version_sw": str,
   "version_hw": str,
   "version_test": str,
   "testtool"  :  str,
   "tester"    :  str
}

iTotalTestcase = 0
iSuccessTestcase = 0
dComponentCounter = {}

class Logger():
   """
Logger class for logging message.
   """
   output_logfile = None
   output_console = True
   color_normal   = col.Fore.WHITE + col.Style.NORMAL
   color_error    = col.Fore.RED + col.Style.BRIGHT
   color_warn     = col.Fore.YELLOW + col.Style.BRIGHT
   color_reset    = col.Style.RESET_ALL + col.Fore.RESET + col.Back.RESET
   prefix_warn    = "WARN: "
   prefix_error   = "ERROR: "
   prefix_fatalerror = "FATAL ERROR: "
   prefix_all = ""
   dryrun = False

   @classmethod
   def config(cls, output_console=True, output_logfile=None, dryrun=False):
      """
Configure Logger class.

**Arguments:**

*  ``output_console``

   / *Condition*: optional / *Type*: bool / *Default*: True /

   Write message to console output.

*  ``output_logfile``

   / *Condition*: optional / *Type*: str / *Default*: None /

   Path to log file output.

*  ``dryrun``

   / *Condition*: optional / *Type*: bool / *Default*: True /

   If set, a prefix as 'dryrun' is added for all messages.

**Returns:**

(*no returns*)
      """
      cls.output_console = output_console
      cls.output_logfile = output_logfile
      cls.dryrun = dryrun
      if cls.dryrun:
         cls.prefix_all = cls.color_warn + "DRYRUN  " + cls.color_reset

   @classmethod
   def log(cls, msg='', color=None, indent=0):
      """
Write log message to console/file output.

**Arguments:**

*  ``msg``

   / *Condition*: optional / *Type*: str / *Default*: '' /

   Message which is written to output.

*  ``color``

   / *Condition*: optional / *Type*: str / *Default*: None /

   Color style for the message.

*  ``indent``

   / *Condition*: optional / *Type*: int / *Default*: 0 /

   Offset indent.

**Returns:**

(*no returns*)
      """
      if color==None:
         color = cls.color_normal
      if cls.output_console:
         print(cls.prefix_all + cls.color_reset + color + " "*indent + msg +
               cls.color_reset)
      if cls.output_logfile!=None and os.path.isfile(cls.output_logfile):
         with open(cls.output_logfile, 'a') as f:
            f.write(" "*indent + msg)
      return

   @classmethod
   def log_warning(cls, msg):
      """
Write warning message to console/file output.

**Arguments:**

*  ``msg``

   / *Condition*: required / *Type*: str /

   Warning message which is written to output.

**Returns:**

(*no returns*)
      """
      cls.log(cls.prefix_warn+str(msg), cls.color_warn)

   @classmethod
   def log_error(cls, msg, fatal_error=False):
      """
Write error message to console/file output.

**Arguments:**

*  ``msg``

   / *Condition*: required / *Type*: str /

   Error message which is written to output.

*  ``fatal_error``

   / *Condition*: optional / *Type*: bool / *Default*: False /

   If set, tool will terminate after logging error message.

**Returns:**

(*no returns*)
      """
      prefix = cls.prefix_error
      if fatal_error:
         prefix = cls.prefix_fatalerror

      cls.log(prefix+str(msg), cls.color_error)
      if fatal_error:
         cls.log(f"{sys.argv[0]} has been stopped!", cls.color_error)
         exit(1)

def collect_xml_result_files(path, search_recursive=False):
   """
Collect all valid Robot xml result file in given path.

**Arguments:**

*  ``path``

   / *Condition*: required / *Type*: str /

   Path to Robot result folder or file to be searched.

*  ``search_recursive``

   / *Condition*: optional / *Type*: bool / *Default*: False /

   If set, the given path is searched recursively for xml result files.

**Returns:**

*  ``lFoundFiles``

   / *Type*: list /

   List of valid xml result file(s) in given path.
   """
   lFoundFiles = []
   if os.path.exists(path):
      if os.path.isfile(path):
         validate_xml_result(path)
         lFoundFiles.append(path)
      else:
         if search_recursive:
            Logger.log("Searching *.xml result files recursively...")
            for root, _, files in os.walk(path):
               for file in files:
                  if file.endswith(".xml"):
                     xml_result_pathfile = os.path.join(root, file)
                     Logger.log(xml_result_pathfile, indent=2)
                     validate_xml_result(xml_result_pathfile)
                     lFoundFiles.append(xml_result_pathfile)
         else:
            Logger.log("Searching *.xml result files...")
            for file in os.listdir(path):
               if file.endswith(".xml"):
                  xml_result_pathfile = os.path.join(path, file)
                  Logger.log(xml_result_pathfile, indent=2)
                  validate_xml_result(xml_result_pathfile)
                  lFoundFiles.append(xml_result_pathfile)

         # Terminate tool with error when no logfile under provided folder
         if len(lFoundFiles) == 0:
            Logger.log_error(f"No *.xml result file under '{path}' folder.", fatal_error=True)
   else:
      Logger.log_error(f"Given resultxmlfile is not existing: '{path}'", fatal_error=True)

   return lFoundFiles

def validate_xml_result(xml_result, xsd_schema=os.path.join(os.path.dirname(__file__),'xsd/robot.xsd'), exit_on_failure=True):
   """
Verify the given xml result file is valid or not.

**Arguments:**

*  ``xml_result``

   / *Condition*: required / *Type*: str /

   Path to Robot result file.

*  ``xsd_schema``

   / *Condition*: optional / *Type*: str / *Default*: <installed_folder>\/xsd\/robot.xsd /

   Path to Robot schema *.xsd file.

*  ``exit_on_failure``

   / *Condition*: optional / *Type*: bool / *Default*: True /

   If set, exit with fatal error if the schema validation of given xml file failed.

**Returns:**

*  / *Type*: bool /

   True if the given xml result is valid with the provided schema *.xsd.
   """
   try:
      xmlschema_doc = etree.parse(xsd_schema)
      xmlschema = etree.XMLSchema(xmlschema_doc)
   except Exception as reason:
      Logger.log_error(f"schema xsd file '{xsd_schema}' is not a valid.\nReason: {reason}", fatal_error=True)

   if exit_on_failure:
      try:
         xml_doc = etree.parse(xml_result)
         xmlschema.assert_(xml_doc)
      except AssertionError as reason:
         Logger.log_error(f"xml result file '{xml_result}' is not a valid Robot result.\nReason: {reason}", fatal_error=True)
      except Exception as reason:
         Logger.log_error(f"result file '{xml_result}' is not a valid xml format.\nReason: {reason}", fatal_error=True)

   return xmlschema.validate(xml_doc)

def is_valid_uuid(uuid_to_test, version=4):
   """
Verify the given UUID is valid or not.

**Arguments:**

*  ``uuid_to_test``

   / *Condition*: required / *Type*: str /

   UUID to be verified.

*  ``version``

   / *Condition*: optional / *Type*: int / *Default*: 4 /

   UUID version.

**Returns:**

*  ``bValid``

   / *Type*: bool /

   True if the given UUID is valid.
   """
   bValid = False
   try:
      uuid_obj = uuid.UUID(uuid_to_test, version=version)
   except:
      return bValid

   if str(uuid_obj) == uuid_to_test:
      bValid = True

   return bValid

def is_valid_config(dConfig, dSchema=CONFIG_SCHEMA, bExitOnFail=True):
   """
Validate the json configuration base on given schema.

Default schema supports below information:

.. code:: python

   CONFIG_SCHEMA = {
      "components": [str, dict],
      "variant"   : str,
      "version_sw": str,
      "version_hw": str,
      "version_test": str,
      "testtool"  :  str,
      "tester"    :  str
   }

**Arguments:**

*  ``dConfig``

   / *Condition*: required / *Type*: dict /

   Json configuration object to be verified.

*  ``dSchema``

   / *Condition*: optional / *Type*: dict / *Default*: CONFIG_SCHEMA /

   Schema for the validation.

*  ``bExitOnFail``

   / *Condition*: optional / *Type*: bool / *Default*: True /

   If True, exit tool in case the validation is fail.

**Returns:**

*  ``bValid``

   / *Type*: bool /

   True if the given json configuration data is valid.
   """
   bValid = True
   for key in dConfig:
      if key in dSchema.keys():
         # List of support types
         if isinstance(dSchema[key], list):
            if type(dConfig[key]) not in dSchema[key]:
               bValid = False
         # Fixed type
         else:
            if type(dConfig[key]) != dSchema[key]:
               bValid = False

         if not bValid:
            Logger.log_error(f"Value of '{key}' has wrong type '{type(dConfig[key])}' in configuration json file.",
                             fatal_error=bExitOnFail)
            break

      else:
         bValid = False
         Logger.log_error(f"Information '{key}' is not supported in configuration json file.",
                          fatal_error=bExitOnFail)
         break

   return bValid

def get_from_tags(lTags, reInfo):
   """
Extract testcase information from tags.

Example:
   ``TCID-xxxx``, ``FID-xxxx``, ...

**Arguments:**

*  ``lTags``

   / *Condition*: required / *Type*: list /

   List of tag information.

*  ``reInfo``

   / *Condition*: required / *Type*: str /

   Regex to get the expectated info (ID) from tag info.

**Returns:**

*  ``lInfo``

   / *Type*: list /

   List of expected information (ID)
   """
   lInfo = []
   if len(lTags) != 0:
      for tag in lTags:
         oMatch = re.search(reInfo, tag, re.I)
         if oMatch:
            lInfo.append(oMatch.group(1))
   return lInfo

def get_branch_from_swversion(sw_version):
   """
Get branch name from software version information.

Convention of branch information in suffix of software version:

*  All software version with .0F is the main/freature branch.
   The leading number is the current year. E.g. ``17.0F03``
*  All software version with ``.1S``, ``.2S``, ... is a stabi branch.
   The leading number is the year of branching out for stabilization.
   The number before "S" is the order of branching out in the year.

**Arguments:**

*  ``sw_version``

   / *Condition*: required / *Type*: str /

   Software version.

**Returns:**

*  ``branch_name``

   / *Type*: str /

   Branch name.
   """
   branch_name = "main"
   version_number=re.findall(r"(\d+\.)(\d+)([S,F])\d+",sw_version.upper())
   try:
      branch_name = "".join(version_number[0])
   except:
      pass
   if branch_name.endswith(".0F"):
      branch_name="main"
   return branch_name

def format_time(sTime):
   """
Format the given time string to TestResultWebApp's format for importing to db.

**Arguments:**

*  ``stime``

   / *Condition*: required / *Type*: str /

   String of time.

**Returns:**

*  ``sFormatedTime``

   / *Type*: str /

   TestResultWebApp's time as format ``%Y-%m-%d %H:%M:%S``.
   """
   try:
      sFormatedTime = sTime[0:4]+"-"+sTime[4:6]+"-"+sTime[6:]
   except Exception as reason:
      Logger.log_error(f"Cannot convert given time '{sTime}' to TestResultWebApp's time format.\nReason: {reason}",
                        fatal_error=True)
   return sFormatedTime

def retrieve_result_starttime(objResult):
   """
Retrieve starttime infomration from given result object (TestSuite or TestCase).
In case the starttime in given suite is 'N/A', it will try to get this information from its children suite/test.

**Arguments:**

*  ``stime``

   / *Condition*: required / *Type*: `TestSuite` or `TestCase` object /

   Result object to retrieve starttime.

**Returns:**

*  / *Type*: str /

   Start time of given result.
   """
   lStarttime = []
   # Try to get starttime from root TestSuite to children TestCase
   if type(objResult).__name__ == "TestSuite":
      if objResult.starttime:
         return objResult.starttime
      elif len(objResult.suites) > 0:
         lStarttime = [suite_starttime for suite in objResult.suites if (suite_starttime:=retrieve_result_starttime(suite)) is not None]
      else:
         lStarttime = [test_starttime for test in objResult.tests if (test_starttime:=retrieve_result_starttime(test)) is not None]
   elif type(objResult).__name__ == "TestCase":
      if objResult.starttime:
         return objResult.starttime

   if len(lStarttime):
      return min(lStarttime)

   return None

def retrieve_result_endtime(objResult):
   """
Retrieve endtime infomration from given result object (TestSuite or TestCase).
In case the endtime in given suite is 'N/A', it will try to get this information from its children suite/test.

**Arguments:**

*  ``stime``

   / *Condition*: required / *Type*: `TestSuite` or `TestCase` object /

   Result object to retrieve endtime.

**Returns:**

*  / *Type*: str /

   End time of given result.
   """
   lEndtime = []
   # Try to get endtime from root TestSuite to children TestCase
   if type(objResult).__name__ == "TestSuite":
      if objResult.endtime:
         return objResult.endtime
      elif len(objResult.suites) > 0:
         lEndtime = [suite_endtime for suite in objResult.suites if (suite_endtime:=retrieve_result_endtime(suite)) is not None]
      else:
         lEndtime = [test_endtime for test in objResult.tests if (test_endtime:=retrieve_result_endtime(test)) is not None]
   elif type(objResult).__name__ == "TestCase":
      if objResult.endtime:
         return objResult.endtime

   if len(lEndtime):
      return max(lEndtime)

   return None


def __process_commandline():
   """
Process provided argument(s) from command line.

Avalable arguments in command line:

   - `-v`, `--version` : tool version information.
   - `resultxmlfile` : path to the xml result file or directory of result files to be imported.
   - `server` : server which hosts the database (IP or URL).
   - `user` : user for database login.
   - `password` : password for database login.
   - `database` : database name.
   - `--recursive` : if True, then the path is searched recursively for log files to be imported.
   - `--dryrun` : if True, then verify all input arguments (includes DB connection) and show what would be done.
   - `--append` : if True, then allow to append new result(s) to existing execution result UUID which is provided by --UUID argument.
   - `--UUID` : UUID used to identify the import and version ID on TestResultWebApp.
   - `--variant` : variant name to be set for this import.
   - `--versions` : metadata: Versions (Software;Hardware;Test) to be set for this import.
   - `--config` : configuration json file for component mapping information.

**Arguments:**

(*no arguments*)

**Returns:**

   / *Type*: `ArgumentParser` object /

   ArgumentParser object.
   """
   PROG_NAME = "RobotLog2DB (RobotXMLResult to TestResultWebApp importer)"
   PROG_DESC = "RobotLog2DB imports XML result files (default: output.xml) "+\
               "generated by the Robot Framework into a WebApp database."

   cmdParser = argparse.ArgumentParser(prog=PROG_NAME, description=PROG_DESC)

   cmdParser.add_argument('-v', '--version', action='version',
                           version=f'v{VERSION} ({VERSION_DATE})',
                           help='version of the RobotLog2DB importer.')
   cmdParser.add_argument('resultxmlfile', type=str,
                           help='absolute or relative path to the result file or directory of result files to be imported.')
   cmdParser.add_argument('server', type=str,
                           help='server which hosts the database (IP or URL).')
   cmdParser.add_argument('user', type=str,
                           help='user for database login.')
   cmdParser.add_argument('password', type=str,
                           help='password for database login.')
   cmdParser.add_argument('database', type=str,
                           help='database schema for database login.')
   cmdParser.add_argument('--recursive', action="store_true",
                           help='if set, then the path is searched recursively for output files to be imported.')
   cmdParser.add_argument('--dryrun', action="store_true",
                           help='if set, then verify all input arguments (includes DB connection) and show what would be done.')
   cmdParser.add_argument('--append', action="store_true",
                           help='is used in combination with --UUID <UUID>.'+\
                                'If set, allow to append new result(s) to existing execution result UUID in --UUID argument.')
   cmdParser.add_argument('--UUID', type=str,
                           help='UUID used to identify the import and version ID on webapp. '+\
                                'If not provided RobotLog2DB will generate an UUID for the whole import.')
   cmdParser.add_argument('--variant', type=str,
                           help='variant name to be set for this import.')
   cmdParser.add_argument('--versions', type=str,
                           help='metadata: Versions (Software;Hardware;Test) to be set for this import (semicolon separated).')
   cmdParser.add_argument('--config', type=str,
                           help='configuration json file for component mapping information.')
   cmdParser.add_argument('--interface', choices=['db', 'rest'], default='db', help='database access interface.')

   return cmdParser.parse_args()

def process_suite_metadata(suite, default_metadata=DEFAULT_METADATA):
   """
Try to find metadata information from all suite levels.

Metadata at top suite level has a highest priority.

**Arguments:**

*  ``suite``

   / *Condition*: required / *Type*: `TestSuite` object /

   Robot suite object.

*  ``default_metadata``

   / *Condition*: optional / *Type*: dict / *Default*: DEFAULT_METADATA /

   Initial Metadata information for updating.

**Returns:**

*  ``dMetadata``

   / *Type*: dict /

   Dictionary of Metadata information.
   """
   dMetadata = dict(default_metadata)
   # Try to get metadata from first child of suite - multiple log files
   if suite.suites != None and len(list(suite.suites)) > 0:
      dMetadata = process_suite_metadata(suite.suites[0], dMetadata)
   # The higher suite level metadata have higher priority
   if suite.metadata != None:
      dMetadata = process_metadata(suite.metadata, dMetadata)

   return dMetadata

def process_metadata(metadata, default_metadata=DEFAULT_METADATA):
   """
Extract metadata from suite result bases on DEFAULT_METADATA.

**Arguments:**

*  ``metadata``

   / *Condition*: required / *Type*: dict /

   Robot metadata object.

*  ``default_metadata``

   / *Condition*: optional / *Type*: dict / *Default*: DEFAULT_METADATA /

   Initial Metadata information for updating.

**Returns:**

*  ``dMetadata``

   / *Type*: dict /

   Dictionary of Metadata information.
   """
   dMetadata = dict(default_metadata)
   for key in dMetadata.keys():
      if key in metadata:
         if metadata[key] != None:
            dMetadata[key] = metadata[key]

   return dMetadata

def process_suite(db, suite, _tbl_test_result_id, root_metadata, dConfig=None):
   """
Process to the lowest suite level (test file):

* Create new file and its header information
* Then, process all child test cases

**Arguments:**

*  ``db``

   / *Condition*: required / *Type*: `CDataBase` object /

   CDataBase object.

*  ``suite``

   / *Condition*: required / *Type*: `TestSuite` object /

   Robot suite object.

*  ``_tbl_test_result_id``

   / *Condition*: required / *Type*: str /

   UUID of test result for importing.

*  ``root_metadata``

   / *Condition*: required / *Type*: dict /

   Metadata information from root level.

*  ``dConfig``

   / *Condition*: required / *Type*: dict / *Default*: None /

   Configuration data which is parsed from given json configuration file.

**Returns:**

(*no returns*)
   """
   if len(list(suite.suites)) > 0:
      for subsuite in suite.suites:
         process_suite(db, subsuite, _tbl_test_result_id, root_metadata,
                       dConfig)
   else:
      # File metadata
      metadata_info = process_metadata(suite.metadata, root_metadata)
      _tbl_file_name = str(suite.source)
      _tbl_file_tester_account = metadata_info['tester']
      if dConfig != None and 'tester' in dConfig:
         _tbl_file_tester_account = dConfig['tester']
      _tbl_file_tester_machine = metadata_info['machine']

      sSuiteStarttime = retrieve_result_starttime(suite)
      sSuiteEndtime   = retrieve_result_endtime(suite)
      if not sSuiteStarttime:
         Logger.log_error(f"Could not retieve start time of suite '{suite.name}'.")
      if not sSuiteEndtime:
         Logger.log_error(f"Could not retieve end time of suite '{suite.name}'.")
      _tbl_file_time_start     = format_time(sSuiteStarttime)
      _tbl_file_time_end       = format_time(sSuiteEndtime)

      # Process component information if not provided in metadata
      if metadata_info['component'] == '':
         # assign default component name as 'unknown'
         metadata_info['component'] = 'unknown'

         # process component mapping if provided in config file
         if dConfig != None and 'components' in dConfig:
            if isinstance(dConfig['components'], dict):
               for cmpt_name in dConfig['components']:
                  if isinstance(dConfig['components'][cmpt_name], list):
                     bFound = False
                     for path in dConfig['components'][cmpt_name]:
                        if (normalize_path(path) in
                            normalize_path(_tbl_file_name)):
                           metadata_info['component'] = cmpt_name
                           bFound = True
                           break
                     if bFound:
                        break
                  elif isinstance(dConfig['components'][cmpt_name], str):
                     cmpt_path = normalize_path(dConfig['components'][cmpt_name])
                     if cmpt_path in normalize_path(_tbl_file_name):
                        metadata_info['component'] = cmpt_name
                        break
            elif (isinstance(dConfig['components'], str) and
                  dConfig['components'].strip() != ""):
               metadata_info['component'] = dConfig['components']

      # New test file
      if not Logger.dryrun:
         try:
            _tbl_file_id = db.nCreateNewFile(_tbl_file_name,
                                             _tbl_file_tester_account,
                                             _tbl_file_tester_machine,
                                             _tbl_file_time_start,
                                             _tbl_file_time_end,
                                             _tbl_test_result_id)
         except Exception as reason:
            Logger.log_error(f"Cannot create new test file result for file '{_tbl_file_name}' in database.\nReason: {reason}",
                             fatal_error=True)
      else:
         _tbl_file_id = "file id for dryrun"
      Logger.log(f"Created test file result for file '{_tbl_file_name}' successfully: {str(_tbl_file_id)}",
                 indent=2)

      _tbl_header_testtoolname    = ""
      _tbl_header_testtoolversion = ""
      _tbl_header_pythonversion   = ""
      sTestTool = metadata_info['testtool']
      if dConfig != None and 'testtool' in dConfig:
         sTestTool = dConfig['testtool']
      if sTestTool != "":
         sFindstring=r"([a-zA-Z\s\_]+[^\s])\s+([\d\.rcab]+)\s+\(Python\s+(.*)\)"
         oTesttool = re.search(sFindstring, sTestTool)
         if oTesttool:
            _tbl_header_testtoolname   = oTesttool.group(1)
            _tbl_header_testtoolversion= oTesttool.group(2)
            _tbl_header_pythonversion  = oTesttool.group(3)

      _tbl_header_projectname = metadata_info['project']
      _tbl_header_logfileencoding = "UTF-8"
      _tbl_header_testfile    = _tbl_file_name
      _tbl_header_logfilepath = ""
      _tbl_header_logfilemode = ""
      _tbl_header_ctrlfilepath= ""
      _tbl_header_configfile  = metadata_info['configfile']
      _tbl_header_confname    = ""

      _tbl_header_author        = metadata_info['author']
      _tbl_header_project       = metadata_info['project']
      _tbl_header_testfiledate  = ""
      _tbl_header_version_major = ""
      _tbl_header_version_minor = ""
      _tbl_header_version_patch = ""
      _tbl_header_keyword       = ""
      _tbl_header_shortdescription = suite.doc
      _tbl_header_useraccount   = metadata_info['tester']
      _tbl_header_computername  = metadata_info['machine']

      _tbl_header_testrequirements_documentmanagement = ""
      _tbl_header_testrequirements_testenvironment    = ""

      _tbl_header_testbenchconfig_name    = ""
      _tbl_header_testbenchconfig_data    = ""
      _tbl_header_preprocessor_filter     = ""
      _tbl_header_preprocessor_parameters = ""

      if not Logger.dryrun:
         try:
            db.vCreateNewHeader(_tbl_file_id,
                              _tbl_header_testtoolname,
                              _tbl_header_testtoolversion,
                              _tbl_header_projectname,
                              _tbl_header_logfileencoding,
                              _tbl_header_pythonversion,
                              _tbl_header_testfile,
                              _tbl_header_logfilepath,
                              _tbl_header_logfilemode,
                              _tbl_header_ctrlfilepath,
                              _tbl_header_configfile,
                              _tbl_header_confname,

                              _tbl_header_author,
                              _tbl_header_project,
                              _tbl_header_testfiledate,
                              _tbl_header_version_major,
                              _tbl_header_version_minor,
                              _tbl_header_version_patch,
                              _tbl_header_keyword,
                              _tbl_header_shortdescription,
                              _tbl_header_useraccount,
                              _tbl_header_computername,

                              _tbl_header_testrequirements_documentmanagement,
                              _tbl_header_testrequirements_testenvironment,

                              _tbl_header_testbenchconfig_name,
                              _tbl_header_testbenchconfig_data,
                              _tbl_header_preprocessor_filter,
                              _tbl_header_preprocessor_parameters
                              )
         except Exception as reason:
            Logger.log_error(f"Cannot create new test file header result for file '{_tbl_file_name}' in database.\nReason: {reason}",
                             fatal_error=True)
      if len(list(suite.tests)) > 0:
         test_number = 1
         for test in suite.tests:
            process_test(db, test, _tbl_file_id, _tbl_test_result_id,
                         metadata_info, test_number)
            test_number = test_number + 1

def process_test(db, test, file_id, test_result_id, metadata_info, test_number):
   """
Process test case data and create new test case record.

**Arguments:**

*  ``db``

   / *Condition*: required / *Type*: `CDataBase` object /

   CDataBase object.

*  ``test``

   / *Condition*: required / *Type*: `TestCase` object /

   Robot test object.

*  ``file_id``

   / *Condition*: required / *Type*: int /

   File ID for mapping.

*  ``test_result_id``

   / *Condition*: required / *Type*: str /

   Test result ID for mapping.

*  ``metadata_info``

   / *Condition*: required / *Type*: dict /

   Metadata information.

*  ``test_number``

   / *Condition*: required / *Type*: int /

   Order of test case in file.

**Returns:**

(*no returns*)
   """
   global iTotalTestcase
   global iSuccessTestcase
   global dComponentCounter
   iTotalTestcase += 1
   _tbl_case_name  = test.name
   _tbl_case_issue = ";".join(get_from_tags(test.tags, "ISSUE-(.+)"))
   _tbl_case_tcid  = ";".join(get_from_tags(test.tags, "TCID-(.+)"))
   _tbl_case_fid   = ";".join(get_from_tags(test.tags, "FID-(.+)"))
   _tbl_case_testnumber  = test_number
   _tbl_case_repeatcount = 1
   _tbl_case_component   = metadata_info['component']
   _tbl_case_time_start  = format_time(test.starttime)
   _tbl_case_time_end    = format_time(test.endtime)
   if _tbl_case_component not in dComponentCounter:
      dComponentCounter[_tbl_case_component] = 0
   try:
      _tbl_case_result_main = DRESULT_MAPPING[test.status]
   except Exception:
      # Robotframework result's validation is done before
      # Set further status as unknown
      _tbl_case_result_main = DRESULT_MAPPING['UNKNOWN']

   _tbl_case_result_state   = "complete"
   _tbl_case_result_return  = 11
   _tbl_case_counter_resets = 0
   try:
      _tbl_case_lastlog = str(base64.b64encode(test.message.encode()), encoding="utf-8")
   except:
      _tbl_case_lastlog = None
   _tbl_test_result_id = test_result_id
   _tbl_file_id = file_id

   if not Logger.dryrun:
      try:
         tbl_case_id = db.nCreateNewSingleTestCase(_tbl_case_name,
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
      except Exception as reason:
         Logger.log_error(f"Cannot create new test case result for test '{_tbl_case_name}' in database.\nReason: {reason}")
         return
   else:
      tbl_case_id = "testcase id for dryrun"
   iSuccessTestcase += 1
   dComponentCounter[_tbl_case_component] += 1
   component_msg = f" (component: {_tbl_case_component})" if _tbl_case_component != "unknown" else ""
   Logger.log(f"Created test case result for test '{_tbl_case_name}' successfully: {str(tbl_case_id)}{component_msg}", indent=4)

def process_config_file(config_file):
   """
Parse information from configuration file:

*  ``component``:

   .. code:: python

      {
         "components" : {
            "componentA" : "componentA/path/to/testcase",
            "componentB" : "componentB/path/to/testcase",
            "componentC" : [
               "componentC1/path/to/testcase",
               "componentC2/path/to/testcase"
            ]
         }
      }

   Then all testcases which their paths contain ``componentA/path/to/testcase``
   will be belong to ``componentA``, ...

*  ``variant``, ``version_sw``: configuration file has low priority than command line.

**Arguments:**

*  ``config_file``

   / *Condition*: required / *Type*: str /

   Path to configuration file.

**Returns:**

*  ``dConfig``

   / *Type*: dict /

   Configuration object.
   """

   with open(config_file, encoding='utf-8') as f:
      try:
         dConfig = json.load(f)
      except Exception as reason:
         Logger.log_error(f"Cannot parse the json file '{config_file}'. Reason: {reason}",
                          fatal_error=True)

   if not is_valid_config(dConfig, bExitOnFail=False):
      Logger.log_error(f"Error in configuration file '{config_file}'.",
                       fatal_error=True)
   return dConfig

def normalize_path(sPath):
   """
Normalize path file.

**Arguments:**

*  ``sPath``

   / *Condition*: required / *Type*: str /

   Path file to be normalized.

*  ``sNPath``

   / *Type*: str /

   Normalized path file.
   """
   if sPath.strip()=='':
      return ''

   #make all backslashes to slash, but mask
   #UNC indicator \\ before and restore after.
   sNPath=re.sub(r"\\\\",r"#!#!#",sPath.strip())
   sNPath=re.sub(r"\\",r"/",sNPath)
   sNPath=re.sub(r"#!#!#",r"\\\\",sNPath)

   return sNPath


def RobotLog2DB(args=None):
   """
Import robot results from ``output.xml`` to TestResultWebApp's database.

Flow to import Robot results to database:

1. Process provided arguments from command line.
2. Parse Robot results.
3. Connect to database.
4. Import results into database.
5. Disconnect from database.

**Arguments:**

*  ``args``

   / *Condition*: required / *Type*: `ArgumentParser` object /

   Argument parser object which contains:

   * `resultxmlfile` : path to the xml result file or directory of result files to be imported.
   * `server` : server which hosts the database (IP or URL).
   * `user` : user for database login.
   * `password` : password for database login.
   * `database` : database name.
   * `recursive` : if True, then the path is searched recursively for log files to be imported.
   * `dryrun` : if True, then verify all input arguments (includes DB connection) and show what would be done.
   * `append` : if True, then allow to append new result(s) to existing execution result UUID which is provided by --UUID argument.
   * `UUID` : UUID used to identify the import and version ID on TestResultWebApp.
   * `variant` : variant name to be set for this import.
   * `versions` : metadata: Versions (Software;Hardware;Test) to be set for this import.
   * `config` : configuration json file for component mapping information.

**Returns:**

(*no returns*)
   """
   # 1. process provided arguments from command line as default
   args = __process_commandline()
   Logger.config(dryrun=args.dryrun)

   # 2. Parse results from Robotframework xml result file(s)
   listEntries = collect_xml_result_files(args.resultxmlfile, args.recursive)

   sources = tuple(listEntries)
   result = ExecutionResult(*sources)
   result.configure()

   # get metadata from top level of testsuite
   metadata_info = {}
   if result.suite != None:
      metadata_info = process_suite_metadata(result.suite)

   else:
      Logger.log_error("Could not get suite data from xml result file",
                       fatal_error=True)

   # Validate provided UUID
   if args.UUID!=None:
      if is_valid_uuid(args.UUID):
         pass
      else:
         Logger.log_error(f"The uuid provided is not valid: '{args.UUID}'", fatal_error=True)

   # Validate provided versions info (software;hardware;test)
   arVersions = []
   if args.versions!=None and args.versions.strip() != "":
      arVersions=args.versions.split(";")
      arVersions=[x.strip() for x in arVersions]
      if len(arVersions)>3:
         Logger.log_error(f"The provided versions information is not valid: '{str(args.versions)}'",
                          fatal_error=True)

   # Validate provided configuration file (component, variant, version_sw)
   dConfig = None
   if args.config != None:
      if os.path.isfile(args.config):
         dConfig = process_config_file(args.config)
      else:
         Logger.log_error(f"The provided config file is not existing: '{args.config}'" ,
                          fatal_error=True)

   # 3. Connect to database
   db = DBAccessFactory().create(args.interface)
   try:
      db.connect(args.server,
                 args.user,
                 args.password,
                 args.database,
                 "utf8mb4")
   except Exception as reason:
      Logger.log_error(f"Could not connect to database: '{reason}'",
                       fatal_error=True)

   # 4. Import results into database
   #    Create new execution result in database
   #    |
   #    '---Create new file result(s)
   #        |
   #        '---Create new test result(s)
   try:
      bUseDefaultPrjVariant = True
      bUseDefaultVersionSW  = True
      sMsgVarirantSetBy = sMsgVersionSWSetBy = "default value"

      # Process project/variant info
      sVariant = metadata_info['project']
      if args.variant!=None and args.variant.strip() != "":
         bUseDefaultPrjVariant = False
         sMsgVarirantSetBy = "from --variant commandline argument"
         sVariant = args.variant.strip()
      elif dConfig != None and 'variant' in dConfig:
         bUseDefaultPrjVariant = False
         sMsgVarirantSetBy = f"from configuration '{args.config}' file provided by --config"
         sVariant = dConfig['variant']
      _tbl_prj_project = _tbl_prj_variant = sVariant

      # Process versions info
      sVersionSW = metadata_info['version_sw']
      sVersionHW  = metadata_info['version_hw']
      sVersionTest   = metadata_info['version_test']
      if len(arVersions) > 0:
         bUseDefaultVersionSW = False
         sMsgVersionSWSetBy = "from --versions commandline argument"
         if len(arVersions)==1 or len(arVersions)==2 or len(arVersions)==3:
            sVersionSW = arVersions[0]
         if len(arVersions)==2 or len(arVersions)==3:
            sVersionHW = arVersions[1]
         if len(arVersions)==3:
            sVersionTest = arVersions[2]
      elif dConfig != None:
         if 'version_sw' in dConfig:
            bUseDefaultVersionSW = False
            sMsgVersionSWSetBy = f"from configuration '{args.config}' file provided by --config"
            sVersionSW = dConfig['version_sw']
         if 'version_hw' in dConfig:
            sVersionHW = dConfig['version_hw']
         if 'version_test' in dConfig:
            sVersionTest = dConfig['version_test']
      _tbl_result_version_sw_target = sVersionSW
      _tbl_result_version_hardware  = sVersionHW
      _tbl_result_version_sw_test   = sVersionTest

      # Process start/end time info
      sExecutionStarttime = retrieve_result_starttime(result.suite)
      sExecutionEndtime   = retrieve_result_endtime(result.suite)
      if not sExecutionStarttime:
         Logger.log_error(f"Could not retieve execution start time."+
                           "\nPlease use rebot with option '--starttime timestamp' when merging/combining result files."+
                           "\nOr rerun Robotframework testcase(s) to get proper *.xml result file.",
                           fatal_error=True)
      if not sExecutionEndtime:
         Logger.log_error(f"Could not retieve execution end time."+
                           "\nPlease use rebot with option '--endtime timestamp' when merging/combining result files."+
                           "\nOr rerun Robotframework testcase(s) to get proper *.xml result file",
                           fatal_error=True)

      _tbl_result_time_start = format_time(sExecutionStarttime)
      _tbl_result_time_end   = format_time(sExecutionEndtime)

      # Set version as start time of the execution if not provided in metadata
      # Format: %Y%m%d_%H%M%S
      if _tbl_result_version_sw_target=="":
         bUseDefaultVersionSW = True
         _tbl_result_version_sw_target = re.sub(r'(\d{8})\s(\d{2}):(\d{2}):(\d{2})\.\d+',
                                                r'\1_\2\3\4', sExecutionStarttime)
      if not args.append:
         Logger.log(f"Set project/variant to '{sVariant}' ({sMsgVarirantSetBy})")
         Logger.log(f"Set version_sw to '{_tbl_result_version_sw_target}' ({sMsgVersionSWSetBy})")

      # Process branch info from software version
      _tbl_prj_branch = get_branch_from_swversion(_tbl_result_version_sw_target)

      # Process UUID info
      if args.UUID != None:
         _tbl_test_result_id = args.UUID
      else:
         _tbl_test_result_id = str(uuid.uuid4())
         if args.append:
            Logger.log_error("'--append' argument should be used in combination with '--UUID <UUID>` argument.", fatal_error=True)

      # Process other info
      _tbl_result_interpretation = ""
      _tbl_result_jenkinsurl     = ""
      _tbl_result_reporting_qualitygate = ""

      # Check the UUID is existing or not
      error_indent = len(Logger.prefix_fatalerror)*' '
      _db_result_info = db.arGetProjectVersionSWByID(_tbl_test_result_id)
      if _db_result_info:
         if args.append:
            # Check given variant/project and version_sw (not default values) with existing values in db
            _db_prj_variant = _db_result_info[0]
            _db_version_sw  = _db_result_info[1]
            if not bUseDefaultPrjVariant and _tbl_prj_variant != _db_prj_variant:
               Logger.log_error(f"Given project/variant '{_tbl_prj_variant}' ({sMsgVarirantSetBy}) is different with existing value '{_db_prj_variant}' in database.", fatal_error=True)
            elif not bUseDefaultVersionSW and _tbl_result_version_sw_target != _db_version_sw:
               Logger.log_error(f"Given version software '{_tbl_result_version_sw_target}' ({sMsgVersionSWSetBy}) is different with existing value '{_db_version_sw}' in database.", fatal_error=True)
            else:
               Logger.log(f"Append to existing test execution result for variant '{_db_prj_variant}' - version '{_db_version_sw}' - UUID '{_tbl_test_result_id}'.")
         else:
            Logger.log_error(f"Execution result with UUID '{_tbl_test_result_id}' is already existing. \
               \n{error_indent}Please use other UUID (or remove '--UUID' argument from your command) for new execution result. \
               \n{error_indent}Or add '--append' argument in your command to append new result(s) to this existing UUID.",
               fatal_error=True)
      else:
         if args.append:
            Logger.log_error(f"Execution result with UUID '{_tbl_test_result_id}' is not existing for appending.\
               \n{error_indent}Please use an existing UUID to append new result(s) to that UUID. \
               \n{error_indent}Or remove '--append' argument in your command to create new execution result with given UUID.",
               fatal_error=True)
         else:
            # Process new test result
            if not Logger.dryrun:
               db.sCreateNewTestResult(_tbl_prj_project,
                                       _tbl_prj_variant,
                                       _tbl_prj_branch,
                                       _tbl_test_result_id,
                                       _tbl_result_interpretation,
                                       _tbl_result_time_start,
                                       _tbl_result_time_end,
                                       _tbl_result_version_sw_target,
                                       _tbl_result_version_sw_test,
                                       _tbl_result_version_hardware,
                                       _tbl_result_jenkinsurl,
                                       _tbl_result_reporting_qualitygate)
            Logger.log(f"Created test execution result for variant '{_tbl_prj_variant}' - version '{_tbl_result_version_sw_target}' successfully: {str(_tbl_test_result_id)}")
   except Exception as reason:
      Logger.log_error(f"Could not create new execution result in database. Reason: {reason}", fatal_error=True)

   process_suite(db, result.suite, _tbl_test_result_id, metadata_info, dConfig)

   if not Logger.dryrun:
      db.vUpdateEvtbls()
      db.vFinishTestResult(_tbl_test_result_id)
      if args.append:
         db.vUpdateEvtbl(_tbl_test_result_id)

   # 5. Disconnect from database
   db.disconnect()
   import_mode_msg = "append" if args.append else "written"
   testcnt_msg = f"All {iTotalTestcase}"
   extended_msg = ""
   if (iTotalTestcase>iSuccessTestcase):
      testcnt_msg  = f"{iSuccessTestcase} of {iTotalTestcase}"
      extended_msg = f" {iTotalTestcase-iSuccessTestcase} test cases are skipped because of errors."
   Logger.log()
   Logger.log(f"{testcnt_msg} test cases are {import_mode_msg} to database successfully.{extended_msg}")

   # Components's statistics
   iMaxlenCmptStr = len(max(dComponentCounter, key=len))
   for component in dComponentCounter:
      Logger.log(f"Component {component.ljust(iMaxlenCmptStr, ' ')} : {dComponentCounter[component]} test cases")

if __name__=="__main__":
   RobotLog2DB()
