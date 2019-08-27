#!/usr/bin/env python3
# vim: ts=3:sw=3:et

import os
import sys
import traceback
import re
import csv
import time
import logging
import logging.config
import argparse
import datetime
import configparser
import threading
import smtplib
from saq.constants import *
from saq.client import Alert
import csv

from splunklib import SplunkQueryObject
from master_search_file import get_search_string

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--search', required=False, default=None, dest='search',
   help="The splunk search to execute.")
parser.add_argument('-g', '--group-by', required=False, default=None, dest='group_by',
   help="Group results by the given field name.")
parser.add_argument('-c', '--config', required=False, default='splunk_detect.cfg', dest='config',
   help="Configuration file to use.")
parser.add_argument('--log-config', required=False, default='splunk_detect_logging.cfg', dest='log_config',
   help="Use the given configuration file to configure logging.")

parser.add_argument('--cron', required=False, default=False, action='store_true', dest='cron_mode',
   help="Execute in cron mode, where we run whatever searches are scheduled at this minute.")
parser.add_argument('searches', nargs="*", default=[],
   help="Execute the given searches by name.  Partial string matching is OK.")
parser.add_argument('--csv', required=False, default='Splunk_Search_Master.csv', dest='csv_path',
   help="Path to the CSV file to execute.  Defaults to Splunk_Search_Master.csv")

parser.add_argument('--earliest', required=False, default=None, dest='earliest',
   help="Override earliest parameter to splunk search.  Does not apply to --cron mode.  Format is MM/DD/YYYY:hh:mm:ss (or short form)")
parser.add_argument('--latest', required=False, default=None, dest='latest',
   help="Override latest parameter to splunk search.  Does not apply to --cron mode.  Format is MM/DD/YYYY:hh:mm:ss (or short form)")

args = parser.parse_args()
print(args)

try:
   # configure logging
   logging.config.fileConfig(args.log_config)
except Exception as e:
   sys.stderr.write("unable to load logging configuration file {0}: {1}".format(
      args.log_config, str(e)))
   sys.exit(1)

# load splunk_detect configuration
config = configparser.ConfigParser()
config.read(args.config)

# clear proxy settings
for setting in [ 'http_proxy', 'https_proxy' ]:
   if setting in os.environ:
      logging.warning("clearing proxy environment variable {0}".format(setting))
      del os.environ[setting]

search_queue = [] # list of (search, group_by) tuples to execute in parallel

# are we running in cron mode?
if args.cron_mode:
   # get the current minute
   current_minute = str(datetime.datetime.now().minute)
   # open the csv file and find searches that are scheduled for this minute
   reader = csv.DictReader(open(args.csv_path, 'r'))
   for row in reader:

      # XXX all the columns have <TITLE> but the other functions doesn't expect them
      for key in list(row.keys()):
         row[key[1:-1]] = row[key]

      if row['Schedule'] == current_minute:
         search_string = get_search_string(row)
         group_by = None
         if row['Group_By'] != '':
            group_by = row['Group_By']

         logging.info(search_string)
         search_queue.append((search_string, group_by))

# select searches by name?
elif len(args.searches) > 0:
   # open the csv file and find searches that have names that match
   reader = csv.DictReader(open(args.csv_path, 'r'))
   for row in reader:

      # XXX all the columns have <TITLE> but the other functions doesn't expect them
      for key in list(row.keys()):
         row[key[1:-1]] = row[key]

      # allow time spec override
      if args.earliest is not None:
         if args.latest is None:
            args.latest='now'

         row['Earliest_Latest'] = ' _index_earliest={0} _index_latest={1}'.format(args.earliest, args.latest)

      for search in args.searches:
         if search.lower() in row['Saved_Search_Name'].lower():
            search_string = get_search_string(row)
            group_by = None
            if row['Group_By'] != '':
               group_by = row['Group_By']

            search_queue.append((search_string, group_by))

# manual search?
elif args.search:
   search_queue.append((args.search, args.group_by))

else:
   logging.fatal("you must specifiy --cron, -s (and -g), or search names to execute")
   sys.exit(1)

def handle_search_failure(search, group_by, exception=None):
   if not config.getboolean('smtp', 'enabled'):
      return

   header = '\r\n'.join([
      'From: splunk_detect@localhost',
      'To: {0}'.format(config.get('smtp', 'recipients')),
      'Subject: Splunk Search Failure'])

   message = '{0}\r\n\r\n{1}'.format(
      header, "The following splunk search failed.\r\n\r\n{0}".format(
         search))

   if exception is not None:
      message += "\r\n\r\nThe following exception was thrown.\r\n\r\n{0}".format(
         traceback.format_exc())
   else:
      message += "\r\n\r\nThe splunk server returned an HTTP error code."

   try:
      server = smtplib.SMTP(config.get('smtp', 'server'))
      server.set_debuglevel(1)
      logging.warning("sending email to {0}".format(config.get('smtp', 'recipients')))
      server.sendmail('splunk_detect@localhost', config.get('smtp', 'recipients').split(','), message)
      server.quit()
   except Exception as e:
      logging.error("unable to send email: {0}".format(str(e)))

def execute_search_wrapper(search, group_by):
   try:
      execute_search(search, group_by)
   except Exception as e:
      logging.error("caught exception {0}".format(str(e)))
      handle_search_failure(search, group_by, e)
      traceback.print_exc()

def indicator_lookup(row):
   ltable_file = config.get('splunk', 'lookuptablefile')
   csvfile = csv.DictReader(open(ltable_file))
   for indrow in csvfile:
      if indrow['Indicator_Type'] == row['Indicator_Type']: 
         #if we have specified specific fields to match this indicator type on, then only check those fields for matches
         if 'Field_Matches' in row:
            for key in row['Field_Matches'].split('<!FIELD!>'):
               logging.debug("checking {0} against specific field {1} value {2}".format(indrow['Indicator'].lower(), str(key), str(row[key]).lower()))
               if isinstance(row[key], list):
                  logging.debug("field is a list")
                  for val in row[key]:
                     logging.debug("checking {0} against specific field {1} value {2}".format(indrow['Indicator'].lower(), str(key), str(val).lower()))
                     if indrow['Indicator'].lower() in str(val).lower():
                        return indrow['Indicator'], indrow['ObjectID']
               elif indrow['Indicator'].lower() in str(row[key]).lower():
                  return indrow['Indicator'], indrow['ObjectID']


         else:
         #else, try all fields
            for key in row:
               logging.debug("checking {0} against {1}".format(indrow['Indicator'].lower(), str(row[key]).lower()))
               if isinstance(row[key], list):
                  for val in row[key]:
                     logging.debug("checking {0} against {1}".format(indrow['Indicator'].lower(), str(val).lower()))
                     if indrow['Indicator'].lower() in str(val).lower():
                        return indrow['Indicator'], indrow['ObjectID'] 
               elif indrow['Indicator'].lower() in str(row[key]).lower():
                  return indrow['Indicator'], indrow['ObjectID']

   logging.debug("indicator lookup returned no results for {0} {1}".format(str(row['Alert_Name']),str(row)))
   return None,None

   

def execute_search(search, group_by):
   """Execute the given search, optionally grouped into alerts by the given field (or None if no grouping is required.)"""

   logging.info("running search {0} grouped by {1}".format(search, group_by))

   query_object = SplunkQueryObject(
      uri=config.get('splunk', 'Splunk_Server'),
      username=config.get('splunk', 'User'),
      password=config.get('splunk', 'Pass'),
      max_result_count=50,
      query_timeout='00:59:59')
   company = config.get('saq','company')
   compid  = config.get('saq','id')


   search_result = query_object.query(search)
   if not search_result:
      logging.error("searched failed")
      handle_search_failure(search, group_by)
      return False

   results_list = query_object.json()
   if results_list is None:
      logging.error("searched failed")
      handle_search_failure(search, group_by)
      return False

   if len(results_list) == 0:
      logging.debug("search returned no results")
      return True

   # now we want to split these alerts up according to how they should be grouped
   # for example if the alerts are based on a search of IDS hits then we might want to group them by src_ip
   if group_by:
      results = {} # key = group_by column value, value = [] of results
      for result in results_list:
         #match indicator to row, only add those items to results
         ind_value, objectid = indicator_lookup(result)
         if ind_value and objectid:
            result['Indicator'] = ind_value
            result['ObjectID'] = objectid

            if group_by not in result:
               logging.error("missing group_by column {0}".format(group_by))
               continue
         
            # handle splunk returning a list for a field value
            key = None
            if isinstance(result[group_by], list):
               key = ' '.join(result[group_by])
            else:
               key = result[group_by]

            if key not in results:
               results[key] = []

            results[key].append(result)
   else:
      # if we're not grouping then just move this entire result into a dummy dict
      results = { '': results_list } # kind of a hack to allow the same logic below for both conditions

   for group_by_item in list(results.keys()):
      results_list = results[group_by_item]

      if group_by_item != '':
         logging.debug("sending {0} alert details for {1}".format(len(results_list), group_by_item))

      if len(results_list) > 0:
         # decide on a name for this alert
         alert_name = results_list[0]['Alert_Name']
         
         # special case for indicators
         if 'Indicator' in results_list[0] and results_list[0]['Indicator'] is not None: 
            alert_name = '{0} - {1}'.format(alert_name, results_list[0]['Indicator'])
         elif group_by_item != '' and group_by_item is not None:
            alert_name = '{0} - {1}'.format(alert_name, group_by_item)
         else:
            alert_name = '{0}'.format(alert_name)

         alert_contents = {}
         alert_contents['details'] = results_list
         a = Alert(
            tool='splunk',
            company_name=company,
            company_id=compid,
            tool_instance='splunk_detect',
            alert_type='splunk', 
            desc=alert_name, 
            event_time=time.strftime("%Y-%m-%d %H:%M:%S"), 
            details=alert_contents)

         FIELD_MAPPING = {
            F_IPV4: [ 'src_ip', 'Framed_IP_Address', 'Calling_Station_ID', 'ip_address', 'dest_ip', 'remote_host_ip', 'dst_ip', 'Source_Network_Address' ],
            F_FQDN: [ 'uri_host' ],
            F_HOSTNAME: [ 'dest_nt_host', 'src_nt_host', 'Computer_Name', 'HostName', 'Workstation_Name', 'ComputerName', 'computer_name' ],
            F_ASSET: [ ],
            F_USER: [ 'user', 'User_Name', 'username','Account_Name','extracted_username' ],
            F_URL: [ 'URI','extracted_urls_mv' ],
            F_PCAP: [ ],
            F_FILE_PATH: [ 'file_path', 'FullPath', 'ProcessPath', 'docs{}.path', 'docs{}.process_name','attachment_names_mv' ],
            F_FILE_NAME: [ 'attachment_names_mv' ],
            F_EMAIL_ADDRESS: ['rcpto','from','mailfrom','reply-to','sender','extracted_fromaddr','extracted_toaddr','mail_to','mail_from','env_mail_from','env_mail_to' ],
            F_YARA: [ ],
            F_INDICATOR: [ 'ObjectID' ],
            F_SHA256: ['attachment_hashes_mv','FileHash','ProcessHash','hash_value'],
            F_MD5: ['MD5_Checksum','md5'],
            F_SHA1: ['hash_value','sha1'],
            F_MESSAGE_ID: ['message_id','msg_id']
         }

         TEMPORAL_OBSERVABLES = [ F_IPV4, F_IPV4_CONVERSATION, F_HOSTNAME ]
         INDICATOR_OBSERVABLE = [ F_INDICATOR ]

         for row in results_list:
            # is this observable type a temporal type?
            o_time = row['_time'] if '_time' in row else None
            if o_time is not None:
               m = re.match(r'^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{3}[-+][0-9]{2}:[0-9]{2}$', o_time)
               if not m:
                  logging.error("_time field does not match expected format: {0}".format(o_time))
               else:
                  # reformat this time for ACE
                  o_time = '{0}-{1}-{2} {3}:{4}:{5}'.format(
                     m.group(1),
                     m.group(2),
                     m.group(3),
                     m.group(4),
                     m.group(5),
                     m.group(6))

            # special case for F_IPV4_CONVERSATION types because they have multiple fields 
            # generate all permutations of combinations of IP addresses
            # the check for "is not None" is a hack, not sure why it could be None but we'll catch it here
            ipv4s = [row[field] for field in FIELD_MAPPING[F_IPV4] if field in row and row[field] is not None]
            if len(ipv4s) > 0:
               conversations = []
               while len(ipv4s) > 0:
                  ipv4 = ipv4s.pop()
                  for other_ipv4 in ipv4s:
                     a.add_observable(F_IPV4_CONVERSATION, create_ipv4_conversation(ipv4, other_ipv4), o_time)

            for o_type in FIELD_MAPPING:
               for field_name in FIELD_MAPPING[o_type]:
                  # does this field exist in this row?
                  if field_name in row:
                     # is the value of this field a list of things?
                     if isinstance(row[field_name], list):
                        for value in row[field_name]:
                           if value.strip() != '' and value.strip() != '-':
                              a.add_observable(o_type, value, o_time if o_type in TEMPORAL_OBSERVABLES else None)
                     # this is what we pretty much expect
                     elif isinstance(row[field_name], str):
                        if row[field_name].strip() != '' and row[field_name].strip() != '-':
                           a.add_observable(o_type, row[field_name], o_time if o_type in TEMPORAL_OBSERVABLES else None)
                     elif row[field_name] is None:
                        if o_type in INDICATOR_OBSERVABLE:
                           #for the instance where a substring is matched in the log, and the way splunk lookup tables work, it is impossible to lookup the indicator value that matched based on the full string in the log, so re-search the lookup table file and return the match here
                           ind_value, objectid = indicator_lookup(row) 
                           if ind_value and objectid:
                              row['Indicator'] = ind_value
                              row['ObjectID'] = objectid
                              a.description='{0} - {1}'.format(alert_name, ind_value)
                              a.add_observable(o_type, objectid, o_time if o_type in TEMPORAL_OBSERVABLES else None)
                           else:
                              logging.debug("skipping None value for field {0}".format(field_name))
                        else:
                           logging.debug("skipping None value for field {0}".format(field_name))
                     else:
                        print(a)
                        print("field_name:"+field_name)
                        print("row[fn]:"+row[field_name])
                        print("type:"+str(type(row[field_name])))
                        logging.error("unexpected data type for field {0}: {1}: {2}: alert:{3}".format(field_name, type(row[field_name]),row[field_name],a))
         
         try:
            #logging.info("submitting alert {0} to {1}".format(a, config.get('saq', 'SAQ_Server')))
            logging.info("submitting alert {0} to {1}".format(a, config['saq']['SAQ_Server']))
            #a.submit(config.get('saq', 'SAQ_Server'), 'blah')
            a.submit(config['saq']['SAQ_Server'], 'blah')
         except Exception as e:
            logging.error("unable to submit alert: {0}".format(str(e)))
            traceback.print_exc()

threads = []
for (search, group_by) in search_queue:
   t = threading.Thread(target=execute_search_wrapper, args=(search, group_by))
   t.start()
   threads.append(t)

for thread in threads:
   thread.join()
