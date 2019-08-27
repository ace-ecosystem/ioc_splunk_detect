#!/usr/bin/env python3
# vim: ts=3:sw=3:et

import csv
import configparser
from optparse import OptionParser

def get_search_string(row):
   #[|inputlookup test_all_indicators_lookup | search Indicator_Type="URI - Path" | fields Indicator | rename Indicator as query] index=bluecoat _index_earliest=-72m _index_latest=-10m OBSERVED AND NOT "windowsupdate.com" NOT "goskope.com" NOT "Unauthenticated" | eval URI = uri_host.uri_path.uri_query | eval Alert_Name="CRITS_Proxy_OBSERVED_Bluecoat_URLPATH" | eval Indicator_Type="URI - Path" | fields *
      
   search = "search " #prerequisite for using the library
   if row['Search_Type'] == "LookupTableSearch":
      search += ' [|inputlookup ' + row['Lookup_Table']
      search += ' | search Indicator_Type=\"'+row['Indicator_Type_Name']+'\"'
      search += ' | fields Indicator'
      search += ' | rename Indicator as query]'
   
   search += ' ' + row['Index_Source'] + ' ' + row['Earliest_Latest']
   if row['Eval']: 
      search += ' '  + row['Eval']


   search += ' | eval Alert_Name=\"'+row['Saved_Search_Name']+'\"'
   search += ' | eval Indicator_Type=\"'+row['Indicator_Type_Name']+'\"'
   if row['Field_Matches']: 
      search += ' | eval Field_Matches=\"'+row['Field_Matches']+'\"'

   search += ' | fields *' 
   return search

def print_file_searches(filename):
   print_searches(get_file_search_rows(filename))
   return

def print_searches(rows):
   for row in rows:
      print(get_search_string(row)) 
   return

def get_file_search_rows(filename):
   csvfile = csv.DictReader(open(filename))
   rows = []
   for each in csvfile:
      row = {}
      row['Search_Type'] = each["<Search_Type>"]
      row['Index_Source'] = each["<Index_Source>"]
      row['Lookup_Table'] = each['<Lookup_Table>']
      row['Indicator_Type_Name'] = each['<Indicator_Type_Name>']
      #row['Substring_Type'] = each['<Substring_Type>']
      #row['Source_Field_Name'] = each['<Source_Field_Name>']
      row['Earliest_Latest'] = each['<Earliest_Latest>']
      row['Eval'] = each['<Eval>']
      #row['Table_Field_List'] = each['<Table_Field_List>']
      row['Saved_Search_Name'] = each['<Saved_Search_Name>']
      #row['Severity'] = each['Severity']
      #row['Alert Recipients'] = each['Alert Recipients']
      row['Schedule'] = each['<Schedule>']
      row['Group_By'] = each['<Group_By>']
      row['Field_Matches'] = each['<Field_Matches>']
      rows.append(row)

   return rows

def create_cron_from_master_file(filename):
   rows = get_file_search_rows(filename)

   config = configparser.ConfigParser()
   config.read("splunk_detect.cfg") 
   execution_path = config.get('scheduler','program_path')
   program = config.get('scheduler','alert_splunk_program')
   program += ' ' + config.get('scheduler','alert_splunk_program_options')
   logpath = config.get('scheduler','alert_splunk_log_path')

   cron = open("cron","w")

   for row in rows:
      search = get_search_string(row)

      # pass the group_by option if it's configured as such in the configuration file
      if row['Group_By'] and len(row['Group_By']) > 0:
         _program = program + ' {0}'.format(row['Group_By'])
      else:
         _program = program

      cron_line = '{schedule} * * * * cd {execution_path} && env/bin/python {program} \'{search}\' {group_by} >> {log_path}{saved_search_name}.log 2>&1\n'.format(
         schedule = row['Schedule'],
         execution_path = execution_path,
         program = program,
         search = get_search_string(row),
         group_by = '-g {0}'.format(row['Group_By']) if row['Group_By'] and len(row['Group_By']) > 0 else '',
         log_path = logpath,
         saved_search_name = row['Saved_Search_Name'])

      #cron_line = row['Schedule'] + " * * * * cd "+execution_path +"; env/bin/python "+ _program +" '" + search + "' >> "+logpath+row['Saved_Search_Name']+".log 2>&1\n"
      cron.write(cron_line)

   cron.close()
   

def main():

   parser = OptionParser()
   parser.add_option("-f","--file",dest="filename",default="nope",help="Master search file containing csv structured saved search content")
   parser.add_option("-c","--create_cron_content",action="store_true",dest="cron",default=False,help="use -c to create a cron file in the local directory")
   parser.add_option("-p", "--print",action="store_true", dest="printit", default=False,help="use -p to print the saved search strings only")
   (options, args) = parser.parse_args()

   if options.filename == "nope":
      print("-f or -s option is required.")
      exit()

   if options.cron and options.filename == "nope":
      print("-c requires the -f option as well")
      exit()

   if options.cron:
      create_cron_from_master_file(options.filename) 

   if options.printit:
      rows = get_file_search_rows(options.filename)
      print_searches(rows)


if __name__ == "__main__":
    main()
