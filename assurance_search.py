#!/usr/bin/env python3
# vim: sw=3:ts=3:et

import csv
import json
import master_search_file
import search_splunk
from optparse import OptionParser

def main():

   parser = OptionParser()
   parser.add_option("-f","--file",dest="filename",default="nope",help="search file containing csv structured saved search content")
   (options, args) = parser.parse_args()

   if options.filename == "nope":
      print("-f option is required.")
   else:
      rows = master_search_file.get_file_search_rows(options.filename)
      for row in rows:
         search_string = master_search_file.get_search_string(row)

         #I've had some issues with the result returning multiple rows (not sure why), so I'm only grabbing the first line of the string to create the json/dict
         results = search_splunk.search_splunk(search_string).split('\n')
         results_list = []
         if 'result' in results[0]:
            for each in results:
               if each != "":
                  json_out = json.loads(each)
                  if 'result' in json_out.keys():
                     results_list.append(json_out['result'])

         if len(results_list) == 0:
            print(search_string)
            print(('FAILED:' + row['Saved_Search_Name'] + ': ' + str(len(results_list)))) 
         else:
            print(('PASSED:' + row['Saved_Search_Name'] + ': ' + str(len(results_list))))

      #if issue log is > 0 then send email with log file contents
      exit()

   

if __name__ == "__main__":
    main()
