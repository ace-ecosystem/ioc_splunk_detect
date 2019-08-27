import csv
import datetime
import io
import urllib.request, urllib.parse, urllib.error
import master_search_file
import pycurl
import configparser
from optparse import OptionParser
import traceback

def search_splunk_verbose(search_string):
   results = search_splunk(search_string)
   print("START============================================================")
   print(("UTC: " + str(datetime.datetime.utcnow())))
   print("SEARCH")
   print(search_string)
   print("RESULTS")
   print(results)
   print("STOP=============================================================")
   print("")
   return results

def search_splunk(search_string):
   config = configparser.ConfigParser()
   config.read("splunk_detect.cfg")
   user = config.get('splunk','User')
   passwd = config.get('splunk','Pass')
   server = config.get('splunk','Splunk_Hostname')
   port = config.get('splunk','Port')
   endpoint = config.get('splunk','Splunk_REST_search_endpoint')
   
   server += ':'+port
   server += endpoint
   
   fields = {}
   fields['exec_mode'] = "oneshot"
   fields['output_mode'] = "json"
   fields['search'] = search_string
   
   try:
      data = io.BytesIO()
      c = pycurl.Curl()

      c.setopt(pycurl.URL,server)
      c.setopt(pycurl.SSL_VERIFYHOST,0)
      c.setopt(pycurl.SSL_VERIFYPEER,0)
      c.setopt(pycurl.USERPWD,user + ":" + passwd)
      c.setopt(pycurl.POSTFIELDS,urllib.parse.urlencode(fields))
      c.setopt(pycurl.WRITEFUNCTION,data.write)
      c.perform()

      return data.getvalue().decode('utf-8')
      
   except pycurl.error as error:
      #errno, errstr = error
      print(('An error occured: ', str(error)))
      traceback.print_exc()
      exit()
   
   return
    

def main():

   parser = OptionParser()
   parser.add_option("-f","--file",dest="filename",default="nope",help="Master search file containing csv structured saved search content")
   parser.add_option("-p","--print",action="store_true",dest="printit",default=False,help="use -p to print the saved search strings only")
   parser.add_option("-s","--search",dest="search",default="nope",help="Run the search provided at the command line")
   parser.add_option("-u","--urlencode",dest="urlencode",default="nope",help="As searches can get long with = / and quotes, use -u to url encode the search string")
   parser.add_option("-v","--verbose",action="store_true",dest="verbose",default=False,help="use to print out the date, search, and results")
   #parser.add_option("w","--write",dest="write",default="nope",help="Write all of the searches to a search file at this location (filenames will be the <search_name.splunksearch>)")
   (options, args) = parser.parse_args()

   if options.filename == "nope" and options.search == "nope":
      print("-f or -s option is required.")
      exit()

   if options.filename != "nope" and options.search != "nope":
      print("Only 1 of the following arguments is allowed at once (-f or -s)")
      exit()

   if options.search != "nope":
      if options.verbose:
         results = search_splunk_verbose(options.search)
         print(results)
      else:
         results = search_splunk(options.search)
         print(results)

   if options.printit:
      master_search_file.print_file_searches(options.filename)
      exit()

if __name__ == "__main__":
    main()
