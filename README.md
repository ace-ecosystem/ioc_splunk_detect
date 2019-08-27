### Splunk Detect Scripts
Managing tens of saved searches is difficult within splunk, this framework allows you to understand what coverage you have (indicator to log matrix), easily add additional searches, and have any matches sent to ACE for alert triage. Simply update the lookuptables on a regular basis with new indicators and your atomic indicator detection is covered.

### Prerequisites
The following assumes the code is cloned to /opt/splunk_detect
- cd /opt/splunk_detect
- git clone https://github.com/IntegralDefense/splunklib.git splunklib
- git clone https://github.com/IntegralDefense/ACE_client_lib.git saq

### Setup Steps
- create a Master csv file (example: Splunk_Search_Master.csv)
- configure splunk_detect.cfg (add splunk server & creds, ACE server & creds)
- make sure lookup tables are available on the splunk system that are referenced in the csv
- test the csv file "python3 master_search_file.py -f Splunk_Search_Master.csv -p"
- you should be able to copy and paste the search into splunk to verify the search syntax
- setup the crontab, verify the detect_wrapper.sh is correct (in case you changed any file names)

### Programs and Files    
**master_search_file.py** - Used to parse the Master csv files that contain the metadata for the operational searches. This program also will create the cron file for all the searches for the csv provided to the program - master_search_file.py -h for help.  
**Splunk_Search_Master.csv** - contains all the metadata needed to run the operational saved searches. Used to more easily maintain the searches we rely on.  
**splunk.cfg** - credentials and server to use for searching  
**search_splunk.py** - Send it a search, it will run it and return results  
**assurance_search.py** - This program uses the master_search_file.py and will parse the csv provided, and run each of those searches sequentially and will print out the results. The intent of this program is to run almost the same searches as the operational searches but use a lookup table that will produce results so we can verify the searches are working correctly.  
**Splunk_Search_Assurance.csv** - a copy of the Splunk_Search_Master.csv with the lookup table to use changed as well as the schedule as to produce results to verify our searches are still working correctly.  
**alert.py** - run specified search and write results into alerts table in crits mongo db
