#!/usr/bin/env bash
cd /home/detect/splunk_detect && export -n http_proxy && export -n https_proxy && python3 alert_saq.py --cron --config='/home/detect/splunk_detect/splunk_detect.cfg' --log-config='/home/detect/splunk_detect/splunk_detect_logging.cfg' --csv='/home/detect/splunk_detect/Splunk_Search_Master.csv' > /dev/null
