# Log Scanner

A beginner python project which scans a authentication log and flags possible brute attacks

## what it does
- Reads a log of authentication attempts
- The logs are checked against both a threshold for the amount of failed login attempts from the same IP address (THRESHOLD) and if this occurred within a set amount of time (WINDOW_SECONDS)
- Raises an alert if a flagged IP ##logs in later successfully##, as that account may be compromised 
This log scanner has a threshold of 10 failed attempts within a time frame of 60s

## hgow to run it

put 'smample_auth.log' in the same folder as the script, then run:
'''
python scan_logs.py
'''
## Log format
One event per line:

'''
2026-11-20 10:15:00 LOGIN FAILED user=admin ip=203.0.113.45
'''

The data in 'sample_auth.log' has been made up for testing

## Example output

'''
==============================
LOGIN LOG SCAN REPORT
==============================
events analysed: 21

Suspicious activity:
 - 203.42.100.43 (burst began 2026-11-20 10:28:20)

Possible compromised accounts:
 - ben from 203.42.100.43 at 2026-11-20 10:35:44
'''

## Ideas for next steps
- add automated tests
- save the report to a file
- introduce a rule for a single IP trying multiple usernames
