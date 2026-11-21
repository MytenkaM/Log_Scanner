from datetime import datetime
THRESHOLD = 10
WINDOW_SECONDS = 60

# Reading the file

def parse_line(line):
    parts = line.split()
    event = {
        'time': parts[0]+' '+parts[1],
        'status': parts[3],
        'user': parts[4].split('=')[1],
        'ip': parts[5].split('=')[1],
    }
    return event

events = []

with open(r'sample_auth.log') as file:
    for line in file:
        if line.strip()== '':
            continue
        events.append(parse_line(line))

# count failed logins

failures = {}

for event in events:
    if event['status'] == 'FAILED':
        ip = event['ip']
        time = datetime.strptime(event['time'], '%Y-%m-%d %H:%M:%S')
        failures.setdefault(ip,[]).append(time)

# Burst detection

flagged = {}

for ip, times in failures.items():
    times.sort()
    for i in range(len(times) -THRESHOLD + 1):
        first = times [i]
        last = times [i + THRESHOLD - 1]
        gap = (last - first).total_seconds()
        if gap <= WINDOW_SECONDS:
            flagged[ip] = first
            break

# checking for compromised logins

compromised = []

for event in events:
    if event['status'] == 'SUCCESS':
        ip = event['ip']
        user = event['user']
        time = datetime.strptime(event['time'], '%Y-%m-%d %H:%M:%S')
        if ip in flagged and time >= flagged[ip]:
            compromised.append(f'{user} from {ip} at {time}')

# The report
print('=' * 30)
print('LOGIN LOG SCAN REPORT')
print('=' * 30)
print(f'events analysed: {len(events)}')
print()
if flagged:
    print('Suspicious activity:')
    for ip, start in flagged.items():
        print(f' - {ip} (burst began {start})')
else:
    print('No suspicious activity detected')
print()
if compromised:
    print('Possible compromised accounts:')
    for item in compromised:
        print(f' - {item}')
else:
    print('No compromised accounts detected')