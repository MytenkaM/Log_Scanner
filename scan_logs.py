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

print(len(events))
print(events[0])

status = ['SUCCESS', 'FAILED','SUCCESS','FAILED','FAILED','SUCCESS','FAILED','FAILED','FAILED','FAILED','FAILED','FAILED','FAILED','FAILED','FAILED','FAILED','SUCCESS','FAILED','SUCCESS','SUCCESS']
failures = {}

for event in events:
    if event['status'] == 'FAILED':
        failures[event['ip']] = failures.get(event['ip'],0) +1

print(failures)

THRESHOLD = 10
for ip, count in failures.items():
    if count >=THRESHOLD:
        print(f'{ip} failed {count} login attempts')

from datetime import datetime

failures = {}

for event in events:
    if event['status'] == 'FAILED':
        ip = event['ip']
        time = datetime.strptime(event['time'], '%Y-%m-%d %H:%M:%S')
        failures.setdefault(ip,[]).append(time)

print(failures)
