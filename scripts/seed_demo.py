"""Load synthetic telemetry for a reproducible dashboard demonstration."""
import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from uuid import NAMESPACE_URL, uuid5


def demo_logs(now=None):
    now = (now or datetime.now(timezone.utc)).replace(second=0, microsecond=0)
    randomizer = random.Random(42)
    hosts = ['web-prod-01', 'db-prod-02', 'worker-03', 'gateway-01']
    logs = []
    for hour in range(24):
        count = randomizer.randint(4, 17)
        for index in range(count):
            timestamp = now - timedelta(hours=23-hour, minutes=randomizer.randint(0, 45))
            success = index % 3 == 0
            logs.append({'hostname': hosts[index % len(hosts)], 'timestamp': timestamp.isoformat(),
                         'raw': f'sshd[2100]: Accepted publickey for deploy from 192.0.2.{10 + index} port 53201 ssh2' if success
                         else 'systemd[1]: Finished scheduled service health check.'})
    for index in range(7):
        logs.append({'hostname': 'web-prod-01', 'timestamp': (now - timedelta(seconds=150-index*15)).isoformat(),
                     'raw': 'sshd[2841]: Failed password for invalid user admin from 203.0.113.42 port 54322 ssh2'})
    logs.extend([
        {'hostname': 'web-prod-01', 'timestamp': (now-timedelta(seconds=20)).isoformat(),
         'raw': 'sshd[2901]: Accepted password for admin from 203.0.113.42 port 54323 ssh2'},
        {'hostname': 'db-prod-02', 'timestamp': (now-timedelta(seconds=10)).isoformat(),
         'raw': "usermod[3112]: add 'service-backup' to group 'sudo'"},
        {'hostname': 'gateway-01', 'timestamp': now.isoformat(), 'raw': 'useradd[3120]: new user: name=audit-agent, UID=1042'}
    ])
    for index, log in enumerate(logs):
        log['id'] = str(uuid5(NAMESPACE_URL, f'logsentinel-demo:{now.isoformat()}:{index}'))
    return sorted(logs, key=lambda log: log['timestamp'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', default='http://127.0.0.1:8000/api/ingest')
    args = parser.parse_args()
    headers = {'Content-Type': 'application/json'}
    if os.getenv('LOGSENTINEL_API_KEY'):
        headers['X-API-Key'] = os.environ['LOGSENTINEL_API_KEY']
    with urlopen(Request(args.endpoint, data=json.dumps(demo_logs()).encode(), headers=headers), timeout=30) as response:
        result = json.load(response)
        print(f"Synthetic logs accepted: {result['accepted']}; duplicates: {result['duplicates']}")
