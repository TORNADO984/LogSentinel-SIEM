"""Exercise a running stack through Nginx using synthetic logs and the real collector.

Adds ten events under a unique verification hostname; never deletes existing data.
Use --state-file, recreate the containers, then --resume to check persistent state.
Only Python's standard library is required.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]


def check(condition, message):
    if not condition:
        raise AssertionError(message)


class Stack:
    def __init__(self, base_url, expected_storage):
        self.base_url = base_url.rstrip('/')
        self.key = os.getenv('LOGSENTINEL_API_KEY', '')
        self.expected_storage = expected_storage

    def request(self, path, data=None, method=None, status=200, authenticated=True):
        headers = {'Content-Type': 'application/json'}
        if authenticated and self.key:
            headers['X-API-Key'] = self.key
        request = Request(self.base_url + path, headers=headers, method=method,
                          data=json.dumps(data).encode() if data is not None else None)
        try:
            with urlopen(request, timeout=10) as response:
                actual, body = response.status, response.read().decode()
        except HTTPError as error:
            actual, body = error.code, error.read().decode()
        check(actual == status, f'{request.get_method()} {path}: expected {status}, got {actual}: {body[:500]}')
        return json.loads(body) if path.startswith('/api/') else body

    def ready(self):
        deadline = time.monotonic() + 120
        while True:
            try:
                health = self.request('/api/health')
                break
            except (URLError, TimeoutError, AssertionError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        check(health['storage'] == self.expected_storage, 'Unexpected event storage mode')
        check(health['queue'] == 'durable-sqlite', 'Expected a durable inbox')
        return health

    def events(self, hostname, **filters):
        return self.request('/api/events?' + urlencode({'hostname': hostname, **filters}))

    def drain(self):
        deadline = time.monotonic() + 120
        while self.request('/api/health')['queued']:
            check(time.monotonic() < deadline, 'Inbox did not drain within 120 seconds')
            time.sleep(0.25)

    def verify_saved(self, state):
        events = self.events(state['hostname'])
        check({item['id'] for item in events['items']} == set(state['event_ids']),
              'Stored evidence changed or disappeared')
        detail = self.request('/api/alerts/' + state['alert_id'])
        check(detail['workflow']['revision'] == 1, 'Workflow revision was not preserved')
        check(detail['workflow']['status'] == 'investigating', 'Workflow status was not preserved')
        check(detail['workflow']['assignee'] == 'Verification analyst', 'Assignment was not preserved')
        check(len(detail['workflow']['history']) == 1, 'Workflow history was not preserved')
        check(detail['workflow']['history'][0]['note'] == 'Synthetic verification scenario',
              'Investigation note was not preserved')
        replay = self.request('/api/ingest', [state['replay']], status=202)
        check(replay['accepted'] == 0 and replay['duplicates'] == 1, 'Inbox forgot a completed event ID')
        conflict = {**state['replay'], 'raw': 'Different content under the same ID'}
        self.request('/api/ingest', [conflict], status=409)
        check(self.events(state['hostname'])['total'] == 10, 'Replay changed the event count')


def collect(stack, path, hostname, source):
    subprocess.run([sys.executable, str(ROOT / 'collector' / 'collect.py'), str(path),
                    '--hostname', hostname, '--source', source,
                    '--endpoint', stack.base_url + '/api/ingest',
                    '--checkpoint', str(path) + '.checkpoint.json'], check=True, timeout=60)


def verify(stack, expect_empty):
    health = stack.ready()
    html = stack.request('/')
    check('id="root"' in html, 'Dashboard HTML does not contain the React root')
    assets = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', html)
    check(any(asset.endswith('.js') for asset in assets), 'Dashboard JavaScript bundle is missing')
    for asset in assets:
        check(bool(stack.request(asset)), 'Dashboard asset is empty')
    if stack.key:
        stack.request('/api/events', status=401, authenticated=False)
        stack.request('/api/ingest', [], status=401, authenticated=False)
    # Query before ingestion to catch mappings/sort errors on brand-new indices.
    initial_events = stack.request('/api/events')['total']
    initial_alerts = stack.request('/api/alerts')['total']
    stack.request('/api/overview')
    if expect_empty:
        check(initial_events == initial_alerts == 0, '--expect-empty requires a fresh event store')
    print('PASS: dashboard assets, API proxy, storage mode, initial search and access checks', flush=True)

    hostname = 'verify-' + uuid4().hex[:12]
    now = datetime.now(timezone.utc)
    failures_at = (now - timedelta(seconds=10)).isoformat()
    success_at = (now - timedelta(seconds=5)).isoformat()
    linux_lines = [f'{failures_at} sshd[42]: Failed password for admin from 192.0.2.42 port 22 ssh2'] * 6
    linux_lines += [f'{success_at} sshd[42]: Accepted password for admin from 192.0.2.42 port 22 ssh2',
                    f"{now.isoformat()} usermod[42]: add 'backup' to group 'sudo'"]
    windows = {'id': str(uuid4()), 'hostname': hostname, 'source': 'windows',
               'timestamp': now.isoformat(), 'event_id': 4720, 'username': 'synthetic-user',
               'raw': 'Synthetic Windows account creation'}
    sysmon = {'id': str(uuid4()), 'hostname': hostname, 'source': 'sysmon',
              'timestamp': now.isoformat(), 'event_id': 1, 'raw': 'Synthetic Sysmon process creation'}
    with tempfile.TemporaryDirectory(prefix='logsentinel-verify-') as directory:
        directory = Path(directory)
        sources = [('auth.log', 'linux', '\n'.join(linux_lines)),
                   ('security.jsonl', 'windows', json.dumps(windows)),
                   ('sysmon.jsonl', 'sysmon', json.dumps(sysmon))]
        for filename, source, content in sources:
            path = directory / filename
            path.write_text(content + '\n', encoding='utf-8')
            collect(stack, path, hostname, source)
            collect(stack, path, hostname, source)  # A checkpoint replay must add nothing.
    stack.drain()
    check(stack.request('/api/health')['failed'] == health['failed'], 'New dead letters appeared')
    result = stack.events(hostname)
    check(result['total'] == 10, f'Expected ten collected events, got {result["total"]}')
    check({event['event_type'] for event in result['items']} ==
          {'login_failure', 'login_success', 'privilege_change', 'account_created', 'process_created'},
          'Linux/Windows/Sysmon normalization is incomplete')
    check(stack.events(hostname, source_ip='192.0.2.42', severity='medium')['total'] == 6,
          'IP/severity filters did not return the six failures')
    check(stack.events(hostname, q='Accepted password')['total'] == 1, 'Message search failed')
    check(stack.events(hostname, event_type='account_created')['total'] == 1, 'Event type filter failed')
    check(stack.events(hostname, start=failures_at, end=success_at)['total'] == 7, 'Time range filter failed')
    check(stack.events(hostname, start=(now + timedelta(seconds=1)).isoformat())['total'] == 0,
          'Future time filter returned old events')
    limited = stack.events(hostname, limit=2)
    check(len(limited['items']) == 2 and limited['total'] == 10, 'Search limit/total count mismatch')
    print('PASS: Linux/Windows/Sysmon collection, checkpoints, normalization, indexing and search filters', flush=True)

    alerts = [item for item in stack.request('/api/alerts?limit=1000')['items'] if item['hostname'] == hostname]
    check(len(alerts) == 4, f'Expected four alerts, got {len(alerts)}')
    check({item['technique_id'] for item in alerts} == {'T1110', 'T1078', 'T1136', 'T1098'},
          'Detection coverage is incomplete')
    compromise = next(item for item in alerts if item['technique_id'] == 'T1078')
    check(len(compromise['event_ids']) == 7, 'Compromise alert must reference six failures and one success')
    evidence = [stack.request('/api/events/' + event_id) for event_id in compromise['event_ids']]
    check(all(item['hostname'] == hostname and item['raw'] for item in evidence), 'Evidence lookup failed')
    overview = stack.request('/api/overview')
    check(overview['events_24h'] >= 10 and overview['alerts_24h'] >= 4 and overview['failures_24h'] >= 6,
          'Overview counts omit the scenario')
    check(len(overview['trend']) == 24 and sum(item['count'] for item in overview['trend']) >= 10,
          'Hourly timeline omits the scenario')
    print('PASS: all four detection rules, original evidence and hourly timeline', flush=True)

    workflow_path = '/api/alerts/' + compromise['id'] + '/workflow'
    update = {'expected_revision': 0, 'actor': 'Verification analyst', 'assignee': 'Verification analyst',
              'status': 'investigating', 'note': 'Synthetic verification scenario'}
    stack.request(workflow_path, update, method='PATCH')
    stack.request(workflow_path, update, method='PATCH', status=409)
    state = {'hostname': hostname, 'event_ids': [event['id'] for event in result['items']],
             'alert_id': compromise['id'], 'replay': windows}
    stack.verify_saved(state)
    print('PASS: investigation workflow, stale-edit protection, duplicate replay and ID conflicts', flush=True)
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='http://127.0.0.1:8080', help='Dashboard/Nginx origin')
    parser.add_argument('--expected-storage', choices=['opensearch', 'sqlite'], default='opensearch')
    parser.add_argument('--expect-empty', action='store_true', help='Require empty events and alerts before ingestion')
    parser.add_argument('--state-file', type=Path, help='Save synthetic IDs for verification after a restart')
    parser.add_argument('--resume', action='store_true', help='Verify saved state without collecting more events')
    args = parser.parse_args()
    if args.resume and not args.state_file:
        parser.error('--resume requires --state-file')
    if args.resume and args.expect_empty:
        parser.error('--resume cannot be combined with --expect-empty')
    stack = Stack(args.base_url, args.expected_storage)
    if args.resume:
        stack.ready()
        stack.verify_saved(json.loads(args.state_file.read_text(encoding='utf-8')))
        print('PASS: evidence, workflow history and inbox deduplication survived restart', flush=True)
    else:
        state = verify(stack, args.expect_empty)
        if args.state_file:
            args.state_file.parent.mkdir(parents=True, exist_ok=True)
            args.state_file.write_text(json.dumps(state, indent=2), encoding='utf-8')
        print(f'Verified ten synthetic events on {state["hostname"]}.', flush=True)


if __name__ == '__main__':
    main()
