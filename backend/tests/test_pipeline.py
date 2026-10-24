import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app
from app.models import LogInput
from app.parser import normalize


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'DATABASE_PATH': os.path.join(self.temp.name, 'test.db'),
                                           'OPENSEARCH_URL': '', 'API_KEY': 'test-secret'})
        self.env.start()
        self.client = TestClient(app)
        self.client.__enter__()
        self.headers = {'X-API-Key': 'test-secret'}

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.env.stop()
        self.temp.cleanup()

    def post(self, records):
        response = self.client.post('/api/ingest', json=records, headers=self.headers)
        self.assertEqual(response.status_code, 202, response.text)
        deadline = time.monotonic() + 5
        while self.client.get('/api/health').json()['queued']:
            if time.monotonic() > deadline:
                self.fail('Worker did not drain accepted logs')
            time.sleep(0.01)

    def get(self, path, **params):
        response = self.client.get(path, params=params, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_spike_compromise_filters_and_overview(self):
        now = datetime.now(timezone.utc)
        logs = [{'hostname': 'web-01', 'timestamp': (now - timedelta(seconds=20-i)).isoformat(),
                 'raw': 'sshd[2]: Failed password for invalid user admin from 203.0.113.42 port 22 ssh2'} for i in range(6)]
        logs.append({'hostname': 'web-01', 'timestamp': now.isoformat(),
                     'raw': 'sshd[3]: Accepted password for admin from 203.0.113.42 port 22 ssh2'})
        self.post(logs)
        events = self.get('/api/events', hostname='web-01', source_ip='203.0.113.42', severity='medium')
        self.assertEqual(events['total'], 6)
        self.assertEqual(events['items'][0]['username'], 'admin')
        self.assertEqual(self.get('/api/events/' + events['items'][0]['id'])['hostname'], 'web-01')
        alerts = self.get('/api/alerts')['items']
        self.assertEqual({alert['technique_id'] for alert in alerts}, {'T1110', 'T1078'})
        self.assertEqual(len([alert for alert in alerts if alert['technique_id'] == 'T1078'][0]['event_ids']), 7)
        self.assertEqual(self.get('/api/events', hostname='other')['total'], 0)
        self.assertEqual(self.get('/api/events', q='Accepted')['total'], 1)
        self.assertEqual(self.get('/api/events', start=(now + timedelta(seconds=1)).isoformat())['total'], 0)
        self.assertEqual(self.get('/api/overview')['events_24h'], 7)

    def test_window_and_host_isolation(self):
        now = datetime.now(timezone.utc)
        records = [{'hostname': 'old-host', 'timestamp': (now - timedelta(minutes=6)).isoformat(),
                    'raw': 'Failed password for root from 192.0.2.1 port 22'} for _ in range(5)]
        records += [{'hostname': host, 'timestamp': now.isoformat(),
                     'raw': 'Failed password for root from 192.0.2.1 port 22'} for host in ('old-host', 'new-host')]
        self.post(records)
        alerts = self.get('/api/alerts')['items']
        self.assertTrue(all(datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00')) < now for item in alerts))

    def test_windows_and_privilege_changes(self):
        self.post([{'source': 'windows', 'hostname': 'dc-01', 'event_id': 4720, 'username': 'new-admin', 'raw': 'Account created'},
                   {'hostname': 'db-01', 'raw': "usermod[12]: add 'backup' to group 'sudo'"}])
        self.assertEqual({item['technique_id'] for item in self.get('/api/alerts')['items']}, {'T1136', 'T1098'})

    def test_validation_and_authorization(self):
        self.assertEqual(self.client.get('/api/events').status_code, 401)
        self.assertEqual(self.client.post('/api/ingest', json=[], headers=self.headers).status_code, 422)
        for entry in ({'timestamp': '2026-01-01T00:00:00'}, {'source_ip': 'not-an-ip'}):
            self.assertEqual(self.client.post('/api/ingest', json=[{'hostname': 'a', 'raw': 'b', **entry}], headers=self.headers).status_code, 422)
        self.assertEqual(self.client.get('/api/events', params={'start': '2026-01-01'}, headers=self.headers).status_code, 422)

    def test_api_idempotency_and_dead_letter_authorization(self):
        record = {'id': str(uuid4()), 'hostname': 'a', 'raw': 'system ready'}
        self.post([record])
        response = self.client.post('/api/ingest', json=[record], headers=self.headers)
        self.assertEqual(response.json()['duplicates'], 1)
        self.assertEqual(response.json()['accepted'], 0)
        self.assertEqual(self.get('/api/events')['total'], 1)
        changed = {**record, 'raw': 'different content'}
        self.assertEqual(self.client.post('/api/ingest', json=[changed], headers=self.headers).status_code, 409)
        self.assertEqual(self.client.get('/api/queue/dead-letters').status_code, 401)
        self.assertEqual(self.get('/api/queue/dead-letters')['items'], [])

    def test_parser_handles_ipv6_and_sysmon(self):
        event = normalize(LogInput(hostname='a', raw='Failed publickey for root from 2001:db8::1 port 22'))
        self.assertEqual(event.source_ip, '2001:db8::1')
        self.assertEqual(normalize(LogInput(hostname='b', raw='Process created', source='sysmon', event_id=1)).event_type, 'process_created')


if __name__ == '__main__':
    unittest.main()
