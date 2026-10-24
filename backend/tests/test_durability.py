import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from app.detections import detect
from app.models import LogInput
from app.parser import normalize
from app.queue import IdConflict, Inbox, QueueFull
from app.storage import Store


class DurabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / 'inbox.db')

    def tearDown(self):
        self.temp.cleanup()

    def test_acceptance_survives_restart_and_inflight_recovery(self):
        inbox = Inbox(self.path)
        log = LogInput(hostname='web', raw='useradd[1]: new user: name=alice')
        inbox.enqueue([log])
        inbox.close()
        inbox = Inbox(self.path)
        self.assertEqual(inbox.claim().id, log.id)
        inbox.close()  # Simulated process loss after claim, before completion.
        inbox = Inbox(self.path)
        self.assertEqual(inbox.claim().id, log.id)
        inbox.complete(log.id)
        inbox.close()
        inbox = Inbox(self.path)
        self.assertEqual(inbox.enqueue([log])['duplicates'], 1)
        self.assertIsNone(inbox.claim())
        inbox.close()

    def test_duplicate_ids_conflicts_and_atomic_capacity(self):
        inbox = Inbox(self.path, capacity=1)
        first = LogInput(hostname='web', raw='one')
        second = LogInput(hostname='web', raw='two')
        self.assertEqual(inbox.enqueue([first, first])['duplicates'], 1)
        with self.assertRaises(QueueFull):
            inbox.enqueue([second])
        self.assertEqual(inbox.stats()['queued'], 1)
        with self.assertRaises(IdConflict):
            inbox.enqueue([LogInput(id=first.id, hostname='web', raw='changed')])
        inbox.complete(first.id)
        self.assertEqual(inbox.enqueue([second])['accepted'], 1)
        inbox.close()

    def test_retry_backoff_dead_letter_and_manual_recovery(self):
        inbox = Inbox(self.path, max_attempts=2)
        log = LogInput(hostname='a', raw='test')
        inbox.enqueue([log])
        with patch('app.queue.time.time', return_value=100):
            inbox.claim()
            inbox.fail(log.id, OSError('private details'))
            self.assertIsNone(inbox.claim())
        with patch('app.queue.time.time', return_value=103):
            self.assertEqual(inbox.claim().id, log.id)
            inbox.fail(log.id, OSError())
        self.assertEqual(inbox.stats()['failed'], 1)
        self.assertEqual(inbox.dead_letters()[0]['last_error'], 'OSError')
        self.assertTrue(inbox.retry(str(log.id)))
        self.assertEqual(inbox.claim().id, log.id)
        inbox.complete(log.id)
        inbox.close()

    def test_replay_after_partial_processing_is_idempotent(self):
        with patch.dict(os.environ, {'DATABASE_PATH': str(Path(self.temp.name) / 'events.db'), 'OPENSEARCH_URL': ''}):
            store = Store()
            log = LogInput(id=uuid4(), hostname='web', raw='useradd[1]: new user: name=alice')
            for _ in range(2):
                event = normalize(log)
                store.save('events', event)
                detect(event, store)
            self.assertEqual(store.query()['total'], 1)
            self.assertEqual(store.query('alerts')['total'], 1)
            store.close()


if __name__ == '__main__':
    unittest.main()
