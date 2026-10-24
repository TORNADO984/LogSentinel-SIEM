import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from collect import collect


class CollectorTests(unittest.TestCase):
    def test_resume_append_and_unknown_delivery_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'auth.log'
            path.write_text('Failed password for root from 192.0.2.1\n', encoding='utf-8')
            args = argparse.Namespace(file=str(path), checkpoint=str(path) + '.checkpoint.json',
                                      endpoint='http://localhost/api/ingest', hostname='web', source='linux', follow=False)
            deliveries = []

            def unknown_delivery(batch, endpoint, key):
                deliveries.extend(batch)
                raise RuntimeError('Connection lost after server accepted records')

            with patch('collect.send', side_effect=unknown_delivery), self.assertRaises(RuntimeError):
                collect(args)
            original_id = deliveries[0]['id']
            original_timestamp = deliveries[0]['timestamp']
            with patch('collect.send', side_effect=lambda batch, *_: deliveries.extend(batch)):
                collect(args)
                self.assertEqual(deliveries[1]['id'], original_id)
                self.assertEqual(deliveries[1]['timestamp'], original_timestamp)
                collect(args)
                self.assertEqual(len(deliveries), 2)
                with path.open('a', encoding='utf-8') as output:
                    output.write('Accepted password for root from 192.0.2.1\n')
                collect(args)
            self.assertEqual(len(deliveries), 3)
            self.assertNotEqual(deliveries[2]['id'], original_id)
            self.assertFalse(json.loads(Path(args.checkpoint).read_text())['pending'])

    def test_file_replacement_starts_new_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'auth.log'
            path.write_text('first line\n')
            args = argparse.Namespace(file=str(path), checkpoint=str(path) + '.checkpoint.json',
                                      endpoint='http://localhost/api/ingest', hostname='web', source='linux', follow=False)
            deliveries = []
            with patch('collect.send', side_effect=lambda batch, *_: deliveries.extend(batch)):
                collect(args)
                path.write_text('other line\n')
                collect(args)
            self.assertEqual(len(deliveries), 2)
            self.assertNotEqual(deliveries[0]['id'], deliveries[1]['id'])


if __name__ == '__main__':
    unittest.main()
