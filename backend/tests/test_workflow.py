import tempfile
import unittest
from pathlib import Path

from app.workflow import RevisionConflict, WorkflowStore, WorkflowUpdate


class WorkflowStoreTests(unittest.TestCase):
    def test_persistence_and_concurrent_edit_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'workflow.db')
            first, second = WorkflowStore(path), WorkflowStore(path)
            try:
                self.assertEqual(first.get('alert')['revision'], 0)
                saved = first.update('alert', WorkflowUpdate(expected_revision=0, actor='Alice', status='investigating', assignee='Alice', note='Checking source host'))
                self.assertEqual(saved['revision'], 1)
                with self.assertRaises(RevisionConflict):
                    second.update('alert', WorkflowUpdate(expected_revision=0, actor='Bob', status='resolved'))
                current = second.get('alert', include_history=True)
                self.assertEqual(current['status'], 'investigating')
                self.assertEqual(len(current['history']), 1)
                second.update('alert', WorkflowUpdate(expected_revision=1, actor='Bob', status='resolved', note='Confirmed authorized test'))
            finally:
                first.close()
                second.close()
            reopened = WorkflowStore(path)
            try:
                current = reopened.get('alert', include_history=True)
                self.assertEqual(current['status'], 'resolved')
                self.assertEqual(current['assignee'], 'Alice')
                self.assertEqual([entry['actor'] for entry in current['history']], ['Bob', 'Alice'])
                self.assertEqual(current['history'][0]['changes']['status'], {'from': 'investigating', 'to': 'resolved'})
                with self.assertRaises(ValueError):
                    reopened.update('alert', WorkflowUpdate(expected_revision=2, actor='Bob'))
                self.assertEqual(reopened.get('alert')['revision'], 2)
            finally:
                reopened.close()
