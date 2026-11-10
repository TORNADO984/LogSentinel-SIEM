"""Analyst state is separate from detections so detector retries cannot erase it."""
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from typing import Literal


class WorkflowUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    expected_revision: int = Field(ge=0)
    actor: str = Field(min_length=1, max_length=80)
    status: Literal['new', 'investigating', 'resolved', 'false_positive'] | None = None
    assignee: str | None = Field(default=None, max_length=80)
    note: str | None = Field(default=None, min_length=1, max_length=4000)


class RevisionConflict(Exception):
    pass


class WorkflowStore:
    def __init__(self, path=None):
        path = path or os.getenv('WORKFLOW_DATABASE_PATH', os.getenv('DATABASE_PATH', 'logsentinel.db') + '.workflow.db')
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS workflows (
            alert_id TEXT PRIMARY KEY, status TEXT NOT NULL, assignee TEXT NOT NULL,
            revision INTEGER NOT NULL, updated_at TEXT NOT NULL)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS history (
            alert_id TEXT NOT NULL, revision INTEGER NOT NULL, timestamp TEXT NOT NULL,
            actor TEXT NOT NULL, changes TEXT NOT NULL, note TEXT,
            PRIMARY KEY(alert_id,revision))''')
        self.db.commit()

    @staticmethod
    def initial():
        return {'status': 'new', 'assignee': '', 'revision': 0, 'updated_at': None}

    def get(self, alert_id, include_history=False):
        row = self.db.execute('SELECT status,assignee,revision,updated_at FROM workflows WHERE alert_id=?', (alert_id,)).fetchone()
        result = dict(row) if row else self.initial()
        if include_history:
            rows = self.db.execute('SELECT revision,timestamp,actor,changes,note FROM history WHERE alert_id=? ORDER BY revision DESC', (alert_id,))
            result['history'] = [{**dict(row), 'changes': json.loads(row['changes'])} for row in rows]
        return result

    def update(self, alert_id, update):
        # Lock before reading the revision, including across separate connections.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            current = self.get(alert_id)
            if current['revision'] != update.expected_revision:
                raise RevisionConflict('Alert was updated elsewhere. Reload it before saving again.')
            changes = {}
            for field in ('status', 'assignee'):
                value = getattr(update, field)
                if value is not None and value != current[field]:
                    changes[field] = {'from': current[field], 'to': value}
                    current[field] = value
            if not changes and not update.note:
                raise ValueError('Change the status or assignee, or add a note')
            revision = current['revision'] + 1
            timestamp = datetime.now(timezone.utc).isoformat()
            self.db.execute('INSERT OR REPLACE INTO workflows VALUES (?,?,?,?,?)',
                            (alert_id, current['status'], current['assignee'], revision, timestamp))
            self.db.execute('INSERT INTO history VALUES (?,?,?,?,?,?)',
                            (alert_id, revision, timestamp, update.actor, json.dumps(changes), update.note))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return self.get(alert_id, include_history=True)

    def close(self):
        self.db.close()
