"""SQLite inbox: acknowledge only committed records and replay unfinished work.

One worker process owns this inbox. Keep the file on persistent local storage.
Completed IDs are retained for replay deduplication until an operator prunes them.
"""
import json
import os
import sqlite3
import time
from hashlib import sha256
from pathlib import Path

from .models import LogInput


class QueueFull(Exception):
    pass


class IdConflict(Exception):
    pass


class Inbox:
    def __init__(self, path=None, capacity=10000, max_attempts=5):
        path = path or os.getenv('QUEUE_DATABASE_PATH', os.getenv('DATABASE_PATH', 'logsentinel.db') + '.queue.db')
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS inbox (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
            payload TEXT NOT NULL, fingerprint TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
            available_at REAL NOT NULL DEFAULT 0, last_error TEXT)''')
        self.db.execute('CREATE INDEX IF NOT EXISTS inbox_pending ON inbox(status, available_at, seq)')
        # An interrupted write/detection is safe to repeat with the same event ID.
        self.db.execute("UPDATE inbox SET status='pending' WHERE status='processing'")
        self.db.commit()
        self.capacity = capacity
        self.max_attempts = max_attempts

    def enqueue(self, logs):
        added, duplicates = 0, 0
        with self.db:
            for log in logs:
                data = log.model_dump(mode='json')
                # Receipt time may differ on a retry when the client omitted timestamp.
                identity = {k: v for k, v in data.items() if k != 'timestamp'}
                fingerprint = sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
                existing = self.db.execute('SELECT fingerprint FROM inbox WHERE id=?', (data['id'],)).fetchone()
                if existing:
                    if existing['fingerprint'] != fingerprint:
                        raise IdConflict(f"Event ID {data['id']} was already used for different log content")
                    duplicates += 1
                    continue
                self.db.execute('INSERT INTO inbox(id,payload,fingerprint) VALUES (?,?,?)',
                                (data['id'], json.dumps(data), fingerprint))
                added += 1
            active = self.db.execute("SELECT COUNT(*) FROM inbox WHERE status IN ('pending','processing')").fetchone()[0]
            if active > self.capacity:
                raise QueueFull('Inbox full; retry later')
        return {'accepted': added, 'duplicates': duplicates, 'ids': [str(log.id) for log in logs]}

    def claim(self):
        with self.db:
            row = self.db.execute("SELECT * FROM inbox WHERE status='pending' AND available_at<=? ORDER BY seq LIMIT 1",
                                  (time.time(),)).fetchone()
            if not row:
                return None
            self.db.execute("UPDATE inbox SET status='processing', attempts=attempts+1 WHERE id=?", (row['id'],))
        return LogInput.model_validate_json(row['payload'])

    def complete(self, event_id):
        with self.db:
            self.db.execute("UPDATE inbox SET status='done', last_error=NULL WHERE id=?", (str(event_id),))

    def fail(self, event_id, error):
        row = self.db.execute('SELECT attempts FROM inbox WHERE id=?', (str(event_id),)).fetchone()
        status = 'dead' if row['attempts'] >= self.max_attempts else 'pending'
        with self.db:
            self.db.execute('UPDATE inbox SET status=?, available_at=?, last_error=? WHERE id=?',
                            (status, time.time() + min(2 ** row['attempts'], 60), type(error).__name__, str(event_id)))

    def stats(self):
        counts = {row['status']: row['count'] for row in self.db.execute('SELECT status, COUNT(*) AS count FROM inbox GROUP BY status')}
        return {'queued': counts.get('pending', 0) + counts.get('processing', 0),
                'processed': counts.get('done', 0), 'failed': counts.get('dead', 0)}

    def dead_letters(self, limit=100):
        rows = self.db.execute("SELECT id, attempts, last_error FROM inbox WHERE status='dead' ORDER BY seq LIMIT ?", (limit,))
        return [dict(row) for row in rows]

    def retry(self, event_id):
        with self.db:
            if self.stats()['queued'] >= self.capacity:
                raise QueueFull('Inbox full; retry later')
            result = self.db.execute("UPDATE inbox SET status='pending', attempts=0, available_at=0, last_error=NULL WHERE id=? AND status='dead'", (event_id,))
        return result.rowcount == 1

    def close(self):
        self.db.close()
