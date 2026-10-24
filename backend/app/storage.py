"""Persistent local storage or an OpenSearch HTTP repository."""
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

import httpx


class Store:
    def __init__(self):
        self.url = os.getenv('OPENSEARCH_URL', '').rstrip('/')
        self.client = httpx.Client(timeout=15)
        self.db = None
        if not self.url:
            path = os.getenv('DATABASE_PATH', 'logsentinel.db')
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.db = sqlite3.connect(path, check_same_thread=False)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('CREATE TABLE IF NOT EXISTS records (collection TEXT, id TEXT, data TEXT, PRIMARY KEY(collection,id))')
            self.db.commit()

    def initialize(self):
        if self.url:
            properties = {key: {'type': 'keyword'} for key in
                          ('hostname', 'source_ip', 'severity', 'event_type', 'username', 'source')}
            properties.update(timestamp={'type': 'date'}, raw={'type': 'text'})
            for collection in ('events', 'alerts'):
                response = self.client.put(f'{self.url}/logsentinel-{collection}',
                                           json={'mappings': {'properties': properties}})
                if response.status_code != 400 or response.json().get('error', {}).get('type') != 'resource_already_exists_exception':
                    response.raise_for_status()

    def save(self, collection, record):
        data = record.model_dump(mode='json')
        if self.url:
            response = self.client.put(f'{self.url}/logsentinel-{collection}/_doc/{record.id}',
                                       params={'refresh': 'true'}, json=data)
            response.raise_for_status()
        else:
            self.db.execute('INSERT OR REPLACE INTO records VALUES (?,?,?)',
                            (collection, record.id, json.dumps(data)))
            self.db.commit()

    def query(self, collection='events', *, limit=100, q='', start=None, end=None, **filters):
        filters = {k: v for k, v in filters.items() if v is not None}
        if self.url:
            clauses = [{'term': {key: value}} for key, value in filters.items()]
            bounds = {key: value.isoformat() for key, value in [('gte', start), ('lte', end)] if value}
            if bounds:
                clauses.append({'range': {'timestamp': bounds}})
            if q:
                clauses.append({'match_phrase': {'raw': q}})
            response = self.client.post(f'{self.url}/logsentinel-{collection}/_search', json={
                'size': limit, 'track_total_hits': True, 'sort': [{'timestamp': 'desc'}, {'id.keyword': 'asc'}],
                'query': {'bool': {'filter': clauses}}})
            response.raise_for_status()
            hits = response.json()['hits']
            return {'items': [hit['_source'] for hit in hits['hits']], 'total': hits['total']['value']}
        rows = [json.loads(row[0]) for row in self.db.execute('SELECT data FROM records WHERE collection=?', (collection,))]
        rows = [row for row in rows if all(row.get(k) == v for k, v in filters.items())
                and (not q or q.lower() in row.get('raw', '').lower())
                and (not start or datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00')) >= start)
                and (not end or datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00')) <= end)]
        rows.sort(key=lambda row: (row['timestamp'], row['id']), reverse=True)
        return {'items': rows[:limit], 'total': len(rows)}

    def get(self, collection, record_id):
        if self.url:
            response = self.client.get(f'{self.url}/logsentinel-{collection}/_doc/{record_id}')
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()['_source']
        row = self.db.execute('SELECT data FROM records WHERE collection=? AND id=?',
                              (collection, record_id)).fetchone()
        return json.loads(row[0]) if row else None

    def close(self):
        self.client.close()
        if self.db:
            self.db.close()
