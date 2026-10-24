"""Dependency-free file collector for auth.log/syslog or exported Windows JSONL."""
import argparse
import hashlib
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4, uuid5
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def send(batch, endpoint, key):
    payload = json.dumps(batch).encode()
    headers = {'Content-Type': 'application/json'}
    if key:
        headers['X-API-Key'] = key
    for attempt in range(6):
        try:
            with urlopen(Request(endpoint, data=payload, headers=headers), timeout=30) as response:
                if response.status != 202:
                    raise RuntimeError(f'Unexpected status: {response.status}')
            return
        except HTTPError as error:
            if error.code not in (429, 500, 502, 503, 504):
                raise
        except (URLError, TimeoutError):
            pass
        time.sleep(min(2 ** attempt, 20))
    raise RuntimeError('Ingestion failed after retries; source file is unchanged. Replay when the API is available.')


def make_log(line, args):
    if args.source != 'linux':
        record = json.loads(line)
        record.setdefault('source', args.source)
        record.setdefault('hostname', args.hostname)
        record.setdefault('raw', line.rstrip())
        record.setdefault('timestamp', datetime.now(timezone.utc).isoformat())
        return record
    timestamp = datetime.now(timezone.utc).isoformat()
    # Prefer an RFC3339 timestamp at the start of the original message.
    try:
        parsed = datetime.fromisoformat(line.split()[0].replace('Z', '+00:00'))
        if parsed.tzinfo:
            timestamp = parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, IndexError):
        pass
    return {'source': 'linux', 'hostname': args.hostname, 'raw': line.rstrip(), 'timestamp': timestamp}


def save_checkpoint(path, state):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w', encoding='utf-8') as output:
        json.dump(state, output)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def file_identity(stream, anchor_length):
    stat = os.fstat(stream.fileno())
    position = stream.tell()
    stream.seek(0)
    anchor = hashlib.sha256(stream.read(anchor_length)).hexdigest()
    stream.seek(position)
    return [stat.st_dev, stat.st_ino, anchor_length, anchor]


def collect(args):
    key = os.getenv('LOGSENTINEL_API_KEY', '')
    checkpoint = Path(args.checkpoint or args.file + '.checkpoint.json')
    state = json.loads(checkpoint.read_text(encoding='utf-8')) if checkpoint.exists() else None
    destination = [str(Path(args.file).resolve()), args.endpoint, args.hostname, args.source]
    if state and state['destination'] != destination:
        raise ValueError('Checkpoint belongs to a different file, endpoint, hostname, or source')

    def flush():
        # Journal the exact payload before sending. Unknown delivery outcomes can
        # safely retry these same IDs and timestamps, even after a process crash.
        save_checkpoint(checkpoint, state)
        send(state['pending'], args.endpoint, key)
        count = len(state['pending'])
        state['offset'] = state.pop('pending_end')
        state['pending'] = []
        save_checkpoint(checkpoint, state)
        print(f'Accepted/checkpointed {count} logs', flush=True)

    if state and state['pending']:
        flush()
    stream = open(args.file, 'rb')
    try:
        while True:
            stat = os.fstat(stream.fileno())
            identity = file_identity(stream, state['identity'][2] if state else min(stat.st_size, 256))
            if state is None or state['identity'] != identity or stat.st_size < state['offset']:
                offset = stat.st_size if state is None and args.follow else 0
                state = {'destination': destination, 'identity': file_identity(stream, min(stat.st_size, 256)),
                         'generation': str(uuid4()), 'offset': offset, 'pending': []}
                save_checkpoint(checkpoint, state)
            stream.seek(state['offset'])
            batch = []
            while len(batch) < 100:
                position = stream.tell()
                line = stream.readline()
                if not line:
                    break
                if args.follow and not line.endswith(b'\n'):
                    stream.seek(position)
                    break
                if line.strip():
                    log = make_log(line.decode('utf-8', errors='replace'), args)
                    log.setdefault('id', str(uuid5(UUID(state['generation']), f'{position}:{hashlib.sha256(line).hexdigest()}')))
                    batch.append(log)
            end = stream.tell()
            if batch:
                state['pending'] = batch
                state['pending_end'] = end
                flush()
                continue
            if end != state['offset']:
                state['offset'] = end
                save_checkpoint(checkpoint, state)
            if not args.follow:
                return
            time.sleep(1)
            try:
                current = os.stat(args.file)
            except FileNotFoundError:
                continue  # Rotation can briefly leave no replacement file.
            if (current.st_dev, current.st_ino) != (stat.st_dev, stat.st_ino):
                replacement = open(args.file, 'rb')
                stream.close()
                stream = replacement
    finally:
        stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', help='Log file; for Windows/Sysmon use JSONL records')
    parser.add_argument('--source', choices=['linux', 'windows', 'sysmon'], default='linux')
    parser.add_argument('--hostname', default=socket.gethostname())
    parser.add_argument('--endpoint', default='http://127.0.0.1:8000/api/ingest')
    parser.add_argument('--follow', action='store_true', help='Start at EOF on first run, then resume checkpoints')
    parser.add_argument('--checkpoint', help='Writable checkpoint file (default: <logfile>.checkpoint.json)')
    args = parser.parse_args()
    collect(args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
