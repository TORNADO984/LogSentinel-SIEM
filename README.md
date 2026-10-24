# LogSentinel SIEM

### Real-Time Security Event Monitoring

A mini Security Information and Event Management platform that centralizes Linux and Windows security logs, detects suspicious behavior, and lets analysts investigate the evidence in a React SOC dashboard.

**Python · FastAPI · OpenSearch · React · Docker**

The dashboard includes a security overview, hourly activity chart, live event stream, MITRE-mapped alerts, and evidence details. A home-page screenshot is pending: desktop capture was blocked by browser URL verification in the development environment.

## Features

- **Collection:** replay or follow Linux authentication/system logs; optionally ingest Windows Security and Sysmon JSONL exports.
- **Normalization:** common UTC timestamps, hostnames, IPv4/IPv6 addresses, accounts, event types, severity, and original messages.
- **Detection:** failed-login spikes, successful logins after repeated failures, account creation, and selected privilege changes.
- **Investigation:** MITRE ATT&CK mappings, alert evidence links, and original event details.
- **Search:** filter events by hostname, source IP, severity, event type, message, and time.
- **SOC dashboard:** hourly security trends, event stream, alerts, queue depth, and five-second automatic refresh.
- **Reliable delivery:** disk-backed inbox, stable IDs, duplicate prevention, retry backoff, dead letters, and collector checkpoints.
- **Operations:** SQLite local mode, Docker/OpenSearch mode, optional shared API key, and automated tests.

This is a working portfolio and learning project with explicit operational limits. It demonstrates the complete collection → normalization → storage → detection → investigation flow.

## Run locally

Requires Python 3.11+ and Node.js 22.12+.

```powershell
git clone https://github.com/TORNADO984/LogSentinel-SIEM.git
cd LogSentinel-SIEM
python -m venv .venv
.venv\Scripts\python -m pip install -r backend/requirements.txt
.venv\Scripts\python -m uvicorn app.main:app --app-dir backend --reload
```

In another terminal:

```powershell
cd frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Open http://localhost:5173. Click **Load demo events** to generate failed logins, a successful login, and a privilege change. Demo data is stored as ordinary events; repeated loads add records. The dashboard refreshes every five seconds. Interactive API docs: http://127.0.0.1:8000/docs.

If port 8000 is occupied, start Uvicorn with `--port 8001` and set `$env:API_PROXY_TARGET='http://127.0.0.1:8001'` in the frontend terminal before running `npm run dev`.

The local default uses SQLite (`logsentinel.db`), so no database service is required. Set `DATABASE_PATH` to change its location.

On Linux/macOS, replace `.venv\Scripts\python` with `.venv/bin/python`. In Bash, set an alternate frontend target with `API_PROXY_TARGET=http://127.0.0.1:8001 npm run dev -- --host 127.0.0.1`.

For a full day of synthetic telemetry, including hourly trends and multiple detection scenarios:

```bash
python scripts/seed_demo.py
# Alternate API port:
python scripts/seed_demo.py --endpoint http://127.0.0.1:8001/api/ingest
```

The script reuses event IDs when run in the same minute. Demo records remain ordinary stored events; the dashboard button generates a new scenario each time.

## Run the full OpenSearch stack

```powershell
docker compose up --build
```

Open http://localhost:8080. OpenSearch must become healthy before the API starts. Allow several minutes on first startup and allocate at least 4 GB of Docker memory. On Linux, OpenSearch may require `vm.max_map_count=262144`.

Docker publishes the API and dashboard only on loopback. OpenSearch has security disabled for this local development stack and is not published to the host. Separate named volumes persist OpenSearch data and the durable inbox. Before deployment, configure authentication, TLS, index retention, backups, and access control. Copy `.env.example` to `.env` and set `API_KEY` to enable shared-key API access. For local development set the `API_KEY` environment variable before starting the API. Enter the same key in dashboard Settings; collectors read `LOGSENTINEL_API_KEY`. Never embed credentials in a frontend build.

## Collect logs

Replay a Linux log file:

```bash
python collector/collect.py /var/log/auth.log --hostname web-01 --checkpoint ./data/auth.checkpoint.json
python collector/collect.py /var/log/syslog --hostname web-01 --follow --checkpoint ./data/syslog.checkpoint.json
```

`--follow` starts at EOF on the first run, then resumes the saved byte offset on later runs. Read permissions on the source and write permissions on the checkpoint directory are required. Without `--checkpoint`, the checkpoint is created next to the log file. Run one collector per checkpoint. The checkpoint belongs to a particular file, endpoint, hostname, and source; use another checkpoint when changing these settings.

RFC3339 timestamps at the start of Linux messages are preserved. Traditional syslog timestamps lack a year and timezone, so those lines use collection time. The API accepts explicit timezone-aware timestamps for accurate historical ingestion. The hostname is supplied by the collector rather than extracted from the message.

Optional Windows Security/Sysmon ingestion accepts exported JSONL, one record per line:

```json
{"hostname":"win-01","source":"windows","event_id":4625,"timestamp":"2026-10-23T10:00:00Z","username":"analyst","source_ip":"192.0.2.10","raw":"An account failed to log on"}
```

```bash
python collector/collect.py security.jsonl --source windows
python collector/collect.py sysmon.jsonl --source sysmon
```

This is an adapter for structured exports, not a native Windows Event Log subscription. Supported Windows IDs: 4624/4625 (authentication), 4720 (account creation), 4728/4732/4756 (group membership). Sysmon ID 1 becomes a process creation event; no process anomaly rule is claimed.

## Pipeline and detections

```text
Linux logs / Windows JSONL → Collector → FastAPI durable inbox
                                            ↓
                                       Normalization
                                            ↓
                                  SQLite or OpenSearch
                                     ↙           ↘
                              Detections       Search API
                                  ↓                ↓
                                Alerts → React SOC dashboard
```

Normalized events contain a UTC timestamp, hostname, source, event type, severity, optional account/source IP, original log, and unique ID.

- **Failed login spike / T1110:** at least five failures from one IP on one host in the preceding five minutes. Repeated alerts are grouped into fixed five-minute buckets.
- **Success after failures / T1078:** a success after at least five failures from the same IP and host in five minutes; evidence includes the success and failures. This is an investigation signal, not proof of compromise.
- **Account created / T1136** and **privilege change / T1098:** selected Linux account/group administration messages and Windows account/group events. Review against authorized administrator activity. MITRE mappings describe potentially relevant behavior, not attribution.

Events are processed in arrival order. Historical/out-of-order arrivals do not retrospectively reevaluate earlier successes. Run a single API worker per inbox. Correlation currently groups authentication activity by host and IP rather than requiring the same account.

## Delivery and recovery

1. The API commits a validated batch to a SQLite inbox before returning **HTTP 202**. Batches are atomic and the inbox allows 10,000 active records.
2. The worker normalizes each record, upserts its event under a stable UUID, runs detections, then marks it complete. Unfinished work returns to pending after restart.
3. Processing failures retry after 2, 4, 8, and 16 seconds. The fifth failed attempt moves the record to dead letters. Open **Settings → Delivery recovery** to retry after correcting the underlying problem.
4. The collector saves the exact pending batch before sending and advances its checkpoint only after a 202 response. A lost response or crash replays the same IDs and timestamps.

Clients may supply a UUID `id`. Reusing the ID with the same log content counts as a duplicate. Different content under the same ID returns **409** and rolls back the batch. The first accepted timestamp is retained on retry. Omitting `id` creates a new identity, so clients needing deduplication must preserve IDs.

This provides **at-least-once processing with idempotent event/alert writes**, not an exactly-once distributed transaction. Completed inbox IDs are retained; pruning them reduces the replay protection window. Keep the inbox, event store, and collector checkpoints on reliable persistent storage. Checkpoints contain pending raw logs and must be protected like source logs.

Normal file replacement/rotation and observed truncation are handled. Very fast copy-truncate/rewrite cycles or deleting checkpoints can cause replay or missed historical bytes. Preserve rotated source files until collection completes.

SQLite search uses substring matching; OpenSearch uses analyzed phrase matching. Search returns the newest 100 events by default, up to 1,000 via `limit`, and includes the total match count. Dashboard searches support message, hostname, source IP, severity, and time. Alert details link to supporting events and their original logs. Dashboard hourly trends use exact backend counts; no pagination or long-term retention policy is implemented yet.

## API

- `POST /api/ingest`: array of 1–500 records (`hostname`, `raw`, optional UUID `id`, `source`, `timestamp`, `event_id`, `username`, `source_ip`). Returns accepted/duplicate counts and IDs.
- `GET /api/events`: `q`, `hostname`, `source_ip`, `severity`, `event_type`, `start`, `end`, `limit`. Times require timezone offsets.
- `GET /api/alerts`: newest alerts and total count.
- `GET /api/events/{event_id}`: one event and its original log for investigation.
- `GET /api/overview`: last-24-hour totals and hourly trend.
- `GET /api/health`: storage/queue modes, pending count, completed count, and dead-letter count.
- `GET /api/queue/dead-letters`: failed event IDs, attempts, and exception types.
- `POST /api/queue/dead-letters/{event_id}/retry`: return a failed event to pending.

Send `X-API-Key` on all data endpoints when `API_KEY` is configured. Health is public. Log contents can contain sensitive data; use synthetic data for demos.

Example ingestion body:

```json
[{"id":"b08069bf-b743-471b-9c83-2c8d48ac412e","source":"linux","hostname":"web-01","timestamp":"2026-10-24T10:00:00Z","raw":"sshd[100]: Failed password for root from 192.0.2.10 port 22 ssh2"}]
```

## Configuration

- `API_KEY`: optional shared key for data and recovery endpoints.
- `LOGSENTINEL_API_KEY`: matching collector/demo-script key.
- `OPENSEARCH_URL`: OpenSearch endpoint; unset uses SQLite.
- `DATABASE_PATH`: local event database, default `logsentinel.db`.
- `QUEUE_DATABASE_PATH`: inbox file, default `<DATABASE_PATH>.queue.db`. Docker uses `/app/data/inbox.db`.
- `CORS_ORIGINS`: comma-separated origins, default `http://localhost:5173`. The dashboard normally uses same-origin Vite/Nginx proxying.
- `API_PROXY_TARGET`: Vite's API target, default `http://127.0.0.1:8000`.

## Project structure

```text
backend/app/          FastAPI, durable inbox, parser, storage, detections
backend/tests/        Pipeline, correlation, authorization, and durability tests
collector/           Checkpointed file collector and recovery tests
frontend/src/        React overview, events, alerts, and settings
scripts/seed_demo.py Full-day synthetic telemetry generator
docs/                Project change history and documentation
.github/workflows/   Backend tests and dashboard build checks
compose.yaml         OpenSearch, API, and Nginx services
```

## Verify

```powershell
cd backend
python -m unittest discover -s tests -v
cd ..
python -m unittest discover -s collector -v
```

```powershell
cd frontend
npm run build
cd ..
docker compose config --quiet
```

Tests cover normalization, IPv6, Windows/Sysmon records, correlation, host/time isolation, searches, evidence retrieval, authorization, restart recovery, duplicate conflicts, capacity rollback, backoff/dead letters, and collector replay after unknown delivery. GitHub Actions runs the tests and frontend build on pushes to `main` and pull requests.

Local SQLite integration and the frontend build are verified. The Docker configuration is validated; live OpenSearch/container integration remains unverified because the development machine's Docker engine is stopped.

## Current limits and roadmap

- One API worker per inbox; distributed consumers are not supported.
- SQLite searches load records into memory; larger datasets should use OpenSearch. Bulk indexing, pagination, retention, and archiving remain future work.
- An OpenSearch outage during startup prevents API initialization. Runtime processing failures use the inbox retry path.
- Shared-key access is optional locally. User accounts, analyst/admin roles, and audit trails are not implemented.
- Next: alert ownership, investigation notes, status transitions, and case timelines.
- Next: live OpenSearch integration tests, configurable detection thresholds, authorized-activity exclusions, and account-aware/late-event correlation.
- Next: native Windows Event Log subscriptions and additional Sysmon analytics.
- The system does not automatically contain hosts or change firewall rules.
