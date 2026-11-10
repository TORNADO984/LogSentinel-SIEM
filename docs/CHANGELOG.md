# Changelog

## Unreleased

- Add persistent analyst workflows: New, Investigating, Resolved, and False positive.
- Add assignment labels, investigation notes, and timestamped change history in alert details.
- Reject stale edits using optimistic revisions, preserving drafts for review in the dashboard.
- Store analyst state separately so detector replay cannot erase it; persist workflow data in Docker.
- Test workflow authorization, validation, detection replay, restart persistence, and conflicting edits.
- Capture the running home page and investigation workflow for project documentation.

## 0.2.0

- Replace the memory queue with a SQLite inbox committed before HTTP acknowledgment.
- Recover unfinished records; preserve IDs across retries and prevent duplicate writes.
- Add atomic batch deduplication, conflicting-ID rejection, backoff, and dead letters.
- Add collector checkpoints, byte offsets, generation-based IDs, and pending-request journaling.
- Expose delivery recovery through API endpoints and dashboard Settings.
- Add a full-day demo generator, GitHub Actions checks, and expanded documentation. Home-page screenshot capture remains pending.

## 0.1.0

- Initial FastAPI API, Linux parser, Windows/Sysmon export adapter, SQLite/OpenSearch storage, detection rules, React dashboard, Docker configuration, and integration tests.
