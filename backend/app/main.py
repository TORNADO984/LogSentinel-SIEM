import asyncio
import hmac
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .detections import detect
from .models import LogInput
from .parser import normalize
from .queue import IdConflict, Inbox, QueueFull
from .storage import Store

logger = logging.getLogger('logsentinel')


@asynccontextmanager
async def lifespan(app):
    app.state.store = Store()
    app.state.store.initialize()
    app.state.queue = Inbox()
    app.state.wakeup = asyncio.Event()
    app.state.stopping = False

    async def worker():
        while not app.state.stopping:
            app.state.wakeup.clear()
            log = app.state.queue.claim()
            if log is None:
                try:
                    await asyncio.wait_for(app.state.wakeup.wait(), timeout=0.5)
                except TimeoutError:
                    pass
                continue
            try:
                event = normalize(log)
                app.state.store.save('events', event)
                detect(event, app.state.store)
                app.state.queue.complete(log.id)
            except Exception as error:
                app.state.queue.fail(log.id, error)
                logger.exception('Event processing failed')
            await asyncio.sleep(0)  # Let API requests run between records.
    task = asyncio.create_task(worker())
    try:
        yield
    finally:
        app.state.stopping = True
        app.state.wakeup.set()
        await task
        app.state.queue.close()
        app.state.store.close()


app = FastAPI(title='LogSentinel SIEM', version='0.2.0', lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=os.getenv('CORS_ORIGINS', 'http://localhost:5173').split(','),
                   allow_methods=['GET', 'POST'], allow_headers=['Content-Type', 'X-API-Key'])


def authorize(x_api_key: str | None = Header(default=None)):
    expected = os.getenv('API_KEY')
    if expected and not hmac.compare_digest(x_api_key or '', expected):
        raise HTTPException(401, 'Invalid API key')


@app.get('/api/health')
async def health():
    return {'status': 'ok', 'storage': 'opensearch' if app.state.store.url else 'sqlite',
            'queue': 'durable-sqlite', **app.state.queue.stats()}


@app.post('/api/ingest', status_code=202, dependencies=[Depends(authorize)])
async def ingest(logs: list[LogInput]):
    if not 1 <= len(logs) <= 500:
        raise HTTPException(422, 'Supply between 1 and 500 log entries')
    try:
        result = app.state.queue.enqueue(logs)
    except QueueFull as error:
        raise HTTPException(429, str(error))
    except IdConflict as error:
        raise HTTPException(409, str(error))
    app.state.wakeup.set()
    return result


@app.get('/api/queue/dead-letters', dependencies=[Depends(authorize)])
async def dead_letters(limit: int = Query(100, ge=1, le=1000)):
    return {'items': app.state.queue.dead_letters(limit)}


@app.post('/api/queue/dead-letters/{event_id}/retry', dependencies=[Depends(authorize)])
async def retry_dead_letter(event_id: str):
    try:
        retried = app.state.queue.retry(event_id)
    except QueueFull as error:
        raise HTTPException(429, str(error))
    if not retried:
        raise HTTPException(404, 'Dead-letter event not found')
    app.state.wakeup.set()
    return {'retried': event_id}


def time_bounds(start, end):
    for value in (start, end):
        if value and value.tzinfo is None:
            raise HTTPException(422, 'Time filters must include a timezone')
    if start and end and start > end:
        raise HTTPException(422, 'start must be before end')


@app.get('/api/events', dependencies=[Depends(authorize)])
async def events(q: str = Query('', max_length=300), hostname: str | None = None,
                 source_ip: str | None = None, severity: str | None = None,
                 event_type: str | None = None, start: datetime | None = None,
                 end: datetime | None = None, limit: int = Query(100, ge=1, le=1000)):
    time_bounds(start, end)
    return app.state.store.query(q=q, hostname=hostname, source_ip=source_ip,
                                severity=severity, event_type=event_type, start=start, end=end, limit=limit)


@app.get('/api/alerts', dependencies=[Depends(authorize)])
async def alerts(limit: int = Query(100, ge=1, le=1000)):
    return app.state.store.query('alerts', limit=limit)


@app.get('/api/events/{event_id}', dependencies=[Depends(authorize)])
async def event_detail(event_id: str):
    from uuid import UUID
    try:
        UUID(event_id)
    except ValueError:
        raise HTTPException(422, 'Invalid event ID')
    record = app.state.store.get('events', event_id)
    if not record:
        raise HTTPException(404, 'Event not found')
    return record


@app.get('/api/overview', dependencies=[Depends(authorize)])
async def overview():
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    recent = app.state.store.query(start=now - timedelta(hours=24), end=now, limit=1000)
    alerts = app.state.store.query('alerts', start=now - timedelta(hours=24), end=now, limit=1000)
    buckets = []
    for offset in range(23, -1, -1):
        start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=offset)
        end = start + timedelta(hours=1)
        count = app.state.store.query(start=start, end=end - timedelta(microseconds=1), limit=0)['total']
        buckets.append({'hour': start.isoformat(), 'count': count})
    return {'events_24h': recent['total'], 'alerts_24h': alerts['total'],
            'failures_24h': app.state.store.query(event_type='login_failure', start=now - timedelta(hours=24), end=now, limit=0)['total'],
            'trend': buckets}
