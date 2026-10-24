import React, { useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const date = value => new Date(value).toLocaleString();
const emptyFilters = { q: '', hostname: '', source_ip: '', severity: '', start: '', end: '' };

function App() {
  const [view, setView] = useState('Overview');
  const [filters, setFilters] = useState(emptyFilters);
  const [applied, setApplied] = useState(emptyFilters);
  const [events, setEvents] = useState({ items: [], total: 0 });
  const [alerts, setAlerts] = useState({ items: [], total: 0 });
  const [overview, setOverview] = useState(null);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState('');
  const [updated, setUpdated] = useState(null);
  const [busy, setBusy] = useState(false);
  const [key, setKey] = useState('');
  const [activeKey, setActiveKey] = useState('');
  const [health, setHealth] = useState(null);
  const [deadLetters, setDeadLetters] = useState([]);

  const refresh = useCallback(async (signal) => {
    try {
      const params = new URLSearchParams();
      Object.entries(applied).forEach(([name, value]) => {
        if (value) params.set(name, ['start', 'end'].includes(name) ? new Date(value).toISOString() : value);
      });
      const responses = await Promise.all(['/api/events?' + params, '/api/alerts', '/api/overview', '/api/health', '/api/queue/dead-letters'].map(async url => {
        const response = await fetch(url, { signal, headers: activeKey ? { 'X-API-Key': activeKey } : {} });
        if (!response.ok) throw new Error(response.status === 401 ? 'API key required. Enter your key in Settings.' : `API returned ${response.status}. Check the backend and filters.`);
        return response.json();
      }));
      setEvents(responses[0]); setAlerts(responses[1]); setOverview(responses[2]); setHealth(responses[3]);
      setDeadLetters(responses[4].items);
      setError(''); setUpdated(new Date());
    } catch (err) { if (err.name !== 'AbortError') setError(err.message); }
  }, [applied, activeKey]);

  useEffect(() => {
    const controller = new AbortController();
    refresh(controller.signal);
    const interval = setInterval(() => refresh(controller.signal), 5000);
    return () => { controller.abort(); clearInterval(interval); };
  }, [refresh]);

  useEffect(() => {
    if (!selected) return;
    const handle = event => { if (event.key === 'Escape') setSelected(null); };
    window.addEventListener('keydown', handle);
    return () => window.removeEventListener('keydown', handle);
  }, [selected]);

  async function loadDemo() {
    setBusy(true);
    try {
      const now = Date.now();
      const logs = Array.from({ length: 7 }, (_, index) => ({ source: 'linux', hostname: 'web-prod-01',
        timestamp: new Date(now - (8 - index) * 20000).toISOString(),
        raw: `sshd[2841]: Failed password for invalid user admin from 203.0.113.42 port 54322 ssh2` }));
      logs.push({ hostname: 'web-prod-01', timestamp: new Date(now - 10000).toISOString(), raw: 'sshd[2901]: Accepted password for admin from 203.0.113.42 port 54323 ssh2' });
      logs.push({ hostname: 'db-prod-02', timestamp: new Date(now).toISOString(), raw: "usermod[3112]: add 'service-backup' to group 'sudo'" });
      logs.push({ hostname: 'worker-03', timestamp: new Date(now).toISOString(), raw: 'systemd[1]: Started Daily log rotation.' });
      const response = await fetch('/api/ingest', { method: 'POST', headers: { 'Content-Type': 'application/json', ...(activeKey ? { 'X-API-Key': activeKey } : {}) }, body: JSON.stringify(logs) });
      if (!response.ok) throw new Error(`Demo ingestion returned ${response.status}`);
      await refresh();
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }

  async function inspectEvidence(id) {
    try {
      const response = await fetch(`/api/events/${id}`, { headers: activeKey ? { 'X-API-Key': activeKey } : {} });
      if (!response.ok) throw new Error(`Could not load evidence (${response.status})`);
      setSelected({ ...await response.json(), record: 'event' });
    } catch (err) { setError(err.message); setSelected(null); }
  }

  async function retryEvent(id) {
    try {
      const response = await fetch(`/api/queue/dead-letters/${id}/retry`, { method: 'POST', headers: activeKey ? { 'X-API-Key': activeKey } : {} });
      if (!response.ok) throw new Error(`Retry failed (${response.status})`);
      await refresh();
    } catch (err) { setError(err.message); }
  }

  const stats = [ ['Events ingested', overview?.events_24h, 'All sources · last 24 hours', 'blue'],
    ['Security alerts', overview?.alerts_24h, 'Detections · last 24 hours', 'red'],
    ['Failed logins', overview?.failures_24h, 'Authentication · last 24 hours', 'amber'],
    ['Queue depth', health?.queued, `Durable inbox · ${health?.failed || 0} dead letters`, 'green'] ];
  const max = Math.max(1, ...(overview?.trend || []).map(item => item.count));

  return <div className="shell">
    <aside className="sidebar">
      <a href="#" className="brand" onClick={() => setView('Overview')}><span className="brand-icon">⬡</span><span>LogSentinel<small>SECURITY OPERATIONS</small></span></a>
      <div className="workspace"><span className="workspace-icon">LS</span><div>Local workspace<small>Development environment</small></div></div>
      <div className="nav-label">WORKSPACE</div>
      <nav>{[['Overview', '◫'], ['Events', '≡'], ['Alerts', '⚑'], ['Settings', '⚙']].map(([name, icon]) => <button key={name} className={view === name ? 'nav active' : 'nav'} onClick={() => setView(name)}><span>{icon}</span>{name}{name === 'Alerts' && <b>{alerts.total}</b>}</button>)}</nav>
      <div className="sidebar-bottom"><span className={`dot ${error ? 'offline' : ''}`}/>{error ? 'Connection needs attention' : updated ? 'Pipeline connected' : 'Connecting…'}<small>LogSentinel / v0.2.0</small></div>
    </aside>
    <main>
      <header><div className="breadcrumb">Workspace <span>/</span> <strong>{view}</strong></div><div className="header-right"><span className="live"><span className="dot"/>LIVE · 5s</span><span className="avatar">AN</span></div></header>
      <div className="content">
        <div className="page-title"><div><div className="eyebrow">YOUR SECURITY, IN FOCUS</div><h1>{view === 'Overview' ? 'Security overview' : view === 'Events' ? 'Event explorer' : view === 'Alerts' ? 'Detection alerts' : 'Workspace settings'}</h1><p>{view === 'Overview' ? 'A live view of the signals that matter across your environment.' : view === 'Events' ? 'Search your telemetry and follow the evidence.' : view === 'Alerts' ? 'Investigate suspicious activity with the context you need.' : 'Configure access to your local security pipeline.'}</p></div><button className="primary" onClick={loadDemo} disabled={busy}>{busy ? 'Loading…' : '+ Load demo events'}</button></div>
        {error && <div role="alert" className="error">{error}</div>}
        {view === 'Settings' ? <section className="panel settings"><h2>API access</h2><p>If API_KEY is configured on the server, enter it here. The key stays in memory for this session.</p><form onSubmit={event => { event.preventDefault(); setActiveKey(key); }}><label>API key<input type="password" value={key} onChange={event => setKey(event.target.value)} autoComplete="off"/></label><button className="primary">Connect</button></form><h2>Ingestion endpoint</h2><code>POST /api/ingest</code><p>Send batches of up to 500 Linux, Windows, or Sysmon log entries. Events are acknowledged after the inbox commits them to disk.</p><div className="queue-settings"><h2>Delivery recovery</h2><p>{health?.queued ?? '—'} waiting · {health?.processed ?? '—'} completed · {health?.failed ?? '—'} dead letters</p><p>Transient processing failures retry automatically up to five times. After correcting the underlying problem, retry a dead-letter event below.</p>{deadLetters.length ? deadLetters.map(item => <div className="dead-letter" key={item.id}><code>{item.id}</code><span>{item.attempts} attempts · {item.last_error}</span><button className="secondary" onClick={() => retryEvent(item.id)}>Retry event</button></div>) : <p className="recovery-ok">No dead letters. The delivery pipeline is clear.</p>}</div></section> : <>
          {view === 'Overview' && <><div className="stats">{stats.map(([label, value, hint, color]) => <section className="stat" key={label}><div>{label}<span className={`stat-icon ${color}`}>⌁</span></div><strong>{value?.toLocaleString() ?? '—'}</strong><small>{hint}</small></section>)}</div>
          <div className="overview-grid"><section className="panel"><div className="panel-heading"><div><h2>Event activity</h2><p>Hourly ingestion volume</p></div><span className="tag">Last 24 hours</span></div><div className="chart" role="img" aria-label="Hourly event counts for the last 24 hours">{(overview?.trend || []).map(item => <div className="bar-track" key={item.hour}><div className="bar" style={{ height: `${item.count ? Math.max(3, item.count / max * 100) : 0}%` }} title={`${date(item.hour)}: ${item.count} events`}/></div>)}</div><div className="chart-labels"><span>24 hours ago</span><span>12 hours ago</span><span>Now</span></div></section>
          <section className="panel coverage"><span className="eyebrow">DETECTION COVERAGE</span><h2>Know what you're looking for.</h2><p>Behavior-based rules mapped to the MITRE ATT&CK framework.</p>{[['T1110', 'Brute Force'], ['T1078', 'Valid Accounts'], ['T1136', 'Create Account'], ['T1098', 'Account Manipulation']].map(([id, name]) => <a key={id} href={`https://attack.mitre.org/techniques/${id}/`} target="_blank" rel="noreferrer"><code>{id}</code><span>{name}</span><span>↗</span></a>)}</section></div></>}
          {(view === 'Overview' || view === 'Alerts') && <section className="panel alert-panel"><div className="panel-heading"><div><h2>Security alerts <span className="count">{alerts.total}</span></h2><p>Latest detections across your environment</p></div>{view === 'Overview' && <button className="text-button" onClick={() => setView('Alerts')}>View all alerts →</button>}</div><div className="alert-list">{alerts.items.slice(0, view === 'Overview' ? 4 : 100).map(alert => <button className="alert-row" key={alert.id} onClick={() => setSelected({ ...alert, record: 'alert' })}><span className={`alert-symbol ${alert.severity}`}>!</span><div className="alert-name"><strong>{alert.title}</strong><small>{alert.hostname} <span>•</span> {alert.source_ip || alert.username || 'Local activity'}</small></div><span className="technique">{alert.technique_id}</span><span className={`badge ${alert.severity}`}>{alert.severity}</span><time>{date(alert.timestamp)}</time><span>↗</span></button>)}{!alerts.items.length && <div className="empty">No alerts yet. New detections will appear here as logs arrive.</div>}</div></section>}
          {(view === 'Overview' || view === 'Events') && <section className="panel event-panel"><div className="panel-heading"><div><h2>Event stream <span className="count">{events.total}</span></h2><p>Showing the latest {events.items.length} matching events</p></div><span className="tag">Auto-refreshing</span></div><form className="filters" onSubmit={event => { event.preventDefault(); setApplied({ ...filters }); }}>{[['q', 'Search log messages…'], ['hostname', 'Hostname'], ['source_ip', 'Source IP']].map(([name, placeholder]) => <input key={name} aria-label={placeholder} placeholder={placeholder} value={filters[name]} onChange={event => setFilters({ ...filters, [name]: event.target.value })}/>)}<select aria-label="Severity" value={filters.severity} onChange={event => setFilters({ ...filters, severity: event.target.value })}><option value="">All severities</option>{['info', 'low', 'medium', 'high', 'critical'].map(value => <option key={value}>{value}</option>)}</select><label className="time-filter">From<input aria-label="Start time" type="datetime-local" value={filters.start} onChange={event => setFilters({ ...filters, start: event.target.value })}/></label><label className="time-filter">To<input aria-label="End time" type="datetime-local" value={filters.end} onChange={event => setFilters({ ...filters, end: event.target.value })}/></label><button className="primary">Apply</button><button type="button" className="secondary" onClick={() => { setFilters(emptyFilters); setApplied(emptyFilters); }}>Reset</button></form><div className="table-scroll"><table><thead><tr>{['Timestamp', 'Event type', 'Host', 'Source IP', 'Severity', ''].map((label, index) => <th key={index}>{label}</th>)}</tr></thead><tbody>{events.items.map(event => <tr key={event.id}><td className="mono">{date(event.timestamp)}</td><td><span className="event-type">{event.event_type.replaceAll('_', ' ')}</span></td><td>{event.hostname}</td><td className="mono muted">{event.source_ip || '—'}</td><td><span className={`badge ${event.severity}`}>{event.severity}</span></td><td><button className="text-button" aria-label={`Inspect event ${event.id}`} onClick={() => setSelected({ ...event, record: 'event' })}>Inspect ↗</button></td></tr>)}</tbody></table>{!events.items.length && <div className="empty">No matching events. Start the collector or load demo events to explore.</div>}</div></section>}
        </>}
        <footer><span>LOGSENTINEL <span className="muted">/ Real-time security event monitoring</span></span><span>{updated ? `Updated ${updated.toLocaleTimeString()}` : 'Waiting for connection'}</span></footer>
      </div>
    </main>
    {selected && <div className="modal-backdrop" onClick={() => setSelected(null)}><section className="drawer" role="dialog" aria-modal="true" aria-label="Investigation details" onClick={event => event.stopPropagation()}><button className="close" autoFocus onClick={() => setSelected(null)}>Close ✕</button><div className="eyebrow">INVESTIGATION / {selected.record.toUpperCase()}</div><h2>{selected.title || selected.event_type.replaceAll('_', ' ')}</h2><span className={`badge ${selected.severity}`}>{selected.severity}</span><p>{selected.description}</p><dl>{[['Timestamp', date(selected.timestamp)], ['Host', selected.hostname], ['Source IP', selected.source_ip || '—'], ['Account', selected.username || '—']].map(([label, value]) => <React.Fragment key={label}><dt>{label}</dt><dd>{value}</dd></React.Fragment>)}</dl>{selected.technique_id && <a className="mitre-link" href={`https://attack.mitre.org/techniques/${selected.technique_id}/`} target="_blank" rel="noreferrer">{selected.technique_id} · {selected.technique_name} ↗</a>}{selected.raw && <><h3>Original log</h3><pre>{selected.raw}</pre></>}{selected.event_ids && <><h3>Evidence events ({selected.event_ids.length})</h3><p className="muted">Open an event to inspect its original log.</p><div className="evidence">{selected.event_ids.map(id => <button key={id} onClick={() => inspectEvidence(id)}>{id} ↗</button>)}</div></>}</section></div>}
  </div>;
}

createRoot(document.getElementById('root')).render(<App/>);
