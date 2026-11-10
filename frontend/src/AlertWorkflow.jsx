import React, { useEffect, useState } from 'react';
import './workflow.css';

const statuses = { new: 'New', investigating: 'Investigating', resolved: 'Resolved', false_positive: 'False positive' };

export default function AlertWorkflow({ alertId, apiKey, onSaved }) {
  const [workflow, setWorkflow] = useState(null);
  const [status, setStatus] = useState('new');
  const [assignee, setAssignee] = useState('');
  const [actor, setActor] = useState('');
  const [note, setNote] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [saving, setSaving] = useState(false);
  const headers = apiKey ? { 'X-API-Key': apiKey } : {};

  useEffect(() => {
    const controller = new AbortController();
    setWorkflow(null); setError('');
    fetch(`/api/alerts/${alertId}`, { signal: controller.signal, headers: apiKey ? { 'X-API-Key': apiKey } : {} })
      .then(async response => {
        if (!response.ok) throw new Error(`Could not load investigation (${response.status})`);
        const { workflow } = await response.json();
        setWorkflow(workflow); setStatus(workflow.status); setAssignee(workflow.assignee);
      }).catch(err => { if (err.name !== 'AbortError') setError(err.message); });
    return () => controller.abort();
  }, [alertId, apiKey]);

  async function save(event) {
    event.preventDefault(); setSaving(true); setError(''); setMessage('');
    try {
      const response = await fetch(`/api/alerts/${alertId}/workflow`, {
        method: 'PATCH', headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ expected_revision: workflow.revision, actor: actor.trim(), status, assignee: assignee.trim(), ...(note.trim() ? { note: note.trim() } : {}) })
      });
      if (response.status === 409) {
        const current = await fetch(`/api/alerts/${alertId}`, { headers });
        if (!current.ok) throw new Error('Another analyst changed this alert. Close and reopen it to reload.');
        setWorkflow((await current.json()).workflow);
        throw new Error('This alert changed elsewhere. Review the current state and history below before saving your changes again.');
      }
      if (!response.ok) {
        const body = await response.json();
        throw new Error(typeof body.detail === 'string' ? body.detail : `Save failed (${response.status}). Check the fields.`);
      }
      const saved = await response.json();
      setWorkflow(saved); setStatus(saved.status); setAssignee(saved.assignee); setNote(''); setMessage('Investigation saved.');
      onSaved();
    } catch (err) { setError(err.message); }
    finally { setSaving(false); }
  }

  return <section className="workflow-panel">
    <h3>Investigation workflow</h3>
    {error && <div className="error" role="alert">{error}</div>}
    {message && <p role="status" className="recovery-ok">{message}</p>}
    {!workflow && !error && <p>Loading investigation…</p>}
    {workflow && <>
      <p className="workflow-current">Current: <strong>{statuses[workflow.status]}</strong> · {workflow.assignee || 'Unassigned'}</p>
      <form onSubmit={save} className="workflow-form">
        <label>Status<select value={status} onChange={e => setStatus(e.target.value)} disabled={saving}>{Object.entries(statuses).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label>
        <label>Assigned analyst<input value={assignee} maxLength={80} placeholder="Unassigned" onChange={e => setAssignee(e.target.value)} disabled={saving}/></label>
        <label>Your name<input value={actor} required maxLength={80} onChange={e => setActor(e.target.value)} disabled={saving}/></label>
        <label className="workflow-note">Investigation note<textarea value={note} maxLength={4000} rows={4} placeholder="Findings, evidence, or reason for closing…" onChange={e => setNote(e.target.value)} disabled={saving}/></label>
        <small>Names are self-reported labels; user accounts are not enabled.</small>
        <button className="primary" disabled={saving || !actor.trim() || (status === workflow.status && assignee.trim() === workflow.assignee && !note.trim())}>{saving ? 'Saving…' : 'Save investigation'}</button>
      </form>
      <h3>Investigation history</h3>
      {!workflow.history.length ? <p>No analyst updates yet.</p> : <ol className="workflow-history">{workflow.history.map(entry => <li key={entry.revision}>
        <div><strong>{entry.actor}</strong><time>{new Date(entry.timestamp).toLocaleString()}</time></div>
        {Object.entries(entry.changes).map(([field, change]) => <p key={field}>{field === 'status' ? 'Status' : 'Assignee'}: {field === 'status' ? statuses[change.from] : change.from || 'Unassigned'} → {field === 'status' ? statuses[change.to] : change.to || 'Unassigned'}</p>)}
        {entry.note && <p className="history-note">{entry.note}</p>}
      </li>)}</ol>}
    </>}
  </section>;
}
