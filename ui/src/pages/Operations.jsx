// The automation: where every alert is, what the worker is doing, what it spent, and what a person has to acknowledge.
// Real data only, from the same queue and status the rest of the console uses. The system sends nothing outside this page.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { Chip, ErrorBox, Severity, Skeleton, asText, formatTime } from "../components.jsx";
import Icon from "../icons.jsx";
import { L, PIPELINE_LANE, SEVERITY, SEVERITY_ORDER, SLA_STATE, VERDICT, WORKER_STATE, WORKER_STOP } from "../labels.js";
import { pipelineCounts } from "../queue/model.js";
import { rememberName, rememberedName } from "../ticket/DecisionPanel.jsx";

const POLL_MS = 3000;
const LANE_FILTERS = Object.keys(PIPELINE_LANE);

function Pipeline({ lanes, onQueue }) {
  return <section className="panel ops-panel" aria-labelledby="pipeline-title">
    <div className="section-heading"><h2 id="pipeline-title">{L.pipelineTitle}</h2></div>
    <p className="hint">{L.pipelineHelp}</p>
    <ol className="pipeline">{LANE_FILTERS.map((key, index) => {
      const lane = lanes[key];
      return <li key={key} className={`pipeline-lane lane-${key}`}>
        <button type="button" onClick={() => onQueue({ lane: key })} aria-label={`${PIPELINE_LANE[key]}: ${lane.total}`}>
          <span className="pipeline-name">{PIPELINE_LANE[key]}</span>
          <strong className="pipeline-total num">{lane.total}</strong>
          {key === "person" && <span className="pipeline-needs">{L.pipelineNeedsPerson(lane.needsPerson)}</span>}
          <span className="pipeline-severities">{SEVERITY_ORDER.filter(severity => lane.bySeverity[severity] > 0).map(severity => <span key={severity} className="pipeline-severity"><Severity value={severity} /><span className="num">{lane.bySeverity[severity]}</span></span>)}{lane.bySeverity.unknown > 0 && <span className="pipeline-severity"><span className="muted">{L.na}</span><span className="num">{lane.bySeverity.unknown}</span></span>}</span>
        </button>
        {index < LANE_FILTERS.length - 1 && <span className="pipeline-arrow" aria-hidden="true"><Icon name="arrowRight" /></span>}
      </li>;
    })}</ol>
  </section>;
}

function WorkerPanel({ status, onAction, busy }) {
  const worker = status.worker;
  const state = worker.enabled ? worker.state : "disabled";
  const running = state === "running", paused = state === "paused", stopped = state === "stopped";
  return <section className="panel ops-panel" aria-labelledby="worker-title">
    <div className="section-heading"><h2 id="worker-title">{L.workerTitle}</h2><span className={`worker-state worker-${state}`}><span className="status-dot" />{WORKER_STATE[state]}</span></div>
    {!worker.enabled && <p className="hint">{L.workerDisabled}</p>}
    {worker.enabled && <div className="bar-actions">
      <button type="button" className="btn btn-primary" disabled={busy || running || state === "stopping"} onClick={() => onAction("start")}><Icon name="play" />{paused ? L.workerResume : L.workerStart}</button>
      <button type="button" className="btn" disabled={busy || !running} onClick={() => onAction("pause")}><Icon name="pause" />{L.workerPause}</button>
      <button type="button" className="btn" disabled={busy || stopped || state === "stopping"} onClick={() => { if (window.confirm(L.workerStopConfirm)) onAction("stop"); }}><Icon name="cross" />{L.workerStop}</button>
    </div>}
    {stopped && worker.stop_reason && <p className="inline-warn">{L.workerStoppedBecause(WORKER_STOP[worker.stop_reason] || asText(worker.stop_reason))}</p>}
    <dl className="kv kv-grid">
      <div className="field"><dt>{L.llmCalls}</dt><dd className="num"><strong>{L.llmCallsOf(worker.llm_calls_used, worker.llm_calls_limit)}</strong><div className="sub">{L.llmPerMinute(worker.llm_calls_per_minute, worker.pace_seconds)}</div></dd></div>
      <div className="field"><dt>{L.failures}</dt><dd className="num">{L.failuresValue(worker.failures_in_a_row, worker.max_failures, worker.failures_total)}</dd></div>
      <div className="field"><dt>{L.workerTriaged}</dt><dd className="num">{worker.triaged}</dd></div>
      <div className="field"><dt>{L.workerReports}</dt><dd className="num">{worker.reports} · {L.workerInvestigate} {worker.investigate ? L.workerInvestigateOn : L.workerInvestigateOff}</dd></div>
      {worker.current && <div className="field"><dt>{L.workerCurrent}</dt><dd><code className="id">{asText(worker.current)}</code></dd></div>}
    </dl>
  </section>;
}

function SlaTable({ status, onQueue }) {
  const states = ["on_track", "at_risk", "breached", "met", "batch"];
  return <section className="panel ops-panel" aria-labelledby="sla-counts-title">
    <div className="section-heading"><h2 id="sla-counts-title">{L.slaByStatus}</h2></div>
    <p className="hint">{L.slaClockNote}</p>
    <div className="table-scroll"><table className="ops-table"><thead><tr><th scope="col">{L.colSeverity}</th><th scope="col">{L.pendingPriority}</th>{states.map(state => <th key={state} scope="col">{SLA_STATE[state]}</th>)}</tr></thead>
      <tbody>{SEVERITY_ORDER.map(severity => <tr key={severity}><th scope="row"><Severity value={severity} /></th><td className="num">{status.pending_by_priority[severity]}</td>{states.map(state => <td key={state} className="num">{["at_risk", "breached"].includes(state) && status.sla[severity][state] > 0 ? <button type="button" className="link-btn" onClick={() => onQueue({ severity, sla: state })}>{status.sla[severity][state]}</button> : status.sla[severity][state]}</td>)}</tr>)}</tbody>
    </table></div>
  </section>;
}

function Notifications({ data, name, onAcknowledge, onOpen, busy }) {
  return <section className="panel ops-panel" aria-labelledby="notifications-title">
    <div className="section-heading"><h2 id="notifications-title">{L.notificationsTitle}</h2><span className="muted num">{L.notificationsUnack(data.unacknowledged)}</span></div>
    <p className="hint">{L.notificationsHelp}</p>
    {data.notifications.length === 0 ? <p className="muted">{L.notificationsNone}</p> : <div className="table-scroll"><table className="ops-table"><thead><tr><th scope="col">{L.colRole}</th><th scope="col">{L.colSeverity}</th><th scope="col">{L.colTicket}</th><th scope="col">{L.slaDeadline}</th><th scope="col">{L.colCreated}</th><th scope="col">{L.colReason}</th><th scope="col">{L.acknowledge}</th></tr></thead>
      <tbody>{data.notifications.map(note => <tr key={note.id} className={note.acknowledged_at ? "is-read" : undefined}>
        <td>{asText(note.role)}</td><td><Severity value={note.severity} /></td>
        <td><button type="button" className="id id-jump" onClick={() => onOpen(note.alert_id)}>{asText(note.alert_id)}</button>{note.ticket_id && <div className="sub">{asText(note.ticket_id)}</div>}{note.mode === "example" && <Chip kind="example">{L.exampleTag}</Chip>}</td>
        <td className="num">{note.deadline ? formatTime(note.deadline) : L.slaNoDeadline}</td><td className="num">{formatTime(note.at)}</td><td className="prose">{asText(note.reason)}</td>
        <td>{note.acknowledged_at ? <span className="muted">{L.acknowledgedBy(asText(note.acknowledged_by), formatTime(note.acknowledged_at))}</span> : <button type="button" className="btn btn-sm" disabled={busy || !name.trim()} title={name.trim() ? undefined : L.needNameFirst} onClick={() => onAcknowledge(note.id)}>{L.acknowledge}</button>}</td>
      </tr>)}</tbody>
    </table></div>}
  </section>;
}

function AutoClosed({ status, name, busy, onReview, onReopen, onOpen }) {
  return <section className="panel ops-panel" aria-labelledby="auto-title">
    <div className="section-heading"><h2 id="auto-title">{L.autoCountsTitle}</h2></div>
    <p className="hint">{L.autoCountsHelp}</p>
    {status.auto_closed.length === 0 ? <p className="muted">{L.autoCountsNone}</p> : <div className="table-scroll"><table className="ops-table"><thead><tr><th scope="col">{L.colClosedBy}</th><th scope="col">{L.colDetection}</th><th scope="col">{L.colCount}</th><th scope="col">{L.colReopened}</th></tr></thead>
      <tbody>{status.auto_closed.map(row => <tr key={`${row.closed_by}|${row.detection_rule}`}><td><Chip kind={row.kind === "rule" ? "code" : "llm"}>{asText(row.closed_by)}</Chip></td><td><code className="id">{asText(row.detection_rule) || L.na}</code></td><td className="num">{row.count}</td><td className="num">{row.reopened}</td></tr>)}</tbody>
    </table></div>}
    <div className="section-heading ops-subheading"><h3>{L.samplesTitle(status.sample_percent)}</h3></div>
    <p className="hint">{L.samplesHelp}</p>
    {status.samples.length === 0 ? <p className="muted">{L.samplesNone}</p> : <div className="table-scroll"><table className="ops-table"><thead><tr><th scope="col">{L.colAlert}</th><th scope="col">{L.colSeverity}</th><th scope="col">{L.verdict}</th><th scope="col">{L.colClosedBy}</th><th scope="col">{L.colActions}</th></tr></thead>
      <tbody>{status.samples.map(row => <tr key={row.ticket_id}>
        <td><button type="button" className="id id-jump" onClick={() => onOpen(row.alert_id)}>{asText(row.alert_id)}</button></td><td><Severity value={row.severity} /></td><td>{VERDICT[row.verdict] || asText(row.verdict)}</td><td>{asText(row.closed_by)}</td>
        <td>{row.reopened_by ? <Chip kind="warn">{L.reopened}</Chip> : <div className="row-actions">{row.reviewed_by ? <span className="muted">{L.sampleReviewed(asText(row.reviewed_by))}</span> : <button type="button" className="btn btn-sm" disabled={busy || !name.trim()} title={name.trim() ? undefined : L.needNameFirst} onClick={() => onReview(row.ticket_id)}>{L.sampleReview}</button>}<button type="button" className="btn btn-sm" onClick={() => onOpen(row.alert_id)}>{L.reopen}<Icon name="arrowRight" /></button></div>}</td>
      </tr>)}</tbody>
    </table></div>}
  </section>;
}

export default function Operations({ onOpen, onQueue, onReport }) {
  const [queue, setQueue] = useState(null), [status, setStatus] = useState(null), [notes, setNotes] = useState(null);
  const [error, setError] = useState(null), [busy, setBusy] = useState(false);
  const [name, setName] = useState(rememberedName);
  const alive = useRef(true);
  const load = useCallback(async () => {
    try {
      const [q, s, n] = await Promise.all([api.queue(), api.status(), api.notifications()]);
      if (!alive.current) return;
      setQueue(q); setStatus(s); setNotes(n); setError(null); onReport(q.mode, q.example_results > 0);
    } catch (problem) { if (alive.current) setError(problem.message); }
  }, [onReport]);
  useEffect(() => { alive.current = true; load(); const timer = setInterval(load, POLL_MS); return () => { alive.current = false; clearInterval(timer); }; }, [load]);
  const lanes = useMemo(() => pipelineCounts(queue ? queue.alerts : []), [queue]);
  async function act(call) {
    setBusy(true);
    try { await call(); await load(); } catch (problem) { setError(problem.message); } finally { setBusy(false); }
  }
  const named = call => () => { rememberName(name.trim()); return call(name.trim()); };
  if (error && !status) return <ErrorBox message={error} onRetry={load} />;
  if (!status || !queue || !notes) return <Skeleton rows={6} cols={4} label={L.loading} />;
  return <div className="operations">
    <header className="page-head"><div className="page-title"><h1>{L.operationsTitle}</h1></div><div className="page-actions"><label className="control ops-name"><span className="control-label">{L.yourName}</span><input type="text" value={name} maxLength={100} onChange={event => setName(event.target.value)} autoComplete="name" /></label></div></header>
    <p className="hint">{L.operationsIntro}</p>
    {error && <ErrorBox message={error} onRetry={load} />}
    <Pipeline lanes={lanes} onQueue={onQueue} />
    <div className="ops-grid">
      <WorkerPanel status={status} busy={busy} onAction={action => act(() => api.worker(action))} />
      <SlaTable status={status} onQueue={onQueue} />
    </div>
    <Notifications data={notes} name={name} busy={busy} onOpen={onOpen} onAcknowledge={id => act(named(analyst => api.acknowledge(id, analyst)))} />
    <AutoClosed status={status} name={name} busy={busy} onOpen={onOpen} onReview={id => act(named(analyst => api.sampleReview(id, analyst)))} />
  </div>;
}
