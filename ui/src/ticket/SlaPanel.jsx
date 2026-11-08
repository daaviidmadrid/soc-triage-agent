// The ticket's SLA, the N2 call a person must confirm, and the reopen of an auto-closed ticket. Times come from the server.
import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { Chip, ErrorBox, Field, SlaState, Severity, asText, arr, formatTime, obj } from "../components.jsx";
import { L, SEVERITY } from "../labels.js";
import { formatDuration, liveSla } from "../queue/model.js";
import { rememberName, rememberedName } from "./DecisionPanel.jsx";

function useServerNow(serverNow) {
  const [tick, setTick] = useState(() => Date.now());
  const offset = useRef(0);
  useEffect(() => { const server = Date.parse(serverNow); if (Number.isFinite(server)) offset.current = server - Date.now(); }, [serverNow]);
  useEffect(() => { const timer = setInterval(() => setTick(Date.now()), 1000); return () => clearInterval(timer); }, []);
  return tick + offset.current;
}

function Audit({ alertId, version }) {
  const [entries, setEntries] = useState(null);
  const [open, setOpen] = useState(false);
  useEffect(() => { if (open) api.audit(alertId).then(data => setEntries(data.entries)).catch(() => setEntries([])); }, [open, alertId, version]);
  return <details className="technical-details" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>{L.auditTitle}</summary>
    {!entries ? <p className="muted">{L.loading}</p> : entries.length === 0 ? <p className="muted">{L.auditEmpty}</p> : <ol className="audit-list">{entries.map(e => <li key={e.id}>
      <time className="muted num">{formatTime(e.at)} UTC</time><Chip kind={e.actor_kind === "person" ? "person" : e.actor_kind === "model" ? "llm" : "code"}>{e.actor_kind === "person" ? L.traceAuthorPerson : e.actor_kind === "model" ? L.traceAuthorLlm : L.traceAuthorCode}</Chip>
      <code className="id">{asText(e.action)}</code><span className="muted">{asText(e.actor)}</span><span className="prose">{asText(e.reason)}</span>
    </li>)}</ol>}
  </details>;
}

function NameAndAction({ busy, label, onSubmit, extra, extraLabel, extraRequired, secondary }) {
  const [name, setName] = useState(rememberedName);
  const [text, setText] = useState("");
  const [problem, setProblem] = useState(null);
  async function submit(event, kind) {
    event.preventDefault();
    if (!name.trim()) return setProblem(L.needName);
    if (extraRequired && !text.trim()) return setProblem(L.reopenNeeds);
    setProblem(null);
    rememberName(name.trim());
    await onSubmit(name.trim(), text.trim(), kind);
  }
  return <form className="sla-form" onSubmit={event => submit(event, "call")} noValidate>
    <label className="control"><span className="control-label">{L.yourName}</span><input type="text" value={name} maxLength={100} onChange={event => setName(event.target.value)} autoComplete="name" /></label>
    {extra && <label className="control"><span className="control-label">{extraLabel}</span><input type="text" value={text} maxLength={1000} onChange={event => setText(event.target.value)} /></label>}
    <button type="submit" className="btn btn-primary" disabled={busy}>{label}</button>
    {secondary && <button type="button" className="btn" disabled={busy} onClick={event => submit(event, "handover")}>{secondary}</button>}
    {problem && <p className="inline-warn" role="alert">{problem}</p>}
  </form>;
}

export default function SlaPanel({ alertId, record, ticketRow, decision, serverNow, onSaved }) {
  const nowMs = useServerNow(serverNow);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [version, setVersion] = useState(0);
  const ticket = ticketRow ? obj(ticketRow.ticket) : {};
  const auto = obj(ticket.auto_close);
  const autoClosed = ticket.auto_closed === true && !decision;
  const live = liveSla(record, nowMs);

  async function act(call) {
    setBusy(true); setError(null);
    try { await call(); await onSaved(); setVersion(v => v + 1); } catch (e) { setError(e.message); } finally { setBusy(false); }
  }

  if (!live) return null;
  const confirmation = live.escalation_confirmation && obj(live.escalation_confirmation);
  return <section className="panel sla-panel" aria-labelledby="sla-title">
    <div className="section-heading"><h2 id="sla-title">{L.slaTitle}</h2><SlaState state={live.state} />{live.secondsLeft !== null && <span className="num">{live.secondsLeft >= 0 ? L.slaLeft(formatDuration(live.secondsLeft)) : L.slaOver(formatDuration(live.secondsLeft))}</span>}</div>
    <p className="hint">{L.slaClockNote}</p>
    {live.at_risk_reason === "worker" && <p className="inline-warn">{L.slaWorkerRisk}</p>}
    {ticket && ticketRow && live.stopped_at === null && ticket.verdict === "needs_more_info" && <p className="inline-warn">{L.fallbackSla}</p>}
    {live.severity_assumed && <p className="inline-warn">{L.slaAssumed}</p>}
    <dl className="kv kv-grid">
      <Field label={L.severity}><Severity value={live.severity} />{live.severity_source === "rule" && <span className="sub">{L.fromRule}</span>}</Field>
      <Field label={L.slaStarted}><span className="num">{formatTime(live.started_at) || L.na}</span></Field>
      <Field label={L.slaDeadline}><span className="num">{live.deadline ? formatTime(live.deadline) : L.slaNoDeadline}</span></Field>
      <Field label={L.slaStopped}><span className="num">{live.stopped_at ? formatTime(live.stopped_at) : L.slaRunning}</span>{live.stopped_by === "person" && <span className="sub">{L.slaByPerson}</span>}</Field>
      {live.deadline_severity !== live.severity && <Field label={L.slaBy}><Severity value={live.deadline_severity} /></Field>}
      {arr(live.changes).length > 0 && <Field label={L.slaChanges}>{arr(live.changes).map((c, i) => <div key={i} className="num">{formatTime(c.at)} UTC: {L.slaChange(SEVERITY[c.from] || asText(c.from), SEVERITY[c.to] || asText(c.to))}</div>)}</Field>}
    </dl>

    {live.required_action && <div className="sla-action" role="group" aria-label={L.requiredAction}>
      <p><strong>{L.requiredAction}:</strong> {asText(live.required_action)}{live.deadline && <> · {L.slaDeadline}: <span className="num">{formatTime(live.deadline)}</span></>}</p>
      {confirmation ? <p className="ok">{L.confirmedBy(confirmation.kind, asText(confirmation.by), formatTime(confirmation.at))}{confirmation.note && <span className="muted"> {asText(confirmation.note)}</span>}</p> : <>
        <p className="hint">{L.requiredHint}</p>
        <NameAndAction busy={busy} label={L.confirmCall} secondary={L.confirmHandover} extra extraLabel={L.confirmNote} onSubmit={(analyst, note, kind) => act(() => api.confirmEscalation(alertId, { analyst, kind, note }))} />
      </>}
    </div>}

    {autoClosed && <div className="sla-action" role="group" aria-label={L.autoClosed}>
      <p><strong>{L.autoClosed}.</strong> {asText(auto.reason) || L.autoClosedHelp}</p>
      <p className="muted">{L.autoClosedBy(auto.by_rule ? L.closedByRuleId(asText(auto.by_rule)) : L.autoClosedByModel(asText(auto.by_model) || L.na))} · <span className="num">{formatTime(auto.at)} UTC</span>{auto.sampled && <> · {L.sampleChip}</>}{auto.reviewed_by && <> · {L.sampleReviewed(asText(auto.reviewed_by))}</>}</p>
      <NameAndAction busy={busy} label={L.reopen} extra extraRequired extraLabel={L.reopenReason} onSubmit={(analyst, reason) => act(() => api.reopen(ticketRow.ticket_id, { analyst, reason }))} />
    </div>}
    {!autoClosed && auto.reopened_by && <p className="compact-notice"><strong>{L.reopenedBy(asText(auto.reopened_by), formatTime(auto.reopened_at))}</strong> {asText(auto.reopen_reason)}</p>}
    {error && <ErrorBox message={error} />}
    <Audit alertId={alertId} version={version} />
  </section>;
}
