import { useRef } from "react";
import { usePanelMotion, useSelectionIndicator } from "../motion.js";
import { Field, Ids, ModeTag, NA, None, SlaCell, arr, asText, formatSeconds, formatTime, isBlank, obj, Severity } from "../components.jsx";
import { L, OUTCOME, RUN_STATUS } from "../labels.js";
import { quotaState } from "./runState.js";
import Steps from "./Steps.jsx";
import DecisionPanel, { ActionItem, History } from "./DecisionPanel.jsx";
import SeverityBreakdown from "./SeverityBreakdown.jsx";
import { Affected, EvidenceList, EnrichmentList, InjectionFlags } from "./TicketView.jsx";

function Section({ title, children, id }) {
  return <section className="reading-section" id={id}><h3>{title}</h3>{children}</section>;
}
function TextList({ items }) {
  return items.length ? <ul className="list">{items.map((value, i) => <li key={i} className="prose">{asText(value)}</li>)}</ul> : <None />;
}

export default function TriageWorkspace({ alert, detail, run, running, stream, events, live, tab, onTab, targetSeq, onSelectStep, ticketRow, decision, decisions, retrieved, onSaved, onNext, next }) {
  const tabRefs = useRef({}), tabList = useRef(null), workspace = useRef(null);
  const ticket = obj(ticketRow?.ticket), ready = Boolean(ticketRow && !running);
  const trace = { retrieved, complete: stream === "ended", onJump: onSelectStep };
  const flags = arr(ticket.injection_flags).map(obj), messages = events.filter(e => e.type === "note" || e.type === "error");
  const truncated = events.filter(e => e.truncated), escalation = obj(ticket.escalation);
  const actions = arr(ticket.recommended_actions).map(obj);
  const quota = quotaState(events, running);
  // Related work shares a tab; collections inside it are always continuous.
  const current = ({ evidence: "summary", actions: "policy", notes: "history" })[tab] || tab;
  const marker = useSelectionIndicator(tabList, current, '[aria-selected="true"]');
  usePanelMotion(workspace, current);
  const tabs = [["summary", L.analysis], ["context", L.context], ["policy", L.policyActions], ["decision", L.resolution], ["activity", L.activity], ["original", L.rawAlert], ["history", L.historyNotices]];
  function keyTab(event, index) {
    const nextIndex = ({ ArrowRight: (index + 1) % tabs.length, ArrowLeft: (index + tabs.length - 1) % tabs.length, Home: 0, End: tabs.length - 1 })[event.key];
    if (nextIndex === undefined) return;
    event.preventDefault(); const id = tabs[nextIndex][0]; onTab(id); tabRefs.current[id]?.focus();
  }
  // Keep panels mounted: the resolution form retains unsaved edits across tabs.
  const panel = (id, content) => <section key={id} id={`workspace-${id}`} className="workspace-panel" role="tabpanel" aria-labelledby={`tab-${id}`} tabIndex={0} hidden={current !== id}>{content}</section>;
  const pending = <p className="workspace-empty">{running ? L.pendingTicketText : L.barNoRun}</p>;
  return <>
    <div className="triage-notices">
      {(quota === "waiting" || quota === "exhausted") && <p className="compact-notice" role="status">{quota === "waiting" ? L.quotaWaitingText : L.quotaExhaustedText}</p>}
      {flags.length > 0 && <p className="compact-notice"><strong>{L.barInjections(flags.length)}</strong><button type="button" className="link-btn" onClick={() => onTab("history")}>{L.reviewNotices}</button></p>}
      {truncated.length > 0 && <p className="compact-notice"><strong>{L.truncated} · {truncated.length}</strong><button type="button" className="link-btn" onClick={() => onSelectStep(truncated[0].seq)}>{L.activity}</button></p>}
      {messages.some(e => e.type === "error") && <p className="compact-notice" role="status"><strong>{L.agentErrors}</strong><button type="button" className="link-btn" onClick={() => onTab("history")}>{L.reviewNotices}</button></p>}
    </div>
    <div className="workspace-main panel reading-workspace" ref={workspace}>
      <div className="workspace-tabs" ref={tabList} role="tablist" aria-label={L.details}>{marker && <span className="tab-indicator" aria-hidden="true" style={marker} />}{tabs.map(([id, label], i) => <button type="button" role="tab" key={id} id={`tab-${id}`} aria-controls={`workspace-${id}`} aria-selected={current === id} tabIndex={current === id ? 0 : -1} ref={el => { tabRefs.current[id] = el; }} onClick={() => onTab(id)} onKeyDown={e => keyTab(e, i)}>{label}</button>)}</div>
      {panel("summary", <>
        <div className="workspace-alert"><h2>{asText(alert.rule_name) || L.alertTitle}</h2><Severity value={ready ? ticket.severity : alert.severity} /></div>
        <div className="analysis-layout"><div className="analysis-body">
          {ready && <p className="workspace-ticket-title">{asText(ticket.title)}</p>}
          <Section title={L.summary}><p className="prose">{asText(ready ? ticket.summary : alert.description) || L.na}</p></Section>
          {ready && <Section title={`${L.evidence} · ${arr(ticket.evidence).length}`} id="sec-evidence"><EvidenceList continuous evidence={arr(ticket.evidence)} trace={trace} /></Section>}
        </div><aside className="analysis-facts" aria-label={L.details}><dl className="kv reading-metadata">
          <Field label={L.colProduct}>{asText(alert.source_product) || L.na}</Field>
          <Field label={L.colTime}><span className="num">{formatTime(alert.created_at) || L.na}</span></Field>
          <Field label={L.colRule}><code className="id">{asText(alert.rule_id) || L.na}</code></Field>
          <Field label={L.colRuleSeverity}><Severity value={alert.severity} /></Field>
          {ready && <><Field label={L.ticketId}><code className="id">{ticketRow.ticket_id}</code></Field><Field label={L.alertIds}><Ids ids={ticket.alert_ids} /></Field><Field label={L.triageSeconds}>{formatSeconds(ticket.triage_seconds) || <NA />}</Field></>}
        </dl></aside></div>
      </>)}
      {panel("context", ready ? <>
        <Section title={L.affected}><Affected affected={obj(ticket.affected)} /></Section>
        <Section title={L.enrichment}><EnrichmentList continuous enrichment={arr(ticket.enrichment)} /></Section>
        <Section title={L.mitre}>{arr(ticket.mitre).length ? <Ids ids={ticket.mitre} /> : <None />}</Section>
        <Section title={L.openQuestions}><TextList items={arr(ticket.open_questions)} /></Section>
        {(!isBlank(ticket.authorised_by) || !isBlank(ticket.merged_into)) && <Section title={L.relatedContext}><dl className="kv"><Field label={L.authorisedBy}><span className="prose">{asText(ticket.authorised_by) || L.na}</span></Field><Field label={L.mergedInto}><code className="id">{asText(ticket.merged_into) || L.na}</code></Field></dl></Section>}
      </> : pending)}
      {panel("policy", ready ? <>
        <Section title={L.severityBreakdown}><dl className="kv policy-fields"><SeverityBreakdown ticket={ticket} continuous /></dl></Section>
        <Section title={L.escalation}><dl className="kv"><Field label={L.barProposal}>{escalation.escalate === true ? <strong>{L.escalateYes(asText(escalation.to) || L.na)}</strong> : escalation.escalate === false ? <strong>{L.escalateNo}</strong> : <NA />}</Field><Field label={L.escalationReason}><p className="prose">{asText(escalation.reason) || L.na}</p></Field><Field label={L.runDuration}><SlaCell severity={ticket.severity} seconds={run?.duration_seconds} running={false} /></Field></dl></Section>
        <Section title={`${L.actionsWaiting} · ${actions.length}`} id="sec-proposal">{actions.length ? <ul className="actions-list">{actions.map((action, i) => <ActionItem key={i} continuous action={action} waiting={action.requires_approval === true} />)}</ul> : <None />}</Section>
        <Section title={L.executedActions}><TextList items={arr(ticket.executed_actions)} /></Section>
      </> : pending)}
      {panel("decision", ready ? <><Section title={L.proposedDecision}><strong>{escalation.escalate === true ? `${OUTCOME.escalate} · ${asText(escalation.to) || L.na}` : escalation.escalate === false ? OUTCOME.close : L.na}</strong><p className="prose">{asText(escalation.reason)}</p></Section><DecisionPanel key={ticketRow.run_id} compact ticketRow={ticketRow} current={decision} onNext={onNext} next={next} decisions={decisions} waiting={[]} others={[]} executed={ticket.executed_actions} onSaved={onSaved} /></> : pending)}
      {panel("activity", <Steps events={events} running={running} stream={stream} live={live} targetSeq={targetSeq} active={current === "activity"} />)}
      {panel("original", <><details className="technical-details original-details" open><summary>{L.alertTitle}</summary><pre className="raw-data">{asText(alert)}</pre></details>{ready && <details className="technical-details original-details"><summary>{L.completeTicket}</summary><pre className="raw-data">{asText(ticket)}</pre></details>}</>)}
      {panel("history", <>
        <Section title={L.notes} id="run-notices"><InjectionFlags continuous flags={flags} trace={trace} />{messages.length ? <ol className="run-message-list">{messages.map(e => <li key={e.seq}><span className="state">{e.type === "error" ? L.stageFailed : L.notes}</span><time className="muted num">{formatTime(e.at)} UTC</time><p className="prose">{asText(e.summary)}</p><button type="button" className="link-btn" onClick={() => onSelectStep(e.seq)}>{L.seeStep(e.seq)}</button></li>)}</ol> : !flags.length && <None />}</Section>
        <Section title={L.decisionsHistory}><History continuous decisions={decisions} runId={ticketRow?.run_id} /></Section>
        <Section title={L.runsHistory}>{arr(detail.runs).length ? <ol className="run-history-list">{[...detail.runs].sort((a, b) => String(b.started_at).localeCompare(String(a.started_at))).map(r => <li key={r.run_id}><div className="rows-head"><code className="id">{r.run_id}</code><strong>{RUN_STATUS[r.status] || asText(r.status)}</strong><ModeTag mode={r.mode} /></div><p className="muted num">{formatTime(r.started_at)} UTC → {formatTime(r.finished_at) || "—"} UTC · {formatSeconds(r.duration_seconds) || "—"}</p>{r.error && <p className="prose">{asText(r.error)}</p>}</li>)}</ol> : <None />}</Section>
      </>)}
    </div>
  </>;
}
