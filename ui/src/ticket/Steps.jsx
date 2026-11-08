import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { Chip, asText, arr, isBlank, obj } from "../components.jsx";
import { EVENT_TYPE, L, OUTCOME, TOOL, VERDICT } from "../labels.js";
import { useListMotion } from "../motion.js";
import { clock } from "./runState.js";

const MAX_IDS = 20;

function Author({ who }) {
  const [kind, text] = { code: ["code", L.traceAuthorCode], llm: ["llm", L.traceAuthorLlm], person: ["person", L.traceAuthorPerson] }[who];
  return <Chip kind={kind}>{text}</Chip>;
}

// Who produced a step. Fixed by the step's tool, never by what its text says.
function authorOf(event) {
  return event.tool === "llm" ? "llm" : "code";
}

// A cited event: one click shows its log row as plain text. Log text is never HTML and an indicator is never a link.
function EventIds({ ids }) {
  const [all, setAll] = useState(false);
  const [open, setOpen] = useState(null);
  const [rows, setRows] = useState({});
  const shown = all ? ids : ids.slice(0, MAX_IDS);
  async function toggle(id) {
    if (open === id) return setOpen(null);
    setOpen(id);
    if (rows[id]) return undefined;
    try {
      const data = await api.eventRow(id);
      setRows(previous => ({ ...previous, [id]: { source: data.source, text: asText(data.row) } }));
    } catch (error) {
      setRows(previous => ({ ...previous, [id]: { problem: error.message } }));
    }
    return undefined;
  }
  return <>
    <div className="trace-ids"><span className="muted">{L.eventIds}:</span><span className="ids">{shown.map(id => <button key={id} type="button" className="id id-jump" aria-expanded={open === id} onClick={() => toggle(id)}>{id}</button>)}{ids.length > shown.length && <button type="button" className="link-btn" onClick={() => setAll(true)}>{L.traceEventsMore(ids.length - shown.length)}</button>}</span></div>
    {open && <div className="trace-row">
      {!rows[open] ? <p className="muted">{L.traceRowLoading}</p> : rows[open].problem ? <p className="inline-warn">{asText(rows[open].problem)}</p> : <><p className="muted">{L.traceRowTitle(asText(rows[open].source))}</p><pre className="raw-data">{rows[open].text}</pre></>}
      <button type="button" className="link-btn" onClick={() => setOpen(null)}>{L.traceRowClose}</button>
    </div>}
  </>;
}

function FinalStep({ title, who, children, empty }) {
  return <li className="trace-entry trace-final">
    <div className="trace-meta" />
    <div className="trace-content">
      <div className="trace-heading"><strong>{title}</strong>{who.map(item => <Author key={item} who={item} />)}</div>
      {empty ? <p className="muted">{L.traceNoData}</p> : children}
    </div>
  </li>;
}

// What the run ended in, read from the stored ticket: severity, the policy rule that applied and who decided.
function FinalSteps({ ticket, decision }) {
  const inputs = obj(ticket.severity_inputs);
  const rule = isBlank(ticket.closed_by_rule) ? null : obj(ticket.closed_by_rule);
  const escalation = obj(ticket.escalation);
  const auto = obj(ticket.auto_close);
  const proposal = escalation.escalate === true ? L.traceProposalEscalate(asText(escalation.to) || L.na) : escalation.escalate === false ? L.traceProposalClose : null;
  const verdictBy = rule ? ["code"] : ["llm", "code"];
  return <>
    <FinalStep title={L.traceVerdictStep} who={verdictBy} empty={!ticket.verdict}><p className="prose">{VERDICT[ticket.verdict] || asText(ticket.verdict)}</p></FinalStep>
    <FinalStep title={L.traceSeverityStep} who={["code"]} empty={isBlank(ticket.severity_rationale) && isBlank(ticket.severity_inputs)}>
      {!isBlank(ticket.severity_rationale) && <p className="prose">{asText(ticket.severity_rationale)}</p>}
      {arr(inputs.adjustments).map((a, i) => <p key={i} className="muted num">{Number(obj(a).delta) > 0 ? "+1" : "−1"}: {asText(obj(a).reason)}</p>)}
    </FinalStep>
    <FinalStep title={L.tracePolicyStep} who={["code"]} empty={!rule && isBlank(escalation.reason) && !proposal}>
      {rule && <p className="prose">{L.closedByRuleId(asText(rule.rule_id))}: {asText(rule.name)}</p>}
      {proposal && <p className="prose"><strong>{proposal}</strong></p>}
      {!isBlank(escalation.reason) && <p className="prose">{asText(escalation.reason)}</p>}
    </FinalStep>
    <FinalStep title={L.traceDecisionStep} who={[decision ? "person" : ticket.auto_closed === true ? (auto.by_rule ? "code" : "llm") : "person"].concat(!decision && ticket.auto_closed === true && !auto.by_rule ? ["code"] : [])}>
      {decision ? <p className="prose">{L.tracePersonDecision(OUTCOME[decision.outcome] || asText(decision.outcome), asText(decision.analyst))}</p>
        : ticket.auto_closed === true ? <p className="prose">{L.autoClosed}. {asText(auto.reason)}</p>
          : <p className="prose">{L.traceWaitingPerson}</p>}
    </FinalStep>
  </>;
}

export default function Steps({ events, running, stream, live, targetSeq, active = true, ticket = null, decision = null }) {
  const panel = useRef(null);
  useListMotion(panel, `${active}:${events.map(e => e.seq).join(",")}`);
  useEffect(() => {
    if (!active || targetSeq == null) return;
    const step = panel.current?.querySelector(`[data-seq="${targetSeq}"]`);
    step?.scrollIntoView({ block: "center", behavior: "instant" });
    step?.focus({ preventScroll: true });
  }, [targetSeq, active]);
  const last = events.at(-1);
  // A ticket can cite its own alert. That isn't a log event, so it has no row to open.
  const own = new Set(arr(ticket?.alert_ids).map(asText));
  const logIds = e => arr(e.event_ids).map(asText).filter(id => !own.has(id));
  return <section className="activity-timeline" aria-labelledby="steps-title" ref={panel}>
    <div className="section-heading"><h2 id="steps-title">{L.activity}</h2><span className="muted num">{events.length} pasos</span>{running && <span className="running" role="status"><span className="pulse" />{L.stateRunning}…</span>}</div>
    {stream === "lost" && <p className="compact-notice" role="status">{L.streamLost}</p>}
    {events.length || ticket ? <ol className="trace-list">{events.map(e => <li key={e.seq} className={`trace-entry trace-${e.type}${targetSeq === e.seq ? " is-target" : ""}`} data-motion-key={e.seq} data-seq={e.seq} tabIndex={-1}>
      <div className="trace-meta"><span className="trace-number num">#{e.seq}</span><time className="num" dateTime={e.at}>{clock(e.at)} UTC</time></div>
      <div className="trace-content">
        <div className="trace-heading"><span className={`step-type type-${e.type}`}>{EVENT_TYPE[e.type] || asText(e.type)}</span>{e.tool && <strong>{TOOL[e.tool] || asText(e.tool)}</strong>}<Author who={authorOf(e)} />{e.truncated && <Chip kind="warn">{L.truncated}</Chip>}</div>
        {e.summary ? <p className="prose">{asText(e.summary)}</p> : <p className="muted">{L.traceNoData}</p>}
        {e.truncated && <p className="hint">{L.truncatedHelp}</p>}
        {logIds(e).length > 0 && <EventIds ids={logIds(e)} />}
        {Object.keys(obj(e.args)).length > 0 && <details className="technical-details"><summary>{L.queryParameters}</summary><pre className="raw-data">{asText(e.args)}</pre></details>}
      </div>
    </li>)}{ticket && !running && <FinalSteps ticket={ticket} decision={decision} />}</ol> : <p className="muted">{running ? L.loading : L.stepsEmpty}</p>}
    <p className="visually-hidden" aria-live="polite">{live && running && last ? L.stepLive(last.seq, EVENT_TYPE[last.type] || asText(last.type), TOOL[last.tool] || "") : ""}</p>
  </section>;
}
