// Top of the ticket: where the run is (Consulta → Evidencia → Propuesta → Decisión humana) and the decision at a glance.
// Every state here comes from structured fields (run status, event types, verdict, escalation, decisions), never from free text.
import { Chip, Clip, ModeTag, NA, Severity, arr, asText, formatSeconds, isBlank, obj } from "../components.jsx";
import Icon from "../icons.jsx";
import { L, OUTCOME, SLA, VERDICT } from "../labels.js";
import { formatClock } from "./runState.js";

const STAGES = [
  { key: "consult", name: L.stageConsult, target: "steps-title" },
  { key: "evidence", name: L.stageEvidence, target: "sec-evidence" },
  { key: "proposal", name: L.stageProposal, target: "sec-proposal" },
  { key: "person", name: L.stagePerson, target: "sec-decision" },
];
const STAGE_TEXT = { done: L.stageDone, active: L.stageActive, waiting: L.stageWaiting, todo: L.stageTodo, failed: L.stageFailed };

// done | active | waiting | todo | failed, for each of the four stages.
function stageStates({ run, events, ticket, decided, fallback }) {
  if (!run) return ["todo", "todo", "todo", "todo"];
  const llmStarted = events.some((e) => e.tool === "llm");
  if (run.status === "failed") {
    const at = llmStarted ? 1 : 0;
    return STAGES.map((_, i) => (i < at ? "done" : i === at ? "failed" : "todo"));
  }
  if (run.status === "running") return llmStarted ? ["done", "active", "todo", "todo"] : ["active", "todo", "todo", "todo"];
  if (!ticket) return ["done", "todo", "todo", "todo"];
  return ["done", fallback ? "failed" : "done", "done", decided ? "done" : "waiting"];
}

function Progress({ states, onGo, available }) {
  // Where the run is now: the stage in progress or waiting; a failed stage only when nothing came after it.
  const live = states.findIndex((s) => s === "active" || s === "waiting");
  const current = live !== -1 ? live : states.indexOf("failed");
  return (
    <ol className="stages" aria-label={L.progressLabel}>
      {STAGES.map((stage, i) => {
        const state = states[i];
        const body = (
          <>
            <span className="stage-n num" aria-hidden="true">
              {state === "done" ? <Icon name="check" /> : state === "failed" ? <Icon name="cross" /> : i + 1}
            </span>
            <span className="stage-text">
              <span className="stage-name">{stage.name}</span>
              <span className="stage-state">{STAGE_TEXT[state]}</span>
            </span>
          </>
        );
        return (
          <li key={stage.key} className={`stage stage-${state}`} aria-current={i === current ? "step" : undefined}>
            {available(stage.target) ? (
              <button type="button" className="stage-btn" onClick={() => onGo(stage.target)} title={L.stageGoTo(stage.name)}>
                {body}
              </button>
            ) : (
              <span className="stage-btn is-static">{body}</span>
            )}
          </li>
        );
      })}
    </ol>
  );
}

export function Fact({ label, children }) {
  return (
    <div className="fact">
      <dt>
        {label}
      </dt>
      <dd>{children}</dd>
    </div>
  );
}

function Running({ run, now, ruleSeverity, record }) {
  const started = Date.parse(run.started_at);
  const seconds = isFinite(started) ? (now - started) / 1000 : null;
  const sla = SLA[ruleSeverity];
  // Against the server's deadline, which runs from when the alert entered the app, not from when this run began.
  const deadline = record && record.deadline ? Date.parse(record.deadline) : NaN;
  const over = isFinite(deadline) ? now > deadline : sla && sla.seconds !== null && seconds !== null && seconds > sla.seconds;
  return (
    <div className="bar-running">
      <span className="running">
        <span className="pulse" aria-hidden="true" /> {L.barRunning}…
      </span>
      <span>
        <span className="muted">{L.barElapsed}: </span>
        <strong className={`num${over ? " bad" : ""}`}>{seconds === null ? "—" : formatClock(seconds)}</strong>
      </span>
      {sla && (
        <span className="muted">
          {L.slaTarget(sla.label)} ({L.fromRule})
        </span>
      )}
    </div>
  );
}

function Failed({ run, starting, onStart, onReviewByHand }) {
  return (
    <div className="bar-failed" role="alert">
      <p>
        <strong className="bad with-icon">
          <Icon name="alert" />
          {L.runFailedTitle}.
        </strong>{" "}
        {L.runFailedText} <Clip value={run.error} max={240} />
      </p>
      <p className="muted">{L.runFailedNext}</p>
      <div className="bar-actions">
        <button type="button" className="btn btn-primary" onClick={onStart} disabled={starting}>
          {starting ? L.starting : L.retry}
        </button>
        <button type="button" className="btn" onClick={onReviewByHand}>
          {L.reviewByHand}
        </button>
      </div>
    </div>
  );
}

function Summary({ ticketRow, decision, fallback, next, onGo, onNext, compact }) {
  const ticket = obj(ticketRow.ticket);
  const escalation = obj(ticket.escalation);
  const proposal = escalation.escalate === true ? "escalate" : escalation.escalate === false ? "close" : null;
  const flags = arr(ticket.injection_flags).length;
  const rule = isBlank(ticket.closed_by_rule) ? null : obj(ticket.closed_by_rule);
  // A fallback ticket, or one a fixed rule closed, was filled in by code, so its verdict and confidence are not the LLM's.
  const byCode = fallback || Boolean(rule);
  const authorTag = byCode ? L.tagCode : L.tagLlm;
  const authorKind = byCode ? "code" : "llm";
  const changed = decision && decision.decision !== "accept" && proposal && decision.outcome !== proposal;
  const autoClosed = ticket.auto_closed === true && !decision;

  return (
    <>
      <dl className="facts">
        <Fact tag={authorTag} kind={authorKind} label={L.verdict}>
          {ticket.verdict ? <strong>{VERDICT[ticket.verdict] || asText(ticket.verdict)}</strong> : <NA />}
        </Fact>
        <Fact tag={authorTag} kind={authorKind} label={L.confidence}>
          {typeof ticket.confidence === "number" ? <span className="num">{Math.round(ticket.confidence * 100)} %</span> : <NA />}
        </Fact>
        <Fact tag={L.tagCode} kind="code" label={L.severity}>
          <Severity value={ticket.severity} />
        </Fact>
        <Fact tag={L.tagCode} kind="code" label={L.barProposal}>
          {proposal === "escalate" ? (
            <strong className="bad">{L.escalateYes(isBlank(escalation.to) ? L.na : asText(escalation.to))}</strong>
          ) : proposal === "close" ? (
            <strong>{L.escalateNo}</strong>
          ) : (
            <NA />
          )}
        </Fact>
        <Fact tag={L.tagPerson} kind="person" label={L.stagePerson}>
          {decision ? (
            <span className="decided-line">
              <strong className="ok">{L.barDecided(OUTCOME[decision.outcome] || asText(decision.outcome), asText(decision.analyst))}</strong>
              {changed && <span className="sub">{L.barChanged(OUTCOME[proposal], OUTCOME[decision.outcome] || asText(decision.outcome))}</span>}
            </span>
          ) : autoClosed ? (
            <strong title={L.autoClosedHelp}>{L.autoClosed}</strong>
          ) : (
            <strong className="waiting with-icon">
              <Icon name="pause" />
              {L.barWaiting}
            </strong>
          )}
        </Fact>
      </dl>
      <div className="bar-actions">
        {decision ? (
          <button type="button" className="btn btn-primary" onClick={onNext} disabled={next.busy}>
            {next.busy ? L.nextSearching : L.nextPending}
            <Icon name="arrowRight" />
          </button>
        ) : autoClosed ? null : (
          <button type="button" className="btn btn-primary" onClick={() => onGo("sec-decision")}>
            {L.barDecide}
          </button>
        )}
        <ModeTag mode={ticketRow.mode} />
        {rule && (
          <Chip kind="code" title={L.closedByRuleHelp}>
            {L.closedByRuleId(asText(rule.rule_id))}
          </Chip>
        )}
        {flags > 0 && !compact && (
          <button type="button" className="chip chip-warn chip-btn" onClick={() => onGo("injection-title")}>
            <Icon name="alert" />
            {L.barInjections(flags)}
          </button>
        )}
      </div>
      {next.none && <p className="muted bar-note">{L.nextNone}</p>}
      {fallback && <p className="inline-warn bar-note">{L.barFallback}</p>}
    </>
  );
}

export default function DecisionBar(props) {
  const { run, ticketRow, decision, events, running, fallback, finished, now, ruleSeverity, starting, onStart, onGo, onReviewByHand, onNext, next } = props;
  const ticket = ticketRow && !running ? obj(ticketRow.ticket) : null;
  const states = stageStates({ run, events, ticket, decided: Boolean(decision), fallback });
  const available = (id) => (id === "steps-title" ? Boolean(run) : Boolean(ticket));

  return (
    <section className="panel bar" aria-label={L.barLabel}>
      {!props.compact && <Progress states={states} onGo={onGo} available={available} />}
      <div className="bar-body">
        {!run && (
          <div className="bar-actions">
            <span>{L.barNoRun}</span>
            <button type="button" className="btn btn-primary" onClick={onStart} disabled={starting}>
              {starting ? L.starting : L.triage}
            </button>
          </div>
        )}
        {running && <Running run={run} now={now} ruleSeverity={ruleSeverity} record={props.sla} />}
        {run && run.status === "failed" && <Failed run={run} starting={starting} onStart={onStart} onReviewByHand={onReviewByHand} />}
        {ticket && run && run.status === "done" && (
          <Summary compact={props.compact} ticketRow={ticketRow} decision={decision} fallback={fallback} next={next} onGo={onGo} onNext={onNext} />
        )}
        <p className={`bar-status${props.compact ? " visually-hidden" : ""}`} role="status">
          {finished ? <span className="finished">{L.barFinished(formatSeconds(run && run.duration_seconds))}</span> : ""}
        </p>
      </div>
    </section>
  );
}
