// What the system proposes, split by who decided what: the LLM, plain code, or a person.
// The split is fixed per field. Nothing the ticket's text says changes how it is shown.
import { Chip, Clip, Field, Ids, List, ModeTag, NA, None, SlaCell, arr, asText, formatSeconds, isBlank, obj } from "../components.jsx";
import Icon from "../icons.jsx";
import { L, OUTCOME, VERDICT } from "../labels.js";
import DecisionPanel from "./DecisionPanel.jsx";
import SeverityBreakdown from "./SeverityBreakdown.jsx";

const DECISION_ACTIONS = new Set(["close", "escalate"]);

function splitActions(ticket) {
  const actions = arr(ticket.recommended_actions).map(obj);
  const decision = actions.find((a) => DECISION_ACTIONS.has(a.action) && !a.requires_approval);
  return {
    decision,
    waiting: actions.filter((a) => a.requires_approval === true),
    others: actions.filter((a) => a !== decision && a.requires_approval !== true),
  };
}

// An event ID the ticket cites. If a step of the run returned it, it is a button that jumps to that step.
// If no step returned it (once the whole trace has loaded), it carries a visible warning.
function EventRef({ id, trace }) {
  const text = asText(id);
  const seq = trace.retrieved.get(text);
  if (seq !== undefined) {
    return (
      <button type="button" className="id id-jump" onClick={() => trace.onJump(seq)} aria-label={L.jumpToStep(text, seq)}>
        {text}
        <span className="id-step num" aria-hidden="true">
          #{seq}
        </span>
      </button>
    );
  }
  return (
    <>
      <code className="id">{text}</code>
      {trace.complete && (
        <Chip kind="warn" title={L.notRetrievedHelp}>
          <Icon name="alert" />
          {L.notRetrieved}
        </Chip>
      )}
    </>
  );
}

function Header({ ticketRow, ticket, example }) {
  const alertIds = arr(ticket.alert_ids);
  const authorised = obj(ticket.authorised_by);
  return (
    <header className="ticket-head">
      <div className="ticket-head-row">
        <h2 id="ticket-title">{L.decisionTitle}</h2>
        <ModeTag mode={ticketRow.mode} />
      </div>
      {example && <p className="example-note">{L.exampleTicketNote}</p>}
      <p className="ticket-title">
        <span className="visually-hidden">{L.titleField}: </span>
        <Clip value={ticket.title} max={200} />
      </p>
      <dl className="kv kv-grid">
        <Field label={L.ticketId}>
          <code className="id">{asText(ticketRow.ticket_id)}</code>
        </Field>
        <Field label={L.alertIds}>
          {alertIds.length ? <Ids ids={alertIds} /> : <NA />}
          {alertIds.length > 1 && <div className="sub">{L.grouped(alertIds.length)}</div>}
        </Field>
        {!isBlank(ticket.authorised_by) && (
          <Field label={L.authorisedBy}>
            {isBlank(authorised.type) ? <NA /> : asText(authorised.type)}{" "}
            <code className="id">{isBlank(authorised.id) ? L.na : asText(authorised.id)}</code>
          </Field>
        )}
        {!isBlank(ticket.merged_into) && (
          <Field label={L.mergedInto}>
            <code className="id">{asText(ticket.merged_into)}</code>
          </Field>
        )}
      </dl>
    </header>
  );
}

function InjectionFlags({ flags, trace }) {
  if (flags.length === 0) return null;
  return (
    <section className="injection" aria-labelledby="injection-title" role="note">
      <h3 id="injection-title" className="with-icon" tabIndex={-1}>
        <Icon name="alert" />
        {L.injection}
      </h3>
      <p className="hint">{L.injectionHelp}</p>
      <ul className="list">
        {flags.map((f, i) => (
          <li key={i}>
            {!isBlank(f.event_id) && <EventRef id={f.event_id} trace={trace} />} <Clip value={f.description} max={300} />
          </li>
        ))}
      </ul>
    </section>
  );
}

function Affected({ affected }) {
  const groups = [
    [L.affectedUsers, affected.users],
    [L.affectedHosts, affected.hosts],
    [L.affectedServices, affected.business_services],
    [L.affectedCustomers, affected.customers],
  ];
  // Only the groups with entries; one "ninguno" when every group is empty.
  const filled = groups.filter(([, list]) => arr(list).length > 0);
  if (filled.length === 0) return <None />;
  return filled.map(([label, list]) => (
    <div key={label} className="affected-row">
      <span className="muted">{label}:</span>{" "}
      {arr(list).map((x, i) => (
        <code key={i} className="id">
          {asText(x)}
        </code>
      ))}
    </div>
  ));
}

// Evidence as stacked rows: source and event on one line, the finding below at the column's full width.
// (A three-column table squeezed the finding into a sliver in the narrow LLM column.)
function EvidenceList({ evidence, trace }) {
  if (evidence.length === 0) return <None />;
  return (
    <ul className="rows-list">
      {evidence.map(obj).map((ev, i) => (
        <li key={i}>
          <div className="rows-head">
            <span className="muted">
              {L.evidenceSource}: {isBlank(ev.source) ? <NA /> : asText(ev.source)}
            </span>
            {isBlank(ev.event_id) ? <span className="muted">—</span> : <EventRef id={ev.event_id} trace={trace} />}
          </div>
          <div className="rows-body">
            <span className="visually-hidden">{L.evidenceFinding}: </span>
            <Clip value={ev.finding} max={200} />
          </div>
        </li>
      ))}
    </ul>
  );
}

function EnrichmentList({ enrichment }) {
  if (enrichment.length === 0) return <None />;
  return (
    <>
      <ul className="rows-list">
        {enrichment.map(obj).map((en, i) => (
          <li key={i}>
            <div className="rows-head">
              <code className="indicator">{isBlank(en.indicator) ? L.na : asText(en.indicator)}</code>
              <span className="muted">
                {L.enrichType}: {isBlank(en.type) ? <NA /> : asText(en.type)} · {L.enrichSource}: {isBlank(en.source) ? <NA /> : asText(en.source)}
              </span>
            </div>
            <div className="rows-body">
              <span className="visually-hidden">{L.enrichResult}: </span>
              <Clip value={en.result} max={160} />
            </div>
          </li>
        ))}
      </ul>
      <p className="hint">{L.indicatorNote}</p>
    </>
  );
}

function RoleHeading({ kind, tag, title, help }) {
  return (
    <>
      <h3 className="role-title">
        <Chip kind={kind}>{tag}</Chip> {title}
      </h3>
      <p className="hint">{help}</p>
    </>
  );
}

// A ticket a fixed rule closed: which rule, every condition that held, and the events it relied on.
function RuleClosure({ rule, trace }) {
  return (
    <>
      <Field label={L.ruleName}>
        <Chip kind="code">{L.closedByRuleId(asText(rule.rule_id))}</Chip> <Clip value={rule.name} max={120} />{" "}
        {!isBlank(rule.detection_rule) && <code className="id">{asText(rule.detection_rule)}</code>}
      </Field>
      <Field label={L.ruleConditions}>
        <List items={arr(rule.conditions)} />
      </Field>
      <Field label={L.ruleEvents}>
        {arr(rule.event_ids).length ? (
          <span className="ids">
            {arr(rule.event_ids).map((id, i) => (
              <EventRef key={i} id={id} trace={trace} />
            ))}
          </span>
        ) : (
          <None />
        )}
      </Field>
    </>
  );
}

function LlmColumn({ ticket, fallback, trace }) {
  const rule = isBlank(ticket.closed_by_rule) ? null : obj(ticket.closed_by_rule);
  return (
    <div className="role role-llm">
      {/* A fallback ticket, or one a fixed rule closed, was filled in by code: its heading must not credit the LLM */}
      {rule ? (
        <RoleHeading kind="code" tag={L.tagCode} title={L.ruleTitle} help={L.ruleHelp} />
      ) : fallback ? (
        <RoleHeading kind="code" tag={L.tagCode} title={L.fallbackTitle} help={L.fallbackHelp} />
      ) : (
        <RoleHeading kind="llm" tag={L.tagLlm} title={L.byLlm} help={L.byLlmHelp} />
      )}
      <dl className="kv">
        {rule && <RuleClosure rule={rule} trace={trace} />}
        <Field label={L.verdict}>{ticket.verdict ? <strong>{VERDICT[ticket.verdict] || asText(ticket.verdict)}</strong> : <NA />}</Field>
        <Field label={L.confidence}>{typeof ticket.confidence === "number" ? <span className="num">{Math.round(ticket.confidence * 100)} %</span> : <NA />}</Field>
        <Field label={L.summary}>
          <Clip value={ticket.summary} max={400} />
        </Field>
        <Field label={L.affected}>
          <Affected affected={obj(ticket.affected)} />
        </Field>
        <Field label={L.evidence} id="sec-evidence">
          <EvidenceList evidence={arr(ticket.evidence)} trace={trace} />
        </Field>
        <Field label={L.enrichment}>
          <EnrichmentList enrichment={arr(ticket.enrichment)} />
        </Field>
        <Field label={L.mitre}>{arr(ticket.mitre).length ? <Ids ids={ticket.mitre} /> : <None />}</Field>
        <Field label={L.openQuestions}>
          <List items={arr(ticket.open_questions)} />
        </Field>
      </dl>
    </div>
  );
}

function CodeColumn({ ticket, decision, run }) {
  const escalation = obj(ticket.escalation);
  return (
    <div className="role role-code">
      <RoleHeading kind="code" tag={L.tagCode} title={L.byCode} help={L.byCodeHelp} />
      <dl className="kv">
        <SeverityBreakdown ticket={ticket} />
        <Field label={L.escalation}>
          {escalation.escalate === true ? (
            <strong className="bad">{L.escalateYes(isBlank(escalation.to) ? L.na : asText(escalation.to))}</strong>
          ) : escalation.escalate === false ? (
            <strong>{L.escalateNo}</strong>
          ) : (
            <NA />
          )}
          {!isBlank(escalation.reason) && (
            <div className="sub">
              {L.escalationReason}: <Clip value={escalation.reason} max={240} />
            </div>
          )}
        </Field>
        <Field label={L.proposedDecision} id="sec-proposal">
          {decision ? (
            <>
              <strong>{OUTCOME[decision.action]}</strong> <Icon name="arrowRight" className="icon-inline" /> {asText(decision.target)}
            </>
          ) : (
            <NA />
          )}
        </Field>
        <Field label={L.triageSeconds}>{formatSeconds(ticket.triage_seconds) || <NA />}</Field>
        <Field label={L.runDuration}>
          <SlaCell severity={ticket.severity} seconds={run ? run.duration_seconds : null} running={false} />
        </Field>
      </dl>
    </div>
  );
}

export default function TicketView({ ticketRow, run, decision: personDecision, decisions, fallback, retrieved, traceComplete, onJumpToStep, onSaved, onNext, next }) {
  const ticket = obj(ticketRow.ticket);
  const example = ticketRow.mode === "example";
  const { decision, waiting, others } = splitActions(ticket);
  const trace = { retrieved, complete: traceComplete, onJump: onJumpToStep };

  return (
    <section className={`panel ticket ${example ? "is-example" : "is-real"}`} aria-labelledby="ticket-title">
      <Header ticketRow={ticketRow} ticket={ticket} example={example} />
      <InjectionFlags flags={arr(ticket.injection_flags).map(obj)} trace={trace} />
      <div className="roles">
        <LlmColumn ticket={ticket} fallback={fallback} trace={trace} />
        <CodeColumn ticket={ticket} decision={decision} run={run} />
        <div className="role role-person" id="sec-decision" tabIndex={-1}>
          <RoleHeading kind="person" tag={L.tagPerson} title={personDecision ? L.byPersonDone : L.byPerson} help={L.byPersonHelp} />
          <DecisionPanel
            ticketRow={ticketRow}
            current={personDecision}
            onNext={onNext}
            next={next}
            decisions={decisions}
            waiting={waiting}
            others={others}
            executed={ticket.executed_actions}
            onSaved={onSaved}
          />
        </div>
      </div>
    </section>
  );
}
