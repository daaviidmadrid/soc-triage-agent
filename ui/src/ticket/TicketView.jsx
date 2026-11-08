// The parts of a ticket that the triage workspace and the incident report both show.
// How each is shown is fixed per field. Nothing the ticket's text says changes it.
import { Chip, Clip, Field, List, NA, None, arr, asText, isBlank, obj } from "../components.jsx";
import Icon from "../icons.jsx";
import { L } from "../labels.js";

// An event ID the ticket cites. If a step of the run returned it, it is a button that jumps to that step.
// If no step returned it (once the whole trace has loaded), it carries a visible warning.
function EventRef({ id, trace }) {
  const text = asText(id);
  if (trace.own?.has(text)) return <code className="id">{text}</code>;
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

function InjectionFlags({ flags, trace, continuous = false }) {
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
            {!isBlank(f.event_id) && <EventRef id={f.event_id} trace={trace} />} {continuous ? <span className="prose">{asText(f.description)}</span> : <Clip value={f.description} max={300} />}
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
function EvidenceList({ evidence, trace, continuous = false }) {
  if (evidence.length === 0) return <None />;
  return (
    <ul className="rows-list">
      {evidence.map(obj).map((ev, i) => (
        <li key={i}>
          <div className="rows-head">
            <span className="muted">
              {L.evidenceSource}: {trace.own?.has(asText(ev.event_id)) ? L.alertTitle : isBlank(ev.source) ? <NA /> : asText(ev.source)}
            </span>
            {isBlank(ev.event_id) ? <span className="muted">—</span> : <EventRef id={ev.event_id} trace={trace} />}
          </div>
          <div className="rows-body">
            <span className="visually-hidden">{L.evidenceFinding}: </span>
            {continuous ? <p className="prose">{asText(ev.finding) || L.na}</p> : <Clip value={ev.finding} max={200} />}
          </div>
        </li>
      ))}
    </ul>
  );
}

function EnrichmentList({ enrichment, continuous = false }) {
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
              {continuous ? <p className="prose">{asText(en.result) || L.na}</p> : <Clip value={en.result} max={160} />}
            </div>
          </li>
        ))}
      </ul>
      <p className="hint">{L.indicatorNote}</p>
    </>
  );
}

// A ticket a fixed rule closed: which rule, every condition that held, and the events it relied on.
function RuleClosure({ rule, trace, continuous = false }) {
  return (
    <>
      <Field label={L.ruleName}>
        <Chip kind="code">{L.closedByRuleId(asText(rule.rule_id))}</Chip> {continuous ? asText(rule.name) : <Clip value={rule.name} max={120} />}{" "}
        {!isBlank(rule.detection_rule) && <code className="id">{asText(rule.detection_rule)}</code>}
      </Field>
      <Field label={L.ruleConditions}>
        {continuous ? <ul className="list">{arr(rule.conditions).map((c, i) => <li key={i} className="prose">{asText(c)}</li>)}</ul> : <List items={arr(rule.conditions)} />}
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

export { Affected, EvidenceList, EnrichmentList, InjectionFlags, RuleClosure };
