// How plain code reached the final severity, from the ticket's severity_inputs. It only displays them: the policy is computed elsewhere.
import { Clip, Field, List, NA, None, Severity, arr, asText, isBlank, obj } from "../components.jsx";
import { L } from "../labels.js";

export default function SeverityBreakdown({ ticket, continuous = false }) {
  const inputs = obj(ticket.severity_inputs);
  return (
    <>
      <Field label={L.severity}>
        <Severity value={ticket.severity} />
      </Field>
      <div className="field">
        <dt>{continuous ? L.severityFactors : L.severityBreakdown}</dt>
        <dd>
          {Object.keys(inputs).length === 0 ? (
            <NA />
          ) : (
            <dl className="breakdown">
              <Field label={L.sevRule}>
                <Severity value={inputs.rule_severity} />
              </Field>
              <Field label={L.sevCriticality}>
                {isBlank(inputs.criticality) ? <NA /> : asText(inputs.criticality)}
                {!isBlank(inputs.criticality_source) && (
                  <div className="sub">
                    {L.sevSource}: {continuous ? asText(inputs.criticality_source) : <Clip value={inputs.criticality_source} max={80} />}
                  </div>
                )}
              </Field>
              <Field label={L.sevAdjustments}>
                <List
                  items={arr(inputs.adjustments)}
                  render={(a) => (
                    <>
                      <strong className="num">{obj(a).delta > 0 ? `+${obj(a).delta}` : asText(obj(a).delta)}</strong>{" "}
                      {continuous ? asText(obj(a).reason) : <Clip value={obj(a).reason} max={160} />}
                    </>
                  )}
                />
              </Field>
              <Field label={L.sevFloor}>{isBlank(inputs.runbook_floor) ? <None /> : <Severity value={inputs.runbook_floor} />}</Field>
              <Field label={L.sevAuthorised}>{inputs.authorised === true ? L.yes : inputs.authorised === false ? L.no : <NA />}</Field>
            </dl>
          )}
        </dd>
      </div>
      <Field label={L.sevRationale}>
        {continuous ? <p className="prose">{asText(ticket.severity_rationale) || L.na}</p> : <Clip value={ticket.severity_rationale} max={300} />}
      </Field>
    </>
  );
}
