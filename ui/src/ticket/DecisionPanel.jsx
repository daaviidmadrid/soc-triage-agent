// Where the person steps in: the close-or-escalate decision, its history, and the containment a person approves.
// Containment runs only from the approval screen in Containment.jsx, after every required person has approved.
import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { Chip, Clip, ErrorBox, List, None, arr, asText, formatTime, isBlank, obj } from "../components.jsx";
import Icon from "../icons.jsx";
import Containment from "./Containment.jsx";
import { DECISION, L, OUTCOME } from "../labels.js";

const ANALYST_KEY = "tarvia.analyst";

function rememberedName() {
  try {
    return window.localStorage.getItem(ANALYST_KEY) || "";
  } catch {
    return "";
  }
}

function rememberName(name) {
  try {
    window.localStorage.setItem(ANALYST_KEY, name);
  } catch {
    // storage can be unavailable; the name just isn't remembered
  }
}

function DecisionForm({ ticketRow, onSaved, onCancel }) {
  const escalation = obj(obj(ticketRow.ticket).escalation);
  const escalate = escalation.escalate;
  const proposal = escalate === true ? "escalate" : escalate === false ? "close" : null;
  const [analyst, setAnalyst] = useState(rememberedName);
  const [choice, setChoice] = useState(proposal ? "accept" : "escalate");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const options = proposal
    ? [
        ["accept", L.decisionAccept(OUTCOME[proposal], proposal === "escalate" && !isBlank(escalation.to) ? asText(escalation.to) : "")],
        proposal === "escalate" ? ["close", L.decisionClose] : ["escalate", L.decisionEscalate],
      ]
    : [
        ["close", L.decisionClose],
        ["escalate", L.decisionEscalate],
      ];

  async function submit(event) {
    event.preventDefault();
    setError(null);
    if (!analyst.trim()) return setError(L.needName);
    if (choice !== "accept" && !reason.trim()) return setError(L.needReason);
    setBusy(true);
    try {
      rememberName(analyst.trim());
      await api.decide(ticketRow.ticket_id, { analyst: analyst.trim(), decision: choice, reason: reason.trim(), run_id: ticketRow.run_id });
      setReason("");
      await onSaved();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="decision-form" onSubmit={submit} aria-labelledby="decide-title" noValidate>
      <h4 id="decide-title">{L.decideTitle}</h4>
      <fieldset className="choices">
        <legend className="visually-hidden">{L.decideTitle}</legend>
        {options.map(([value, label]) => (
          <label key={value} className="choice">
            <input type="radio" name="decision" value={value} checked={choice === value} onChange={() => setChoice(value)} />
            <span>{label}</span>
          </label>
        ))}
      </fieldset>
      <label className="control control-block">
        <span className="control-label">{L.analyst}</span>
        <input type="text" value={analyst} maxLength={100} onChange={(e) => setAnalyst(e.target.value)} autoComplete="name" required />
      </label>
      <label className="control control-block">
        <span className="control-label">
          {L.reason} <span className="muted">({choice === "accept" ? L.reasonOptional : L.reasonRequired})</span>
        </span>
        <textarea value={reason} maxLength={2000} rows={3} onChange={(e) => setReason(e.target.value)} required={choice !== "accept"} />
      </label>
      {error && <ErrorBox message={error} />}
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? L.saving : L.submitDecision}
        </button>
        {onCancel && (
          <button type="button" className="btn btn-ghost" onClick={onCancel}>
            {L.dismiss}
          </button>
        )}
      </div>
    </form>
  );
}

// The decision already saved on this version of the ticket. Replaces the form, so the same decision isn't saved twice.
function Saved({ ticketRow, current, justSaved, onChange, onNext, next }) {
  const box = useRef(null);
  const escalate = obj(obj(ticketRow.ticket).escalation).escalate;
  const proposal = escalate === true ? "escalate" : escalate === false ? "close" : null;
  const changed = current.decision !== "accept" && proposal && current.outcome !== proposal;
  // Right after saving, focus lands here: the form it replaces is gone.
  useEffect(() => {
    if (justSaved && box.current) box.current.focus({ preventScroll: true });
  }, [justSaved]);
  return (
    <div className="saved-decision" ref={box} tabIndex={-1} aria-labelledby="saved-title">
      <h4 id="saved-title" className="with-icon">
        <Icon name="check" />
        {L.savedSummary(OUTCOME[current.outcome] || asText(current.outcome), asText(current.analyst))}
      </h4>
      {changed && <p className="sub">{L.changedProposal(OUTCOME[proposal], OUTCOME[current.outcome] || asText(current.outcome))}</p>}
      <div className="form-actions">
        <button type="button" className="btn btn-primary" onClick={onNext} disabled={next.busy}>
          {next.busy ? L.nextSearching : L.nextPending}
          <Icon name="arrowRight" />
        </button>
        <button type="button" className="btn" onClick={onChange}>
          {L.changeDecision}
        </button>
      </div>
      {next.none && <p className="muted">{L.nextNone}</p>}
      <p className="form-status" role="status">
        {justSaved ? <span className="saved">{L.decisionSaved}</span> : ""}
      </p>
    </div>
  );
}

function History({ decisions, runId }) {
  // Rows already there on first render don't animate; a decision saved now fades in.
  const [armed, setArmed] = useState(false);
  useEffect(() => setArmed(true), []);
  if (!decisions.length) return <p className="muted">{L.noDecisions}</p>;
  return (
    <ul className={`list decisions${armed ? " is-armed" : ""}`}>
      {decisions.map((d) => (
        <li key={d.id} className={d.run_id !== runId ? "older" : undefined}>
          <strong>{asText(d.analyst)}</strong> {DECISION[d.decision] || asText(d.decision)} <Icon name="arrowRight" className="icon-inline" />{" "}
          <strong>{OUTCOME[d.outcome] || asText(d.outcome)}</strong>
          <div className="sub num">
            {formatTime(d.decided_at)} UTC
            {d.run_id !== runId && ` · ${L.olderVersion}`}
          </div>
          {!isBlank(d.reason) && (
            <div className="reason">
              <Clip value={d.reason} max={200} />
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

function ActionItem({ action, waiting }) {
  return (
    <li className="action">
      {waiting && (
        <Chip kind="person">
          <Icon name="pause" />
          {L.waitingApproval}
        </Chip>
      )}
      <div>
        <strong>
          <Clip value={action.action} max={120} />
        </strong>{" "}
        <Icon name="arrowRight" className="icon-inline" /> <code className="indicator">{isBlank(action.target) ? L.na : asText(action.target)}</code>{" "}
        {waiting ? <Chip kind="llm">{L.tagLlm}</Chip> : <span className="muted">({L.actionNoApproval})</span>}
      </div>
      {waiting && !isBlank(action.justification) && (
        <div className="sub">
          <Clip value={action.justification} max={200} />
        </div>
      )}
    </li>
  );
}

export default function DecisionPanel({ ticketRow, current, onNext, next, decisions, waiting, others, executed, onSaved }) {
  const [editing, setEditing] = useState(false);
  const [justSaved, setJustSaved] = useState(false);

  async function saved() {
    await onSaved();
    setEditing(false);
    setJustSaved(true);
  }

  return (
    <>
      {current && !editing ? (
        <Saved
          ticketRow={ticketRow}
          current={current}
          justSaved={justSaved}
          onChange={() => {
            setJustSaved(false);
            setEditing(true);
          }}
          onNext={onNext}
          next={next}
        />
      ) : (
        <DecisionForm key={ticketRow.run_id} ticketRow={ticketRow} onSaved={saved} onCancel={current ? () => setEditing(false) : null} />
      )}

      <h4>{L.decisionsHistory}</h4>
      <History decisions={decisions} runId={ticketRow.run_id} />

      <Containment ticketRow={ticketRow} />

      {others.length > 0 && (
        <>
          <h4>{L.otherSuggestions}</h4>
          <ul className="actions-list">
            {others.map((a, i) => (
              <ActionItem key={i} action={a} />
            ))}
          </ul>
        </>
      )}

    </>
  );
}
