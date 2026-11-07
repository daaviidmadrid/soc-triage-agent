// Level 4: containment that people approve and run. Plain code built each proposal from the LLM's suggestion:
// the action, the exact target, the business impact and who must approve. The LLM never approves or runs anything.
// Only these buttons, after every required person has approved, reach the mock API's /approvals and /containment.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Chip, ErrorBox, asText, formatTime } from "../components.jsx";
import Icon from "../icons.jsx";
import { ACTION_NAME, CONTAINMENT_STATUS, L } from "../labels.js";

const NAME_KEY = "tarvia.analyst";

function rememberedName() {
  try {
    return window.localStorage.getItem(NAME_KEY) || "";
  } catch {
    return "";
  }
}

function rememberName(name) {
  try {
    window.localStorage.setItem(NAME_KEY, name);
  } catch {
    // storage can be unavailable; the name just isn't remembered
  }
}

function RoleApproval({ proposal, role, onDone }) {
  const [name, setName] = useState(rememberedName);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const inputId = `approve-${proposal.proposal_id}-${role}`;

  async function submit(event) {
    event.preventDefault();
    setError(null);
    if (!name.trim()) return setError(L.needName);
    setBusy(true);
    try {
      rememberName(name.trim());
      onDone(await api.approveAction(proposal.proposal_id, { role, approver: name.trim() }));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="approve-row" onSubmit={submit}>
      <label htmlFor={inputId} className="approve-role">
        {role}
      </label>
      <input id={inputId} value={name} onChange={(e) => setName(e.target.value)} placeholder={L.approverName} maxLength={100} />
      <button type="submit" className="btn btn-sm" disabled={busy}>
        {busy ? L.saving : L.approveAs}
      </button>
      {error && <span className="form-error">{error}</span>}
    </form>
  );
}

function Execute({ proposal, onDone }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      onDone(await api.executeAction(proposal.proposal_id));
    } catch (e) {
      setError(e.message);
      onDone(null);
    } finally {
      setBusy(false);
      setConfirming(false);
    }
  }

  return (
    <div className="execute-row">
      {!confirming ? (
        <button type="button" className="btn btn-primary btn-sm" onClick={() => setConfirming(true)}>
          {L.execute}
        </button>
      ) : (
        <>
          <span>{L.executeConfirm(ACTION_NAME[proposal.action] || proposal.action, proposal.target)}</span>
          <button type="button" className="btn btn-primary btn-sm" onClick={run} disabled={busy}>
            {busy ? L.executing : L.executeYes}
          </button>
          <button type="button" className="btn btn-sm btn-ghost" onClick={() => setConfirming(false)} disabled={busy}>
            {L.cancel}
          </button>
        </>
      )}
      {error && <span className="form-error">{error}</span>}
    </div>
  );
}

function Reject({ proposal, onDone }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState(null);

  async function submit(event) {
    event.preventDefault();
    const name = rememberedName();
    if (!name) return setError(L.rejectNeedsName);
    try {
      onDone(await api.rejectAction(proposal.proposal_id, { approver: name, reason: reason.trim() }));
    } catch (e) {
      setError(e.message);
    }
  }

  if (!open) {
    return (
      <button type="button" className="link-btn" onClick={() => setOpen(true)}>
        {L.reject}
      </button>
    );
  }
  return (
    <form className="approve-row" onSubmit={submit}>
      <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder={L.rejectReason} maxLength={1000} aria-label={L.rejectReason} />
      <button type="submit" className="btn btn-sm">
        {L.reject}
      </button>
      {error && <span className="form-error">{error}</span>}
    </form>
  );
}

function ProposalCard({ proposal, onChange }) {
  const approved = new Map((proposal.approvals || []).map((a) => [a.role, a]));
  const open = proposal.status === "proposed" || proposal.status === "approved";
  return (
    <li className={`proposal proposal-${proposal.status}`}>
      <div className="proposal-head">
        <strong>{ACTION_NAME[proposal.action] || proposal.action}</strong>
        <Icon name="arrowRight" className="icon-inline" />
        <code className="indicator">{proposal.target}</code>
        <Chip kind={proposal.status === "executed" ? "real" : proposal.status === "approved" ? "person" : proposal.status === "proposed" ? "code" : "warn"}>
          {CONTAINMENT_STATUS[proposal.status] || proposal.status}
        </Chip>
      </div>
      <dl className="proposal-facts">
        <dt>{L.businessImpact}</dt>
        <dd>{proposal.business_impact}</dd>
        <dt>{L.requiredApprovers}</dt>
        <dd>{proposal.approvers.join(" + ")}</dd>
        {proposal.suggestion && (
          <>
            <dt>
              <Chip kind="llm">{L.tagLlm}</Chip> {L.fromSuggestion}
            </dt>
            <dd className="prose">{asText(proposal.suggestion)}</dd>
          </>
        )}
      </dl>
      {(proposal.warnings || []).map((w) => (
        <p key={w} className="proposal-warning">
          <Icon name="alert" className="icon-inline" /> {w}
        </p>
      ))}
      <ul className="approvals">
        {proposal.approvers.map((role) =>
          approved.has(role) ? (
            <li key={role} className="approval-done">
              <Icon name="check" className="icon-inline" /> {role}: <strong>{approved.get(role).approver}</strong>{" "}
              <span className="muted">{formatTime(approved.get(role).at)} UTC</span>
            </li>
          ) : open ? (
            <li key={role}>
              <RoleApproval proposal={proposal} role={role} onDone={onChange} />
            </li>
          ) : null,
        )}
      </ul>
      {proposal.status === "approved" && <Execute proposal={proposal} onDone={onChange} />}
      {open && <Reject proposal={proposal} onDone={onChange} />}
      {proposal.status === "executed" && proposal.result && (
        <p className="proposal-result">
          {L.executedAt(formatTime(proposal.result.timestamp))}: <code>{proposal.result.result}</code>
        </p>
      )}
      {(proposal.status === "refused" || proposal.status === "rejected") && proposal.error && <p className="form-error">{proposal.error}</p>}
      {proposal.status === "rejected" && proposal.decided_by && <p className="muted">{L.rejectedBy(proposal.decided_by)}</p>}
    </li>
  );
}

function Log({ entries, ticketId }) {
  const mine = entries.filter((e) => e.ticket_id === ticketId).reverse();
  return (
    <>
      <h4>{L.containmentLog}</h4>
      <p className="hint">{L.containmentLogHelp(entries.length)}</p>
      {mine.length === 0 ? (
        <p className="muted">{L.noneExecuted}</p>
      ) : (
        <div className="table-wrap">
          <table className="grid">
            <thead>
              <tr>
                <th scope="col">{L.colWhen}</th>
                <th scope="col">{L.colAction}</th>
                <th scope="col">{L.colTarget}</th>
                <th scope="col">{L.colResult}</th>
              </tr>
            </thead>
            <tbody>
              {mine.map((e, i) => (
                <tr key={`${e.timestamp}-${i}`}>
                  <td className="nowrap num">{formatTime(e.timestamp)}</td>
                  <td>{ACTION_NAME[e.action] || e.action}</td>
                  <td>
                    <code className="indicator">{e.target}</code>
                  </td>
                  <td>{e.result}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

// For a ticket, pass ticketRow. For an incident report (level 3), pass reportKey: its proposed steps go through
// the same approvals, checked again by the backend with the same policy rules.
export default function Containment({ ticketRow, reportKey, headingLevel = 3 }) {
  const [data, setData] = useState(null);
  const [log, setLog] = useState([]);
  const [error, setError] = useState(null);
  const ticketId = reportKey || (ticketRow && ticketRow.ticket_id);
  const runId = ticketRow ? ticketRow.run_id : null;
  const Heading = headingLevel === 3 ? "h3" : "h4";

  const load = useCallback(async () => {
    try {
      const fetchProposals = reportKey ? api.reportContainment(reportKey) : api.containment(ticketId, runId);
      const [proposals, logData] = await Promise.all([fetchProposals, api.containmentLog()]);
      setData(proposals);
      setLog(logData.entries || []);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  }, [reportKey, ticketId, runId]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <section className="reading-section containment" id="sec-proposal" aria-labelledby="containment-title">
      <Heading id="containment-title">{L.containmentTitle}</Heading>
      <p className="hint">{L.containmentHelp}</p>
      {error && <ErrorBox message={error} onRetry={load} />}
      {data && data.proposals.length === 0 && <p className="muted">{L.noProposals}</p>}
      {data && data.proposals.length > 0 && (
        <ul className="proposals">
          {data.proposals.map((p) => (
            <ProposalCard key={p.proposal_id} proposal={p} onChange={() => load()} />
          ))}
        </ul>
      )}
      {data && data.not_proposed.length > 0 && (
        <>
          <h4>{L.notProposedTitle}</h4>
          <ul className="list">
            {data.not_proposed.map((item, i) => (
              <li key={i}>
                <span className="prose">{asText(item.suggestion)}</span> <span className="muted">— {item.reason}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      <Log entries={log} ticketId={ticketId} />
    </section>
  );
}
