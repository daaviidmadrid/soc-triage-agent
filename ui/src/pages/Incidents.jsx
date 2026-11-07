// Level 2: alerts from the same attack, grouped by plain code. Every link says exactly what the alerts share,
// so a person can check each grouping. Noise is counted, never merged.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Chip, Clip, ErrorBox, NA, Notice, Severity, Skeleton, asText, formatTime } from "../components.jsx";
import Icon from "../icons.jsx";
import { L, OUTCOME, VERDICT } from "../labels.js";

function Members({ members, onOpen }) {
  return (
    <div className="table-wrap">
      <table className="grid">
        <thead>
          <tr>
            <th scope="col">{L.colAlert}</th>
            <th scope="col">{L.colRule}</th>
            <th scope="col">{L.colTime}</th>
            <th scope="col">{L.colVerdict}</th>
            <th scope="col">{L.colFinalSeverity}</th>
            <th scope="col">{L.ownProposal}</th>
          </tr>
        </thead>
        <tbody>
          {members.map((m) => (
            <tr key={m.alert_id}>
              <td>
                <button type="button" className="id id-jump" onClick={() => onOpen(m.alert_id)} aria-label={`${L.open} ${m.alert_id}`}>
                  {m.alert_id}
                </button>
              </td>
              <td className="rule">
                {m.rule_name ? <Clip value={m.rule_name} max={70} /> : <NA />}
                {m.rule_id && <div className="sub id-plain">{m.rule_id}</div>}
              </td>
              <td className="nowrap num">{formatTime(m.created_at) || <NA />}</td>
              <td>{VERDICT[m.verdict] || m.verdict || <NA />}</td>
              <td>
                <Severity value={m.severity} />
              </td>
              <td>{OUTCOME[m.escalate ? "escalate" : "close"]}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Links({ links }) {
  if (!links || links.length === 0) return <p className="muted">{L.none}</p>;
  return (
    <ul className="list links">
      {links.map((link) => (
        <li key={`${link.alert_id}-${link.linked_to}`}>
          <code className="id">{link.alert_id}</code> {L.linkWith} <code className="id">{link.linked_to}</code>:{" "}
          <span>{link.reasons.join("; ")}</span>
        </li>
      ))}
    </ul>
  );
}

function IncidentCard({ incident, onOpen }) {
  const t = incident.ticket;
  const esc = t.escalation || {};
  const headId = `inc-${incident.incident_id}`;
  return (
    <section className="panel incident" aria-labelledby={headId}>
      <div className="incident-head">
        <h2 id={headId}>{t.title}</h2>
        <code className="id">{incident.incident_id}</code>
      </div>
      <div className="incident-facts">
        <Severity value={t.severity} />
        <span>{VERDICT[t.verdict] || t.verdict}</span>
        <span className={`state ${esc.escalate ? "state-pending" : "state-none"}`}>
          {esc.escalate ? `${L.incidentEscalate} ${esc.to}` : L.incidentClose}
        </span>
        {incident.chain && <Chip kind="warn">{L.chainChip}</Chip>}
        <span className="muted">{L.incidentAlerts(incident.members.length)}</span>
      </div>
      <p className="incident-summary prose">{asText(t.summary)}</p>
      {esc.reason && (
        <p className="hint prose">
          {L.escalationReason}: {asText(esc.reason)}
        </p>
      )}
      <h3>{L.membersTitle}</h3>
      <Members members={incident.members} onOpen={onOpen} />
      <h3>{L.linksTitle}</h3>
      <Links links={t.group_links} />
    </section>
  );
}

function Noise({ rows }) {
  if (!rows || rows.length === 0) return null;
  return (
    <section className="panel" aria-labelledby="noise-title">
      <h2 id="noise-title">{L.noiseTitle}</h2>
      <p className="hint">{L.noiseIntro}</p>
      <div className="table-wrap">
        <table className="grid">
          <thead>
            <tr>
              <th scope="col">{L.colRule}</th>
              <th scope="col">{L.colVerdict}</th>
              <th scope="col">{L.colCount}</th>
              <th scope="col">{L.colSources}</th>
              <th scope="col">{L.colExamples}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.rule_id}-${r.verdict}`}>
                <td className="rule">
                  {r.rule_name ? <Clip value={r.rule_name} max={70} /> : <NA />}
                  <div className="sub id-plain">{r.rule_id}</div>
                </td>
                <td>{VERDICT[r.verdict] || r.verdict}</td>
                <td className="num">{r.count}</td>
                <td className="num">{r.sources}</td>
                <td>
                  {r.examples.map((id) => (
                    <code key={id} className="id">
                      {id}
                    </code>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function Incidents({ onOpen }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const result = await api.incidents();
      setData(result);
      setError(null);
      return result;
    } catch (e) {
      setError(e.message);
      return null;
    }
  }, []);

  const build = useCallback(async () => {
    setBusy(true);
    try {
      await api.buildIncidents();
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }, [load]);

  // The first visit groups straight away if there are triaged alerts and nothing has been grouped yet.
  useEffect(() => {
    load().then((result) => {
      if (result && !result.built_at && result.triaged_now > 0) build();
    });
  }, [load, build]);

  if (error && !data) return <ErrorBox message={error} onRetry={load} />;
  if (!data) return <Skeleton rows={6} cols={4} label={L.loading} />;

  return (
    <div className="incidents">
      <header className="page-head">
        <div className="page-title">
          <h1>{L.incidentsTitle}</h1>
          <span className="muted num">{L.incidentsCount(data.incidents.length, Object.keys(data.memberships || {}).length)}</span>
        </div>
        <div className="page-actions">
          <button type="button" className="btn btn-primary" onClick={build} disabled={busy}>
            <Icon name="incidents" />
            {busy ? L.building : L.buildIncidents}
          </button>
        </div>
      </header>
      {error && <ErrorBox message={error} onRetry={load} />}
      <Notice>{L.incidentsIntro}</Notice>
      {data.built_at && <p className="hint">{L.builtAt(formatTime(data.built_at), data.alerts)}</p>}
      {data.stale && data.built_at && (
        <Notice kind="warn" role="status">
          {L.incidentsStale}
        </Notice>
      )}
      {data.incidents.length === 0 ? (
        <Notice>{data.triaged_now > 0 ? L.incidentsNone : L.incidentsNothingTriaged}</Notice>
      ) : (
        data.incidents.map((incident) => <IncidentCard key={incident.incident_id} incident={incident} onOpen={onOpen} />)
      )}
      <Noise rows={data.noise} />
    </div>
  );
}
