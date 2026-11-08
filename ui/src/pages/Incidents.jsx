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

function Links({ links, onOpen }) {
  if (!links || links.length === 0) return <p className="muted">{L.none}</p>;
  return (
    <ul className="list links">
      {links.map((link) => (
        <li key={`${link.alert_id}-${link.linked_to}`}>
          <button type="button" className="id id-jump" onClick={() => onOpen(link.alert_id)}>{link.alert_id}</button> {L.linkWith} <button type="button" className="id id-jump" onClick={() => onOpen(link.linked_to)}>{link.linked_to}</button>:{" "}
          <span>{link.strength === "lead" ? "Pista por cuenta o equipo · " : link.strength === "specific" ? "Identificador específico compartido · " : ""}{link.reasons.join("; ")}</span>
        </li>
      ))}
    </ul>
  );
}

function IncidentCard({ incident, report, onOpen, onOpenReport }) {
  const t = incident.ticket;
  const esc = t.escalation || {};
  const headId = `inc-${incident.incident_id}`;
  return (
    <section className="panel incident" aria-labelledby={headId}>
      <div className="incident-head">
        <h2 id={headId}>{t.title}</h2>
        <span className="incident-actions">
          <code className="id">{incident.incident_id}</code>
          {(esc.escalate || report) && (
            <button type="button" className={`btn btn-sm${report ? "" : " btn-primary"}`} onClick={() => onOpenReport(incident.incident_id)}>
              {report ? L.reportOpen : L.reportInvestigate}
            </button>
          )}
        </span>
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
      <figure className="relation-map"><figcaption>Relaciones observadas entre alertas. Compartir un identificador no demuestra un ataque.</figcaption>{(t.group_links || []).slice(0, 12).map(link => <div className="relation-pair" key={`${link.alert_id}:${link.linked_to}`}><button className="btn btn-sm id" type="button" onClick={() => onOpen(link.alert_id)}>{link.alert_id}</button><div className="relation-edge"><svg viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true"><path d="M0 4H100" stroke="currentColor" strokeWidth="1" strokeDasharray={link.strength === "lead" ? "4 3" : undefined} /></svg><span>{link.strength === "lead" ? "Pista · " : ""}{link.reasons.join("; ")}</span></div><button className="btn btn-sm id" type="button" onClick={() => onOpen(link.linked_to)}>{link.linked_to}</button></div>)}{(t.group_links || []).length > 12 && <p className="hint">Diagrama limitado a 12 relaciones; lista completa a continuación.</p>}</figure>
      <details className="technical-details"><summary>Lista accesible de todas las relaciones</summary><Links links={t.group_links} onOpen={onOpen} /></details>
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

export default function Incidents({ onOpen, onOpenReport }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [all, setAll] = useState(false), [query, setQuery] = useState(""), [limit, setLimit] = useState(6);

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

  useEffect(() => {
    load();
    const timer = setInterval(load, 2000);
    return () => clearInterval(timer);
  }, [load]);

  if (error && !data) return <ErrorBox message={error} onRetry={load} />;
  if (!data) return <Skeleton rows={6} cols={4} label={L.loading} />;
  const filtered = data.incidents.filter(i => (all || i.ticket.escalation?.escalate) && `${i.incident_id} ${i.ticket.title} ${i.ticket.alert_ids.join(" ")}`.toLowerCase().includes(query.toLowerCase()));

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
      <div className="attention-filters"><label className="control">Filtrar incidentes<input type="search" value={query} onChange={e => { setQuery(e.target.value); setLimit(6); }} /></label><label className="choice"><input type="checkbox" checked={all} onChange={e => { setAll(e.target.checked); setLimit(6); }} />Incluir casos sin propuesta de escalado</label><span className="muted">{filtered.length} casos · hasta {limit} visibles</span></div>
      {data.built_at && <p className="hint">{L.builtAt(formatTime(data.built_at), data.alerts)}</p>}
      {data.stale && data.built_at && (
        <Notice kind="warn" role="status">
          {L.incidentsStale}
        </Notice>
      )}
      {data.incidents.length === 0 ? (
        <Notice>{data.triaged_now > 0 ? L.incidentsNone : L.incidentsNothingTriaged}</Notice>
      ) : (
        filtered.slice(0, limit).map((incident) => (
          <IncidentCard
            key={incident.incident_id}
            incident={incident}
            report={(data.reports || {})[incident.incident_id]}
            onOpen={onOpen}
            onOpenReport={onOpenReport}
          />
        ))
      )}
      {data.incidents.length > 0 && filtered.length === 0 && <Notice>No hay incidentes que coincidan con esta vista.{!all && <button className="link-btn" type="button" onClick={() => setAll(true)}>Incluir casos sin escalado</button>}</Notice>}
      {filtered.length > limit && <button type="button" className="btn" onClick={() => setLimit(n => n + 6)}>Mostrar más incidentes</button>}
      <Noise rows={data.noise} />
    </div>
  );
}
