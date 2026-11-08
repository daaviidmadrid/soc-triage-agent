import { useEffect, useRef } from "react";
import { Chip, Ids, Severity, asText, obj } from "../components.jsx";
import { EVENT_TYPE, L, TOOL } from "../labels.js";
import { useListMotion } from "../motion.js";
import { clock } from "./runState.js";

const CHECK_LABELS = { citations_valid: "Citas recuperadas", authorisation_valid: "Autorización comprobada", evidence_complete: "Evidencia necesaria completa", not_ot: "Fuera de OT", injection_review_clear: "Sin preocupación de inyección pendiente", deterministic_eligible: "Respaldo determinista para cierre automático" };

function Why({ ticket, onPolicy }) {
  const t = obj(ticket), escalation = obj(t.escalation), checks = obj(t.safety_checks);
  return <div className="trace-why"><p><strong>Resultado tras la política en código:</strong> {asText(t.verdict)} · <Severity value={t.severity} /> · {escalation.escalate === true ? "recomienda escalar" : escalation.escalate === false ? "recomienda cerrar" : "sin recomendación registrada"}.</p>
    <p className="hint">{t.analysis_origin === "model" ? "El modelo propone el análisis; el código valida citas, autorización, severidad y escalado." : t.closed_by_rule ? `Regla ${t.closed_by_rule.rule_id}: análisis determinista, sin consulta al modelo.` : "Procedencia del análisis sin registrar."} La disposición y la aprobación de contención se registran por separado.</p>
    <details className="technical-details"><summary>Por qué · comprobaciones registradas</summary><dl className="kv">{Object.entries(CHECK_LABELS).map(([key, label]) => <div key={key}><dt>{label}</dt><dd>{checks[key] === true ? "Validado" : checks[key] === false ? "No superado" : "Desconocido"}</dd></div>)}</dl></details>
    {onPolicy && <button type="button" className="link-btn" onClick={onPolicy}>Ver propuesta del modelo, cálculo y política</button>}
  </div>;
}

export default function Steps({ events, running, stream, live, targetSeq, active = true, onPolicy }) {
  const panel = useRef(null);
  useListMotion(panel, `${active}:${events.map(e => e.seq).join(",")}`);
  useEffect(() => {
    if (!active || targetSeq == null) return;
    const step = panel.current?.querySelector(`[data-seq="${targetSeq}"]`);
    step?.scrollIntoView({ block: "center", behavior: "instant" });
    step?.focus({ preventScroll: true });
  }, [targetSeq, active]);
  const last = events.at(-1);
  return <section className="activity-timeline" aria-labelledby="steps-title" ref={panel}>
    <div className="section-heading"><h2 id="steps-title">{L.activity}</h2><span className="muted num">{events.length} pasos</span>{running && <span className="running" role="status"><span className="pulse" />{L.stateRunning}…</span>}</div>
    {stream === "lost" && <p className="compact-notice" role="status">{L.streamLost}</p>}
    {events.length ? <ol className="trace-list">{events.map(e => <li key={e.seq} className={`trace-entry trace-${e.type}${targetSeq === e.seq ? " is-target" : ""}`} data-motion-key={e.seq} data-seq={e.seq} tabIndex={-1}>
      <div className="trace-meta"><span className="trace-number num">#{e.seq}</span><time className="num" dateTime={e.at}>{clock(e.at)} UTC</time></div>
      <div className="trace-content">
        <div className="trace-heading"><span className={`step-type type-${e.type}`}>{EVENT_TYPE[e.type] || asText(e.type)}</span>{e.tool && <strong>{TOOL[e.tool] || asText(e.tool)}</strong>}{e.truncated && <Chip kind="warn">{L.truncated}</Chip>}</div>
        {e.summary && <p className="prose">{asText(e.summary)}</p>}
        {typeof e.args?.result_count === "number" && <p className="hint num">{e.args.result_count} resultado(s) recuperado(s) · {Array.isArray(e.event_ids) ? e.event_ids.length : 0} IDs de evento disponibles</p>}
        {e.type === "ticket_ready" && e.ticket && <Why ticket={e.ticket} onPolicy={onPolicy} />}
        {e.truncated && <p className="hint">{L.truncatedHelp}</p>}
        {Array.isArray(e.event_ids) && e.event_ids.length > 0 && <div className="trace-ids"><span className="muted">{L.eventIds}:</span><Ids ids={e.event_ids} /></div>}
        {Object.keys(obj(e.args)).length > 0 && <details className="technical-details"><summary>{L.queryParameters}</summary><pre className="raw-data">{asText(e.args)}</pre></details>}
      </div>
    </li>)}</ol> : <p className="muted">{running ? L.loading : L.stepsEmpty}</p>}
    <p className="visually-hidden" aria-live="polite">{live && running && last ? L.stepLive(last.seq, EVENT_TYPE[last.type] || asText(last.type), TOOL[last.tool] || "") : ""}</p>
  </section>;
}
