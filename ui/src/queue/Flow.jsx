import { useState } from "react";
import { api } from "../api.js";
import { ErrorBox, Severity } from "../components.jsx";
import { SEVERITY, TOOL } from "../labels.js";
import { useRunEvents } from "../useRunEvents.js";
import { effective, flowStage } from "./model.js";

const STAGES = [
  ["intake", "Entrada", "Importadas o pendientes de encolar"],
  ["triage", "Triaje", "Reglas fijas → LLM, si aplica → política en código"],
  ["correlation", "Correlación", "Relaciones observadas entre alertas"],
  ["investigation", "Investigación", "Informe cuando la política propone escalar"],
  ["review", "Revisión humana", "Decidir con las evidencias preparadas"],
  ["finished", "Finalizados", "Disposición humana o cierre automático auditado"],
];

export default function Flow({ data, onOpen, onRefresh, connectionError }) {
  const [error, setError] = useState(null), [busy, setBusy] = useState(false);
  const ops = data.automation;
  const current = data.alerts.find(a => a.run?.status === "running");
  const activeReport = ops?.jobs.find(j => j.kind === "report" && j.status === "running");
  // At most one live run here; the persisted queue reconciles every stage after reconnect/end.
  const activeRunId = current?.run?.run_id || activeReport?.run_id;
  const { events, stream } = useRunEvents(activeRunId, onRefresh);
  const streamed = events.at(-1)?.run_id === activeRunId ? events.at(-1) : null;
  const last = current?.processing && (!streamed || current.processing.seq > streamed.seq) ? current.processing : streamed;
  async function control(action) {
    setBusy(true); setError(null);
    try { await api.controlAutomation(action); await onRefresh(); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }
  async function start() {
    setBusy(true); setError(null);
    try { await api.startFlow(); await onRefresh(); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }
  if (!ops) return null;
  const flow = ops.flow || {};
  const failedJobs = flow.retryable > 0;
  const retryPreviousStop = !flow.active && ops.reason === "Límite de fallos consecutivos alcanzado.";
  const canStart = flow.ready > 0 || !flow.active || Boolean(ops.reason) || failedJobs;
  const hasWork = flow.ready > 0 || flow.pending > 0 || failedJobs;
  const status = connectionError ? "Reconectando · último estado confirmado" : retryPreviousStop ? "Listo para reintentar el flujo" : ops.reason ? "Flujo detenido" : ops.paused && flow.active ? "Flujo pausado" : flow.state === "ready" ? "Alertas listas para iniciar" : flow.state === "finished" ? (failedJobs ? "Flujo terminado · hay alertas que reintentar" : "Procesamiento completado · revisa las conclusiones") : "Procesando la cola";
  return <section className="operation-flow" aria-labelledby="flow-title">
    <div className="section-heading flow-heading"><h2 id="flow-title">Flujo en directo</h2><span className="muted" role="status">{status}</span>
      {canStart && <button type="button" className="btn btn-primary start-flow" disabled={busy || !hasWork || !ops.auto_triage} onClick={start}>{busy ? "Comprobando el inicio…" : "Iniciar flujo"}{flow.ready > 0 ? ` (${flow.ready})` : ""}</button>}
      {flow.active && (flow.pending > 0 || flow.running > 0 || ops.paused) && <button type="button" className="btn btn-sm" disabled={busy} onClick={() => control(ops.paused ? "resume" : "pause")}>{ops.paused ? "Reanudar" : "Pausar"}</button>}</div>
    {error && <ErrorBox message={error} />}
    {ops.reason && <p className="compact-notice" role="status">{retryPreviousStop ? "El intento anterior se detuvo tras varios fallos. Pulsa Iniciar flujo para comprobar la conexión y reintentar la cola." : `${ops.reason} Los trabajos pendientes se conservan.`}</p>}
    {ops.last_error && <p className="compact-notice">{ops.last_error.tool === "build_context" ? "Fallo anterior: no se pudo consultar la API simulada para reunir el contexto. Con los servicios arrancados, pulsa Iniciar flujo para reintentar. Para arrancarlos juntos usa python scripts/dev.py." : `Último fallo: ${ops.last_error.message || "consulta no completada"}`}</p>}
    {flow.state === "ready" && !ops.reason && <p className="hint">Primero sube las alertas y revisa la cola. Al iniciar se procesan por su orden de prioridad; los demás niveles continúan automáticamente.</p>}
    <ol className="flow-stages" aria-label="Etapas observadas del procesamiento">
      {STAGES.map(([key, title, help]) => {
        const items = data.alerts.filter(a => flowStage(a) === key);
        return <li key={key} className={`flow-stage flow-${key}`}><div className="flow-stage-head"><h3>{title}</h3><strong className="num">{items.length}</strong></div><p className="hint">{help}</p>
          <div className="flow-points">{items.slice(0, 8).map(a => <button key={a.alert_id} type="button" className={`flow-point sev-${effective(a).severity || "unknown"}`} onClick={() => onOpen(a.alert_id)} title={`${a.alert_id} · ${SEVERITY[effective(a).severity] || "Severidad desconocida"}`} aria-label={`Abrir ${a.alert_id}, ${SEVERITY[effective(a).severity] || "severidad desconocida"}`}><span aria-hidden="true" />{a.alert_id}</button>)}</div>
          {items.length > 8 && <p className="hint">Muestra de 8 · {items.length - 8} casos más en la cola</p>}
        </li>;
      })}
    </ol>
    <div className="flow-observation" aria-live="polite">{current ? <><button type="button" className="link-btn" onClick={() => onOpen(current.alert_id)}>{current.alert_id}</button><Severity value={effective(current).severity} /><span>{last?.tool ? `Última comprobación: ${TOOL[last.tool] || last.tool}. ${last.summary || ""}` : "Procesando"}</span>{stream === "lost" && <span>Reconectando; se conserva el último estado confirmado.</span>}</> : activeReport ? <span>Investigando {activeReport.subject}. {last?.tool ? `Última consulta: ${TOOL[last.tool] || last.tool}. ${last.summary || ""}` : "Procesando"}</span> : <span>Sin ejecuciones activas. El estado se reconcilia con la cola persistida.</span>}</div>
    <div className="flow-branches"><p><strong>Bifurcaciones.</strong> Una regla puede evitar el LLM. Un caso puede pasar a revisión sin informe. Los cierres automáticos elegibles finalizan sin una revisión humana previa.</p><p><strong>Contención · solo personas.</strong> Propuestas: {ops.containment?.proposed || 0} → aprobadas: {ops.containment?.approved || 0} → ejecutadas: {ops.containment?.executed || 0}. Las aprobaciones y la ejecución se registran por separado de la resolución.</p></div>
    <details className="technical-details"><summary>Presupuesto y registro operativo · {ops.budget.used}/{ops.budget.limit} intentos</summary><p className="hint">Compartido entre triaje e informes. Reanudar o reiniciar el servidor no repone llamadas. Inicio: {ops.budget.started_at}.</p><button type="button" className="btn btn-sm" disabled={busy || data.alerts.some(a => a.run?.status === "running") || ops.jobs.some(j => j.status === "running")} onClick={() => control("reset_budget")}>Iniciar deliberadamente otro presupuesto</button>
      <ul className="list">{ops.audit.slice(0, 8).map((a, i) => <li key={`${a.at}-${i}`}><time>{a.at}</time> · {a.origin} · {a.reason} · {String(a.result ?? a.imported ?? "registrado")}</li>)}</ul>
    </details>
    {ops.auto_close_low_risk && <div className="compact-notice"><strong>Cierre automático activo.</strong> R1: {ops.closures_by_rule.R1} · R2: {ops.closures_by_rule.R2}. Muestra aleatoria de auditoría: {Math.round(ops.sample_rate * 100)} %. {ops.review_sample.map(d => <button key={d.ticket_id} type="button" className="link-btn" onClick={() => onOpen(data.alerts.find(a => a.ticket?.ticket_id === d.ticket_id)?.alert_id)}>{d.ticket_id}</button>)}</div>}
  </section>;
}
