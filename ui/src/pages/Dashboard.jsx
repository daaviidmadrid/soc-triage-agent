import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { Clip, ErrorBox, Severity, Skeleton, asText, formatTime, formatSeconds } from "../components.jsx";
import Icon from "../icons.jsx";
import { dashboardData } from "../dashboard/model.js";
import ChartTooltip, { useChartFocus } from "../dashboard/ChartTooltip.jsx";
import { DATA_COLORS, WORKFLOW_SERIES, dayComparison, shareLabel } from "../dashboard/interaction.js";
import { effective, stateOf } from "../queue/model.js";
import { L, VERDICT, STATE_FILTERS, SEVERITY } from "../labels.js";

const number = value => value.toLocaleString("es-ES");
const shortDate = value => new Intl.DateTimeFormat("es-ES", { day: "numeric", month: "short", timeZone: "UTC" }).format(new Date(value));
const fullDate = value => new Intl.DateTimeFormat("es-ES", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" }).format(new Date(value));

function ChartCard({ title, detail, children, className = "", action }) {
  return <section className={`dashboard-panel ${className}`}><div className="chart-heading"><div><h2>{title}</h2>{detail && <span className="chart-detail">{detail}</span>}</div>{action}</div>{children}</section>;
}

function Timeline({ points, interaction }) {
  const container = useRef(null), marks = useRef([]);
  const [width, setWidth] = useState(760), [focusIndex, setFocusIndex] = useState(0);
  useEffect(() => {
    if (!container.current) return;
    const observer = new ResizeObserver(entries => setWidth(Math.max(280, entries[0].contentRect.width)));
    observer.observe(container.current);
    return () => observer.disconnect();
  }, [points.length]);
  if (!points.length) return <div className="chart-empty">{L.noDatedAlerts}</div>;
  const height = 205, left = 34, right = 16, top = 16, bottom = 34;
  const max = Math.max(4, Math.ceil(Math.max(...points.map(point => point.count)) / 4) * 4);
  const firstDay = Date.parse(points[0].day), span = Math.max(86400000, Date.parse(points.at(-1).day) - firstDay);
  const x = i => left + (Date.parse(points[i].day) - firstDay) / span * (width - left - right);
  const y = value => height - bottom - value / max * (height - top - bottom);
  const line = points.map((point, i) => `${i ? "L" : "M"}${x(i)},${y(point.count)}`).join(" ");
  const positions = [...new Set([0, Math.floor((points.length - 1) / 3), Math.floor(2 * (points.length - 1) / 3), points.length - 1])];
  const active = String(interaction.activeKey).startsWith("day:") ? Number(String(interaction.activeKey).slice(4)) : -1;
  function onKey(event, index) {
    const next = { ArrowLeft: Math.max(0, index - 1), ArrowRight: Math.min(points.length - 1, index + 1), Home: 0, End: points.length - 1 }[event.key];
    if (next === undefined) return;
    event.preventDefault();
    setFocusIndex(next);
    const target = marks.current[next];
    if (target) { target.focus(); interaction.activate(`day:${next}`, target); }
  }
  return <div className="timeline-chart" ref={container} data-focused={active >= 0 || undefined}>
    <svg viewBox={`0 0 ${width} ${height}`} role="group" aria-label={L.timelineTitle} aria-describedby="volume-description">
      <desc id="volume-description">{L.chartKeyboardHelp}. {points.map(point => `${shortDate(point.day)}: ${point.count}`).join("; ")}</desc>
      <defs><linearGradient id="volume-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--deloitte-sky)" stopOpacity=".3" /><stop offset="100%" stopColor="var(--deloitte-sky)" stopOpacity=".03" /></linearGradient></defs>
      {[0, 1, 2, 3, 4].map(step => <g key={step}><line x1={left} x2={width - right} y1={y(max * step / 4)} y2={y(max * step / 4)} stroke="var(--deloitte-border)" strokeDasharray="3 5" /><text x={left - 10} y={y(max * step / 4) + 4} textAnchor="end">{max * step / 4}</text></g>)}
      <path className="timeline-area" d={`${line} L${x(points.length - 1)},${y(0)} L${x(0)},${y(0)} Z`} fill="url(#volume-fill)" />
      <path className="timeline-line" d={line} fill="none" stroke="var(--deloitte-blue)" strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" />
      {active >= 0 && points[active] && <line className="chart-crosshair" x1={x(active)} x2={x(active)} y1={top} y2={height - bottom} />}
      {points.map((point, i) => <g key={point.day} ref={element => { marks.current[i] = element; }} className="timeline-mark" {...interaction.bind(`day:${i}`)}
        tabIndex={i === Math.min(focusIndex, points.length - 1) ? 0 : -1} role="img"
        aria-label={`${fullDate(point.day)}: ${point.count} ${L.alertsUnit}`} onKeyDown={event => onKey(event, i)}>
        <circle className="timeline-hit" cx={x(i)} cy={y(point.count)} r="12" />
        <circle className="timeline-dot" cx={x(i)} cy={y(point.count)} r="4" />
      </g>)}
      {positions.map(i => <text key={i} x={x(i)} y={height - 8} textAnchor={i === 0 ? "start" : i === points.length - 1 ? "end" : "middle"}>{shortDate(points[i].day)}</text>)}
    </svg>
    <div className="chart-key"><span className="key-dot blue" />{L.alertVolume}<span className="chart-key-right">UTC</span></div>
  </div>;
}

function arcPath(start, end) {
  const point = angle => [75 + 59 * Math.cos(angle - Math.PI / 2), 75 + 59 * Math.sin(angle - Math.PI / 2)];
  const a = point(start), b = point(end);
  if (end - start >= Math.PI * 2 - .0001) {
    const mid = point(start + Math.PI);
    return `M${a} A59 59 0 1 1 ${mid} A59 59 0 1 1 ${a}`;
  }
  return `M${a} A59 59 0 ${end - start > Math.PI ? 1 : 0} 1 ${b}`;
}

function StateChart({ summary, onQueue }) {
  let offset = 0;
  const segments = WORKFLOW_SERIES.map(([key, color, label]) => {
    const count = summary.states[key], angle = summary.total ? count / summary.total * Math.PI * 2 : 0;
    const segment = { key, color, label, count, start: offset, end: offset + angle, gap: Math.min(.025, angle / 10) };
    offset += angle;
    return segment;
  });
  return <div className="state-chart"><div className="donut-wrap"><svg viewBox="0 0 150 150" role="group" aria-label={L.workloadTitle}>
    <defs><pattern id="workflow-failed" width="6" height="6" patternUnits="userSpaceOnUse"><rect width="6" height="6" fill="var(--deloitte-sky)" /><path d="M0 6L6 0" stroke="var(--deloitte-navy)" strokeWidth="2" /></pattern></defs><circle cx="75" cy="75" r="59" stroke="var(--deloitte-border)" strokeWidth="14" fill="none" />
    {segments.filter(segment => segment.count > 0).map(segment => <path key={segment.key} className="donut-segment"
      d={arcPath(segment.start + (segment.count < summary.total ? segment.gap : 0), segment.end - (segment.count < summary.total ? segment.gap : 0))} fill="none" stroke={segment.color} strokeWidth="14"
      role="img" aria-label={`${L[segment.label]}: ${segment.count}`} />)}
    </svg><div className="donut-center"><strong>{number(summary.total)}</strong><span>{L.alertsUnit}</span></div></div>
    <div className="state-legend">{segments.map(segment => <button key={segment.key} onClick={() => onQueue({ state: segment.key })} className="legend-row"><span className={`key-dot state-swatch-${segment.key}`} style={{ background: segment.key === "failed" ? undefined : segment.color }} /><span>{L[segment.label]}</span><strong>{number(segment.count)}</strong><span className="legend-share">{shareLabel(segment.count, summary.total)}</span></button>)}</div>
  </div>;
}

export default function Dashboard({ onReport, onOpen, onQueue }) {
  const [data, setData] = useState(null), [error, setError] = useState(null), [updated, setUpdated] = useState(null), [refreshing, setRefreshing] = useState(false);
  const interaction = useChartFocus();
  const alive = useRef(false);
  const alertCache = useRef(new Map());
  const [alertDetails, setAlertDetails] = useState({});
  const loadAlert = id => {
    if (alertCache.current.has(id)) return;
    alertCache.current.set(id, true);
    api.alert(id).then(result => { if (alive.current) setAlertDetails(prev => ({ ...prev, [id]: result })); }).catch(() => { alertCache.current.delete(id); });
  };
  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const result = await api.queue();
      if (!alive.current) return;
      setData(result); setError(null); setUpdated(new Date()); onReport(result.mode, result.example_results > 0);
    } catch (problem) { if (alive.current) setError(problem.message); }
    finally { if (alive.current) setRefreshing(false); }
  }, [onReport]);
  useEffect(() => { alive.current = true; load(); const timer = window.setInterval(load, 10000); return () => { alive.current = false; window.clearInterval(timer); }; }, [load]);
  const summary = useMemo(() => dashboardData(data?.alerts), [data]);
  const period = summary.timeline.length ? `${shortDate(summary.timeline[0].day)} — ${shortDate(summary.timeline.at(-1).day)}` : L.noPeriod;
  const kpis = [
    { label: L.totalAlerts, value: summary.total, note: `${summary.products.length} ${L.sourcesUnit}`, action: {} },
    { label: L.highPriority, value: summary.high, note: L.highPriorityNote, action: { severity: "priority" }, tone: "focal" },
    { label: L.pendingReview, value: summary.states.pending, note: `${summary.states.running} ${L.runningUnit}`, action: { state: "pending" } },
    { label: L.resolvedAlerts, value: summary.states.decided, note: `${summary.total ? Math.round(summary.states.decided / summary.total * 100) : 0} % ${L.ofQueue}`, action: { state: "decided" } },
  ];
  // Details are derived on every render, so an open tooltip follows queue updates.
  const details = new Map();
  summary.timeline.forEach((point, i) => details.set(`day:${i}`, { label: fullDate(point.day), value: number(point.count), detail: L.dailyVolumeUtc, comparison: dayComparison(summary.timeline, i) }));
  summary.priority.forEach(row => {
    const alert = alertDetails[row.alert_id]?.alert;
    const fields = [[L.colProduct, row.source_product || "—"], [L.colTime, formatTime(row.created_at) || "—"], [L.colState, STATE_FILTERS[stateOf(row)]], [L.filterSeverity, SEVERITY[effective(row).severity] || "—"]];
    if (row.rule_id) fields.push([L.ruleId, row.rule_id]);
    if (row.ticket?.verdict) fields.push([L.verdict, VERDICT[row.ticket.verdict] || row.ticket.verdict]);
    details.set(`alert:${row.alert_id}`, { kind: "alert", label: row.alert_id, title: row.rule_name, fields, description: alert?.description ? asText(alert.description) : undefined });
  });
  const alertBindings = id => {
    const bindings = interaction.bind(`alert:${id}`);
    return { ...bindings, onPointerEnter: event => { bindings.onPointerEnter(event); loadAlert(id); }, onFocus: event => { bindings.onFocus(event); loadAlert(id); } };
  };

  return <div className="dashboard">
    <header className="page-head dashboard-head"><div><h1>{L.dashboardTitle}</h1></div><div className="page-actions"><span className="period-label"><Icon name="calendar" />{period}</span><button className="btn" onClick={load} disabled={refreshing}><Icon name="refresh" />{L.refresh}</button></div></header>
    {error && <ErrorBox message={error} onRetry={load} />}
    {!data && !error ? <div className="dashboard-loading"><Skeleton rows={3} cols={4} label={L.loading} /></div> : !data ? null : <>
      <div className="kpi-grid">{kpis.map(kpi => <button key={kpi.label} className={`kpi-card ${kpi.tone || "neutral"}`} onClick={() => onQueue(kpi.action)}><span className="kpi-label">{kpi.label}</span><strong className="kpi-value">{number(kpi.value)}</strong><span className="kpi-note">{kpi.note}</span></button>)}</div>
      <ChartCard title={L.priorityTitle} detail={L.prioritySubtitle} className="priority-panel" action={<button className="link-btn" onClick={() => onQueue({})}>{L.viewQueue}<Icon name="arrowRight" /></button>}>
        {summary.priority.length ? <div className="priority-table-wrap"><table className="priority-table"><thead><tr><th>{L.colAlert}</th><th>{L.colRule}</th><th>{L.colProduct}</th><th>{L.filterSeverity}</th><th><span className="visually-hidden">{L.open}</span></th></tr></thead><tbody>{summary.priority.map(row => <tr key={row.alert_id} {...alertBindings(row.alert_id)}><td><button className="id priority-id" onClick={() => onOpen(row.alert_id)}>{row.alert_id}</button></td><td><Clip value={row.rule_name} max={90} /></td><td><span className="source-tag">{row.source_product || "—"}</span></td><td><Severity value={effective(row).severity} /></td><td><button className="btn btn-sm btn-ghost" aria-label={`${L.open} ${row.alert_id}`} onClick={() => onOpen(row.alert_id)}><Icon name="arrowRight" /></button></td></tr>)}</tbody></table></div> : <p className="chart-empty">{L.noPendingAlerts}</p>}
      </ChartCard>
      <div className="dashboard-main-grid">
        <ChartCard title={L.timelineTitle} detail={L.byAlertDate} className="timeline-panel"><Timeline points={summary.timeline} interaction={interaction} /></ChartCard>
        <ChartCard title={L.workloadTitle} detail={`${summary.triaged} / ${summary.total} ${L.triagedUnit}`}><StateChart summary={summary} onQueue={onQueue} /></ChartCard>
      </div>
      <div className="dashboard-bottom-grid">
        <ChartCard title={L.severityTitle} detail={L.severitySubtitle}><div className="severity-bars">{summary.severity.map(row => <button key={row.key} onClick={() => onQueue(row.key === "unknown" ? {} : { severity: row.key })} className="distribution-row"><span className="distribution-name"><span className="key-dot" style={{ background: DATA_COLORS[row.key] }} />{SEVERITY[row.key] || L.na}</span><span className="distribution-track"><span style={{ width: `${summary.total ? row.count / summary.total * 100 : 0}%`, background: DATA_COLORS[row.key] }} /></span><strong>{number(row.count)}</strong></button>)}</div></ChartCard>
        <ChartCard title={L.sourcesTitle} detail={L.sourceProduct}><div className="product-bars">{summary.products.slice(0, 6).map(row => <button className="product-row" key={row.key} onClick={() => onQueue({ product: row.key === "—" ? "" : row.key })}><span className="product-label">{row.key}</span><span className="product-track"><span style={{ width: `${summary.total ? row.count / summary.total * 100 : 0}%` }} /></span><strong>{number(row.count)}</strong></button>)}{!summary.products.length && <p className="chart-empty">{L.noData}</p>}</div></ChartCard>
        <ChartCard title={L.resolutionTitle}><div className="resolution-number"><strong>{summary.total ? Math.round(summary.triaged / summary.total * 100) : 0}<span>%</span></strong><span>{L.withTicket}</span></div><div className="completion-track" role="img" aria-label={`${L.resolutionTitle}: ${shareLabel(summary.triaged, summary.total)}`}><span style={{ width: `${summary.total ? summary.triaged / summary.total * 100 : 0}%` }} /></div><dl className="resolution-facts"><div><dt>{L.stateNone}</dt><dd>{summary.states.none}</dd></div><div><dt>{L.stateFailed}</dt><dd className={summary.states.failed ? "bad" : ""}>{summary.states.failed}</dd></div><div><dt>{L.meanDuration}</dt><dd>{formatSeconds(summary.averageSeconds) || "—"}</dd></div></dl></ChartCard>
      </div>

      <footer className="dashboard-footer">{updated && <span>{L.updatedAt} {updated.toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" })}</span>}</footer>
    </>}
    <ChartTooltip interaction={interaction} data={details.get(interaction.activeKey)} />
  </div>;
}
