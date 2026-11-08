// Pure helpers for the queue: severity order, run state, filtering, counts and the filters kept in the URL hash. No React here.
import { PIPELINE_LANE, SEVERITY_ORDER, SLA_FILTERS, STATE_FILTERS } from "../labels.js";

export function rank(severity) {
  const i = SEVERITY_ORDER.indexOf(severity);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

// Final severity once triaged, rule severity before that.
export function effective(item) {
  const final = item.ticket && item.ticket.severity;
  return final ? { severity: final, fromRule: false } : { severity: item.rule_severity, fromRule: true };
}

// none | running | failed | pending (waiting for a person) | auto_closed (no person needed) | decided
export function stateOf(item) {
  if (!item.run) return "none";
  if (item.run.status === "running") return "running";
  if (item.run.status === "failed") return "failed";
  if (item.decision) return "decided";
  return item.ticket && item.ticket.auto_closed === true ? "auto_closed" : "pending";
}

// The SLA right now, from the server's deadline. A running clock can pass its deadline between two polls.
// nowMs is the server's time. Anything missing or odd stays as the server said.
export function liveSla(sla, nowMs, fraction = 0.25) {
  if (!sla) return null;
  if (sla.stopped_at || !sla.deadline) return { ...sla, secondsLeft: null };
  const deadline = Date.parse(sla.deadline);
  if (!Number.isFinite(deadline) || !Number.isFinite(nowMs)) return { ...sla, secondsLeft: null };
  const secondsLeft = (deadline - nowMs) / 1000;
  let state = sla.state;
  if (secondsLeft < 0) state = "breached";
  else if (state !== "breached" && sla.at_risk_reason !== "worker" && typeof sla.target_seconds === "number") state = secondsLeft <= sla.target_seconds * fraction ? "at_risk" : "on_track";
  return { ...sla, state, secondsLeft };
}

// "45 s", "12 min 05 s", "3 h 20 min", "2 d 4 h": for the countdown.
export function formatDuration(seconds) {
  const total = Math.max(0, Math.floor(Math.abs(seconds)));
  if (total < 60) return `${total} s`;
  if (total < 3600) return `${Math.floor(total / 60)} min ${String(total % 60).padStart(2, "0")} s`;
  if (total < 86400) return `${Math.floor(total / 3600)} h ${String(Math.floor(total % 3600 / 60)).padStart(2, "0")} min`;
  return `${Math.floor(total / 86400)} d ${Math.floor(total % 86400 / 3600)} h`;
}

// Which group of the queue an alert is in. Every alert is in exactly one. Whatever isn't clearly
// on its way or finished goes to a person, so a surprise can't hide an alert that needs someone.
export function groupOf(item) {
  const state = stateOf(item);
  if (state === "decided") return "decided";
  if (state === "auto_closed") return item.ticket.auto_close && item.ticket.auto_close.sampled ? "auto_sample" : "auto_rest";
  if (state === "running") return "waiting";
  if (state === "none") return ["at_risk", "breached"].includes(item.sla && item.sla.state) ? "person" : "waiting";
  return "person";
}

export const GROUP_ORDER = ["person", "waiting", "auto_sample", "auto_rest", "decided"];

function byUrgency(a, b) {
  const deadline = (item) => (item.sla && !item.sla.stopped_at && item.sla.deadline) || "9999";
  return rank(effective(a).severity) - rank(effective(b).severity)
    || deadline(a).localeCompare(deadline(b))
    || String(b.created_at || "").localeCompare(String(a.created_at || ""));
}

export function groupQueue(alerts) {
  const groups = Object.fromEntries(GROUP_ORDER.map((key) => [key, []]));
  for (const item of alerts) groups[groupOf(item)].push(item);
  for (const key of GROUP_ORDER) groups[key].sort(byUrgency);
  return groups;
}

// Which lane of the pipeline an alert is in. Every alert is in exactly one.
export function laneOf(item) {
  if (item.containment_active) return "containment";
  const state = stateOf(item);
  if (state === "none") return "entry";
  if (state === "running") return item.llm_started || !item.has_fixed_rule ? "llm" : "rules";
  if (state === "auto_closed") return item.ticket.closed_by_rule ? "rules" : "policy";
  return "person";
}

export function pipelineCounts(alerts) {
  const lanes = Object.fromEntries(Object.keys(PIPELINE_LANE).map((key) => [key, { total: 0, needsPerson: 0, bySeverity: Object.fromEntries([...SEVERITY_ORDER, "unknown"].map((s) => [s, 0])) }]));
  for (const item of alerts) {
    const lane = lanes[laneOf(item)];
    const severity = effective(item).severity;
    lane.total += 1;
    lane.bySeverity[SEVERITY_ORDER.includes(severity) ? severity : "unknown"] += 1;
    if (groupOf(item) === "person") lane.needsPerson += 1;
  }
  return lanes;
}

export function hasInjection(item) {
  return Boolean(item.ticket && item.ticket.injection_flags > 0);
}

export function filterAndSort(alerts, filters) {
  const q = filters.q.trim().toLowerCase();
  return alerts
    .filter((a) => !filters.product || a.source_product === filters.product)
    .filter((a) => !filters.severity || (filters.severity === "priority" ? ["critical", "high"].includes(effective(a).severity) : effective(a).severity === filters.severity))
    .filter((a) => !filters.state || stateOf(a) === filters.state)
    .filter((a) => !filters.injection || hasInjection(a))
    .filter((a) => !filters.sla || (a.sla && a.sla.state) === filters.sla)
    .filter((a) => !filters.lane || laneOf(a) === filters.lane)
    .filter((a) => !q || [a.alert_id, a.rule_name, a.rule_id].some((v) => typeof v === "string" && v.toLowerCase().includes(q)))
    .sort((a, b) => rank(effective(a).severity) - rank(effective(b).severity) || String(b.created_at || "").localeCompare(String(a.created_at || "")));
}

export function productsOf(alerts) {
  return [...new Set(alerts.map((a) => a.source_product).filter(Boolean))].sort();
}

// How many alerts are in each state, over the whole queue (not the filtered rows).
export function countsOf(alerts) {
  const counts = { none: 0, running: 0, failed: 0, pending: 0, decided: 0, auto_closed: 0, injection: 0, at_risk: 0, breached: 0 };
  for (const a of alerts) {
    counts[stateOf(a)] += 1;
    if (hasInjection(a)) counts.injection += 1;
    if (a.sla && a.sla.state === "at_risk") counts.at_risk += 1;
    if (a.sla && a.sla.state === "breached") counts.breached += 1;
  }
  return counts;
}

export const EMPTY_FILTERS = { q: "", product: "", severity: "", state: "", injection: false, sla: "", lane: "" };

export function isFiltered(filters) {
  return Boolean(filters.q || filters.product || filters.severity || filters.state || filters.injection || filters.sla || filters.lane);
}

// The queue's filters live in the hash ("#/?estado=pending&sev=high"), so a reload or "Volver a la cola" keeps them.
// Values from the hash are checked against the known lists; free text is only ever used as a filter value.
const MAX_TEXT = 200;

export function filtersFromQuery(query) {
  const p = new URLSearchParams(query || "");
  const text = (key) => (p.get(key) || "").slice(0, MAX_TEXT);
  const severity = text("sev");
  const state = text("estado");
  const sla = text("sla");
  const lane = text("carril");
  return {
    q: text("q"),
    product: text("producto"),
    severity: [...SEVERITY_ORDER, "priority"].includes(severity) ? severity : "",
    state: Object.prototype.hasOwnProperty.call(STATE_FILTERS, state) ? state : "",
    injection: p.get("iny") === "1",
    sla: Object.prototype.hasOwnProperty.call(SLA_FILTERS, sla) ? sla : "",
    lane: Object.prototype.hasOwnProperty.call(PIPELINE_LANE, lane) ? lane : "",
  };
}

export function queueHash(filters) {
  const p = new URLSearchParams();
  if (filters.q) p.set("q", filters.q);
  if (filters.product) p.set("producto", filters.product);
  if (filters.severity) p.set("sev", filters.severity);
  if (filters.state) p.set("estado", filters.state);
  if (filters.injection) p.set("iny", "1");
  if (filters.sla) p.set("sla", filters.sla);
  if (filters.lane) p.set("carril", filters.lane);
  const query = p.toString();
  return query ? `#/?${query}` : "#/";
}

// The next alert nobody has decided yet, after `currentId` in queue order with the analyst's filters.
// Alerts waiting for a person come first; then alerts not triaged yet. Wraps around; null when none is left.
export function nextPendingId(alerts, filters, currentId) {
  // The state filter is ignored: the point is to find what is still undecided.
  const all = filterAndSort(alerts, { ...filters, state: "" });
  const start = all.findIndex((a) => a.alert_id === currentId);
  const ordered = start === -1 ? all : [...all.slice(start + 1), ...all.slice(0, start)];
  for (const wanted of ["pending", "none"]) {
    const hit = ordered.find((a) => stateOf(a) === wanted);
    if (hit) return hit.alert_id;
  }
  return null;
}
