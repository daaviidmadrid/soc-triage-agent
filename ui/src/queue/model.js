// Pure helpers for the queue: severity order, run state, filtering, counts and the filters kept in the URL hash. No React here.
import { SEVERITY_ORDER, STATE_FILTERS } from "../labels.js";

export function rank(severity) {
  const i = SEVERITY_ORDER.indexOf(severity);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

// Final severity once triaged, rule severity before that.
export function effective(item) {
  const final = item.ticket && item.ticket.severity;
  return final ? { severity: final, fromRule: false } : { severity: item.rule_severity, fromRule: true };
}

// none | running | failed | pending (waiting for a person) | decided
export function stateOf(item) {
  if (!item.run) return "none";
  if (item.run.status === "running") return "running";
  if (item.run.status === "failed") return "failed";
  return item.decision ? "decided" : "pending";
}

export function hasInjection(item) {
  return Boolean(item.ticket && item.ticket.injection_flags > 0);
}

export function filterAndSort(alerts, filters) {
  const q = filters.q.trim().toLowerCase();
  return alerts
    .filter((a) => !filters.product || a.source_product === filters.product)
    .filter((a) => !filters.severity || effective(a).severity === filters.severity)
    .filter((a) => !filters.state || stateOf(a) === filters.state)
    .filter((a) => !filters.injection || hasInjection(a))
    .filter((a) => !q || [a.alert_id, a.rule_name, a.rule_id].some((v) => typeof v === "string" && v.toLowerCase().includes(q)))
    .sort((a, b) => rank(effective(a).severity) - rank(effective(b).severity) || String(b.created_at || "").localeCompare(String(a.created_at || "")));
}

export function productsOf(alerts) {
  return [...new Set(alerts.map((a) => a.source_product).filter(Boolean))].sort();
}

// How many alerts are in each state, over the whole queue (not the filtered rows).
export function countsOf(alerts) {
  const counts = { none: 0, running: 0, failed: 0, pending: 0, decided: 0, injection: 0 };
  for (const a of alerts) {
    counts[stateOf(a)] += 1;
    if (hasInjection(a)) counts.injection += 1;
  }
  return counts;
}

export const EMPTY_FILTERS = { q: "", product: "", severity: "", state: "", injection: false };

export function isFiltered(filters) {
  return Boolean(filters.q || filters.product || filters.severity || filters.state || filters.injection);
}

// The queue's filters live in the hash ("#/?estado=pending&sev=high"), so a reload or "Volver a la cola" keeps them.
// Values from the hash are checked against the known lists; free text is only ever used as a filter value.
const MAX_TEXT = 200;

export function filtersFromQuery(query) {
  const p = new URLSearchParams(query || "");
  const text = (key) => (p.get(key) || "").slice(0, MAX_TEXT);
  const severity = text("sev");
  const state = text("estado");
  return {
    q: text("q"),
    product: text("producto"),
    severity: SEVERITY_ORDER.includes(severity) ? severity : "",
    state: Object.prototype.hasOwnProperty.call(STATE_FILTERS, state) ? state : "",
    injection: p.get("iny") === "1",
  };
}

export function queueHash(filters) {
  const p = new URLSearchParams();
  if (filters.q) p.set("q", filters.q);
  if (filters.product) p.set("producto", filters.product);
  if (filters.severity) p.set("sev", filters.severity);
  if (filters.state) p.set("estado", filters.state);
  if (filters.injection) p.set("iny", "1");
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
