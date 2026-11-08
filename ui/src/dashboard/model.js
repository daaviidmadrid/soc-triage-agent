import { countsOf, effective, filterAndSort, EMPTY_FILTERS } from "../queue/model.js";
import { SEVERITY_ORDER } from "../labels.js";

// Aggregate only the queue already returned by the API. Dates refer to alert time,
// never to the current day; imported rows without a valid date stay in the totals.
export function dashboardData(rows) {
  const alerts = Array.isArray(rows) ? rows : [];
  const states = countsOf(alerts);
  const severity = SEVERITY_ORDER.map(key => ({ key, count: alerts.filter(row => effective(row).severity === key).length }));
  const unknown = alerts.length - severity.reduce((sum, row) => sum + row.count, 0);
  if (unknown) severity.push({ key: "unknown", count: unknown });
  const products = new Map();
  const days = new Map();
  for (const row of alerts) {
    const product = typeof row.source_product === "string" && row.source_product ? row.source_product : "—";
    products.set(product, (products.get(product) || 0) + 1);
    if (typeof row.created_at !== "string") continue;
    const time = Date.parse(row.created_at);
    if (Number.isFinite(time)) {
      const day = new Date(time).toISOString().slice(0, 10);
      days.set(day, (days.get(day) || 0) + 1);
    }
  }
  let timeline = [...days].sort(([a], [b]) => a.localeCompare(b)).map(([day, count]) => ({ day, count }));
  if (timeline.length > 1) {
    const first = Date.parse(timeline[0].day), last = Date.parse(timeline.at(-1).day);
    // Bound the chart for imports that span years: use only observed days then.
    if ((last - first) / 86400000 <= 90) {
      timeline = [];
      for (let time = first; time <= last; time += 86400000) {
        const day = new Date(time).toISOString().slice(0, 10);
        timeline.push({ day, count: days.get(day) || 0 });
      }
    }
  }
  const duration = alerts.filter(row => row.run?.mode === "real" && row.run?.status === "done")
    .map(row => row.run.duration_seconds).filter(value => typeof value === "number" && Number.isFinite(value) && value >= 0);
  return {
    total: alerts.length, states, severity, timeline,
    high: severity.filter(row => ["critical", "high"].includes(row.key)).reduce((sum, row) => sum + row.count, 0),
    triaged: alerts.filter(row => Boolean(row.ticket)).length,
    products: [...products].map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count || a.key.localeCompare(b.key)),
    priority: filterAndSort(alerts.filter(row => !row.decision && !row.ticket?.auto_closed), EMPTY_FILTERS).slice(0, 5),
    averageSeconds: duration.length ? duration.reduce((sum, seconds) => sum + seconds, 0) / duration.length : null,
  };
}
