// CSS custom properties are the single color source; no chart-local hex palette.
export const DATA_COLORS = {
  critical: "var(--sev-critical)", high: "var(--sev-high)",
  medium: "var(--sev-medium)", low: "var(--sev-low)",
  informational: "var(--sev-informational)", unknown: "var(--deloitte-border)",
};
export const WORKFLOW_SERIES = [
  ["none", "var(--deloitte-blue)", "stateNone"],
  ["running", "var(--deloitte-navy)", "stateRunning"],
  ["pending", "var(--deloitte-gray)", "statePending"],
  ["decided", "var(--deloitte-sky)", "stateDecided"],
  ["auto_closed", "var(--line-strong)", "stateAutoClosed"],
  ["failed", "url(#workflow-failed)", "stateFailed"],
];

export function shareLabel(count, total) {
  return `${(total > 0 ? count / total * 100 : 0).toLocaleString("es-ES", { maximumFractionDigits: 1 })} %`;
}

// Compare adjacent calendar days only. A gap in a long imported series is not a
// previous-day observation. A zero base is shown explicitly, never as infinity.
export function dayComparison(points, index) {
  if (index <= 0 || index >= points.length) return null;
  const current = points[index], previous = points[index - 1];
  if (Date.parse(current.day) - Date.parse(previous.day) !== 86400000) return null;
  const delta = current.count - previous.count;
  if (previous.count === 0) return { previous: 0, percent: current.count === 0 ? "0 %" : null };
  const percent = delta / previous.count * 100;
  return {
    previous: previous.count,
    percent: `${percent > 0 ? "+" : ""}${percent.toLocaleString("es-ES", { maximumFractionDigits: 1 })} %`,
  };
}
