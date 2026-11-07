import test from "node:test";
import assert from "node:assert/strict";
import { dashboardData } from "./model.js";
import { EMPTY_FILTERS, filterAndSort, filtersFromQuery } from "../queue/model.js";

test("effective severity drives both the KPI and its queue filter", () => {
  const rows = [
    { alert_id: "EXAMPLE-A", rule_severity: "low", ticket: { severity: "critical" } },
    { alert_id: "EXAMPLE-B", rule_severity: "high" },
    { alert_id: "EXAMPLE-C", rule_severity: "medium" },
  ];
  const summary = dashboardData(rows);
  const filtered = filterAndSort(rows, { ...EMPTY_FILTERS, severity: "priority" });
  assert.equal(summary.high, 2);
  assert.equal(filtered.length, summary.high);
  assert.equal(filtersFromQuery("sev=priority").severity, "priority");
});

test("timeline uses UTC, fills empty days and retains undated alerts in totals", () => {
  const summary = dashboardData([
    { alert_id: "EXAMPLE-A", created_at: "2026-01-01T23:00:00-02:00" },
    { alert_id: "EXAMPLE-B", created_at: "2026-01-04T00:00:00Z" },
    { alert_id: "EXAMPLE-C", created_at: "invalid" },
  ]);
  assert.equal(summary.total, 3);
  assert.deepEqual(summary.timeline, [
    { day: "2026-01-02", count: 1 }, { day: "2026-01-03", count: 0 }, { day: "2026-01-04", count: 1 },
  ]);
});

test("example replay durations do not become real performance metrics", () => {
  const summary = dashboardData([
    { alert_id: "EXAMPLE-A", run: { mode: "example", status: "done", duration_seconds: 1 } },
    { alert_id: "EXAMPLE-B", run: { mode: "real", status: "done", duration_seconds: 20 } },
    { alert_id: "EXAMPLE-C", run: { mode: "real", status: "failed", duration_seconds: 200 } },
    { alert_id: "EXAMPLE-D", run: { mode: "real", status: "done", duration_seconds: 40 } },
  ]);
  assert.equal(summary.averageSeconds, 30);
});

test("empty, missing and unknown fields produce defined chart values", () => {
  assert.equal(dashboardData([]).averageSeconds, null);
  assert.deepEqual(dashboardData([]).timeline, []);
  const summary = dashboardData([{ alert_id: "EXAMPLE-UNKNOWN" }]);
  assert.equal(summary.total, 1);
  assert.equal(summary.severity.at(-1).key, "unknown");
  assert.equal(summary.severity.at(-1).count, 1);
  assert.equal(summary.states.none, 1);
});

test("wide date ranges remain bounded and identifier numbers do not affect metrics", () => {
  const rows = [
    { alert_id: "EXAMPLE-1", created_at: "2020-01-01T00:00:00Z", rule_severity: "high" },
    { alert_id: "EXAMPLE-9999", created_at: "2026-01-01T00:00:00Z", rule_severity: "low" },
  ];
  const first = dashboardData(rows);
  const second = dashboardData(rows.map((row, i) => ({ ...row, alert_id: `EXAMPLE-REPLACED-${i}` })));
  assert.equal(first.timeline.length, 2);
  assert.deepEqual(first.severity, second.severity);
  assert.deepEqual(first.timeline, second.timeline);
  assert.deepEqual(first.states, second.states);
});
