import test from "node:test";
import assert from "node:assert/strict";
import { EMPTY_FILTERS, GROUP_ORDER, countsOf, filterAndSort, filtersFromQuery, formatDuration, groupOf, groupQueue, isFiltered, laneOf, liveSla, pipelineCounts, queueHash, stateOf } from "./model.js";
import { PIPELINE_LANE, SEVERITY_ORDER, SLA, setSlaTargets } from "../labels.js";

const done = { status: "done", run_id: "R", mode: "real" };
const open = (state, extra = {}) => ({ state, deadline: "2026-11-08T10:30:00.000Z", target_seconds: 1800, stopped_at: null, ...extra });
const ROWS = [
  { alert_id: "none", rule_severity: "low", sla: open("on_track") },
  { alert_id: "none-risk", rule_severity: "high", sla: open("at_risk") },
  { alert_id: "none-late", rule_severity: "critical", sla: open("breached") },
  { alert_id: "none-no-sla", rule_severity: "medium" },
  { alert_id: "running-llm", rule_severity: "medium", run: { status: "running" }, llm_started: true, has_fixed_rule: true },
  { alert_id: "running-rule", rule_severity: "medium", run: { status: "running" }, llm_started: false, has_fixed_rule: true },
  { alert_id: "running-other", rule_severity: "medium", run: { status: "running" }, llm_started: false, has_fixed_rule: false },
  { alert_id: "failed", rule_severity: "high", run: { status: "failed" } },
  { alert_id: "pending", rule_severity: "low", run: done, ticket: { severity: "high" } },
  { alert_id: "fallback", rule_severity: "high", run: done, ticket: { severity: "high", fallback: true } },
  { alert_id: "decided", rule_severity: "low", run: done, ticket: { severity: "low" }, decision: { outcome: "close", analyst: "Ana" } },
  { alert_id: "auto-rule", rule_severity: "low", run: done, ticket: { severity: "low", auto_closed: true, closed_by_rule: "R1", auto_close: { sampled: true } } },
  { alert_id: "auto-llm", rule_severity: "low", run: done, ticket: { severity: "informational", auto_closed: true, auto_close: { sampled: false } } },
  { alert_id: "reopened", rule_severity: "low", run: done, ticket: { severity: "low", auto_closed: false, auto_close: { reopened_by: "Ana", sampled: true } } },
  { alert_id: "contained", rule_severity: "high", run: done, ticket: { severity: "high" }, containment_active: true },
  { alert_id: "unknown-severity", rule_severity: "rara", run: done, ticket: {} },
  { alert_id: "decided-auto", rule_severity: "low", run: done, ticket: { severity: "low", auto_closed: true, auto_close: { sampled: true } }, decision: { outcome: "close", analyst: "Ana" } },
];

test("every alert is in exactly one group of the queue", () => {
  const groups = groupQueue(ROWS);
  const placed = GROUP_ORDER.flatMap((key) => groups[key].map((row) => row.alert_id)).sort();
  assert.deepEqual(placed, ROWS.map((row) => row.alert_id).sort());
});

test("what needs a person goes to that group, including whatever a person must not miss", () => {
  const person = groupQueue(ROWS).person.map((row) => row.alert_id);
  for (const id of ["none-risk", "none-late", "failed", "pending", "fallback", "reopened", "contained", "unknown-severity"]) assert.ok(person.includes(id), id);
  for (const id of ["none", "running-llm", "decided", "auto-rule", "auto-llm"]) assert.ok(!person.includes(id), id);
});

test("an odd item with no SLA or ticket still appears", () => {
  assert.equal(groupOf({ alert_id: "x" }), "waiting");
  assert.equal(groupOf({ alert_id: "x", run: { status: "strange" } }), "person");
});

test("auto-closed alerts split into the sample and the rest, and a person's decision wins", () => {
  const groups = groupQueue(ROWS);
  assert.deepEqual(groups.auto_sample.map((row) => row.alert_id), ["auto-rule"]);
  assert.deepEqual(groups.auto_rest.map((row) => row.alert_id), ["auto-llm"]);
  assert.equal(stateOf(ROWS.find((row) => row.alert_id === "decided-auto")), "decided");
});

test("inside a group, a lower severity never overtakes a higher one because it is older", () => {
  const rows = [
    { alert_id: "old-low", rule_severity: "low", run: { status: "failed" }, sla: open("breached", { deadline: "2020-01-01T00:00:00.000Z" }) },
    { alert_id: "late-high", rule_severity: "high", run: { status: "failed" }, sla: open("on_track", { deadline: "2026-12-02T00:00:00.000Z" }) },
    { alert_id: "soon-high", rule_severity: "high", run: { status: "failed" }, sla: open("on_track", { deadline: "2026-12-01T00:00:00.000Z" }) },
  ];
  assert.deepEqual(groupQueue(rows).person.map((row) => row.alert_id), ["soon-high", "late-high", "old-low"]);
});

test("every alert is in exactly one lane and the pipeline counts add up", () => {
  const lanes = pipelineCounts(ROWS);
  assert.equal(Object.values(lanes).reduce((sum, lane) => sum + lane.total, 0), ROWS.length);
  for (const lane of Object.values(lanes)) {
    assert.equal(Object.values(lane.bySeverity).reduce((sum, count) => sum + count, 0), lane.total);
  }
  assert.deepEqual(Object.keys(lanes), Object.keys(PIPELINE_LANE));
  const by = Object.fromEntries(ROWS.map((row) => [row.alert_id, laneOf(row)]));
  assert.equal(by["none"], "entry");
  assert.equal(by["running-rule"], "rules");
  assert.equal(by["running-other"], "llm");
  assert.equal(by["running-llm"], "llm");
  assert.equal(by["auto-rule"], "rules");
  assert.equal(by["auto-llm"], "policy");
  assert.equal(by["pending"], "person");
  assert.equal(by["contained"], "containment");
  assert.ok(lanes.person.needsPerson > 0);
});

test("the countdown follows the server's deadline, and passing it breaches a running clock", () => {
  const at = (time) => Date.parse(`2026-11-08T${time}Z`);
  const sla = open("on_track");
  assert.equal(liveSla(sla, at("10:00:00")).state, "on_track");
  assert.equal(liveSla(sla, at("10:00:00")).secondsLeft, 1800);
  assert.equal(liveSla(sla, at("10:22:30")).state, "at_risk");
  assert.equal(liveSla(sla, at("10:30:00")).state, "at_risk");
  assert.equal(liveSla(sla, at("10:30:01")).state, "breached");
  assert.equal(liveSla(open("at_risk", { at_risk_reason: "worker" }), at("10:00:00")).state, "at_risk");
  assert.equal(liveSla({ ...sla, state: "met", stopped_at: "2026-11-08T10:01:00.000Z" }, at("12:00:00")).state, "met");
  assert.equal(liveSla({ state: "batch", deadline: null, stopped_at: null }, at("12:00:00")).state, "batch");
  assert.equal(liveSla(null, 0), null);
});

test("durations read as a person would say them", () => {
  assert.equal(formatDuration(45), "45 s");
  assert.equal(formatDuration(-125), "2 min 05 s");
  assert.equal(formatDuration(3 * 3600 + 20 * 60), "3 h 20 min");
  assert.equal(formatDuration(2 * 86400 + 4 * 3600), "2 d 4 h");
});

test("the SLA and lane filters work, survive the URL and refuse unknown values", () => {
  assert.deepEqual(filterAndSort(ROWS, { ...EMPTY_FILTERS, sla: "breached" }).map((row) => row.alert_id), ["none-late"]);
  assert.deepEqual(filterAndSort(ROWS, { ...EMPTY_FILTERS, lane: "containment" }).map((row) => row.alert_id), ["contained"]);
  assert.equal(isFiltered({ ...EMPTY_FILTERS, sla: "at_risk" }), true);
  const hash = queueHash({ ...EMPTY_FILTERS, sla: "at_risk", lane: "person" });
  assert.deepEqual(filtersFromQuery(hash.slice(3)), { ...EMPTY_FILTERS, sla: "at_risk", lane: "person" });
  assert.deepEqual(filtersFromQuery("sla=close_this&carril=skip"), EMPTY_FILTERS);
});

test("counts include the new states without leaving any alert out", () => {
  const counts = countsOf(ROWS);
  assert.equal(["none", "running", "failed", "pending", "decided", "auto_closed"].reduce((sum, key) => sum + counts[key], 0), ROWS.length);
  assert.equal(counts.at_risk, 1);
  assert.equal(counts.breached, 1);
});

test("the SLA targets come only from the API", () => {
  assert.deepEqual(SLA, {});
  setSlaTargets({ critical: { label: "x", seconds: 1 } });
  assert.equal(SLA.critical.seconds, 1);
  delete SLA.critical;
  setSlaTargets(null);
  assert.deepEqual(SLA, {});
  assert.ok(SEVERITY_ORDER.length === 5);
});
