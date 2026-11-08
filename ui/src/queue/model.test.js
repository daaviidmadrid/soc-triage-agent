import assert from "node:assert/strict";
import { test } from "node:test";
import { attentionOf, effective, filterAndSort, flowStage, stateOf, EMPTY_FILTERS, filtersFromQuery } from "./model.js";

const analysed = { alert_id: "SYNTHETIC", run: { status: "done" }, ticket: { severity: "low", closed_by_rule: "R1" } };
test("uploaded cases wait for Start and follow the server queue order", () => {
  const first = { alert_id: "FIRST", job: { status: "staged" }, queue_position: 1, rule_severity: "medium" };
  const second = { alert_id: "SECOND", job: { status: "staged" }, queue_position: 2, rule_severity: "medium" };
  assert.equal(stateOf(first), "queued");
  assert.equal(flowStage(first), "intake");
  assert.deepEqual(filterAndSort([second, first], EMPTY_FILTERS).map(a => a.alert_id), ["FIRST", "SECOND"]);
  assert.equal(flowStage({ ...analysed, job: { status: "failed" }, report_state: { status: "blocked" } }), "review");
});
test("a rule result alone never means disposed or approved", () => {
  assert.equal(stateOf(analysed), "pending");
  assert.equal(attentionOf(analysed), "review");
  assert.equal(flowStage(analysed), "review");
});
test("pending jobs, correlation and investigation reflect their actual stages", () => {
  assert.equal(flowStage({ ...analysed, job: { status: "pending" } }), "intake");
  assert.equal(flowStage({ ...analysed, correlation_pending: true }), "correlation");
  assert.equal(flowStage({ ...analysed, report_state: { status: "pending" } }), "investigation");
  assert.equal(stateOf({ ...analysed, report_state: { status: "running" } }), "running");
});
test("automatic closure, human disposition and audit sampling remain distinct", () => {
  const closed = { ...analysed, disposition: { state: "closed", origin: "automation" } };
  assert.equal(stateOf(closed), "auto_closed");
  assert.equal(attentionOf(closed), "automatic");
  assert.equal(flowStage(closed), "finished");
  assert.equal(attentionOf({ ...closed, disposition: { ...closed.disposition, sampled_for_review: true } }), "review");
  assert.equal(flowStage({ ...closed, disposition: { ...closed.disposition, sampled_for_review: true } }), "finished");
  assert.equal(attentionOf({ ...analysed, decision: { outcome: "close", analyst: "Ana" } }), "human");
});
test("new evidence returns a human decision to attention without deleting it", () => {
  const reopened = { ...analysed, decision: { analyst: "Ana", outcome: "close" }, disposition: { state: "review", origin: "code" } };
  assert.equal(stateOf(reopened), "pending");
  assert.equal(flowStage(reopened), "review");
});
test("attention prioritises unresolved cases and keeps severity independent", () => {
  const closed = { ...analysed, alert_id: "CLOSED", ticket: { severity: "critical" }, decision: { outcome: "close" } };
  const result = filterAndSort([closed, analysed], EMPTY_FILTERS);
  assert.equal(result[0].alert_id, "SYNTHETIC");
  assert.equal(effective(closed).severity, "critical");
  assert.equal(filterAndSort([closed, analysed], { ...EMPTY_FILTERS, state: "attention:review" }).length, 1);
  assert.equal(filtersFromQuery("estado=attention%3Areview").state, "attention:review");
});
