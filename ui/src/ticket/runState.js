// Reading a run's trace events: quota state and timestamps. No React here.
import { obj } from "../components.jsx";

export function clock(at) {
  const m = typeof at === "string" && at.match(/T(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : "";
}

// The agent reports quota limits as note and error events from the LLM step.
// src/agent/llm.py retries silently while it waits for quota and only reports at the end (error event,
// args.kind "quota"). The "waiting" state below only shows if a note event with args.kind "rate_limited" arrives.
function isQuotaEvent(e) {
  const kind = obj(e.args).kind;
  if (kind === "rate_limited" || kind === "quota") return true;
  return e.tool === "llm" && /RateLimit|429|quota|cuota/i.test(e.summary || "");
}

// "waiting" while the run waits for quota, "exhausted" once it gave up, otherwise null.
export function quotaState(events, running) {
  let waiting = false;
  let exhausted = false;
  for (const e of events) {
    if (e.type === "note" && isQuotaEvent(e)) waiting = true;
    else if (e.type === "error" && isQuotaEvent(e)) {
      exhausted = true;
      waiting = false;
    } else if (e.tool === "llm" && e.type === "tool_result") waiting = false;
  }
  if (exhausted) return "exhausted";
  return waiting && running ? "waiting" : null;
}

// Notes and errors the agent reported, in order. Errors the app adds itself are shown with the failed run instead.
export function agentMessages(events) {
  return events.filter((e) => e.type === "note" || (e.type === "error" && e.tool !== "app"));
}

// Which step first returned each event ID. Only tool results count: that is where the system actually read the data.
// The ticket_ready event repeats the ticket's IDs, so it is not a source.
export function retrievedBy(events) {
  const map = new Map();
  for (const e of events) {
    if (e.type !== "tool_result" || !Array.isArray(e.event_ids)) continue;
    for (const id of e.event_ids) {
      if (typeof id === "string" && !map.has(id)) map.set(id, e.seq);
    }
  }
  return map;
}

// A fallback ticket: the run reported errors and code filled in a needs_more_info ticket with no evidence.
export function isFallback(ticket, events) {
  const evidence = Array.isArray(ticket.evidence) ? ticket.evidence : [];
  return events.some((e) => e.type === "error") && ticket.verdict === "needs_more_info" && evidence.length === 0;
}

// "1:05" from seconds, for the live elapsed time.
export function formatClock(seconds) {
  if (typeof seconds !== "number" || !isFinite(seconds) || seconds < 0) return "0:00";
  const s = Math.floor(seconds);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = String(s % 60).padStart(2, "0");
  return h ? `${h}:${String(m).padStart(2, "0")}:${ss}` : `${m}:${ss}`;
}
