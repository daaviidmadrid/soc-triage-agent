import { useEffect, useRef } from "react";
import { Chip, Ids, asText, obj } from "../components.jsx";
import { EVENT_TYPE, L, TOOL } from "../labels.js";
import { clock } from "./runState.js";

export default function Steps({ events, running, stream, live, targetSeq, active = true }) {
  const panel = useRef(null);
  useEffect(() => {
    if (!active || targetSeq == null) return;
    const step = panel.current?.querySelector(`[data-seq="${targetSeq}"]`);
    step?.scrollIntoView({ block: "center", behavior: "instant" });
    step?.focus({ preventScroll: true });
  }, [targetSeq, active]);
  const last = events.at(-1);
  return <section className="activity-timeline" aria-labelledby="steps-title" ref={panel}>
    <div className="section-heading"><h2 id="steps-title">{L.activity}</h2><span className="muted num">{events.length} pasos</span>{running && <span className="running" role="status"><span className="pulse" />{L.stateRunning}…</span>}</div>
    {stream === "lost" && <p className="compact-notice" role="status">{L.streamLost}</p>}
    {events.length ? <ol className="trace-list">{events.map(e => <li key={e.seq} className={`trace-entry trace-${e.type}${targetSeq === e.seq ? " is-target" : ""}`} data-seq={e.seq} tabIndex={-1}>
      <div className="trace-meta"><span className="trace-number num">#{e.seq}</span><time className="num" dateTime={e.at}>{clock(e.at)} UTC</time></div>
      <div className="trace-content">
        <div className="trace-heading"><span className={`step-type type-${e.type}`}>{EVENT_TYPE[e.type] || asText(e.type)}</span>{e.tool && <strong>{TOOL[e.tool] || asText(e.tool)}</strong>}{e.truncated && <Chip kind="warn">{L.truncated}</Chip>}</div>
        {e.summary && <p className="prose">{asText(e.summary)}</p>}
        {e.truncated && <p className="hint">{L.truncatedHelp}</p>}
        {Array.isArray(e.event_ids) && e.event_ids.length > 0 && <div className="trace-ids"><span className="muted">{L.eventIds}:</span><Ids ids={e.event_ids} /></div>}
        {Object.keys(obj(e.args)).length > 0 && <details className="technical-details"><summary>{L.queryParameters}</summary><pre className="raw-data">{asText(e.args)}</pre></details>}
      </div>
    </li>)}</ol> : <p className="muted">{running ? L.loading : L.stepsEmpty}</p>}
    <p className="visually-hidden" aria-live="polite">{live && running && last ? L.stepLive(last.seq, EVENT_TYPE[last.type] || asText(last.type), TOOL[last.tool] || "") : ""}</p>
  </section>;
}
