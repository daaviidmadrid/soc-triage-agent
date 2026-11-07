// What the system consults: every trace event of the run, as it arrives.
// Each step is a jump target (id "step-<seq>") for the evidence links and the agent notes.
import { useLayoutEffect, useRef } from "react";
import { Chip, Clip, Ids, Skeleton, asText, isBlank, obj } from "../components.jsx";
import Icon from "../icons.jsx";
import { EVENT_TYPE, L, TOOL } from "../labels.js";
import { clock } from "./runState.js";

const MAX_IDS_SHOWN = 12;
// How close to the bottom (px) still counts as "following the newest step".
const STICK_PX = 48;

function Step({ e, target }) {
  const args = Object.entries(obj(e.args));
  return (
    <li className={`step step-${e.type}${target ? " is-target" : ""}`} id={`step-${e.seq}`} tabIndex={-1}>
      <div className="step-head">
        <span className={`step-type type-${e.type}`}>{EVENT_TYPE[e.type] || asText(e.type)}</span>
        {e.tool && <span className="step-tool">{TOOL[e.tool] || asText(e.tool)}</span>}
        <span className="step-meta num">
          #{e.seq} · {clock(e.at)}
        </span>
      </div>
      {e.truncated && (
        <Chip kind="warn" title={L.truncatedHelp}>
          <Icon name="alert" />
          {L.truncated}
        </Chip>
      )}
      {!isBlank(e.summary) && (
        <p className="step-summary">
          <Clip value={e.summary} max={200} />
        </p>
      )}
      {args.length > 0 && (
        <p className="step-args">
          {args.map(([k, v]) => (
            <span key={k} className="arg">
              {k}=<Clip value={v} max={80} />
            </span>
          ))}
        </p>
      )}
      {Array.isArray(e.event_ids) && e.event_ids.length > 0 && (
        <p className="step-ids">
          <span className="muted">{L.eventIds}:</span> <Ids ids={e.event_ids} max={MAX_IDS_SHOWN} />
        </p>
      )}
    </li>
  );
}

export default function Steps({ events, running, stream, live, targetSeq }) {
  const panel = useRef(null);
  const stick = useRef(true);

  // While a run streams, keep the newest step in view unless the analyst scrolled up to read.
  // Only matters where the panel scrolls on its own (wide screens); an instant jump, the step's own fade is the motion.
  useLayoutEffect(() => {
    const el = panel.current;
    if (!el || !running || !stick.current) return;
    if (el.scrollHeight > el.clientHeight) el.scrollTop = el.scrollHeight;
  }, [events.length, running]);

  function onScroll() {
    const el = panel.current;
    if (el) stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < STICK_PX;
  }

  const last = events[events.length - 1];
  return (
    <section className="panel steps-panel" aria-labelledby="steps-title" ref={panel} onScroll={onScroll}>
      <h2 id="steps-title" tabIndex={-1}>
        {L.stepsTitle}
      </h2>
      <p className="hint">{L.stepsHelp}</p>
      {stream === "lost" && <p className="inline-warn">{L.streamLost}</p>}
      {events.length === 0 ? (
        running ? <Skeleton rows={3} cols={2} label={L.loading} /> : <p className="muted">{L.stepsEmpty}</p>
      ) : (
        <ol className="steps">
          {events.map((e) => (
            <Step key={e.seq} e={e} target={e.seq === targetSeq} />
          ))}
        </ol>
      )}
      {/* Screen readers hear one short line per new step while a run is watched, not every argument. */}
      <p className="visually-hidden" aria-live="polite">
        {live && running && last ? L.stepLive(last.seq, EVENT_TYPE[last.type] || asText(last.type), last.tool ? TOOL[last.tool] || asText(last.tool) : "") : ""}
      </p>
      {running && (
        <p className="running" role="status">
          <span className="pulse" aria-hidden="true" /> {L.stateRunning}…
        </p>
      )}
    </section>
  );
}
