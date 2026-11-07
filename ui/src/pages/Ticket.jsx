// One alert: what the system consults (live), what it decides on, what it proposes, and where the person steps in.
// Everything from the data is shown as plain text. How a ticket looks never depends on what its text says.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { Clip, ErrorBox, Field, ModeTag, NA, Notice, Severity, Skeleton, asText, formatSeconds, formatTime, isBlank, obj } from "../components.jsx";
import { EVENT_TYPE, L, RUN_STATUS } from "../labels.js";
import { agentMessages, isFallback, quotaState, retrievedBy } from "../ticket/runState.js";
import Icon from "../icons.jsx";
import DecisionBar from "../ticket/DecisionBar.jsx";
import Steps from "../ticket/Steps.jsx";
import TicketView from "../ticket/TicketView.jsx";

// How long a jumped-to step stays highlighted.
const HIGHLIGHT_MS = 2500;

// Live steps. The server replays every stored event first, so a reload shows the whole run again.
function useRunEvents(runId, onEnd) {
  const [events, setEvents] = useState([]);
  const [stream, setStream] = useState("idle");

  useEffect(() => {
    if (!runId) return undefined;
    setEvents([]);
    setStream("connecting");
    const source = new EventSource(api.eventsUrl(runId));
    source.onopen = () => setStream("live");
    source.addEventListener("trace", (message) => {
      let event;
      try {
        event = JSON.parse(message.data);
      } catch {
        return;
      }
      if (!event || typeof event !== "object") return;
      setStream("live");
      setEvents((prev) => (prev.some((p) => p.seq === event.seq) ? prev : [...prev, event].sort((a, b) => a.seq - b.seq)));
    });
    source.addEventListener("end", () => {
      source.close();
      setStream("ended");
      onEnd();
    });
    source.onerror = () => {
      if (source.readyState !== EventSource.CLOSED) setStream("lost");
    };
    return () => source.close();
  }, [runId, onEnd]);

  return { events, stream };
}

function AlertSummary({ alert, run }) {
  return (
    <section className="panel alert-summary" aria-label={L.alertTitle}>
      <dl className="kv kv-row">
        <Field label={L.colRule}>
          <Clip value={alert.rule_name} max={120} />
          {alert.rule_id && <div className="sub id-plain">{asText(alert.rule_id)}</div>}
        </Field>
        <Field label={L.colProduct}>{isBlank(alert.source_product) ? <NA /> : asText(alert.source_product)}</Field>
        <Field label={L.colTime}>
          <span className="num">{formatTime(alert.created_at) || <NA />}</span>
        </Field>
        <Field label={L.colRuleSeverity}>
          <Severity value={alert.severity} />
        </Field>
        <Field label={L.colState}>
          {run ? (
            <span className={`state state-${run.status}`}>
              {RUN_STATUS[run.status] || asText(run.status)} <ModeTag mode={run.mode} />
            </span>
          ) : (
            <span className="state state-none">{L.stateNone}</span>
          )}
        </Field>
      </dl>
      <dl className="kv">
        <Field label={L.description}>
          <Clip value={alert.description} max={300} />
        </Field>
      </dl>
    </section>
  );
}

// Quota state and the agent's own notes. A failed run is shown in the decision bar, with its next step.
function RunNotices({ events, running, onJumpToStep }) {
  const quota = quotaState(events, running);
  const messages = agentMessages(events);
  return (
    <>
      {quota === "waiting" && (
        <Notice kind="warn" role="status" icon="clock" title={`${L.quotaWaiting}.`}>
          {L.quotaWaitingText}
        </Notice>
      )}
      {quota === "exhausted" && (
        <Notice kind="warn" role="status" icon="alert" title={`${L.quotaExhausted}.`}>
          {L.quotaExhaustedText}
        </Notice>
      )}
      {messages.length > 0 && (
        <Notice title={`${L.agentErrors}:`}>
          <ul className="list">
            {messages.map((e) => (
              <li key={e.seq}>
                <span className={`step-type type-${e.type}`}>{EVENT_TYPE[e.type]}</span> <Clip value={e.summary} max={240} />
                <button type="button" className="link-btn" onClick={() => onJumpToStep(e.seq)}>
                  {L.seeStep(e.seq)}
                </button>
              </li>
            ))}
          </ul>
        </Notice>
      )}
    </>
  );
}

function RunHistory({ runs }) {
  if (!runs || runs.length < 2) return null;
  return (
    <details className="panel disclosure">
      <summary>
        {L.runsHistory} <span className="muted num">({runs.length})</span>
      </summary>
      <ul className="list">
        {runs.map((r) => (
          <li key={r.run_id}>
            <code className="id">{r.run_id}</code> <ModeTag mode={r.mode} /> {RUN_STATUS[r.status] || r.status}{" "}
            <span className="muted num">
              {formatTime(r.started_at)} UTC · {formatSeconds(r.duration_seconds) || "—"}
            </span>
            {r.error && (
              <div className="sub">
                <Clip value={r.error} max={160} />
              </div>
            )}
          </li>
        ))}
      </ul>
    </details>
  );
}

// Holds the ticket's place while the run streams, so nothing jumps when the ticket arrives.
function TicketPending() {
  return (
    <section className="panel ticket-pending" aria-labelledby="pending-title">
      <h2 id="pending-title">{L.pendingTicketTitle}</h2>
      <p className="hint">{L.pendingTicketText}</p>
      <Skeleton rows={4} cols={3} label={L.pendingTicketText} />
    </section>
  );
}

// Scroll an element into view and move focus to it. Instant: these jumps are often keyboard-triggered.
function goTo(id, block = "start") {
  const el = document.getElementById(id);
  if (!el) return;
  el.scrollIntoView({ block });
  el.focus({ preventScroll: true });
}

export default function Ticket({ alertId, onBack, onNext, onReport }) {
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);
  const [starting, setStarting] = useState(false);
  const [targetSeq, setTargetSeq] = useState(null);
  const [finished, setFinished] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [next, setNext] = useState({ busy: false, none: false });
  const rawAlert = useRef(null);
  const live = useRef(false);
  const prevStatus = useRef(null);

  const load = useCallback(async () => {
    try {
      const d = await api.alert(alertId);
      setDetail(d);
      setError(null);
      onReport(d.mode, Boolean(d.latest_run && d.latest_run.mode === "example"));
    } catch (e) {
      setError(e.message);
    }
  }, [alertId, onReport]);

  useEffect(() => {
    load();
  }, [load]);

  const run = detail ? detail.latest_run : null;
  const running = Boolean(run && run.status === "running");
  // Motion for steps and the ticket arriving plays only when the analyst watched this run live.
  if (running) live.current = true;
  const { events, stream } = useRunEvents(run ? run.run_id : null, load);

  // The moment a watched run finishes.
  const status = run ? run.status : null;
  useEffect(() => {
    if (prevStatus.current === "running" && status === "done") setFinished(true);
    if (status === "running") setFinished(false);
    prevStatus.current = status;
  }, [status]);

  // Elapsed time while running.
  useEffect(() => {
    if (!running) return undefined;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [running]);

  // A jumped-to step stays highlighted for a moment.
  useEffect(() => {
    if (targetSeq === null) return undefined;
    const timer = setTimeout(() => setTargetSeq(null), HIGHLIGHT_MS);
    return () => clearTimeout(timer);
  }, [targetSeq]);

  const jumpToStep = useCallback((seq) => {
    setTargetSeq(seq);
    goTo(`step-${seq}`, "center");
  }, []);

  const go = useCallback((id) => {
    if (id === "sec-decision") {
      // Straight to the first choice of the form when it is open; otherwise to the saved decision.
      const section = document.getElementById(id);
      const first = section && section.querySelector("input[name='decision']");
      if (first) {
        section.scrollIntoView({ block: "start" });
        first.focus({ preventScroll: true });
        return;
      }
    }
    goTo(id);
  }, []);

  const reviewByHand = useCallback(() => {
    const el = rawAlert.current;
    if (!el) return;
    el.open = true;
    el.scrollIntoView({ block: "start" });
    const summary = el.querySelector("summary");
    if (summary) summary.focus({ preventScroll: true });
  }, []);

  const goNext = useCallback(async () => {
    setNext({ busy: true, none: false });
    try {
      const id = await onNext(alertId);
      if (!id) setNext({ busy: false, none: true });
    } catch (e) {
      setNext({ busy: false, none: false });
      setError(e.message);
    }
  }, [alertId, onNext]);

  async function start() {
    if (detail && detail.ticket && !window.confirm(L.retriageConfirm)) return;
    setStarting(true);
    try {
      await api.triage(alertId);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setStarting(false);
    }
  }

  const retrieved = useMemo(() => retrievedBy(events), [events]);

  const back = (
    <button type="button" className="btn btn-ghost" onClick={onBack}>
      <Icon name="arrowLeft" />
      {L.back}
    </button>
  );

  if (error && !detail) {
    return (
      <div className="stack">
        <div>{back}</div>
        <ErrorBox message={error} onRetry={load} />
      </div>
    );
  }
  if (!detail) return <Skeleton rows={5} cols={4} label={L.loading} />;

  const alert = obj(detail.alert);
  const ticketRow = detail.ticket;
  const decisions = detail.decisions || [];
  // Decisions come newest first; the one that counts is the newest on this version of the ticket.
  const decision = ticketRow ? decisions.find((d) => d.run_id === ticketRow.run_id) || null : null;
  const fallback = Boolean(ticketRow && !running && isFallback(obj(ticketRow.ticket), events));

  return (
    <div className="ticket-page" data-live={live.current || undefined}>
      <header className="page-head">
        <div className="page-title">
          {back}
          <h1>
            {L.alertTitle} <code className="id id-lg">{asText(alert.alert_id || alertId)}</code>
          </h1>
        </div>
        {run && (
          <div className="page-actions">
            {/* Secondary on purpose: re-running replaces the ticket the person is about to decide on */}
            <button type="button" className="btn" onClick={start} disabled={running || starting}>
              {starting ? L.starting : L.retriage}
            </button>
          </div>
        )}
      </header>

      {error && <ErrorBox message={error} onRetry={load} />}
      <DecisionBar
        run={run}
        ticketRow={ticketRow}
        decision={decision}
        events={events}
        running={running}
        fallback={fallback}
        finished={finished}
        now={now}
        ruleSeverity={alert.severity}
        starting={starting}
        onStart={start}
        onGo={go}
        onReviewByHand={reviewByHand}
        onNext={goNext}
        next={next}
      />
      <AlertSummary alert={{ ...alert, ...obj(detail.shown) }} run={run} />
      <RunNotices events={events} running={running} onJumpToStep={jumpToStep} />

      <div className="ticket-layout">
        {run && <Steps events={events} running={running} stream={stream} live={live.current} targetSeq={targetSeq} />}
        {running && <TicketPending />}
        {ticketRow && !running && (
          <TicketView
            ticketRow={ticketRow}
            run={run}
            decision={decision}
            decisions={decisions}
            fallback={fallback}
            retrieved={retrieved}
            traceComplete={stream === "ended"}
            onJumpToStep={jumpToStep}
            onSaved={load}
            onNext={goNext}
            next={next}
          />
        )}
      </div>

      <details className="panel disclosure raw-alert" ref={rawAlert}>
        <summary>{L.rawAlert}</summary>
        <p className="hint">{L.rawAlertHelp}</p>
        <Clip value={detail.alert} max={4000} pre />
      </details>

      <RunHistory runs={detail.runs} />
    </div>
  );
}
