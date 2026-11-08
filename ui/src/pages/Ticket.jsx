// One alert: what the system consults (live), what it decides on, what it proposes, and where the person steps in.
// Everything from the data is shown as plain text. How a ticket looks never depends on what its text says.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { ErrorBox, Skeleton, asText, obj } from "../components.jsx";
import { L } from "../labels.js";
import { isFallback, retrievedBy } from "../ticket/runState.js";
import Icon from "../icons.jsx";
import DecisionBar from "../ticket/DecisionBar.jsx";
import TriageWorkspace from "../ticket/TriageWorkspace.jsx";
import { useRunEvents } from "../useRunEvents.js";

export default function Ticket({ alertId, onBack, onNext, onReport, onIncidents, onOpenReport }) {
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);
  const [starting, setStarting] = useState(false);
  const [targetSeq, setTargetSeq] = useState(null);
  const [tab, setTab] = useState("summary");
  const [finished, setFinished] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [next, setNext] = useState({ busy: false, none: false });
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
    const timer = setInterval(load, 2000);
    return () => clearInterval(timer);
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

  const jumpToStep = useCallback(seq => { setTargetSeq(seq); setTab("activity"); }, []);
  const go = useCallback(id => setTab(({ "steps-title": "activity", "sec-evidence": "evidence", "sec-proposal": "policy", "sec-decision": "decision", "injection-title": "notes" })[id] || "summary"), []);
  const reviewByHand = useCallback(() => setTab("original"), []);

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
    if (detail && detail.ticket && detail.job?.status !== "staged" && !window.confirm(L.retriageConfirm)) return;
    setStarting(true);
    try {
      if (detail?.job?.status === "staged") await api.startFlow();
      else await api.triage(alertId);
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
  const ticketRow = detail.ticket ? { ...detail.ticket, disposition: detail.disposition } : null;
  const decisions = detail.decisions || [];
  // Decisions come newest first; the one that counts is the newest on this version of the ticket.
  const decision = ticketRow && detail.disposition?.state !== "review" ? decisions.find((d) => d.run_id === ticketRow.run_id) || null : null;
  const fallback = Boolean(ticketRow && !running && isFallback(obj(ticketRow.ticket), events));

  return (
    <div className="ticket-page triage-page" data-live={live.current || undefined}>
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
      <DecisionBar compact
        waitingForFlow={detail.job?.status === "staged"}
        queued={detail.job?.status === "pending"}
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
      <TriageWorkspace alert={{ ...alert, ...obj(detail.shown) }} detail={detail} run={run} running={running} stream={stream} events={events} live={live.current}
        tab={tab} onTab={setTab} targetSeq={targetSeq} onSelectStep={jumpToStep} ticketRow={ticketRow} decision={decision} decisions={decisions}
        fallback={fallback} retrieved={retrieved} onSaved={load} onNext={goNext} next={next} onIncidents={onIncidents} onOpenReport={onOpenReport} />

    </div>
  );
}
