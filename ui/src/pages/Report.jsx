// Level 3: the incident report of an escalated incident or ticket, with its timeline.
// Who wrote what is fixed per field: code sets every time, the order, the approvers and the related incidents;
// the model writes the analysis; a person approves any containment. Everything from the data is plain text.
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { Chip, Clip, ErrorBox, Field, Ids, List, NA, Notice, Skeleton, arr, asText, formatSeconds, formatTime, isBlank, obj } from "../components.jsx";
import Icon from "../icons.jsx";
import { EVENT_TYPE, L, RUN_STATUS } from "../labels.js";
import { agentMessages, retrievedBy } from "../ticket/runState.js";
import Containment from "../ticket/Containment.jsx";
import Steps from "../ticket/Steps.jsx";
import { useRunEvents } from "../useRunEvents.js";

const SIMILAR_SHOWN = 60;

function datePart(ts) {
  const m = typeof ts === "string" && ts.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/);
  return m ? { day: m[1], time: m[2] } : { day: "", time: asText(ts) };
}

function By({ who }) {
  if (who === "llm") return <Chip kind="llm">{L.tagLlm}</Chip>;
  if (who === "code") return <Chip kind="code">{L.tagCode}</Chip>;
  return <Chip kind="person">{L.tagPerson}</Chip>;
}

function SectionTitle({ id, children, who }) {
  return (
    <div className="role-title">
      <h3 id={id}>{children}</h3>
      {who && <By who={who} />}
    </div>
  );
}

// An event ID of the timeline. If a step of the run returned it, it jumps to that step.
function EventId({ id, retrieved, onJump }) {
  const seq = retrieved.get(id);
  if (seq === undefined) return <code className="id">{id}</code>;
  return (
    <button type="button" className="id id-jump" onClick={() => onJump(seq)} aria-label={L.jumpToStep(id, seq)}>
      {id}
      <span className="id-step num" aria-hidden="true">
        #{seq}
      </span>
    </button>
  );
}

function TimelineStep({ step, retrieved, onJump }) {
  const s = obj(step);
  const utc = datePart(s.timestamp);
  const madrid = datePart(s.timestamp_madrid);
  const linked = arr(s.linked_by_alerts);
  const similar = arr(s.similar_event_ids);
  const found = linked.length === 0;
  return (
    <li className={`tl-step${found ? " is-found" : ""}`}>
      <div className="tl-time num">
        <span>{utc.time}</span>
        {madrid.time && (
          <span className="muted" title={L.timelineMadrid}>
            {madrid.time} {L.timelineMadrid}
          </span>
        )}
      </div>
      <div className="tl-body">
        <div className="tl-head">
          <EventId id={asText(s.event_id)} retrieved={retrieved} onJump={onJump} />
          {s.source && <span className="tl-source">{asText(s.source)}</span>}
          {s.mitre && <code className="id-plain">{asText(s.mitre)}</code>}
          {found ? (
            <Chip kind="found" title={L.timelineFoundHelp}>
              {L.timelineFound}
            </Chip>
          ) : (
            <span className="muted tl-linked">{L.timelineLinked(linked.join(", "))}</span>
          )}
          {s.added_by === "code" && (
            <Chip kind="code" title={L.timelineByCodeHelp}>
              {L.timelineByCode}
            </Chip>
          )}
        </div>
        <p className="tl-desc">
          <Clip value={s.description} max={400} />
        </p>
        {similar.length > 0 && (
          <details className="tl-similar">
            <summary>{L.timelineSimilar(similar.length)}</summary>
            <Ids ids={similar} max={SIMILAR_SHOWN} />
          </details>
        )}
      </div>
    </li>
  );
}

// Grouped by day, because incidents last days. Order and times come from the logs.
function Timeline({ steps, retrieved, onJump }) {
  const days = [];
  for (const step of arr(steps)) {
    const day = datePart(obj(step).timestamp).day || "—";
    if (!days.length || days[days.length - 1].day !== day) days.push({ day, steps: [] });
    days[days.length - 1].steps.push(step);
  }
  if (!days.length) return <p className="muted">{L.none}</p>;
  return (
    <div className="timeline">
      {days.map((d) => (
        <section key={d.day} className="tl-day" aria-label={d.day}>
          <h4 className="tl-date num">{d.day}</h4>
          <ol className="tl-list">
            {d.steps.map((step, i) => (
              <TimelineStep key={`${obj(step).event_id}-${i}`} step={step} retrieved={retrieved} onJump={onJump} />
            ))}
          </ol>
        </section>
      ))}
    </div>
  );
}

// Level 4 on the report: the same approvals as a ticket. A person approves each role and runs the action once.
function ReportContainment({ reportKey, fallback }) {
  return (
    <div className="role role-person">
      {fallback ? (
        <>
          <h3>{L.containmentTitle}</h3>
          <p className="muted">{L.none}</p>
        </>
      ) : (
        <Containment reportKey={reportKey} headingLevel={3} />
      )}
    </div>
  );
}

function People({ people }) {
  const rows = arr(people).map(obj);
  if (!rows.length) return null;
  return (
    <>
      <h4>
        {L.peopleTitle} <By who="code" />
      </h4>
      <ul className="list">
        {rows.map((p) => (
          <li key={p.upn}>
            <code className="id">{asText(p.upn)}</code> {asText(p.display_name)}
            <span className="muted">
              {" "}
              · {[p.title, p.department].filter(Boolean).map(asText).join(", ")}
              {p.account_type === "service" ? ` · ${L.peopleService}` : ""}
              {p.privileged ? ` · ${L.peoplePrivileged}` : ""}
              {p.vip ? " · VIP" : ""}
            </span>
          </li>
        ))}
      </ul>
    </>
  );
}

function LinkRow({ link }) {
  const l = obj(link);
  return (
    <li>
      <code className="id">{asText(l.alert_id)}</code>
      {l.incident_id && (
        <>
          {" "}
          · <code className="id">{asText(l.incident_id)}</code>
        </>
      )}{" "}
      <span className="muted num">{formatTime(l.created_at)}</span> <Clip value={l.rule_name || l.rule_id} max={80} />
      <div className="sub">{arr(l.shared).map(asText).join("; ")}</div>
    </li>
  );
}

function Related({ report }) {
  const links = arr(report.related_links).map(obj);
  const strong = links.filter((l) => l.strength === "specific");
  const leads = links.filter((l) => l.strength !== "specific");
  return (
    <section className="role role-code" aria-labelledby="rep-related">
      <SectionTitle id="rep-related" who="code">
        {L.relatedTitle}
      </SectionTitle>
      <p className="hint">{L.relatedHelp}</p>
      <p className="report-narrative">
        <Clip value={report.related_note} max={400} />
      </p>
      {strong.length > 0 && (
        <>
          <h4>{L.relatedStrong}</h4>
          <ul className="list links">
            {strong.map((l) => (
              <LinkRow key={l.alert_id} link={l} />
            ))}
          </ul>
        </>
      )}
      {leads.length > 0 && (
        <details className="disclosure-inline">
          <summary>{L.relatedLeads(leads.length)}</summary>
          <ul className="list links">
            {leads.map((l) => (
              <LinkRow key={l.alert_id} link={l} />
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}

function EvidenceFacts({ report }) {
  const e = obj(report.evidence_summary);
  const bySource = Object.entries(obj(e.rows_by_source));
  return (
    <section className="role role-code" aria-labelledby="rep-evidence">
      <SectionTitle id="rep-evidence" who="code">
        {L.evidenceTitle}
      </SectionTitle>
      <dl className="kv kv-grid">
        <Field label={L.evidenceWindow}>
          <span className="num">
            {formatTime(e.window_from) || <NA />} → {formatTime(e.window_to) || <NA />}
          </span>
        </Field>
        <Field label={L.evidenceRows}>
          <span className="num">{L.evidenceRowsValue(e.rows_retrieved ?? 0, e.rows_not_linked_by_alerts ?? 0, e.searches ?? 0)}</span>
        </Field>
        <Field label={L.evidenceSent}>
          <span className="num">{e.rows_sent_to_llm ?? 0}</span>
        </Field>
        {!isBlank(report.report_seconds) && <Field label={L.reportSeconds}>{formatSeconds(report.report_seconds)}</Field>}
      </dl>
      {bySource.length > 0 && (
        <p className="sub num">
          {L.evidenceBySource}: {bySource.map(([source, n]) => `${source} ${n}`).join(" · ")}
        </p>
      )}
      {arr(e.truncated_sources).length > 0 && (
        <Notice kind="warn" icon="alert" title={`${L.evidenceTruncated}:`}>
          {arr(e.truncated_sources).join(", ")}
        </Notice>
      )}
      {arr(e.skipped_pivots).length > 0 && (
        <p className="sub">
          {L.evidenceSkipped}: {arr(e.skipped_pivots).map(asText).join("; ")}
        </p>
      )}
      {arr(report.code_notes).length > 0 && (
        <>
          <h4>{L.codeNotes}</h4>
          <List items={report.code_notes} />
        </>
      )}
    </section>
  );
}

function ReportView({ row, reportKey, retrieved, onJump }) {
  const report = obj(row.report);
  const scope = obj(report.scope);
  const steps = arr(report.timeline);
  const found = steps.filter((s) => arr(obj(s).linked_by_alerts).length === 0).length;
  const confidence = typeof report.confidence === "number" ? Math.round(report.confidence * 100) : null;
  return (
    <article className="panel report" aria-labelledby="report-title">
      <header className="ticket-head">
        <div className="ticket-head-row">
          <h2 id="report-title">{L.reportTitle}</h2>
          <code className="id">{asText(report.incident_id)}</code>
        </div>
        {report.fallback && (
          <Notice kind="warn" icon="alert" title={`${L.reportFallbackTitle}.`}>
            {L.reportFallbackText}
          </Notice>
        )}
        <p className="ticket-title">
          <Clip value={report.title} max={240} />
        </p>
        <dl className="kv kv-grid">
          <Field label={L.alertIds}>
            <Ids ids={report.alert_ids} />
          </Field>
          <Field label={L.confidence}>
            {confidence === null ? <NA /> : <span className="num">{L.confidenceValue(confidence)}</span>} <By who="llm" />
          </Field>
          <Field label={L.timelineTitle}>
            <span className="num">{L.timelineCount(steps.length, found)}</span>
          </Field>
        </dl>
      </header>

      <section className="role role-llm" aria-labelledby="rep-start">
        <SectionTitle id="rep-start" who="llm">
          {L.howItStarted}
        </SectionTitle>
        <dl className="kv">
          <Field label={L.patientZero}>
            <Clip value={report.patient_zero} max={400} />
          </Field>
          <Field label={L.initialAccess}>
            <Clip value={report.initial_access} max={400} />
          </Field>
          <Field label={L.rootCause}>
            <Clip value={report.root_cause} max={400} />
          </Field>
        </dl>
        {!isBlank(report.narrative) && (
          <>
            <h4>{L.narrative}</h4>
            <p className="report-narrative">
              <Clip value={report.narrative} max={1400} />
            </p>
          </>
        )}
      </section>

      <section className="role" aria-labelledby="rep-timeline">
        <div className="role-title">
          <h3 id="rep-timeline">{L.timelineTitle}</h3>
          <By who="code" />
          <By who="llm" />
        </div>
        <p className="hint">{L.timelineHelp}</p>
        <Timeline steps={steps} retrieved={retrieved} onJump={onJump} />
      </section>

      <section className="role role-llm" aria-labelledby="rep-scope">
        <SectionTitle id="rep-scope" who="llm">
          {L.scopeTitle}
        </SectionTitle>
        <dl className="kv kv-grid">
          <Field label={L.affectedUsers}>{arr(scope.users).length ? <Ids ids={scope.users} /> : <NA />}</Field>
          <Field label={L.affectedHosts}>{arr(scope.hosts).length ? <Ids ids={scope.hosts} /> : <NA />}</Field>
        </dl>
        <dl className="kv">
          <Field label={L.scopeData}>
            <Clip value={scope.data} max={400} />
          </Field>
          <Field label={L.scopeImpact}>
            <Clip value={scope.business_impact} max={400} />
          </Field>
        </dl>
        <People people={report.people} />
      </section>

      <ReportContainment reportKey={reportKey} fallback={report.fallback} />
      <Related report={report} />

      <section className="role role-llm" aria-labelledby="rep-next">
        <SectionTitle id="rep-next" who="llm">
          {L.openQuestions}
        </SectionTitle>
        <List items={report.open_questions} />
        <h4>{L.eradication}</h4>
        <List items={report.eradication_and_recovery} />
        <h4>{L.notifications}</h4>
        <List items={report.notifications} />
        <h4>{L.detectionGaps}</h4>
        <List items={report.detection_gaps} />
      </section>

      {arr(report.injection_flags).length > 0 && (
        <section className="role injection" aria-labelledby="rep-injection">
          <h3 id="rep-injection">{L.injection}</h3>
          <p className="hint">{L.injectionHelp}</p>
          <List
            items={report.injection_flags}
            render={(f) => (
              <>
                {obj(f).event_id && <code className="id">{asText(obj(f).event_id)}</code>} <Clip value={obj(f).description} max={300} />
              </>
            )}
          />
        </section>
      )}

      <EvidenceFacts report={report} />
    </article>
  );
}

function goTo(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.scrollIntoView({ block: "center" });
  el.focus({ preventScroll: true });
}

export default function Report({ reportKey, onBack }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [starting, setStarting] = useState(false);
  const [targetSeq, setTargetSeq] = useState(null);

  const load = useCallback(async () => {
    try {
      setData(await api.report(reportKey));
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  }, [reportKey]);

  useEffect(() => {
    load();
  }, [load]);

  const run = data ? data.latest_run : null;
  const running = Boolean(run && run.status === "running");
  const { events, stream } = useRunEvents(run ? run.run_id : null, load);
  const retrieved = useMemo(() => retrievedBy(events), [events]);
  const messages = agentMessages(events).filter((e) => e.type === "error");

  useEffect(() => {
    if (targetSeq === null) return undefined;
    const timer = setTimeout(() => setTargetSeq(null), 2500);
    return () => clearTimeout(timer);
  }, [targetSeq]);

  const jump = useCallback((seq) => {
    setTargetSeq(seq);
    goTo(`step-${seq}`);
  }, []);

  async function start() {
    if (data && data.report && !window.confirm(L.reportRerunConfirm)) return;
    setStarting(true);
    try {
      await api.investigate(reportKey);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setStarting(false);
    }
  }

  const back = (
    <button type="button" className="btn btn-ghost" onClick={onBack}>
      <Icon name="arrowLeft" />
      {L.reportBack}
    </button>
  );

  if (error && !data) {
    return (
      <div className="stack">
        <div>{back}</div>
        <ErrorBox message={error} onRetry={load} />
      </div>
    );
  }
  if (!data) return <Skeleton rows={5} cols={4} label={L.loading} />;

  const subject = obj(data.subject);
  const row = data.report;
  const canRun = Boolean(data.subject && subject.escalated);

  return (
    <div className="report-page">
      <header className="page-head">
        <div className="page-title">
          {back}
          <h1>
            {L.reportTitle} <code className="id id-lg">{reportKey}</code>
          </h1>
        </div>
        {canRun && (
          <div className="page-actions">
            <button type="button" className={`btn${row ? "" : " btn-primary"}`} onClick={start} disabled={running || starting}>
              {starting ? L.starting : running ? `${L.reportRunning}…` : row ? L.reportRerun : L.reportInvestigate}
            </button>
          </div>
        )}
      </header>
      {error && <ErrorBox message={error} onRetry={load} />}
      <Notice>{L.reportIntro}</Notice>

      <section className="panel" aria-labelledby="subject-title">
        <h2 id="subject-title">{L.reportSubject}</h2>
        <dl className="kv kv-grid">
          <Field label={subject.kind === "ticket" ? L.reportForTicket : L.reportForIncident}>
            {subject.title ? <Clip value={subject.title} max={160} /> : <NA />}
          </Field>
          <Field label={L.alertIds}>{arr(subject.alert_ids).length ? <Ids ids={subject.alert_ids} /> : <NA />}</Field>
          {run && (
            <Field label={L.colState}>
              <span className={`state state-${run.status}`}>{RUN_STATUS[run.status] || asText(run.status)}</span>{" "}
              <span className="muted num">{formatSeconds(run.duration_seconds)}</span>
            </Field>
          )}
        </dl>
        {data.subject && <p className="hint">{L.reportLeads(subject.leads || 0)}</p>}
        {!row && !run && <p className="hint">{L.reportNoneHelp}</p>}
      </section>

      {run && run.status === "failed" && (
        <Notice kind="error" role="alert" icon="alert" title={`${L.reportFailedTitle}:`}>
          <Clip value={run.error} max={300} />
        </Notice>
      )}
      {messages.length > 0 && (
        <Notice kind="warn" title={`${L.agentErrors}:`}>
          <ul className="list">
            {messages.map((e) => (
              <li key={e.seq}>
                <span className={`step-type type-${e.type}`}>{EVENT_TYPE[e.type]}</span> <Clip value={e.summary} max={240} />
              </li>
            ))}
          </ul>
        </Notice>
      )}

      <div className="ticket-layout">
        {run && <Steps events={events} running={running} stream={stream} live={running} targetSeq={targetSeq} />}
        {running && (
          <section className="panel ticket-pending" aria-labelledby="report-pending">
            <h2 id="report-pending">{L.reportTitle}</h2>
            <p className="hint">{L.reportPending}</p>
            <Skeleton rows={6} cols={3} label={L.reportPending} />
          </section>
        )}
        {!running && row && <ReportView row={row} reportKey={reportKey} retrieved={retrieved} onJump={jump} />}
        {!running && !row && !run && <Notice>{L.reportNone}</Notice>}
      </div>
    </div>
  );
}
