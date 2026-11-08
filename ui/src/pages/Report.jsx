// Level 3: the incident report of an escalated incident or ticket, with its timeline.
// Who wrote what is fixed per field: code sets every time, the order, the approvers and the related incidents;
// the model writes the analysis; a person approves any containment. Everything from the data is plain text.
// The page uses the same layout as an alert: a summary bar, short notices, then a workspace with tabs.
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { Chip, ErrorBox, Field, Ids, NA, None, Skeleton, arr, asText, formatSeconds, formatTime, isBlank, obj } from "../components.jsx";
import Icon from "../icons.jsx";
import { L, RUN_STATUS } from "../labels.js";
import { agentMessages, retrievedBy } from "../ticket/runState.js";
import Containment from "../ticket/Containment.jsx";
import { Fact } from "../ticket/DecisionBar.jsx";
import Steps from "../ticket/Steps.jsx";
import { InjectionFlags } from "../ticket/TicketView.jsx";
import Workspace, { Section, TextList, workspacePanel } from "../ticket/Workspace.jsx";
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

function Prose({ value }) {
  return isBlank(value) ? <NA /> : <p className="prose">{asText(value)}</p>;
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

function TimelineStep({ step, previous, retrieved, onJump }) {
  const s = obj(step);
  const utc = datePart(s.timestamp);
  const madrid = datePart(s.timestamp_madrid);
  const linked = arr(s.linked_by_alerts);
  const similar = arr(s.similar_event_ids);
  const found = linked.length === 0;
  const gap = previous ? Date.parse(s.timestamp) - Date.parse(obj(previous).timestamp) : null;
  return (
    <li className={`tl-step${found ? " is-found" : ""}`}>
      <div className="tl-time num">
        <span>{utc.time ? `${utc.time} UTC` : "Fecha no disponible"}</span>
        {Number.isFinite(gap) && gap >= 3600000 && <span className="muted">{(gap / 3600000).toLocaleString("es-ES", { maximumFractionDigits: 1 })} h desde el evento anterior</span>}
        {madrid.time && (
          <span className="muted">
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
          <span className="muted">{s.added_by === "code" ? "Seleccionado por código" : s.added_by === "llm" ? "Seleccionado por el modelo" : "Selección sin procedencia registrada"}</span>
        </div>
        <p className="tl-desc prose">{asText(s.description)}</p>
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
  const timeOf = step => { const time = Date.parse(obj(step).timestamp); return Number.isFinite(time) ? time : Infinity; };
  const ordered = [...arr(steps)].sort((a, b) => timeOf(a) - timeOf(b));
  const previous = new Map(ordered.map((step, index) => [step, ordered[index - 1]]));
  for (const step of ordered) {
    const day = datePart(obj(step).timestamp).day || "—";
    if (!days.length || days[days.length - 1].day !== day) days.push({ day, steps: [] });
    days[days.length - 1].steps.push(step);
  }
  if (!days.length) return <None />;
  return (
    <div className="timeline">
      {days.map((d) => (
        <section key={d.day} className="tl-day" aria-label={d.day}>
          <h4 className="tl-date num">{d.day}</h4>
          <ol className="tl-list">
            {d.steps.map((step, i) => (
              <TimelineStep key={`${obj(step).event_id}-${i}`} step={step} previous={previous.get(step)} retrieved={retrieved} onJump={onJump} />
            ))}
          </ol>
        </section>
      ))}
    </div>
  );
}

function People({ people }) {
  const rows = arr(people).map(obj);
  if (!rows.length) return null;
  return (
    <Section title={L.peopleTitle} who={<By who="code" />}>
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
    </Section>
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
      <span className="muted num">{formatTime(l.created_at)}</span> {asText(l.rule_name || l.rule_id)}
      <div className="sub">{arr(l.shared).map(asText).join("; ")}</div>
    </li>
  );
}

function Related({ report }) {
  const links = arr(report.related_links).map(obj);
  const strong = links.filter((l) => l.strength === "specific");
  const leads = links.filter((l) => l.strength !== "specific");
  return (
    <Section title={L.relatedTitle} who={<By who="code" />}>
      <p className="hint">{L.relatedHelp}</p>
      <Prose value={report.related_note} />
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
    </Section>
  );
}

function EvidenceFacts({ report }) {
  const e = obj(report.evidence_summary);
  const bySource = Object.entries(obj(e.rows_by_source));
  return (
    <Section title={L.evidenceTitle} who={<By who="code" />}>
      <dl className="kv">
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
        {bySource.length > 0 && (
          <Field label={L.evidenceBySource}>
            <span className="num">{bySource.map(([source, n]) => `${source} ${n}`).join(" · ")}</span>
          </Field>
        )}
        {arr(e.truncated_sources).length > 0 && <Field label={L.evidenceTruncated}>{arr(e.truncated_sources).map(asText).join(", ")}</Field>}
        {arr(e.skipped_pivots).length > 0 && <Field label={L.evidenceSkipped}>{arr(e.skipped_pivots).map(asText).join("; ")}</Field>}
      </dl>
    </Section>
  );
}

export default function Report({ reportKey, onBack }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [starting, setStarting] = useState(false);
  const [targetSeq, setTargetSeq] = useState(null);
  const [tab, setTab] = useState(null);

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
    const timer = setInterval(load, 2000);
    return () => clearInterval(timer);
  }, [load]);

  const run = data ? data.latest_run : null;
  const running = Boolean(run && run.status === "running");
  const { events, stream } = useRunEvents(run ? run.run_id : null, load);
  const retrieved = useMemo(() => retrievedBy(events), [events]);
  const errors = agentMessages(events).filter((e) => e.type === "error");
  // An event ID in the timeline or the flags opens the step of the run that returned it.
  const jump = useCallback((seq) => {
    setTargetSeq(seq);
    setTab("activity");
  }, []);

  async function start() {
    if (data && data.report && !window.confirm(L.reportRerunConfirm)) return;
    setStarting(true);
    try {
      await api.investigate(reportKey, Boolean(data?.report));
      setTab("activity");
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
  const ready = Boolean(row && !running);
  const report = obj(row && row.report);
  const scope = obj(report.scope);
  const steps = arr(report.timeline);
  const found = steps.filter((s) => arr(obj(s).linked_by_alerts).length === 0).length;
  const confidence = typeof report.confidence === "number" ? Math.round(report.confidence * 100) : null;
  const flags = arr(report.injection_flags).map(obj);
  const truncated = arr(obj(report.evidence_summary).truncated_sources);
  const canRun = Boolean(data.subject && subject.escalated);
  const trace = { retrieved, complete: stream === "ended", onJump: jump };

  // While a run streams, the analyst watches its steps; otherwise the report opens on its summary.
  const current = tab || (running ? "activity" : "summary");
  const tabs = [
    ["summary", L.summary],
    ["timeline", L.reportTimelineTitle],
    ["scope", L.reportTabScope],
    ["containment", L.reportTabContainment],
    ["next", L.reportTabNext],
    ["activity", L.activity],
    ["evidence", L.reportTabEvidence],
  ];
  const panel = workspacePanel(current);
  const pending = (
    <div className="workspace-empty">
      <p>{running ? L.reportPending : L.reportNone}</p>
      {!row && !run && <p className="hint">{L.reportNoneHelp}</p>}
    </div>
  );

  return (
    <div className="ticket-page triage-page report-page">
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

      <section className="panel bar" aria-label={L.reportSubject}>
        <div className="bar-body">
          <dl className="facts">
            <Fact label={subject.kind === "ticket" ? L.reportForTicket : L.reportForIncident}>
              <strong>{asText(subject.title) || L.na}</strong>
            </Fact>
            <Fact label={L.reportAlerts}>
              <span className="num">{arr(subject.alert_ids).length}</span>
            </Fact>
            <Fact label={L.colState}>
              {run ? (
                <span className={`state state-${run.status}`}>
                  {RUN_STATUS[run.status] || asText(run.status)}
                  {run.duration_seconds != null && <span className="muted num"> · {formatSeconds(run.duration_seconds)}</span>}
                </span>
              ) : (
                <span className="state state-none">{L.reportNone}</span>
              )}
            </Fact>
            {ready && (
              <Fact label={L.confidence}>
                {confidence === null ? <NA /> : <span className="num">{L.confidenceValue(confidence)}</span>}
              </Fact>
            )}
            {ready && (
              <Fact label={L.reportTimelineTitle}>
                <span className="num">{L.timelineCount(steps.length, found)}</span>
              </Fact>
            )}
          </dl>
        </div>
      </section>

      <div className="triage-notices">
        {data.state?.stale && <p className="compact-notice" role="status"><strong>Informe desactualizado.</strong> La evidencia cambió desde su preparación. Consulta el estado de la nueva investigación antes de decidir.</p>}
        {run && run.status === "failed" && (
          <p className="compact-notice" role="alert">
            <strong>{L.reportFailedTitle}</strong> {asText(run.error)}
          </p>
        )}
        {ready && report.fallback && (
          <p className="compact-notice" role="status">
            <strong>{L.reportFallbackTitle}</strong> {L.reportFallbackText}
          </p>
        )}
        {errors.length > 0 && (
          <p className="compact-notice" role="status">
            <strong>{L.agentErrors}</strong>
            <button type="button" className="link-btn" onClick={() => jump(errors[0].seq)}>
              {L.seeStep(errors[0].seq)}
            </button>
          </p>
        )}
        {ready && flags.length > 0 && (
          <p className="compact-notice">
            <strong>{L.barInjections(flags.length)}</strong>
            <button type="button" className="link-btn" onClick={() => setTab("evidence")}>
              {L.reviewNotices}
            </button>
          </p>
        )}
        {ready && truncated.length > 0 && (
          <p className="compact-notice">
            <strong>{L.evidenceTruncated}</strong> {truncated.map(asText).join(", ")}
            <button type="button" className="link-btn" onClick={() => setTab("evidence")}>
              {L.reportTabEvidence}
            </button>
          </p>
        )}
      </div>

      <Workspace tabs={tabs} current={current} onTab={setTab} label={L.reportTabs}>
        {panel(
          "summary",
          ready ? (
            <>
              <div className="workspace-alert">
                <h2>{asText(report.title) || L.reportTitle}</h2>
              </div>
              <div className="analysis-layout">
                <div className="analysis-body">
                  <Section title={L.howItStarted} who={<By who="llm" />}>
                    <dl className="kv">
                      <Field label={L.patientZero}>
                        <Prose value={report.patient_zero} />
                      </Field>
                      <Field label={L.initialAccess}>
                        <Prose value={report.initial_access} />
                      </Field>
                      <Field label={L.rootCause}>
                        <Prose value={report.root_cause} />
                      </Field>
                    </dl>
                  </Section>
                  {!isBlank(report.narrative) && (
                    <Section title={L.narrative} who={<By who="llm" />}>
                      <Prose value={report.narrative} />
                    </Section>
                  )}
                </div>
                <aside className="analysis-facts" aria-label={L.details}>
                  <dl className="kv reading-metadata">
                    <Field label={L.reportForIncident}>
                      <code className="id">{asText(report.incident_id) || L.na}</code>
                    </Field>
                    <Field label={L.reportAlerts}>
                      <Ids ids={report.alert_ids} />
                    </Field>
                    <Field label={L.confidence}>
                      {confidence === null ? <NA /> : <span className="num">{L.confidenceValue(confidence)}</span>} <By who="llm" />
                    </Field>
                    {!isBlank(report.report_seconds) && <Field label={L.reportSeconds}>{formatSeconds(report.report_seconds)}</Field>}
                    {data.subject && <Field label={L.reportSubject}>{L.reportLeads(subject.leads || 0)}</Field>}
                  </dl>
                </aside>
              </div>
            </>
          ) : (
            pending
          ),
        )}
        {panel(
          "timeline",
          ready ? (
            <Section
              title={L.reportTimelineTitle}
              who={
                <>
                  <By who="code" />
                  <By who="llm" />
                </>
              }
            >
              <p className="hint">{L.timelineHelp}</p>
              <Timeline steps={steps} retrieved={retrieved} onJump={jump} />
            </Section>
          ) : (
            pending
          ),
        )}
        {panel(
          "scope",
          ready ? (
            <>
              <Section title={L.scopeTitle} who={<By who="llm" />}>
                <dl className="kv">
                  <Field label={L.affectedUsers}>{arr(scope.users).length ? <Ids ids={scope.users} /> : <NA />}</Field>
                  <Field label={L.affectedHosts}>{arr(scope.hosts).length ? <Ids ids={scope.hosts} /> : <NA />}</Field>
                  <Field label={L.scopeData}>
                    <Prose value={scope.data} />
                  </Field>
                  <Field label={L.scopeImpact}>
                    <Prose value={scope.business_impact} />
                  </Field>
                </dl>
              </Section>
              <People people={report.people} />
              <Related report={report} />
            </>
          ) : (
            pending
          ),
        )}
        {panel(
          "containment",
          ready ? (
            report.fallback ? (
              <Section title={L.containmentTitle}>
                <None />
              </Section>
            ) : (
              // The same approvals as a ticket's: a person approves each role, then runs the action once
              <Containment key={row.run_id} reportKey={reportKey} />
            )
          ) : (
            pending
          ),
        )}
        {panel(
          "next",
          ready ? (
            <>
              <Section title={L.openQuestions} who={<By who="llm" />}>
                <TextList items={arr(report.open_questions)} />
              </Section>
              <Section title={L.eradication} who={<By who="llm" />}>
                <TextList items={arr(report.eradication_and_recovery)} />
              </Section>
              <Section title={L.notifications} who={<By who="llm" />}>
                <TextList items={arr(report.notifications)} />
              </Section>
              <Section title={L.detectionGaps} who={<By who="llm" />}>
                <TextList items={arr(report.detection_gaps)} />
              </Section>
            </>
          ) : (
            pending
          ),
        )}
        {panel("activity", <Steps events={events} running={running} stream={stream} live={running} targetSeq={targetSeq} active={current === "activity"} />)}
        {panel(
          "evidence",
          <>
            <p className="hint">{L.reportIntro}</p>
            {ready && (
              <>
                {flags.length > 0 && (
                  <Section title={L.notes}>
                    <InjectionFlags continuous flags={flags} trace={trace} />
                  </Section>
                )}
                <EvidenceFacts report={report} />
                {arr(report.code_notes).length > 0 && (
                  <Section title={L.codeNotes} who={<By who="code" />}>
                    <TextList items={arr(report.code_notes)} />
                  </Section>
                )}
              </>
            )}
          </>,
        )}
      </Workspace>
    </div>
  );
}
