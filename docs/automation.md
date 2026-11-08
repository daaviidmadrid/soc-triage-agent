# Automatic processing in the local console

The scheduler in `src/app/automation.py` invokes the same `work`/`work_report` functions as
`POST /api/triage/{alert_id}` and `POST /api/reports/{key}`. These still consume the generators in
`src/app/runner.py`, persist every event/ticket/report and serve the existing SSE replay route.
Correlation calls the same `build_incidents` function and `src/agent/correlate.py`. Policy verdicts,
severity arithmetic, mandatory escalation, `_escalation_target` and `_final_actions` are unchanged.

The managed worker starts/stops with FastAPI's lifespan. Use **one backend process per database**.
Graceful shutdown drains the current job and manual threads. Crash recovery marks old runs failed
and returns only previously claimed durable jobs to pending. Recovery never scans the development
sample for work. Import stores alerts and inserts their jobs in a single SQLite transaction; duplicate
imports do neither. An explicit batch enrolls historical alerts. Concurrent manual/worker starts use
`BEGIN IMMEDIATE` to test for an active run and insert its replacement atomically, including across
SQLite connections. Jobs keep their origin, queued/started/finished times, run reference and reason.

Priority uses rule severity before triage, final severity for investigations, then the existing
`resolve_criticality` selection with local CMDB/directory context. Equal priorities keep enqueue order.
Neither ID numbering nor evidence text ranks work. Rules run first inside each alert; there is no
low-risk pre-pass before urgent work. The worker is sequential; an already running call is allowed
to finish before another job starts. Manual calls may run concurrently and share the same budget.

Quick completions are coalesced. Correlation is refreshed after the queue becomes quiet or at most
once per two-second interval between jobs. Input hashes skip unchanged reconstructions. Ticket
storage and disposition checks share a lock with correlation, preventing a closure against a
different ticket revision. Only completed analyses can close. Closed tickets remain correlation inputs.

## Budget and recovery

Defaults reuse `src/agent/batch.py`: 100 calls, three failures in a row, two-second pacing. A context
guard in `src/agent/llm.py` durably reserves one attempt immediately before **each** provider request,
including retries, fallback providers and correction calls in either triage or investigation. Pacing
applies to attempts. The SDK's existing hidden retries remain disabled. Trace attempt accounting
reuses `_calls_used`/`_out_of_quota` to handle injected runners and captured quota errors; guarded
attempts are never counted twice. Reservations are not refunded after a crash. Examples cost no
provider calls. A report always uses the same budget as a real triage.

The budget epoch belongs to the SQLite database. It has no midnight, pause or restart reset.
Changing `MAX_CALLS_PER_RUN` changes the limit, preserving consumed calls. Starting a new database
creates a new budget; it is an operator-selected independent store, not a restart mechanism.
`pause`/`resume` preserve the epoch, used calls, provider quota stop and failure counter. Only an
explicit `reset_budget`, with no active runs, creates another epoch and clears the stop/counter.
It cannot restore provider quota. Ordinary failed jobs require a deliberate retry; quota/budget
interruptions preserve the affected job as pending behind the operational stop. There is no retry
timer. A fallback ticket/report remains available to a person and never authorises closure.

## Compatible contract additions

Existing ticket fields/routes remain valid. SQLite adds `jobs`, `operations`, `dispositions` and
`operation_audit` without deleting historical runs, decisions or proposals.

| Contract | Additions |
|---|---|
| Ticket | Optional `analysis_origin`, `policy_flags`, `safety_checks`, `model_proposal` (original model verdict/escalate/adjustments before code validation); absent/null means unknown |
| `policy_flags` | Retains confirmed malicious execution, credential theft, persistence, personal-data exposure and economic fraud. Model fields omitted in its answer remain null, even though the existing policy draft uses false defaults for arithmetic |
| `safety_checks` | `citations_valid`, `authorisation_valid`, `evidence_complete`, `not_ot`, `injection_review_clear`, `deterministic_eligible`; all must be explicitly true for automatic closure |
| Queue item | `job`, `processing` (latest stored event for an active triage), `correlation_pending`, `disposition`, `report_key`, `report_state`; ticket summary also carries affected entities, attention reason and evidence completeness |
| Queue response | `automation`: flags, persisted pause/budget, jobs, recorded containment counts, audit, closure counts by rule and audit sample |
| Alert/ticket detail | Current `disposition` plus append-only `disposition_history`; a prior disposition with a mismatched revision is presented as requiring review immediately |
| Report response | `state.status` = pending/running/ready/stale/needed/not_required, plus `stale` and saved run reference |
| `POST /api/reports/{key}` | Reuses a successful current revision (`already_done: true`); the existing confirmed Repeat action explicitly passes `?repeat=1`. Failures/fallbacks can still be retried |
| Incidents response | Report state includes staleness; correlation staleness compares actual input revision, not just alert counts |
| `GroupLink` | Optional `strength`: `lead` for account/host-only reasons, `specific` when a saved reason names a specific shared identifier. It annotates existing correlation reasons without changing links or escalation; old rows can lack it |
| `DecisionIn.decision` | Also accepts `reopen`, with analyst and reason required; records review disposition and preserves history |
| `GET /api/automation` | Operational status, rule closure counts and randomly selected audit cases |
| `POST /api/automation/control` | `{ "action": "pause" / "resume" / "reset_budget" }` |
| `POST /api/automation/enqueue` | `{ "alert_ids": ["SYNTHETIC-CASE"] }`, maximum 2,000 existing alerts; pending/running work is not duplicated |

All write endpoints retain the local host/origin checks and `X-Tarvia-UI: 1` requirement.
No new endpoint approves or executes containment. Approval/execution routes remain human-only.
The existing console names approvers without authenticating their identity; its local-only scope
remains essential. Alert content and indicator strings are rendered as plain text, never visited.

## Revisions, closure and reports

A case revision hashes its stored ticket/run and its current incident, including membership and
correlation reasons. A change records a new review disposition with its predecessor, leaving human
decisions untouched. A human reopen cannot be immediately undone by automatic closure. Automatic
closure is only considered for cases without a prior disposition, backed by R1/R2 with complete
required checks and current correlation; severity alone and model confidence never suffice. Unknown
OT status, any unknown safety/mandatory flag, failed execution, unresolved injection concern,
`needs_more_info`, or individual/incident escalation refuses automatic closure. R1 can establish
complete linked evidence despite secondary searches being truncated; R2's later-activity searches
must all be complete. No new general closure rule is introduced.

Report jobs deduplicate by case key and input revision. Their snapshot includes the subject,
current triaged corpus and stored alert corpus. Invalidation is deliberately conservative:
unrelated new imports can make a report stale, because shared-identifier frequency and related-alert
discovery depend on the corpus. Obsolete pending revisions are superseded. A running report keeps
its original input fingerprint and becomes stale if inputs change; a new revision can then run.
No report-ready event itself rebuilds incidents. Reports only propose containment and never send
notifications to N2, SOC management or the CISO.

Automatic closure records origin `automation`, timestamp, reason, rule and cited evidence, plus
a random `sampled_for_review` selection. It does not create an analyst, human decision, approval
token or containment call. Counts describe current automatic closures; reopened cases keep the
earlier closure in history. `closed_by_rule` remains the historical triage-result origin field;
it is **not** proof of a final closed disposition.

## Visualisation and verification

Dashboard/queue show persisted stage counts and up to eight identifiable alert points per stage,
with an explicit sample label above that volume. A rule can bypass the LLM, reports are conditional,
and automatic dispositions do not complete a human-review stage. Containment is a separate branch
whose counts come only from saved proposals. The flow opens at most one SSE connection for an
active run; detail pages reuse the existing run stream. Polling reconciles persisted state every two
seconds and on reconnection. Native SSE reconnection is retained; a permanently closed proxy
connection is explicitly reopened after two seconds with the last persisted-event cursor. Streams
also reopen after the polling API recovers, covering proxies that retain an upstream socket without
reporting an SSE error. Streams and timers are cleaned up on run changes/navigation. Unknown subphases say processing; the last recorded lookup is labelled
as an observation, never as invented progress. Stages do not interpolate unrecorded durations.

Attention filters distinguish review, processing/pending, automatic closures and human resolutions.
Queue rows keep their reading order during background updates; explicit refresh or filtering
reprioritises. Resolution drafts survive tab changes and navigation using session storage per run.
Existing evidence links resolve to stored retrieval steps. No raw log viewer is fabricated.
There is no review countdown: queue times are original event time, queued time and actual run
duration. Policy SLA text remains a triage objective, not a deadline derived from historical dates.

Incident views default to escalations, with filtering, bounded HTML/SVG diagrams of saved alert
links and a complete accessible list. No inferred entity topology is drawn. Reports use verified
timestamps, daily groups, actual elapsed hours and an accessible ordered list; `added_by` labels
selection by model/code, never the actor who performed the event. Missing provenance/dates remain
explicit. Existing severity tokens, tooltip behaviour and reduced-motion utilities are retained.

Tests in `tests/test_automation.py` cover import-to-report, priority, duplicate/racing claims,
recovery, pause/resume, shared retries/corrections budget, both quota paths, failures, report
deduplication/invalidation, closure conditions/unknown metadata, new chains and manual mode.
`ui/src/queue/model.test.js` checks disposition/attention/stage distinctions. Browser verification
uses a temporary SQLite store and explicitly synthetic runners, never the real provider.
Results and remaining browser limits are recorded in [automation_verification.md](automation_verification.md).
