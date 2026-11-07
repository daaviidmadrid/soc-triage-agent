// The alert queue: what is waiting, what has been triaged, and what a person still has to decide.
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { Chip, Clip, ErrorBox, ModeTag, NA, Notice, Severity, Skeleton, SlaCell, formatTime } from "../components.jsx";
import { Pager } from "../ticket/Paging.jsx";
import Icon from "../icons.jsx";
import { ImportButton, ImportReport } from "../queue/ImportBox.jsx";
import { EMPTY_FILTERS, countsOf, effective, filterAndSort, isFiltered, productsOf, stateOf } from "../queue/model.js";
import { L, OUTCOME, SEVERITY, SEVERITY_ORDER, STATE_FILTERS, VERDICT } from "../labels.js";

const POLL_MS = 2000;
const PAGE_SIZE = 8;
// The last queue the screen showed, so coming back from a ticket draws it at once (then refreshes).
let cachedData = null;

function StateCell({ item, changed }) {
  const state = stateOf(item);
  const flash = changed ? " state-changed" : "";
  if (state === "decided") {
    return (
      <span className={`state state-decided${flash}`}>
        {L.stateDecided}: {OUTCOME[item.decision.outcome] || item.decision.outcome}
        <span className="muted"> · {item.decision.analyst}</span>
      </span>
    );
  }
  const text = { none: L.stateNone, running: `${L.stateRunning}…`, failed: L.stateFailed, pending: L.statePending }[state];
  return <span className={`state state-${state}${flash}`}>{text}</span>;
}

// Counts over the whole queue. Each one is also a filter: press it to show only those alerts, press again to undo.
function Counts({ counts, filters, setFilters }) {
  const states = ["pending", "running", "failed", "decided", "none"];
  const labels = { pending: L.statePending, running: L.stateRunning, failed: L.stateFailed, decided: L.stateDecided, none: L.stateNone };
  return (
    <div className="counts" role="group" aria-label={L.countsLabel}>
      {states.map((key) => (
        <button
          key={key}
          type="button"
          className={`count count-${key}${counts[key] === 0 ? " is-zero" : ""}`}
          aria-pressed={filters.state === key}
          onClick={() => setFilters((f) => ({ ...f, state: f.state === key ? "" : key }))}
        >
          <span className="count-n num">{counts[key]}</span>
          <span>{labels[key]}</span>
        </button>
      ))}
      <button
        type="button"
        className={`count count-injection${counts.injection === 0 ? " is-zero" : ""}`}
        aria-pressed={filters.injection}
        onClick={() => setFilters((f) => ({ ...f, injection: !f.injection }))}
      >
        <span className="count-n num">{counts.injection}</span>
        <Icon name="alert" />
        <span>{L.countInjection}</span>
      </button>
      {isFiltered(filters) && (
        <button type="button" className="link-btn" onClick={() => setFilters(EMPTY_FILTERS)}>
          {L.countClear}
        </button>
      )}
    </div>
  );
}

function Filters({ filters, setFilters, products }) {
  const set = (key) => (event) => {
    const value = event.target.value;
    setFilters((f) => ({ ...f, [key]: value }));
  };
  return (
    <form className="filters" onSubmit={(e) => e.preventDefault()} role="search">
      <label className="control">
        <span className="control-label">{L.filterSearch}</span>
        <input type="search" value={filters.q} onChange={set("q")} placeholder={L.filterSearchPlaceholder} />
      </label>
      <label className="control">
        <span className="control-label">{L.filterProduct}</span>
        <select value={filters.product} onChange={set("product")}>
          <option value="">{L.filterAll}</option>
          {products.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </label>
      <label className="control">
        <span className="control-label">{L.filterSeverity}</span>
        <select value={filters.severity} onChange={set("severity")}>
          <option value="">{L.filterAllF}</option>
          <option value="priority">{L.priorityFilter}</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {SEVERITY[s]}
            </option>
          ))}
        </select>
      </label>
      <label className="control">
        <span className="control-label">{L.filterState}</span>
        <select value={filters.state} onChange={set("state")}>
          <option value="">{L.filterAll}</option>
          {Object.entries(STATE_FILTERS).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
      </label>
    </form>
  );
}

function Shortcuts({ onClose }) {
  return (
    <section className="panel shortcuts" id="shortcuts" aria-labelledby="shortcuts-title">
      <div className="shortcuts-head">
        <h2 id="shortcuts-title">{L.shortcutsTitle}</h2>
        <button type="button" className="btn btn-sm btn-ghost" onClick={onClose}>
          {L.dismiss}
        </button>
      </div>
      <dl className="shortcut-list">
        {L.shortcutsList.map(([key, what]) => (
          <div key={key} className="shortcut">
            <dt>
              <kbd>{key}</kbd>
            </dt>
            <dd>{what}</dd>
          </div>
        ))}
      </dl>
      <p className="hint">{L.shortcutsNote}</p>
    </section>
  );
}

// The whole row opens the alert. Clicks on the row's own buttons, or while selecting text, don't.
function Row({ item, active, tabbable, changed, starting, onStart, onOpen, onFocusRow, rowRef }) {
  const eff = effective(item);
  const t = item.ticket;
  const example = Boolean(t && item.run && item.run.mode === "example");
  const running = Boolean(item.run && item.run.status === "running");
  const startLabel = item.run ? L.retriage : L.triage;
  const id = item.alert_id;

  function onClick(event) {
    if (event.target.closest("button, a, input, select, textarea")) return;
    const selection = window.getSelection && String(window.getSelection());
    if (selection) return;
    onOpen(id);
  }
  function onKeyDown(event) {
    if (event.key === "Enter" && event.target === event.currentTarget) {
      event.preventDefault();
      onOpen(id);
    }
  }

  const classes = ["row", example && "row-example", active && "is-active"].filter(Boolean).join(" ");
  return (
    <tr ref={rowRef} className={classes} tabIndex={tabbable ? 0 : -1} onClick={onClick} onKeyDown={onKeyDown} onFocus={() => onFocusRow(id)}>
      <td className="rule" data-label={L.colAlert}>
        <strong className="queue-rule">{item.rule_name || L.na}</strong>
        <div className="queue-meta"><code className="id">{id}</code>{item.origin === "imported" && <Chip kind="origin">{L.originImported}</Chip>}</div>
        <div className="sub">{item.source_product || L.na}{item.rule_id && <> · <span className="id-plain">{item.rule_id}</span></>}</div>
      </td>
      <td className="num" data-label={L.colTime}><span className="queue-date">{formatTime(item.created_at) || L.na}</span><span className="sub">UTC</span></td>
      <td data-label={L.filterSeverity}><Severity value={eff.severity} /><div className="sub">{L.fromRule}: {SEVERITY[item.rule_severity] || L.na}</div></td>
      <td data-label={L.queueResult}>
        {t && <div className="queue-verdict">{VERDICT[t.verdict] || t.verdict || L.na}</div>}
        <StateCell item={item} changed={changed} />
        <div className="queue-meta">{t && <ModeTag mode={t.mode} />}{t?.injection_flags > 0 && <Chip kind="warn"><Icon name="alert" />{L.injectionShort}</Chip>}</div>
      </td>
      <td data-label={L.colSla}><SlaCell severity={eff.severity} fromRule={eff.fromRule} seconds={item.run?.status === "done" ? item.run.duration_seconds : null} running={running} /></td>
      <td className="actions">
        <button
          type="button"
          className="btn btn-sm btn-primary"
          onClick={() => onStart(item)}
          disabled={running || starting}
          aria-label={`${startLabel} ${id}`}
        >
          {starting ? L.starting : item.run ? L.retriageShort : L.triage}
        </button>
        <button type="button" className="btn btn-sm" onClick={() => onOpen(id)} aria-label={`${L.open} ${id}`}>
          {L.open}
        </button>
      </td>
    </tr>
  );
}

export default function Queue({ onOpen, onReport, filters, setFilters, returnTo }) {
  const [data, setData] = useState(cachedData);
  const [error, setError] = useState(null);
  const [starting, setStarting] = useState({});
  const [startError, setStartError] = useState(null);
  const [importReport, setImportReport] = useState(null);
  const [activeId, setActiveId] = useState(returnTo && returnTo.alertId);
  const [page, setPage] = useState(0);
  const pendingFocus = useRef(null);
  const [help, setHelp] = useState(false);
  const [changed, setChanged] = useState(() => new Set());
  const rowEls = useRef(new Map());
  const prevStates = useRef(new Map());
  const restored = useRef(false);

  const load = useCallback(async () => {
    try {
      const result = await api.queue();
      cachedData = result;
      setData(result);
      setError(null);
      onReport(result.mode, result.example_results > 0);
    } catch (e) {
      setError(e.message);
    }
  }, [onReport]);

  useEffect(() => {
    load();
  }, [load]);

  // A run that finished since the last poll gets a short highlight on its state. Nothing else animates here.
  useEffect(() => {
    if (!data) return;
    const next = new Map(data.alerts.map((a) => [a.alert_id, stateOf(a)]));
    const finished = new Set();
    for (const [id, state] of next) {
      if (prevStates.current.get(id) === "running" && state !== "running") finished.add(id);
    }
    prevStates.current = next;
    setChanged(finished);
  }, [data]);

  const anyRunning = Boolean(data && data.alerts.some((a) => a.run && a.run.status === "running"));
  useEffect(() => {
    if (!anyRunning) return undefined;
    const timer = setInterval(load, POLL_MS);
    return () => clearInterval(timer);
  }, [anyRunning, load]);

  const start = useCallback(
    async (item) => {
      const alertId = item.alert_id;
      if (item.ticket && !window.confirm(L.retriageConfirm)) return;
      setActiveId(alertId);
      setStarting((s) => ({ ...s, [alertId]: true }));
      setStartError(null);
      try {
        await api.triage(alertId);
        await load();
      } catch (e) {
        setStartError(`${alertId}: ${e.message}`);
      } finally {
        setStarting((s) => ({ ...s, [alertId]: false }));
      }
    },
    [load],
  );

  const products = useMemo(() => (data ? productsOf(data.alerts) : []), [data]);
  const counts = useMemo(() => (data ? countsOf(data.alerts) : null), [data]);
  const rows = useMemo(() => (data ? filterAndSort(data.alerts, filters) : []), [data, filters]);

  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const currentPage = Math.min(page, pages - 1);
  const visibleRows = rows.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
  const filterKey = JSON.stringify(filters);
  const previousFilters = useRef(filterKey);
  useEffect(() => { if (previousFilters.current !== filterKey) { previousFilters.current = filterKey; setPage(0); } }, [filterKey]);
  useLayoutEffect(() => {
    if (pendingFocus.current) {
      const el = rowEls.current.get(pendingFocus.current);
      if (el) { el.focus({ preventScroll: true }); pendingFocus.current = null; }
    }
  }, [currentPage, activeId, data]);

  // Back from a ticket: same scroll position, focus on the row that was opened.
  useLayoutEffect(() => {
    if (restored.current || !data) return;
    restored.current = true;
    if (!returnTo || !returnTo.alertId) return;
    const index = rows.findIndex(row => row.alert_id === returnTo.alertId);
    if (index >= 0) { setPage(Math.floor(index / PAGE_SIZE)); pendingFocus.current = returnTo.alertId; }
    window.scrollTo(0, returnTo.scrollY || 0);
    const el = rowEls.current.get(returnTo.alertId);
    if (el) el.focus({ preventScroll: true });
  }, [data, returnTo]);

  // Keyboard: j/k move, Enter opens (on the row itself), t triages, ? toggles help. Moves are instant, never animated.
  const keyState = useRef({});
  keyState.current = { rows, activeId, starting, start, help };
  useEffect(() => {
    function focusRow(id) {
      const el = rowEls.current.get(id);
      if (!el) return;
      el.focus({ preventScroll: true });
      el.scrollIntoView({ block: "nearest" });
    }
    function onKey(event) {
      if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) return;
      const target = event.target;
      if (target && target.closest && target.closest("input, select, textarea, [contenteditable='true']")) return;
      const s = keyState.current;
      if (event.key === "?") {
        event.preventDefault();
        setHelp((h) => !h);
      } else if (event.key === "Escape" && s.help) {
        setHelp(false);
      } else if ((event.key === "j" || event.key === "k") && s.rows.length > 0) {
        event.preventDefault();
        const i = s.rows.findIndex((r) => r.alert_id === s.activeId);
        const delta = event.key === "j" ? 1 : -1;
        const next = i === -1 ? (delta > 0 ? 0 : s.rows.length - 1) : Math.min(s.rows.length - 1, Math.max(0, i + delta));
        const id = s.rows[next].alert_id;
        pendingFocus.current = id;
        setPage(Math.floor(next / PAGE_SIZE));
        setActiveId(id);
        focusRow(id);
      } else if (event.key === "t") {
        const item = s.rows.find((r) => r.alert_id === s.activeId);
        if (item && !(item.run && item.run.status === "running") && !s.starting[item.alert_id]) {
          event.preventDefault();
          s.start(item);
        }
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (error && !data) return <ErrorBox message={error} onRetry={load} />;
  if (!data) return <Skeleton rows={10} cols={6} label={L.loading} />;

  // Only one row is a Tab stop: the active one, or the first.
  const tabRow = visibleRows.some((r) => r.alert_id === activeId) ? activeId : visibleRows[0]?.alert_id;

  return (
    <div className="queue">
      <header className="page-head">
        <div className="page-title">
          <h1>{L.queueTitle}</h1>
          <span className="muted num">{L.queueCount(rows.length, data.alerts.length)}</span>
        </div>
        <div className="page-actions">
          <ImportButton onDone={load} onReport={setImportReport} />
          <button type="button" className="btn" onClick={load}>
            {L.refresh}
          </button>
          <button type="button" className="btn btn-ghost shortcuts-toggle" aria-expanded={help} aria-controls="shortcuts" onClick={() => setHelp((h) => !h)}>
            <kbd aria-hidden="true">?</kbd>
            {L.shortcutsButton}
          </button>
        </div>
      </header>

      {help && <Shortcuts onClose={() => setHelp(false)} />}
      {error && <ErrorBox message={error} onRetry={load} />}
      {data.sample && data.sample.error && (
        <Notice kind="warn" role="status" title={`${L.sampleProblem}:`}>
          {data.sample.error}
        </Notice>
      )}
      {startError && <ErrorBox message={startError} />}
      <ImportReport report={importReport} onDismiss={() => setImportReport(null)} />

      <Counts counts={counts} filters={filters} setFilters={setFilters} />
      <Filters filters={filters} setFilters={setFilters} products={products} />

      {data.alerts.length === 0 ? (
        <Notice>
          {L.queueEmpty} {L.queueEmptyAction}
        </Notice>
      ) : rows.length === 0 ? (
        <Notice>
          {L.queueNoMatch}{" "}
          <button type="button" className="btn btn-sm notice-action" onClick={() => setFilters(EMPTY_FILTERS)}>
            {L.countClear}
          </button>
        </Notice>
      ) : (
        <div className="table-wrap">
          <p className="table-caption" id="queue-sort">
            {L.sortCaption}
          </p>
          <table className="grid" aria-describedby="queue-sort">
            <thead>
              <tr>
                <th scope="col">{L.colAlert}</th><th scope="col">{L.colTime}</th><th scope="col">{L.filterSeverity}</th><th scope="col">{L.queueResult}</th><th scope="col">{L.colSla}</th><th scope="col" className="actions">{L.colActions}</th>
              </tr>
            </thead>
            <tbody>
              {visibleRows.map((item) => (
                <Row
                  key={item.alert_id}
                  item={item}
                  active={item.alert_id === activeId}
                  tabbable={item.alert_id === tabRow}
                  changed={changed.has(item.alert_id)}
                  starting={Boolean(starting[item.alert_id])}
                  onStart={start}
                  onOpen={onOpen}
                  onFocusRow={setActiveId}
                  rowRef={(el) => {
                    if (el) rowEls.current.set(item.alert_id, el);
                    else rowEls.current.delete(item.alert_id);
                  }}
                />
              ))}
            </tbody>
          </table>
          <Pager page={currentPage} pages={pages} onPage={setPage} label={L.queueTitle} />
        </div>
      )}
    </div>
  );
}
