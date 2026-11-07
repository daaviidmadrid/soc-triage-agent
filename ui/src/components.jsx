// Shared building blocks. All data is rendered as React text, so HTML in it shows as text.
// Never use dangerouslySetInnerHTML, and never turn data into links or images.
import { useState } from "react";
import Icon from "./icons.jsx";
import { L, SEVERITY, SLA } from "./labels.js";

// Data helpers: the formats may change, so every read tolerates missing or odd values.
export function obj(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

export function arr(value) {
  return Array.isArray(value) ? value : [];
}

export function isBlank(value) {
  return value === null || value === undefined || value === "" || (Array.isArray(value) && value.length === 0);
}

export function asText(value) {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

// "2026-10-05T07:56:30.000Z" -> "2026-10-05 07:56". Anything else is shown as given.
export function formatTime(value) {
  if (typeof value !== "string") return null;
  const m = value.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/);
  return m ? `${m[1]} ${m[2]}` : value;
}

export function formatSeconds(seconds) {
  if (typeof seconds !== "number" || !isFinite(seconds)) return null;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

export function NA() {
  return <span className="na">{L.na}</span>;
}

export function None() {
  return <span className="muted">{L.none}</span>;
}

// Long text is cut, with a button to expand it.
export function Clip({ value, max = 280, pre = false }) {
  const [open, setOpen] = useState(false);
  if (isBlank(value)) return <NA />;
  const text = asText(value);
  const long = text.length > max;
  const shown = long && !open ? text.slice(0, max) + "…" : text;
  const Tag = pre ? "pre" : "span";
  return (
    <>
      <Tag className={pre ? "raw" : "text"}>{shown}</Tag>
      {long && (
        <button type="button" className="link-btn" aria-expanded={open} onClick={() => setOpen(!open)}>
          {open ? L.showLess : L.showMore(text.length)}
        </button>
      )}
    </>
  );
}

// Severity is always text plus colour, never colour alone.
export function Severity({ value, note }) {
  if (!Object.prototype.hasOwnProperty.call(SEVERITY, value)) {
    return isBlank(value) ? <NA /> : <span className="sev sev-unknown">{asText(value)}</span>;
  }
  return (
    <span className={`sev sev-${value}`}>
      <span className="sev-mark" aria-hidden="true" />
      {SEVERITY[value]}
      {note && <span className="sev-note">{note}</span>}
    </span>
  );
}

export function ModeTag({ mode }) {
  if (mode === "example") return <span className="chip chip-example">{L.exampleTag}</span>;
  if (mode === "real") return <span className="chip chip-real">{L.realTag}</span>;
  return null;
}

export function Chip({ kind, children, title }) {
  return (
    <span className={`chip chip-${kind}`} title={title}>
      {children}
    </span>
  );
}

export function List({ items, render = (x) => <Clip value={x} /> }) {
  if (!Array.isArray(items) || items.length === 0) return <None />;
  return (
    <ul className="list">
      {items.map((item, i) => (
        <li key={i}>{render(item, i)}</li>
      ))}
    </ul>
  );
}

export function Ids({ ids, max }) {
  const all = arr(ids);
  if (all.length === 0) return null;
  const shown = max ? all.slice(0, max) : all;
  return (
    <span className="ids">
      {shown.map((id, i) => (
        <code key={i} className="id">
          {asText(id)}
        </code>
      ))}
      {shown.length < all.length && <span className="muted">+{all.length - shown.length}</span>}
    </span>
  );
}

// `id` makes the field a target for the in-page jumps (progress strip, evidence links).
export function Field({ label, children, id }) {
  return (
    <div className="field" id={id} tabIndex={id ? -1 : undefined}>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

// Policy target for a severity, and how long triage took against it. Never a countdown from the alert's time.
export function SlaCell({ severity, fromRule, seconds, running }) {
  const sla = SLA[severity];
  if (!sla) return <NA />;
  const took = formatSeconds(seconds);
  return (
    <span className="sla" title={L.slaHelp}>
      <span>
        {L.slaTarget(sla.label)}
        {fromRule && <span className="muted"> ({L.fromRule})</span>}
      </span>
      {running && <span className="muted">{L.stateRunning}…</span>}
      {!running && took && (
        <span>
          {L.slaTook(took)}{" "}
          {sla.seconds === null ? (
            <span className="muted">({L.slaBatch})</span>
          ) : seconds <= sla.seconds ? (
            <span className="ok with-icon">
              <Icon name="check" />
              {L.slaWithin}
            </span>
          ) : (
            <span className="bad with-icon">
              <Icon name="cross" />
              {L.slaOutside}
            </span>
          )}
        </span>
      )}
    </span>
  );
}

// Loading placeholder shaped like the content it stands for. Screen readers get the label.
export function Skeleton({ rows = 6, cols = 4, label }) {
  return (
    <div className="skeleton" role="status">
      <span className="visually-hidden">{label}</span>
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="skeleton-row" aria-hidden="true">
          {Array.from({ length: cols }, (_, c) => (
            <span key={c} className="skeleton-bar" />
          ))}
        </div>
      ))}
    </div>
  );
}

export function Notice({ kind = "info", title, icon, children, role }) {
  return (
    <div className={`notice notice-${kind}`} role={role}>
      {icon && <Icon name={icon} className="notice-icon" />}
      <div className="notice-body">
        {title && <strong className="notice-title">{title}</strong>} {children}
      </div>
    </div>
  );
}

export function ErrorBox({ message, onRetry }) {
  return (
    <Notice kind="error" role="alert" icon="alert" title={`${L.errorPrefix}:`}>
      <span className="text">{message}</span>
      {onRetry && (
        <button type="button" className="btn btn-sm notice-action" onClick={onRetry}>
          {L.retry}
        </button>
      )}
    </Notice>
  );
}
