// Import alerts from a JSON, JSONL or CSV file. The file's text is sent as the request body; no path ever leaves the browser.
import { useRef, useState } from "react";
import { api } from "../api.js";
import { ErrorBox, Notice } from "../components.jsx";
import Icon from "../icons.jsx";
import { L } from "../labels.js";

const MAX_IMPORT_BYTES = 2_000_000;
const MAX_ERRORS_SHOWN = 50;

export function ImportButton({ onDone, onReport }) {
  const input = useRef(null);
  const [busy, setBusy] = useState(false);

  async function onFile(event) {
    const file = event.target.files && event.target.files[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > MAX_IMPORT_BYTES) {
      onReport({ error: L.importTooBig });
      return;
    }
    setBusy(true);
    onReport(null);
    try {
      onReport({ result: await api.importAlerts(await file.text()) });
      onDone();
    } catch (e) {
      onReport({ error: e.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <input
        ref={input}
        id="import-file"
        type="file"
        accept=".json,.jsonl,.csv,.tsv,.txt,application/json,text/csv,text/plain"
        className="visually-hidden"
        tabIndex={-1}
        aria-hidden="true"
        onChange={onFile}
        disabled={busy}
      />
      <button type="button" className="btn" onClick={() => input.current && input.current.click()} disabled={busy} aria-describedby="import-help">
        <Icon name="upload" />{busy ? L.importing : L.importButton}
      </button>
      <span id="import-help" className="hint">
        {L.importHelp}
      </span>
    </>
  );
}

export function ImportReport({ report, onDismiss }) {
  if (!report) return null;
  if (report.error) return <ErrorBox message={report.error} />;
  const { imported, skipped, errors } = report.result;
  return (
    <Notice kind={errors.length ? "warn" : "info"} role="status" title={`${L.importTitle}.`}>
      {L.importResult(imported.length, skipped.length, errors.length)}
      <button type="button" className="link-btn" onClick={onDismiss}>
        {L.dismiss}
      </button>
      {errors.length > 0 && (
        <ul className="list import-errors">
          {errors.slice(0, MAX_ERRORS_SHOWN).map((e) => (
            <li key={e.row}>
              <strong>{L.importRow(e.row)}:</strong> {e.error}
            </li>
          ))}
        </ul>
      )}
    </Notice>
  );
}
