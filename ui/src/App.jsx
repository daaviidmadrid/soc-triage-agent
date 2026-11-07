import { useCallback, useEffect, useRef, useState } from "react";
import Queue from "./pages/Queue.jsx";
import Ticket from "./pages/Ticket.jsx";
import { api } from "./api.js";
import { L } from "./labels.js";
import { filtersFromQuery, nextPendingId, queueHash } from "./queue/model.js";

// Two screens and no router: "#/alerta/<id>" opens an alert; "#/" or "#/?estado=…" shows the queue with its filters.
function readRoute() {
  const hash = window.location.hash;
  const m = hash.match(/^#\/alerta\/(.+)$/);
  if (m) {
    try {
      return { alertId: decodeURIComponent(m[1]), query: "" };
    } catch {
      return { alertId: null, query: "" };
    }
  }
  const q = hash.match(/^#\/\?(.*)$/);
  return { alertId: null, query: q ? q[1] : "" };
}

function ExampleBanner({ mode }) {
  return (
    <div className="banner-example" role="note">
      <strong className="banner-label">{L.exampleBannerTitle}</strong>
      <span>{mode === "example" ? L.exampleBannerText : L.exampleMixedText}</span>
    </div>
  );
}

export default function App() {
  const [route, setRoute] = useState(readRoute);
  const [filters, setFilters] = useState(() => filtersFromQuery(readRoute().query));
  // What the backend reports: "example" or "real", plus whether example results are on screen.
  const [mode, setMode] = useState(null);
  const [exampleOnScreen, setExampleOnScreen] = useState(false);
  const main = useRef(null);
  // Where the analyst was in the queue, so "Volver a la cola" lands on the same row.
  const returnTo = useRef({ scrollY: 0, alertId: null });
  const firstRender = useRef(true);
  const alertId = route.alertId;

  useEffect(() => {
    const onHash = () => {
      const r = readRoute();
      setRoute(r);
      if (!r.alertId) setFilters(filtersFromQuery(r.query));
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Filter changes rewrite the hash in place: a reload keeps them, and they don't fill the Back history.
  useEffect(() => {
    if (alertId) return;
    const wanted = queueHash(filters);
    const current = window.location.hash || "#/";
    if (current !== wanted && !(wanted === "#/" && current === "#")) window.history.replaceState(null, "", wanted);
  }, [filters, alertId]);

  useEffect(() => {
    document.title = alertId ? `${alertId} · ${L.appTitle}` : L.appTitle;
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    // A new screen starts at its top, with focus at the start of the content. The queue restores its own place.
    if (alertId) {
      window.scrollTo(0, 0);
      if (main.current) main.current.focus({ preventScroll: true });
    }
  }, [alertId]);

  const openAlert = useCallback((id) => {
    returnTo.current = { scrollY: window.scrollY, alertId: id };
    window.location.hash = `#/alerta/${encodeURIComponent(id)}`;
  }, []);
  const openQueue = useCallback(() => {
    window.location.hash = queueHash(filters);
  }, [filters]);
  // After a decision: the next alert nobody has decided, in the queue's order and with the analyst's filters.
  const openNext = useCallback(
    async (currentId) => {
      const data = await api.queue();
      const id = nextPendingId(data.alerts, filters, currentId);
      if (id) {
        returnTo.current = { scrollY: 0, alertId: id };
        window.location.hash = `#/alerta/${encodeURIComponent(id)}`;
      }
      return id;
    },
    [filters],
  );
  const report = useCallback((m, example) => {
    setMode(m);
    setExampleOnScreen(Boolean(example));
  }, []);

  return (
    <div className="app">
      {/* A button, not a #fragment link: the hash is this app's navigation */}
      <button type="button" className="btn skip-link" onClick={() => main.current && main.current.focus()}>
        {L.skipToContent}
      </button>
      <header className="topbar">
        <div className="brand">
          <button type="button" className="brand-btn" onClick={openQueue}>
            {L.appTitle}
          </button>
          <span className="muted">{L.appSubtitle}</span>
        </div>
        {mode && <span className={`mode mode-${mode === "real" ? "real" : "example"}`}>{mode === "real" ? L.modeReal : L.modeExample}</span>}
      </header>
      {(mode === "example" || exampleOnScreen) && <ExampleBanner mode={mode} />}
      <main className="content" id="main" ref={main} tabIndex={-1}>
        {alertId ? (
          <Ticket key={alertId} alertId={alertId} onBack={openQueue} onNext={openNext} onReport={report} />
        ) : (
          <Queue onOpen={openAlert} onReport={report} filters={filters} setFilters={setFilters} returnTo={returnTo.current} />
        )}
      </main>
    </div>
  );
}
