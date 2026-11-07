import { useCallback, useEffect, useRef, useState } from "react";
import Queue from "./pages/Queue.jsx";
import Ticket from "./pages/Ticket.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Icon from "./icons.jsx";
import { api } from "./api.js";
import { L } from "./labels.js";
import { filtersFromQuery, nextPendingId, queueHash } from "./queue/model.js";

// Two screens and no router: "#/alerta/<id>" opens an alert; "#/" or "#/?estado=…" shows the queue with its filters.
function readRoute() {
  const hash = window.location.hash;
  if (!hash || hash === "#" || hash === "#/dashboard") return { view: "dashboard", alertId: null, query: "" };
  const m = hash.match(/^#\/alerta\/(.+)$/);
  if (m) {
    try {
      return { view: "ticket", alertId: decodeURIComponent(m[1]), query: "" };
    } catch {
      return { view: "queue", alertId: null, query: "" };
    }
  }
  const q = hash.match(/^#\/\?(.*)$/);
  return { view: "queue", alertId: null, query: q ? q[1] : "" };
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
  const [menuOpen, setMenuOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [mobile, setMobile] = useState(() => window.matchMedia("(max-width: 700px)").matches);
  const sidebar = useRef(null);
  const restoreMenuFocus = useRef(false);
  const closeMenu = useCallback(() => { restoreMenuFocus.current = true; setMenuOpen(false); }, []);
  useEffect(() => {
    if (!menuOpen && restoreMenuFocus.current) {
      restoreMenuFocus.current = false;
      document.getElementById("menu-toggle")?.focus({ preventScroll: true });
    }
  }, [menuOpen]);
  useEffect(() => {
    const media = window.matchMedia("(max-width: 700px)");
    const change = () => { setMobile(media.matches); setMenuOpen(false); };
    media.addEventListener("change", change);
    return () => media.removeEventListener("change", change);
  }, []);
  const main = useRef(null);
  // Where the analyst was in the queue, so "Volver a la cola" lands on the same row.
  const returnTo = useRef({ scrollY: 0, alertId: null });
  const firstRender = useRef(true);
  const alertId = route.alertId;

  useEffect(() => {
    const onHash = () => {
      const r = readRoute();
      setRoute(r);
      setMenuOpen(false);
      if (r.view === "queue") setFilters(filtersFromQuery(r.query));
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // Filter changes rewrite the hash in place: a reload keeps them, and they don't fill the Back history.
  useEffect(() => {
    if (route.view !== "queue") return;
    const wanted = queueHash(filters);
    const current = window.location.hash || "#/";
    if (current !== wanted && !(wanted === "#/" && current === "#")) window.history.replaceState(null, "", wanted);
  }, [filters, route.view]);

  useEffect(() => {
    document.title = `${alertId || (route.view === "dashboard" ? L.dashboardTitle : L.queueTitle)} · ${L.appTitle}`;
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    // A new screen starts at its top, with focus at the start of the content. The queue restores its own place.
    if (route.view !== "queue") {
      window.scrollTo(0, 0);
      if (main.current) main.current.focus({ preventScroll: true });
    }
  }, [alertId, route.view]);

  useEffect(() => {
    if (!mobile || !menuOpen) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    sidebar.current?.querySelector(".sidebar-link.selected")?.focus({ preventScroll: true });
    const close = event => {
      if (event.key === "Escape") { event.preventDefault(); closeMenu(); }
      if (event.key === "Tab") {
        const controls = [...sidebar.current.querySelectorAll("a, button")];
        const first = controls[0], last = controls.at(-1);
        if (!sidebar.current.contains(document.activeElement)) { event.preventDefault(); first?.focus(); }
        else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    };
    window.addEventListener("keydown", close);
    return () => { document.body.style.overflow = previousOverflow; window.removeEventListener("keydown", close); };
  }, [menuOpen, mobile, closeMenu]);

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

  const showQueue = useCallback((patch = {}) => {
    const next = { q: "", product: "", severity: "", state: "", injection: false, ...patch };
    setFilters(next);
    window.location.hash = queueHash(next);
    setMenuOpen(false);
    window.scrollTo(0, 0);
  }, []);
  const current = route.view === "dashboard" ? "dashboard" : alertId ? "queue" : filters.state === "pending" ? "review" : filters.state === "decided" ? "resolved" : "queue";
  const navigation = [
    { id: "dashboard", icon: "dashboard", label: L.navDashboard, href: "#/dashboard" },
    { id: "queue", icon: "queue", label: L.navAlerts, filters: {} },
    { id: "review", icon: "review", label: L.navReview, filters: { state: "pending" } },
    { id: "resolved", icon: "archive", label: L.navResolved, filters: { state: "decided" } },
  ];

  return (
    <div className={`app console-shell${menuOpen ? " menu-open" : ""}${collapsed ? " sidebar-collapsed" : ""}`}>
      {/* A button, not a #fragment link: the hash is this app's navigation */}
      <button type="button" className="btn skip-link" onClick={() => main.current && main.current.focus()}>
        {L.skipToContent}
      </button>
      <aside className="sidebar" id="main-navigation" ref={sidebar} inert={mobile && !menuOpen} role={mobile && menuOpen ? "dialog" : undefined} aria-modal={mobile && menuOpen ? true : undefined} aria-label={L.navLabel}>
        <button className="btn sidebar-close" aria-label={L.closeMenu} onClick={closeMenu}><Icon name="cross" /></button>
        <a className="console-brand" href="#/dashboard" onClick={() => setMenuOpen(false)} aria-label="Tarvia · Operaciones de seguridad"><span className="console-mark"><Icon name="shield" /></span><span className="brand-name">Tarvia<span className="brand-caption">{L.brandCaption}</span></span></a>
        <div className="sidebar-section">{L.navWorkspace}</div>
        <nav aria-label={L.navLabel}>{navigation.map(item => <a key={item.id} href={item.href || queueHash({ q: "", product: "", severity: "", state: "", injection: false, ...item.filters })} className={`sidebar-link${current === item.id ? " selected" : ""}`} aria-label={item.label} aria-current={current === item.id ? "page" : undefined} onClick={event => { if (item.filters) { event.preventDefault(); showQueue(item.filters); } else setMenuOpen(false); }}><Icon name={item.icon} /><span className="nav-label">{item.label}</span>{current === item.id && <span className="nav-active-dot" />}</a>)}</nav>
      </aside>
      {mobile && menuOpen && <button className="menu-scrim" tabIndex={-1} aria-label={L.closeMenu} onClick={closeMenu} />}
      <div className="console-workspace" inert={mobile && menuOpen}>
        <header className="topbar">
          <div className="topbar-left"><button className="btn btn-icon navigation-toggle" id="menu-toggle" aria-label={mobile ? (menuOpen ? L.closeMenu : L.openMenu) : (collapsed ? L.expandMenu : L.collapseMenu)} aria-expanded={mobile ? menuOpen : !collapsed} aria-controls="main-navigation" onClick={() => mobile ? setMenuOpen(value => !value) : setCollapsed(value => !value)}><Icon name={mobile && menuOpen ? "cross" : "menu"} /></button><span className="topbar-workspace">{L.workspaceName}</span><span className="breadcrumb-divider">/</span><strong>{alertId ? L.alertTitle : route.view === "dashboard" ? L.dashboardTitle : L.queueTitle}</strong></div>
          <div className="topbar-right">{mode && <span className={`mode mode-${mode === "real" ? "real" : "example"}`}><span className="status-dot" />{mode === "real" ? L.modeReal : L.modeExample}</span>}<span className="workspace-avatar" aria-label={L.workspaceName}>TG</span></div>
        </header>
        {(mode === "example" || exampleOnScreen) && <ExampleBanner mode={mode} />}
        <main className="content" id="main" ref={main} tabIndex={-1}>
        {route.view === "dashboard" ? <Dashboard onOpen={openAlert} onQueue={showQueue} onReport={report} /> : alertId ? (
          <Ticket key={alertId} alertId={alertId} onBack={openQueue} onNext={openNext} onReport={report} />
        ) : (
          <Queue onOpen={openAlert} onReport={report} filters={filters} setFilters={setFilters} returnTo={returnTo.current} />
        )}
        </main>
      </div>
    </div>
  );
}
