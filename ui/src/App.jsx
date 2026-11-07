import { useCallback, useEffect, useRef, useState } from "react";
import Incidents from "./pages/Incidents.jsx";
import Queue from "./pages/Queue.jsx";
import Report from "./pages/Report.jsx";
import Ticket from "./pages/Ticket.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Icon from "./icons.jsx";
import { useMotionInput, useSelectionIndicator, useWorkspaceMotion } from "./motion.js";
import { api } from "./api.js";
import { L } from "./labels.js";
import { filtersFromQuery, nextPendingId, queueHash } from "./queue/model.js";

// Five screens and no router: "#/" with no filters or "#/dashboard" shows the dashboard, "#/alerta/<id>" opens an alert,
// "#/incidentes" shows the incidents (level 2), "#/informe/<key>" the report of an incident or escalated ticket (level 3),
// and "#/?estado=…" shows the queue with its filters.
function readRoute() {
  const hash = window.location.hash;
  if (!hash || hash === "#" || hash === "#/dashboard") return { view: "dashboard", alertId: null, query: "" };
  if (hash === "#/incidentes") return { view: "incidents", alertId: null, query: "" };
  const r = hash.match(/^#\/informe\/(.+)$/);
  if (r) {
    try {
      return { view: "report", alertId: null, query: "", reportKey: decodeURIComponent(r[1]) };
    } catch {
      return { view: "incidents", alertId: null, query: "" };
    }
  }
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
  const sidebar = useRef(null), nav = useRef(null), workspace = useRef(null);
  useMotionInput();
  const prepareWorkspace = useWorkspaceMotion(workspace, collapsed);
  const restoreMenuFocus = useRef(null);
  const closeMenu = useCallback(() => { restoreMenuFocus.current = "menu-toggle"; setMenuOpen(false); }, []);
  useEffect(() => {
    if (!menuOpen && restoreMenuFocus.current) {
      const target = restoreMenuFocus.current;
      restoreMenuFocus.current = null;
      document.getElementById(target)?.focus({ preventScroll: true });
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
  const screenTitle = alertId ? L.alertTitle : route.view === "dashboard" ? L.dashboardTitle : route.view === "incidents" ? L.incidentsTitle : route.view === "report" ? `${L.reportTitle} ${route.reportKey}` : L.queueTitle;

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
    document.title = `${alertId || screenTitle} · ${L.appTitle}`;
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
  const openIncidents = useCallback(() => {
    window.location.hash = "#/incidentes";
  }, []);
  const openReport = useCallback((key) => {
    window.location.hash = `#/informe/${encodeURIComponent(key)}`;
  }, []);
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
  const current = route.view === "dashboard" || route.view === "incidents" ? route.view : route.view === "report" ? "incidents" : alertId ? "queue" : filters.state === "pending" ? "review" : filters.state === "decided" ? "resolved" : "queue";
  const navigation = [
    { id: "dashboard", icon: "dashboard", label: L.navDashboard, href: "#/dashboard" },
    { id: "queue", icon: "queue", label: L.navAlerts, filters: {} },
    { id: "review", icon: "review", label: L.navReview, filters: { state: "pending" } },
    { id: "resolved", icon: "archive", label: L.navResolved, filters: { state: "decided" } },
    { id: "incidents", icon: "incidents", label: L.navIncidents, href: "#/incidentes" },
  ];

  const navigationStyle = useSelectionIndicator(nav, `${current}:${collapsed}:${mobile}:${menuOpen}`, '[aria-current="page"]', true);

  return (
    <div className={`app console-shell${menuOpen ? " menu-open" : ""}${collapsed ? " sidebar-collapsed" : ""}`}>
      {/* A button, not a #fragment link: the hash is this app's navigation */}
      <button type="button" className="btn skip-link" onClick={() => main.current && main.current.focus()}>
        {L.skipToContent}
      </button>
      <aside className="sidebar" id="main-navigation" ref={sidebar} inert={mobile && !menuOpen} role={mobile && menuOpen ? "dialog" : undefined} aria-modal={mobile && menuOpen ? true : undefined} aria-label={L.navLabel}>
        <button className="btn sidebar-close" aria-label={L.closeMenu} onClick={closeMenu}><Icon name="cross" /></button>
        <a className="console-brand" href="#/dashboard" onClick={() => { if (mobile && menuOpen) restoreMenuFocus.current = "main"; setMenuOpen(false); }} aria-label="Tarvia · Operaciones de seguridad"><span className="console-mark"><Icon name="shield" /></span><span className="brand-name">Tarvia</span></a>
        <nav aria-label={L.navLabel} ref={nav}>{navigationStyle && <span className="navigation-indicator" aria-hidden="true" style={navigationStyle} />}{navigation.map(item => <a key={item.id} href={item.href || queueHash({ q: "", product: "", severity: "", state: "", injection: false, ...item.filters })} className={`sidebar-link${current === item.id ? " selected" : ""}`} aria-label={item.label} aria-current={current === item.id ? "page" : undefined} onClick={event => { if (mobile && menuOpen) restoreMenuFocus.current = "main"; if (item.filters) { event.preventDefault(); showQueue(item.filters); } else setMenuOpen(false); }}><Icon name={item.icon} /><span className="nav-label">{item.label}</span></a>)}</nav>
      </aside>
      {mobile && menuOpen && <button className="menu-scrim" tabIndex={-1} aria-label={L.closeMenu} onClick={closeMenu} />}
      <div className="console-workspace" ref={workspace} inert={mobile && menuOpen}>
        <header className="topbar">
          <div className="topbar-left"><button className="btn btn-icon navigation-toggle" id="menu-toggle" aria-label={mobile ? (menuOpen ? L.closeMenu : L.openMenu) : (collapsed ? L.expandMenu : L.collapseMenu)} aria-expanded={mobile ? menuOpen : !collapsed} aria-controls="main-navigation" onClick={() => { if (mobile) setMenuOpen(value => !value); else { prepareWorkspace(); setCollapsed(value => !value); } }}><Icon name={mobile && menuOpen ? "cross" : "menu"} /></button><span className="topbar-workspace">{L.workspaceName}</span><span className="breadcrumb-divider">/</span><strong>{screenTitle}</strong></div>
          <div className="topbar-right">{mode && <span className={`mode mode-${mode === "real" ? "real" : "example"}`}><span className="status-dot" />{mode === "real" ? L.modeReal : L.modeExample}</span>}</div>
        </header>
        {(mode === "example" || exampleOnScreen) && <ExampleBanner mode={mode} />}
        <main className="content" id="main" ref={main} tabIndex={-1}>
        {route.view === "dashboard" ? <Dashboard onOpen={openAlert} onQueue={showQueue} onReport={report} /> : alertId ? (
          <Ticket key={alertId} alertId={alertId} onBack={openQueue} onNext={openNext} onReport={report} onIncidents={openIncidents} onOpenReport={openReport} />
        ) : route.view === "report" ? (
          <Report key={route.reportKey} reportKey={route.reportKey} onBack={openIncidents} />
        ) : route.view === "incidents" ? (
          <Incidents onOpen={openAlert} onOpenReport={openReport} />
        ) : (
          <Queue onOpen={openAlert} onReport={report} filters={filters} setFilters={setFilters} returnTo={returnTo.current} />
        )}
        </main>
      </div>
    </div>
  );
}
