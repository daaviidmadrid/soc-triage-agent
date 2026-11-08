// A reading workspace with tabs, shared by the triage (one alert) and the incident report (level 3).
// Every panel stays mounted, so a half-written form keeps its draft when the analyst changes tab.
import { useRef } from "react";
import { None, asText } from "../components.jsx";
import { usePanelMotion, useSelectionIndicator } from "../motion.js";

// tabs: [[id, label], …]. The children are the panels, made with workspacePanel(current).
export default function Workspace({ tabs, current, onTab, label, children }) {
  const tabRefs = useRef({}), tabList = useRef(null), workspace = useRef(null);
  const marker = useSelectionIndicator(tabList, current, '[aria-selected="true"]');
  usePanelMotion(workspace, current);
  function keyTab(event, index) {
    const nextIndex = ({ ArrowRight: (index + 1) % tabs.length, ArrowLeft: (index + tabs.length - 1) % tabs.length, Home: 0, End: tabs.length - 1 })[event.key];
    if (nextIndex === undefined) return;
    event.preventDefault(); const id = tabs[nextIndex][0]; onTab(id); tabRefs.current[id]?.focus();
  }
  return <div className="workspace-main panel reading-workspace" ref={workspace}>
    <div className="workspace-tabs" ref={tabList} role="tablist" aria-label={label}>{marker && <span className="tab-indicator" aria-hidden="true" style={marker} />}{tabs.map(([id, text], i) => <button type="button" role="tab" key={id} id={`tab-${id}`} aria-controls={`workspace-${id}`} aria-selected={current === id} tabIndex={current === id ? 0 : -1} ref={el => { tabRefs.current[id] = el; }} onClick={() => onTab(id)} onKeyDown={e => keyTab(e, i)}>{text}</button>)}</div>
    {children}
  </div>;
}

// Returns panel(id, content): one tab's panel, hidden unless it is the current tab.
export function workspacePanel(current) {
  return (id, content) => <section key={id} id={`workspace-${id}`} className="workspace-panel" role="tabpanel" aria-labelledby={`tab-${id}`} tabIndex={0} hidden={current !== id}>{content}</section>;
}

// A block of a panel. "who" holds the chips that say who wrote it (LLM, code, person), where a page shows them.
export function Section({ title, children, id, who }) {
  return <section className="reading-section" id={id}>{who ? <div className="section-title"><h3>{title}</h3>{who}</div> : <h3>{title}</h3>}{children}</section>;
}

// A list of texts from the data, shown whole and as plain text.
export function TextList({ items }) {
  return items.length ? <ul className="list">{items.map((value, i) => <li key={i} className="prose">{asText(value)}</li>)}</ul> : <None />;
}
