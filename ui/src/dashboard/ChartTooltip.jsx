import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { L } from "../labels.js";

// Pointer and keyboard are independent: leaving a row never retains its hover.
export function useChartFocus() {
  const [pointer, setPointer] = useState(null), [focus, setFocus] = useState(null);
  const id = useId();
  const active = pointer || focus;
  const dismiss = useCallback(() => { setPointer(null); setFocus(null); }, []);
  const activate = useCallback((key, anchor) => setFocus({ key, anchor }), []);
  useEffect(() => {
    if (!active) return;
    const escape = event => { if (event.key === "Escape") dismiss(); };
    window.addEventListener("keydown", escape);
    window.addEventListener("scroll", dismiss, true);
    window.addEventListener("resize", dismiss);
    return () => {
      window.removeEventListener("keydown", escape);
      window.removeEventListener("scroll", dismiss, true);
      window.removeEventListener("resize", dismiss);
    };
  }, [Boolean(active), dismiss]);
  useEffect(() => {
    const anchor = !pointer && focus?.anchor;
    if (!anchor) return;
    const previous = anchor.getAttribute("aria-describedby");
    anchor.setAttribute("aria-describedby", [previous, id].filter(Boolean).join(" "));
    return () => { if (previous) anchor.setAttribute("aria-describedby", previous); else anchor.removeAttribute("aria-describedby"); };
  }, [pointer, focus, id]);
  const point = (key, event) => {
    if (event.pointerType === "touch") return;
    setPointer({ key, anchor: event.currentTarget, x: event.clientX, y: event.clientY });
  };
  const bind = key => ({
    onPointerEnter: event => point(key, event),
    onPointerMove: event => point(key, event),
    onPointerLeave: () => setPointer(previous => previous?.key === key ? null : previous),
    onFocus: event => { if (event.target.matches(":focus-visible")) activate(key, event.target); },
    onBlur: event => { if (!event.currentTarget.contains(event.relatedTarget)) setFocus(previous => previous?.key === key ? null : previous); },
    "data-pointer": pointer?.key === key || undefined,
    "data-active": active?.key === key || undefined,
    "data-dimmed": active && String(active.key).split(":")[0] === String(key).split(":")[0] && active.key !== key || undefined,
  });
  return { activeKey: active?.key ?? null, anchor: active?.anchor, point: pointer, id, dismiss, activate, bind };
}

export default function ChartTooltip({ interaction, data }) {
  const element = useRef(null);
  const [position, setPosition] = useState(null);
  const open = interaction.activeKey !== null && data && interaction.anchor?.isConnected;
  useLayoutEffect(() => {
    if (!open || !element.current) return;
    const anchor = interaction.anchor.getBoundingClientRect(), tip = element.current.getBoundingClientRect();
    const margin = 12, gap = 14;
    const x = interaction.point?.x ?? anchor.left + anchor.width / 2;
    const topEdge = interaction.point?.y ?? anchor.top;
    const bottomEdge = interaction.point?.y ?? anchor.bottom;
    const left = Math.max(margin, Math.min(x - tip.width / 2, window.innerWidth - tip.width - margin));
    const above = topEdge - tip.height - gap;
    const top = Math.max(margin, Math.min(above >= margin ? above : bottomEdge + gap, window.innerHeight - tip.height - margin));
    setPosition({ left, top });
  }, [open, interaction.anchor, interaction.point, data]);
  if (!open) return null;
  return createPortal(
    <div ref={element} id={interaction.id} role="tooltip" className={`chart-tooltip${data.kind === "alert" ? " alert-tooltip" : ""}`}
      data-open data-position={interaction.point ? "pointer" : "focus"}
      style={{ left: position?.left ?? 12, top: position?.top ?? 12, visibility: position ? "visible" : "hidden" }}>
      <div className="chart-tooltip-heading"><span className="tooltip-dot" />{data.label}</div>
      {data.kind === "alert" ? <>
        <p className="alert-tooltip-title">{data.title}</p>
        <dl className="alert-tooltip-fields">{data.fields.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
        {data.description && <p className="alert-tooltip-description">{data.description}</p>}
      </> : <div className="chart-tooltip-value"><strong>{data.value}</strong><span>{data.unit || L.alertsUnit}</span></div>}
      {data.detail && <p className="chart-tooltip-detail">{data.detail}</p>}
      {data.share !== undefined && <div className="chart-tooltip-breakdown"><span>{L.shareOfQueue}</span><strong>{data.share}</strong></div>}
      {data.comparison && <div className="chart-tooltip-comparison">
        <div><span>{L.previousDay}</span><strong>{data.comparison.previous}</strong></div>
        <div><span>{L.volumeChange}</span><strong>{data.comparison.percent === null ? L.noComparisonBase : data.comparison.percent}</strong></div>
      </div>}
    </div>, document.body,
  );
}
