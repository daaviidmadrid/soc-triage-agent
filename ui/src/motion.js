import { useEffect, useLayoutEffect, useRef, useState } from "react";

const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
export function canAnimate() {
  return typeof Element.prototype.animate === "function" && !document.hidden && document.documentElement.dataset.motionInput !== "keyboard"
    && !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function useMotionInput() {
  useEffect(() => {
    const stop = () => document.getAnimations().filter(a => a.id === "tarvia-motion").forEach(a => a.cancel());
    const keyboard = () => { document.documentElement.dataset.motionInput = "keyboard"; stop(); };
    const pointer = () => { document.documentElement.dataset.motionInput = "pointer"; };
    const visibility = () => { document.documentElement.toggleAttribute("data-page-hidden", document.hidden); if (document.hidden) stop(); };
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const reduced = () => { if (media.matches) stop(); };
    document.addEventListener("keydown", keyboard, true);
    document.addEventListener("pointerdown", pointer, true);
    document.addEventListener("visibilitychange", visibility);
    media.addEventListener("change", reduced);
    visibility();
    return () => {
      document.removeEventListener("keydown", keyboard, true);
      document.removeEventListener("pointerdown", pointer, true);
      document.removeEventListener("visibilitychange", visibility);
      media.removeEventListener("change", reduced);
    };
  }, []);
}

function animate(element, frames, duration = 180, delay = 0) {
  return element.animate(frames, { id: "tarvia-motion", duration, delay, easing: EASE });
}

// A single marker tracks the selected navigation item; layout itself never animates.
export function useSelectionIndicator(ref, value, selector, vertical = false) {
  const [style, setStyle] = useState(null);
  const initialized = useRef(false);
  useLayoutEffect(() => {
    const container = ref.current;
    if (!container) return;
    const measure = (motion = false) => {
      const item = container.querySelector(selector);
      if (!item || !item.getClientRects().length) return;
      const parent = container.getBoundingClientRect(), selected = item.getBoundingClientRect();
      const x = selected.left - parent.left, y = selected.top - parent.top;
      setStyle(vertical ? {
        height: selected.height, transform: `translateY(${y}px)`,
        transition: motion && initialized.current && canAnimate() ? `transform 220ms ${EASE}` : "none",
      } : {
        transform: `translate(${x}px, ${y + selected.height - 2}px) scaleX(${selected.width})`,
        transition: motion && initialized.current && canAnimate() ? `transform 180ms ${EASE}` : "none",
      });
      initialized.current = true;
    };
    measure(true);
    let firstResize = true;
    const observer = new ResizeObserver(() => { if (firstResize) firstResize = false; else measure(false); });
    observer.observe(container);
    return () => observer.disconnect();
  }, [ref, value, selector, vertical]);
  return style;
}

// FLIP follows row identities through a filter/page change. First paint stays still.
export function useListMotion(ref, signature) {
  const previous = useRef(new Map()), previousSignature = useRef(signature), width = useRef(null);
  const animations = useRef(new Map());
  useLayoutEffect(() => {
    const parent = ref.current;
    if (!parent || !parent.getBoundingClientRect().height) return;
    const bounds = parent.getBoundingClientRect();
    const nodes = [...parent.querySelectorAll("[data-motion-key]")];
    const values = new Map(nodes.map(node => {
      const computed = getComputedStyle(node);
      const offset = computed.transform === "none" ? 0 : new DOMMatrixReadOnly(computed.transform).m42;
      return [node.dataset.motionKey, { top: node.getBoundingClientRect().top - bounds.top - offset, offset, opacity: Number(computed.opacity) }];
    }));
    const changed = signature !== previousSignature.current;
    if (changed && previous.current.size && width.current === bounds.width && canAnimate()) nodes.forEach((node, index) => {
      const key = node.dataset.motionKey, old = previous.current.get(key), current = values.get(key);
      animations.current.get(key)?.cancel();
      if (node.contains(document.activeElement)) return;
      const delta = old ? old.top + current.offset - current.top : 6;
      if (old && Math.abs(delta) < 1) return;
      const motion = animate(node, [{ transform: `translateY(${delta}px)`, opacity: old ? current.opacity : .65 }, { transform: "translateY(0)", opacity: 1 }], 180, old ? 0 : Math.min(index * 12, 72));
      animations.current.set(key, motion);
      motion.onfinish = motion.oncancel = () => { if (animations.current.get(key) === motion) animations.current.delete(key); };
    });
    previous.current = new Map([...values].map(([key, value]) => [key, { top: value.top }]));
    previousSignature.current = signature;
    width.current = bounds.width;
  });
  useEffect(() => () => animations.current.forEach(motion => motion.cancel()), []);
}

export function usePanelMotion(ref, value) {
  const previous = useRef(value);
  useLayoutEffect(() => {
    if (previous.current !== value && canAnimate()) {
      const panel = ref.current?.querySelector('[role="tabpanel"]:not([hidden])');
      if (panel) {
        const motion = animate(panel, [{ opacity: .8, transform: "translateY(4px)" }, { opacity: 1, transform: "translateY(0)" }], 150);
        previous.current = value;
        return () => motion.cancel();
      }
    }
    previous.current = value;
  }, [ref, value]);
}

export function useWorkspaceMotion(ref, value) {
  const before = useRef(null), motion = useRef(null);
  const prepare = () => { before.current = ref.current?.getBoundingClientRect(); motion.current?.cancel(); };
  useLayoutEffect(() => {
    if (!before.current || !ref.current) return;
    const delta = before.current.left - ref.current.getBoundingClientRect().left;
    if (canAnimate() && delta) motion.current = animate(ref.current, [{ transform: `translateX(${delta}px)` }, { transform: "translateX(0)" }], 220);
    before.current = null;
  }, [ref, value]);
  useEffect(() => () => motion.current?.cancel(), []);
  return prepare;
}
