// Live steps of a run (a triage or an investigation). The server replays every stored event first,
// so a reload shows the whole run again.
import { useEffect, useState } from "react";
import { api } from "./api.js";

export function useRunEvents(runId, onEnd) {
  const [events, setEvents] = useState([]);
  const [stream, setStream] = useState("idle");

  useEffect(() => {
    if (!runId) return undefined;
    setEvents([]);
    setStream("connecting");
    let source, retry = null, lastSeq = 0, stopped = false, ended = false;
    function connect() {
      retry = null;
      if (stopped || ended) return;
      const opened = new EventSource(api.eventsUrl(runId, lastSeq));
      source = opened;
      opened.onopen = () => { if (!stopped && source === opened) setStream("live"); };
      opened.addEventListener("trace", (message) => {
        if (stopped || source !== opened) return;
        let event;
        try { event = JSON.parse(message.data); } catch { return; }
        if (!event || typeof event !== "object" || !Number.isInteger(event.seq)) return;
        lastSeq = Math.max(lastSeq, event.seq);
        setStream("live");
        setEvents(prev => prev.some(p => p.seq === event.seq) ? prev : [...prev, event].sort((a, b) => a.seq - b.seq));
      });
      opened.addEventListener("end", () => {
        if (stopped || source !== opened) return;
        ended = true;
        opened.close();
        setStream("ended");
        onEnd();
      });
      opened.onerror = () => {
        if (stopped || ended || source !== opened) return;
        setStream("lost");
        // Native EventSource retries CONNECTING. A proxy's 5xx can close it permanently.
        if (opened.readyState === EventSource.CLOSED && retry === null) {
          opened.close();
          retry = setTimeout(connect, 2000);
        }
      };
    }
    function reconnect() {
      if (stopped || ended) return;
      if (retry !== null) clearTimeout(retry);
      source?.close();
      connect();
    }
    window.addEventListener("online", reconnect);
    window.addEventListener("tarvia:api-restored", reconnect);
    connect();
    return () => { stopped = true; if (retry !== null) clearTimeout(retry); source?.close(); window.removeEventListener("online", reconnect); window.removeEventListener("tarvia:api-restored", reconnect); };
  }, [runId, onEnd]);

  return { events, stream };
}
