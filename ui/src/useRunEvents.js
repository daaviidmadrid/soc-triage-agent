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
    const source = new EventSource(api.eventsUrl(runId));
    source.onopen = () => setStream("live");
    source.addEventListener("trace", (message) => {
      let event;
      try {
        event = JSON.parse(message.data);
      } catch {
        return;
      }
      if (!event || typeof event !== "object") return;
      setStream("live");
      setEvents((prev) => (prev.some((p) => p.seq === event.seq) ? prev : [...prev, event].sort((a, b) => a.seq - b.seq)));
    });
    source.addEventListener("end", () => {
      source.close();
      setStream("ended");
      onEnd();
    });
    source.onerror = () => {
      if (source.readyState !== EventSource.CLOSED) setStream("lost");
    };
    return () => source.close();
  }, [runId, onEnd]);

  return { events, stream };
}
