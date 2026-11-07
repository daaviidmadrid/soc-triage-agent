// Calls to the local backend, through Vite's /api proxy.
import { L } from "./labels.js";

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(method, path, body, contentType = "application/json") {
  const headers = { Accept: "application/json" };
  if (method !== "GET") headers["X-Tarvia-UI"] = "1";
  if (body !== undefined) headers["Content-Type"] = contentType;
  let response;
  try {
    response = await fetch(path, { method, headers, body, credentials: "same-origin" });
  } catch {
    throw new ApiError(L.backendDown, 0);
  }
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (!response.ok) {
    // Vite's proxy answers 5xx with no JSON body when the backend isn't running.
    if (data === null && response.status >= 500) throw new ApiError(L.backendDown, response.status);
    const detail = data && data.detail;
    const message = typeof detail === "string" ? detail : `${L.errorPrefix} ${response.status}`;
    throw new ApiError(message, response.status);
  }
  return data;
}

export const api = {
  queue: () => request("GET", "/api/queue"),
  alert: (id) => request("GET", `/api/alerts/${encodeURIComponent(id)}`),
  ticket: (id) => request("GET", `/api/tickets/${encodeURIComponent(id)}`),
  triage: (id) => request("POST", `/api/triage/${encodeURIComponent(id)}`),
  importAlerts: (text) => request("POST", "/api/alerts/import", text, "application/json"),
  decide: (ticketId, body) =>
    request("POST", `/api/tickets/${encodeURIComponent(ticketId)}/decision`, JSON.stringify(body)),
  incidents: () => request("GET", "/api/incidents"),
  buildIncidents: () => request("POST", "/api/incidents/build"),
  containment: (ticketId, runId) =>
    request("GET", `/api/tickets/${encodeURIComponent(ticketId)}/containment${runId ? `?run_id=${encodeURIComponent(runId)}` : ""}`),
  approveAction: (id, body) => request("POST", `/api/containment/${encodeURIComponent(id)}/approve`, JSON.stringify(body)),
  rejectAction: (id, body) => request("POST", `/api/containment/${encodeURIComponent(id)}/reject`, JSON.stringify(body)),
  executeAction: (id) => request("POST", `/api/containment/${encodeURIComponent(id)}/execute`, JSON.stringify({})),
  containmentLog: () => request("GET", "/api/containment/log"),
  report: (key) => request("GET", `/api/reports/${encodeURIComponent(key)}`),
  investigate: (key) => request("POST", `/api/reports/${encodeURIComponent(key)}`),
  reportContainment: (key) => request("GET", `/api/reports/${encodeURIComponent(key)}/containment`),
  eventsUrl: (runId) => `/api/runs/${encodeURIComponent(runId)}/events`,
};
