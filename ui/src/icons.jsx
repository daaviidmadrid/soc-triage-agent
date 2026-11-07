// One small icon family: 16px grid, 1.75 stroke, round caps, drawn in currentColor.
// Authored here, never loaded from anywhere. Icons are decorative; the text next to them carries the meaning.
const PATHS = {
  search: <><circle cx="6.5" cy="6.5" r="4.5" /><path d="m10 10 4 4" /></>,
  device: <><rect x="2" y="2" width="12" height="9" rx="1.5" /><path d="M6 14h4M8 11v3" /></>,
  identity: <><circle cx="8" cy="5" r="2.5" /><path d="M3 14v-1a5 5 0 0 1 10 0v1" /></>,
  mail: <><rect x="1.5" y="3" width="13" height="10" rx="1.5" /><path d="m2 4 6 4.5L14 4" /></>,
  network: <><rect x="6" y="1.5" width="4" height="4" rx="1" /><rect x="1.5" y="10.5" width="4" height="4" rx="1" /><rect x="10.5" y="10.5" width="4" height="4" rx="1" /><path d="M8 5.5v3M3.5 10.5v-2h9v2" /></>,
  cloud: <path d="M4 12.5a3 3 0 0 1-.4-6 4.5 4.5 0 0 1 8.7 0 3 3 0 0 1-.3 6Z" />,
  code: <><path d="m5 4-4 4 4 4M11 4l4 4-4 4M9 2 7 14" /></>,
  play: <path d="m5 2.5 8 5.5-8 5.5Z" />,
  upload: <><path d="M8 11V1.5M4.5 5 8 1.5 11.5 5M2 10v3.5h12V10" /></>,
  dashboard: <><rect x="2" y="2" width="4.5" height="4.5" rx="1" /><rect x="9.5" y="2" width="4.5" height="4.5" rx="1" /><rect x="2" y="9.5" width="4.5" height="4.5" rx="1" /><rect x="9.5" y="9.5" width="4.5" height="4.5" rx="1" /></>,
  queue: <><rect x="2" y="2.5" width="12" height="11" rx="1.5" /><path d="M5 6h6M5 9h6" /></>,
  review: <><circle cx="7" cy="7" r="4.5" /><path d="m10.5 10.5 3 3M7 4.5V7l1.5 1" /></>,
  archive: <><rect x="2" y="2" width="12" height="3" rx="1" /><path d="M3.5 5v8h9V5M6 8h4" /></>,
  shield: <><path d="m8 1.5 5.5 2v4.2c0 3.3-5.5 6.8-5.5 6.8S2.5 11 2.5 7.7V3.5L8 1.5Z" /><path d="m5.5 7.5 1.7 1.7 3.3-3.4" /></>,
  trend: <><path d="M2 12.5 6 8l3 2 5-7M10 3h4v4" /></>,
  refresh: <><path d="M13 5a5.5 5.5 0 1 0 .2 5M13.5 1.5V5H10" /></>,
  menu: <path d="M2 4h12M2 8h12M2 12h12" />,
  calendar: <><rect x="2" y="3.5" width="12" height="10" rx="1.5" /><path d="M5 2v3M11 2v3M2 7h12" /></>,
  incidents: <><circle cx="4" cy="4" r="2" /><circle cx="12" cy="4" r="2" /><circle cx="8" cy="12" r="2" /><path d="M6 4h4M5 5.8l2 4.4M11 5.8l-2 4.4" /></>,
  alert: (
    <>
      <path d="M8 2.2 14.3 13H1.7L8 2.2Z" />
      <path d="M8 6.4v3" />
      <path d="M8 11.3h.01" />
    </>
  ),
  pause: (
    <>
      <path d="M6 3.5v9" />
      <path d="M10 3.5v9" />
    </>
  ),
  clock: (
    <>
      <circle cx="8" cy="8" r="5.8" />
      <path d="M8 4.8V8l2.2 1.4" />
    </>
  ),
  check: <path d="m3.5 8.4 2.8 2.8 6.2-6.4" />,
  cross: (
    <>
      <path d="m4.5 4.5 7 7" />
      <path d="m11.5 4.5-7 7" />
    </>
  ),
  arrowLeft: (
    <>
      <path d="M13 8H3.5" />
      <path d="M7.5 4 3.5 8l4 4" />
    </>
  ),
  arrowRight: (
    <>
      <path d="M3 8h9.5" />
      <path d="m8.5 4 4 4-4 4" />
    </>
  ),
};

export default function Icon({ name, className = "" }) {
  return (
    <svg
      className={`icon ${className}`}
      viewBox="0 0 16 16"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}
