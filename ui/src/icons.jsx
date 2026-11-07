// One small icon family: 16px grid, 1.75 stroke, round caps, drawn in currentColor.
// Authored here, never loaded from anywhere. Icons are decorative; the text next to them carries the meaning.
const PATHS = {
  dashboard: <><rect x="2" y="2" width="4.5" height="4.5" rx="1" /><rect x="9.5" y="2" width="4.5" height="4.5" rx="1" /><rect x="2" y="9.5" width="4.5" height="4.5" rx="1" /><rect x="9.5" y="9.5" width="4.5" height="4.5" rx="1" /></>,
  queue: <><rect x="2" y="2.5" width="12" height="11" rx="1.5" /><path d="M5 6h6M5 9h6" /></>,
  review: <><circle cx="7" cy="7" r="4.5" /><path d="m10.5 10.5 3 3M7 4.5V7l1.5 1" /></>,
  archive: <><rect x="2" y="2" width="12" height="3" rx="1" /><path d="M3.5 5v8h9V5M6 8h4" /></>,
  shield: <><path d="m8 1.5 5.5 2v4.2c0 3.3-5.5 6.8-5.5 6.8S2.5 11 2.5 7.7V3.5L8 1.5Z" /><path d="m5.5 7.5 1.7 1.7 3.3-3.4" /></>,
  trend: <><path d="M2 12.5 6 8l3 2 5-7M10 3h4v4" /></>,
  refresh: <><path d="M13 5a5.5 5.5 0 1 0 .2 5M13.5 1.5V5H10" /></>,
  menu: <path d="M2 4h12M2 8h12M2 12h12" />,
  calendar: <><rect x="2" y="3.5" width="12" height="10" rx="1.5" /><path d="M5 2v3M11 2v3M2 7h12" /></>,
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
