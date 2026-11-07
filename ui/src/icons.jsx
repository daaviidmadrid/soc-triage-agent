// One small icon family: 16px grid, 1.75 stroke, round caps, drawn in currentColor.
// Authored here, never loaded from anywhere. Icons are decorative; the text next to them carries the meaning.
const PATHS = {
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
