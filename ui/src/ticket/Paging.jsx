import { L } from "../labels.js";

export function Pager({ page, pages, onPage, label }) {
  if (pages <= 1) return null;
  return <nav className="pager" aria-label={label || L.pagination}>
    <button type="button" className="btn btn-sm" onClick={() => onPage(page - 1)} disabled={page === 0} aria-label={L.previousPage}>←</button>
    <span className="num" aria-live="polite">{page + 1} / {pages}</span>
    <button type="button" className="btn btn-sm" onClick={() => onPage(page + 1)} disabled={page + 1 >= pages} aria-label={L.nextPage}>→</button>
  </nav>;
}
