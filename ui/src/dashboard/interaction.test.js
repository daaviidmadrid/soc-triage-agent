import test from "node:test";
import assert from "node:assert/strict";
import { dayComparison, shareLabel } from "./interaction.js";

test("daily variation is computed from adjacent UTC days", () => {
  const points = [{ day: "2026-01-01", count: 8 }, { day: "2026-01-02", count: 10 }];
  assert.deepEqual(dayComparison(points, 1), { previous: 8, percent: "+25 %" });
  assert.equal(dayComparison(points, 0), null);
  assert.equal(dayComparison([{ day: "2026-01-01", count: 10 }, { day: "2026-01-02", count: 5 }], 1).percent, "-50 %");
});

test("zero and unavailable baselines never invent percentage growth", () => {
  assert.deepEqual(dayComparison([{ day: "2026-01-01", count: 0 }, { day: "2026-01-02", count: 5 }], 1), { previous: 0, percent: null });
  assert.deepEqual(dayComparison([{ day: "2026-01-01", count: 0 }, { day: "2026-01-02", count: 0 }], 1), { previous: 0, percent: "0 %" });
  assert.equal(dayComparison([{ day: "2026-01-01", count: 5 }, { day: "2026-01-03", count: 20 }], 1), null);
  assert.equal(dayComparison([], 0), null);
});

test("category shares use the actual queue denominator", () => {
  assert.equal(shareLabel(3, 4), "75 %");
  assert.equal(shareLabel(1, 3), "33,3 %");
  assert.equal(shareLabel(0, 0), "0 %");
});
