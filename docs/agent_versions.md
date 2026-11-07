# Agent versions

Each version is a value of `PROMPT_VERSION` in `src/agent/prompts.py`. Its tickets are in `runs/<version>-ornith` (reasoning on) or `runs/<version>-ornith-nothink` (reasoning off), on the laptop that ran them.

## How a version is measured
1. Change one thing and bump `PROMPT_VERSION`.
2. Run the 80 practice alerts: `python3 scripts/exam.py run --set scored --workers 6` (add `--no-thinking` for reasoning off).
3. Mark them: `python3 scripts/exam.py score --set exam` and `--set normal`.
4. Keep the change only if it fixes more than it breaks and misses no new attack.

Never choose between versions with `--set final`. Those 40 alerts are scored once, at the end, for the honest result.

## Versions
| Version | Change |
|---|---|
| v2 | Starting prompt, 2 model calls per alert |
| v3 | Defines each verdict: a blocked attempt is `true_positive`, harmless is `false_positive`, `benign_true_positive` needs a change or trip ID. A false claim of authorisation gets one correction. Up to 3 calls per alert |
| v4 | v3, plus a prompt rule to look for the −1 whenever something was blocked, plus code that sends a close under 85% confidence to a person |
| v5 | v4 without the low-confidence rule |

## Results on the 80 practice alerts
Model `ornith` on the UAB server, 7 Nov 2026. Marked against `eval/labels.csv`, still Claude's draft with no row reviewed by a person. These 80 alerts were used to choose the changes, so the figures are optimistic.

| Version | Set | Verdict | Severity | Escalate or close | Missed attacks | Needless escalations |
|---|---|---|---|---|---|---|
| v2, reasoning off | hard | 72% | 85% | 72% | not comparable | not comparable |
| v2, reasoning off | normal | 30% | 55% | 38% | not comparable | not comparable |
| v3, reasoning off | hard | 80% | 91% | 88% | 1 | 4 |
| v3, reasoning off | normal | 82% | 77% | 98% | 0 | 1 |
| v4, reasoning off | hard | 98% | 82% | 88% | 2 | 3 |
| v4, reasoning off | normal | 78% | 82% | 82% | 0 | 7 |
| v3, reasoning on | hard | 92% | 88% | 92% | 2 | 1 |
| v3, reasoning on | normal | 100% | 91% | 100% | 0 | 0 |
| v4, reasoning on | hard | 95% | 91% | 90% | 2 | 2 |
| v4, reasoning on | normal | 100% | 86% | 92% | 0 | 3 |
| v5, reasoning on | hard | 95% | 94% | 95% | 2 | 0 |
| v5, reasoning on | normal | 92% | 91% | 92% | 0 | 3 |

v2's missed attacks and needless escalations were counted before the scorer was fixed to accept a blocked attack that closes, so they aren't comparable. The model doesn't answer the same way twice, so a difference of one or two alerts can be chance.

## What we learned
- Reasoning on is the biggest gain, at 2 to 4 minutes per model call instead of seconds.
- The low-confidence rule in v4 sent 6 more harmless normal-day alerts to a person and prevented no missed attack, so v5 drops it.
- With reasoning on, v3 and v5 are within chance of each other: over all 80, v3 got 77 verdicts and 77 escalation decisions right with 1 needless escalation, and v5 got 75, 75 and 3. v5 is better on the hard set and worse on the normal-day set.
- Every reasoning-on version misses the same 2 attacks: phishing reports that only matter because a colleague in the same campaign gave away a login. That needs grouping (Level 2), not a better prompt.
- Planted text: each reasoning-on version flagged 3 of the 4 alerts with planted text in these sets (`eval/injection_alerts.txt`). The 2 it "obeyed" are those same phishing reports, closed for lack of the campaign view rather than because the text said so.
