# Agent versions

Each version is a value of `PROMPT_VERSION` in `src/agent/prompts.py`. Its tickets are in `runs/<version>-ornith` (reasoning on) or `runs/<version>-ornith-nothink` (reasoning off), on the laptop that ran them.

## How a version is measured
1. Change one thing and bump `PROMPT_VERSION`.
2. Run the 80 practice alerts: `python3 scripts/exam.py run --set scored --workers 6` (add `--no-thinking` for reasoning off).
3. Mark them: `python3 scripts/exam.py score --set exam` and `--set normal`, then the look-alike pairs with `--set pairs`.
4. Keep the change only if it fixes more than it breaks and misses no new attack.

Never choose between versions with `--set final`. Those 40 alerts are scored once, at the end, for the honest result.

## Versions
| Version | Change |
|---|---|
| v2 | Starting prompt, 2 model calls per alert |
| v3 | Defines each verdict: a blocked attempt is `true_positive`, harmless is `false_positive`, `benign_true_positive` needs a change or trip ID. A false claim of authorisation gets one correction. Up to 3 calls per alert |
| v4 | v3, plus a prompt rule to look for the −1 whenever something was blocked, plus code that sends a close under 85% confidence to a person |
| v5 | v4 without the low-confidence rule |
| v6 | v5 plus two fixed rules in `src/agent/rules.py` that close known noise with no model call: R1, the approved SCCM software inventory (`UC-EDR-002`), and R2, a blocked internet scan on the shop (`UC-WEB-001`). Every other alert goes to the model as in v5 |
| v7 | v6 with a data budget of 60,000 characters and a prompt budget of 75,000, up from 14,000 and 29,000, which were set for Gemini's free tier. Rows cut to fit drop from 54 to 17 of the 80 practice alerts (`python3 scripts/rows_cut.py`) |
| v8 | v7 with three changes from the night of 8 Nov, each on by default and off with its variable set to the other value: JSON mode off (`LLM_JSON_MODE=1` turns it on), phishing campaign context (`AGENT_CAMPAIGN=0`), and the answer checklist repeated at the end of the prompt (`AGENT_FORMAT_REMINDER=0`). Its results are rounds R5 and R7 below, whose checklist said `<untrusted_data>` where v8 says "the data block" |

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
| v6, reasoning on | hard | 98% | 94% | 92% | 2 | 1 |
| v6, reasoning on | normal | 98% | 86% | 95% | 1 | 1 |
| v7, reasoning on | hard | 95% | 94% | 92% | 2 | 1 |
| v7, reasoning on | normal | 98% | 95% | 98% | 0 | 1 |

v2's missed attacks and needless escalations were counted before the scorer was fixed to accept a blocked attack that closes, so they aren't comparable. The model doesn't answer the same way twice, so a difference of one or two alerts can be chance.

Planted text on the hard set (`eval/injection_alerts.txt`): v5, v6 and v7 all flagged 3 of 4, and the 2 they "obeyed" are the same two phishing reports.

| Version | Model calls on the 80 | Average call | Median call | Prompt tokens per call, average and largest | Whole run, 8 at a time |
|---|---|---|---|---|---|
| v5 | 106 | 155 s | not measured | not measured | not measured |
| v6 | 95 | 159 s | 137 s | 9,279 and 10,589 | 34 min |
| v7 | 88 | 172 s | 163 s | 17,802 and 33,364 | 33 min |

v7's calls take about 9% longer on average, with prompts nearly twice as large; the calls it made before another run shared the server averaged 174 s, so that sharing doesn't explain it. It needed fewer calls, so the whole run took no longer. Ten alerts at once still finish in about the time of the slowest one, a few minutes, as in v6.

## Look-alike pairs
`python3 scripts/exam.py score --set pairs` marks the 31 answered alerts of `eval/extra_alerts.txt` that are in the hard or normal set: look-alike pairs where one detail flips the answer (inside or outside a change window, approved recipient or not, dated trip or not, permitted source or not), plus the traced case and some rare rules. The one in the final set is left out. "Fully right" means verdict, severity and escalation all match the key.

| Version | Fully right | Wrong |
|---|---|---|
| v5, reasoning on | 28/31 | vendor VPN inside its exception (`true_positive`, still closed); alert with no linked events (`needs_more_info`, to a person); a phishing report that needs Level 2 |
| v6, reasoning on | 28/31 | vendor VPN inside its exception (`needs_more_info`, to a person); a phishing report that needs Level 2; the internal scan not from the scanner (medium and closed: a missed attack) |
| v7, reasoning on | 27/31 | vendor VPN inside its exception (`false_positive`, closed); a phishing report that needs Level 2; the upload by a departing employee (medium instead of high, still escalated); the rare build alert (`true_positive`, high and escalated, key `false_positive`) |

None of these 31 alerts is a `UC-EDR-002` or `UC-WEB-001` alert, so no rule touched them: the changes are the model's.

## Fixed rules (v6)
A rule only closes. Every condition must hold on parsed log fields, the CMDB and the change calendar; the alert's text is never a condition. If anything is missing or different, the alert goes to the model. Counted with no model by `python3 scripts/rule_counts.py`, over the 11,057 alerts of `alertas.jsonl` that aren't held out:

| Rule | Closes | Goes to the model |
|---|---|---|
| R1, approved SCCM inventory (`UC-EDR-002`) | 1,349 of 1,349, as `benign_true_positive`, low | none |
| R2, blocked internet scan on the shop (`UC-WEB-001`) | 3,386 of 3,406, as `true_positive`, low, with the −1 | 19 with truncated or cut evidence, 1 matching the pentest change |

Together they close 4,735 alerts, 43% of all, in about a second each. R1 reads only the alert's linked events, which are fetched by ID and never cut, so other searches that were cut don't stop it and the ticket lists them. If it also required the host's EDR search to be complete it would close 147 of the 1,349, and 95 if it required every search to be complete (the `truncated_sources` column of `rule_counts.py --out`). R2 needs every row, because its "no later activity" depends on them. In the 80 practice alerts the rules closed 12 (R1 2, R2 10). All 12 match the key, none should escalate, and v5 had given the same answers. With v7's budget R2 closes the same 3,386 alerts. 16 go to the model for truncated evidence and 4 for the pentest change: three pentest alerts that were cut before now have full evidence and stop at the change instead.

## Overnight experiments (8 Nov, 02:30 to 06:30)
Model `ornith` with reasoning on, the 80 practice alerts per round, run by `scripts/night_loop.py`. Each row switches things on top of v7. Lessons could come only from exam-set mistakes, and a change was kept only if the normal set didn't get worse; the final set was never run. Choosing on the normal set several times still overfits it a little. All rows: `runs/night/summary.md`.

| Round | On top of v7 | Hard: verdict / severity / escalation | Hard: missed, needless | Normal: verdict / severity / escalation | Normal: missed, needless | Fully right of 80 | Pairs | Rejected calls | Average call |
|---|---|---|---|---|---|---|---|---|---|
| v7 | nothing | 95 / 94 / 92 | 2, 1 | 98 / 95 / 98 | 0, 1 | 74 | 27/31 | 15 of 88 | 172 s |
| R1 | lessons L1 | 95 / 91 / 90 | 2, 2 | 95 / 100 / 95 | 0, 2 | 73 | 27/31 | 20 of 91 | 158 s |
| R2 | JSON mode off | 98 / 94 / 92 | 2, 1 | 100 / 100 / 100 | 0, 0 | 76 | 28/31 | 14 of 85 | 153 s |
| R3 | campaign context | 95 / 94 / 95 | 0, 2 | 100 / 95 / 100 | 0, 0 | 75 | 28/31 | 16 of 92 | 154 s |
| R4 | JSON off + campaign | 92 / 94 / 98 | 0, 1 | 95 / 95 / 95 | 0, 2 | 74 | 28/31 | 13 of 87 | 165 s |
| R5 | JSON off + campaign + reminder | 95 / 97 / 95 | 0, 2 | 100 / 100 / 100 | 0, 0 | 77 | 28/31 | 4 of 73 | 144 s |
| R6 | R4 again | 95 / 94 / 95 | 0, 2 | 98 / 100 / 98 | 0, 1 | 75 | 27/31 | 16 of 85 | 163 s |
| R7 | R5 again | 92 / 97 / 95 | 0, 2 | 100 / 95 / 100 | 0, 0 | 76 | 28/31 | 14 of 84 | 144 s |
| R8 | v7 again, nothing added | 90 / 85 / 95 | 1, 1 | 100 / 95 / 100 | 0, 0 | 72 | 26/31 | 21 of 90 | 149 s |

"Rejected calls" are answers our code refused, each costing a full retry; a log search request isn't counted.

- **Campaign context fixes the 2 attacks every earlier version missed.** In all five rounds with it, no attack was missed on either set, and planted text was obeyed 0 times instead of 2. The two phishing reports came from people who didn't click; the attack only shows in a colleague's login posted to the same site and a high-risk sign-in from that site's IP. Code now fetches those rows (`AGENT_CAMPAIGN=1`, `src/tools/context.py`). The idea came from reading the hard set's misses, so the normal set's phishing alerts are the honest check, and it held there.
- **Repeating plain v7 (R8) shows the noise:** 72 fully right against 74 the first time, one of the two phishing attacks missed instead of both, and 2 fallbacks to a person. The rounds with campaign context and JSON mode off scored 74 to 77 and never missed an attack, so the gain on missed attacks is larger than the noise; the gain in fully right answers is about the size of it.
- **JSON mode off stops the empty answers.** With JSON mode on, 7 of v6's 95 calls came back as just `{}` after a complete reasoning. With it off there were none in any round. What is still rejected is mostly evidence with no event ID.
- **The reminder helps a little.** R5 and R7 had the most fully right answers (77 and 76) and the fastest calls (144 s). The drop to 4 rejected calls in R5 didn't repeat in R7 (14), so it was partly luck.
- **Lessons didn't help.** L1 said to judge a phishing report by its whole campaign and to cite event IDs. It changed neither miss and added a needless escalation on each set, because the model can't judge a campaign it can't see. Code had to fetch it. L1 was dropped.
- **What is still wrong**, the same in almost every round: the vendor VPN inside its change (sent to a person as `needs_more_info`), a network alert answered `needs_more_info` instead of `true_positive`, and the rare build alert escalated where the draft key says `false_positive`. All three err towards a person, never towards closing an attack.
- **v8** makes those three the defaults, so the app gets them too. It hasn't been run under its own name: its figures are R5 and R7.

## What we learned
- Reasoning on is the biggest gain, at 2 to 4 minutes per model call instead of seconds.
- The low-confidence rule in v4 sent 6 more harmless normal-day alerts to a person and prevented no missed attack, so v5 drops it.
- With reasoning on, v3 and v5 are within chance of each other: over all 80, v3 got 77 verdicts and 77 escalation decisions right with 1 needless escalation, and v5 got 75, 75 and 3. v5 is better on the hard set and worse on the normal-day set.
- Every reasoning-on version misses the same 2 attacks: phishing reports that only matter because a colleague in the same campaign gave away a login. That needs grouping (Level 2), not a better prompt. On 8 Nov, code that fetches the campaign at level 1 fixed both (Overnight experiments, above).
- Planted text: each reasoning-on version flagged 3 of the 4 alerts with planted text in these sets (`eval/injection_alerts.txt`). The 2 it "obeyed" are those same phishing reports, closed for lack of the campaign view rather than because the text said so.
- v6's rules changed no answer on the 80 practice alerts: v5 already got right the 12 they close. Every difference between v5 and v6 is on the 68 alerts the model still answers: 3 fixed and 1 broken. The broken one is the internal scan not from the scanner. The model proposed a −1, code dropped it because rows had been cut, and the alert stayed medium and closed; in v5 the model saw allowed connections and proposed +1. So v6 is kept for speed and repeatability, not accuracy, and the new missed attack is the model's, not a rule's.
- v7 against v6, over the 80: fully right 74 against 73, escalation 76 against 75, exact severity 52 against 50 of 55, verdict 77 against 78, missed attacks 2 against 3, needless escalations 2 and 2. That is within chance. Two fixes come from the budget as intended: rows were no longer cut, so the −1 applied and severity matched the key. v7 also no longer misses the internal scan. It breaks 3 others. One is the departing employee's upload, a pair: the model listed a +1 and a −1 whose reason says it doesn't apply. With complete evidence code counts that −1, so the alert ends at medium instead of high; in v6 the incomplete-evidence rule dropped it. The other two are needless escalations: the rare build alert, where the model now reads the extra rows as a malicious install (the key, still a draft, says `false_positive`, and a person should check which is right), and a DNS alert sent to a person as `needs_more_info`.
- By the keep rule, v7 is not kept: it breaks a pair. It misses no new attack and isn't too slow. The pair it breaks comes from a model mistake that complete evidence exposes, not from lost data.
- Rule-closed alerts get no `injection_flags`, because no model reads them. The rules read no free text, so planted text can't move them, but a person sees no flag either. None of the planted-text alerts in these sets is covered by a rule.
