# Dataset findings that affect agent design

Source: executed [notebook](../analysis/explore.ipynb). Contextual matches and rare patterns are not ground-truth verdicts.

| Finding and number | Section | What to do |
|---|---|---|
| Identity collisions: **149 username-prefix pairs**. One query returns **153** sign-ins, including **80** for another UPN. Hostname search misses **220** firewall rows found by IP. | 3, 12 | Resolve directory/CMDB aliases; match parsed fields exactly. |
| Links are incomplete: **15,683 references**, **0 missing**; Laura's five-alert chain omits **40 mailbox-access events**. One proxy window has **18,721** rows; the default limit returns **200**. | 4, 10 | Expand by entity/session/message ID; split saturated windows and deduplicate. Use event time for timelines. |
| Context exceeds budget: median proxy-only ±24 h context is **9,172.7 KiB**. One identity-runbook example still yields **1,215.1 KiB** after exact raw-entity filtering. | 5 | Summarise repetition, preserve transitions and citations, and budget follow-ups. Token counts are estimates. |
| Untrusted approval claims: **12 alerts** cite absent `SEC-4471`; **3 TPV alerts** cite absent `SEC-2210` in service descriptions. Hidden HTML occurs in **45 email records**. | 8, 9 | Keep retrieved text untrusted. Validate calendar existence, scope and time in code; keep approval tools outside LLM authority. |
| Severity arithmetic matters: the matrix changes severity for **3,570 alerts under stated assumptions**. The example ticket reduces `medium` to `informational`: **two levels**, exceeding policy's one. | 6 | Record criticality provenance, matrix base and one bounded adjustment. Resolve reference conflicts; these are provisional calculations. |
| Calendar ambiguity: **26** start/end values lack offsets. **19** scanner alerts follow Madrid's schedule, including **5** after DST. Fixed-offset windows also contain these examples. | 7 | Use `Europe/Madrid`, retaining the timezone inference as an assumption. Window inclusion alone cannot prove authorisation. |
| Repetition needs context: **1,349** encoded-PowerShell alerts share one selected pattern; **18** fall outside the stated local inventory window. | 2, 8 | Check command, account, host and schedule before allowing activity. Rarity does not prove malice. |
| Sample gaps: **150 alerts** omit **20 of 41 observed rules**, with **0 critical alerts**. The proposed held-out cloud alert is already included. **24** additions are listed. | 11 | Label behavioural cases independently; split whole incident groups. Do not claim a clean holdout. |
| Mock gaps: exact OT-host isolation returns **403**; **2 aliases** return **200**. Token replay and single-approver server/TPV isolation also return **200**. | 12 | Authenticate human approval, enforce roles and canonical targets, reject OT actions, and use single-use approvals. Require a person for every containment action. |

Unverified: other incident leads, injection-screen recall, incomplete authorisation matches, model quality, exact tokenisation, live-test performance and real-world effects. No indicator was contacted or looked up.
