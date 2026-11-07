# Decisions

Change "proposed" to "agreed" once the team confirms it.

| Topic | Decision | Status |
|---|---|---|
| Repo | Private team repo, no fork | Done |
| Dataset | Deloitte's repo cloned into `data/`, not committed | Done |
| Live test | 10 alerts | From the deck |
| Main LLM | `gemini-3.6-flash` on Gemini's free tier | Proposed |
| LLM calls | One per alert, one follow-up at most | Proposed |
| UI | Python backend, React and CSS frontend | For now |
| Ticket language | Spanish text, English field names | Proposed |
| Contracts | Pydantic models in `contracts/models.py`, examples in `contracts/examples/` | Proposed |
| Tickets | Each alert in one ticket, grouping merges tickets, one report per escalated ticket | Proposed |
| Criticality | The machine named, then the user's workstation, then `Crítica` for RB-05 (the online shop), then `Media`. `Media` and `Alta` give the same result for every alert, so only `Crítica` and `Baja` matter (analysis section 6) | Proposed |
| Severity arithmetic | One adjustment in total, up or down. Don't copy the example ticket's −2. A runbook floor beats that cap, and only `UC-EML-004` (`critical`) has one. An authorised alert is `low`, or `informational` if its base already is | Proposed |
| What counts as authorised | Code checks that a change or flow exists and fits by event time, scope and identity. A notified trip with dates covering the event also counts. Other HR events and accepted exemptions never do (analysis section 8) | Proposed |
| SCCM account | Accept `NT AUTHORITY\SYSTEM` for the calendar's `svc_sccm` only with the `CcmExec` parent, the one known command and the daily window | Proposed |
| Approved-change verdict | `benign_true_positive`, following `politica_soc.md` rather than deck slide 5 | Decided by Francesco |
| Containment | A person approves every action, including `block_ioc` and `purge_email`, which is stricter than section 4 of the policy. OT actions are never proposed | Proposed |
| Prompt budget | 28,000 characters, about 14,000 of them for data. Don't search on IPs shared by many identities. Data sends rows most important first: linked events, then changes of state, then repeats as counts (analysis section 5) | Proposed |
| Incomplete evidence | A truncated search or rows cut from the prompt can't support the −1, and the ticket says the evidence is incomplete (analysis section 4) | Proposed |
| Data leakage | ID numbers are only citation handles: no code, prompt, rule, test selection, label or score uses them as a signal. Prompts stay general and use no alert from the data as an example. Labels are written without seeing the agent's answer | Proposed |
| Held-out incident | The stolen cloud key case: `ALR-20261015-011819`, `ALR-20261015-011820` and `ALR-20261016-011821`, the last of which is in the development sample. Also `ALR-20261013-011901` until someone checks the link. Leave them out while tuning, and don't call it blind: the analysis has read them | Proposed |

