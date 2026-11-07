# Decisions

Change "proposed" to "agreed" once the team confirms it.

| Topic | Decision | Status |
|---|---|---|
| Repo | Private team repo, no fork | Done |
| Dataset | Deloitte's repo cloned into `data/`, not committed | Done |
| Live test | 10 alerts | From the deck |
| Main LLM | `gemini-3.6-flash` on Gemini's free tier | Proposed |
| LLM calls | One per alert, one follow-up at most | Proposed |
| Ticket language | Spanish text, English field names | Proposed |
| Contracts | Pydantic models in `contracts/models.py`, examples in `contracts/examples/` | Proposed |
| Tickets | Each alert in one ticket, grouping merges tickets, one report per escalated ticket | Proposed |
| Criticality | The machine named, then the service the rule targets, then the user's workstation, then `Media` | Proposed |
| Held-out incident | The stolen cloud key case. Leave `ALR-20261016-011821` out while tuning | Proposed |

