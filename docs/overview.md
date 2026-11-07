# Overview

## The challenge
Tarvia is a fictional retailer preparing for Black Friday. Its SOC gets about 4,000 alerts a day and is only staffed 8:00-20:00 on weekdays. We build an AI system that investigates each alert and gives a person a reasoned decision.

Deloitte's own material is in `data/`:
- `data/README.md`: the challenge
- `data/01_contexto/`: company, SOC policy, runbooks, output schemas
- `data/Reto IA en ciberseguridad.pptx`: the deck

## Levels
| Level | Question | Output |
|---|---|---|
| 1. Basic triage | What is this alert: close or escalate? | One ticket per alert |
| 2. Judgement | Which alerts belong together, and which are authorised? | Merged tickets, policy severity, reasons |
| 3. Investigation | How did the attack unfold? | Incident report with a timeline |
| 4. Response | How do we stop it, and who approves? | Proposal, human approval, simulated action |

We build them in order and finish each one before moving up. Level 1 has to work on any alert. Levels 3 and 4 are shown on incidents we found.

## What we present
- A visual demo: the queue, what the system looks up, why it decides, where the person steps in
- The same 10 alerts every team gets, published at 09:00 on Sunday, shown in a 3-minute video made by noon
- The level we reached and how we built it
- One page for Tarvia's executive committee

Judged on: correct and well-argued triage, working on the real data, clear roles for AI and person, honesty about what it doesn't solve.

## Rules from Deloitte
- No real malware or real systems
- Containment only against the mock API, with human approval
- Some indicators in the data are real. Look them up only in reputation services. Never visit, download from or scan them

## How our system works
1. Plain code gathers the facts for an alert from the mock API. Log search uses each log's identity format and filters on exact fields.
2. The LLM gets those facts, the policy and the runbook, and returns a ticket. It can ask for one more lookup.
3. Plain code checks the ticket: the format, that the evidence was really retrieved, and the final severity.
4. The web UI shows the queue, every lookup and the reasoning.
5. The LLM can propose containment. Plain code works out who must approve, and only a person's click runs it.
6. For an escalated ticket or incident, plain code searches every entity across the whole incident and expands by session and message ID. The LLM writes the incident report, and code checks every timeline event against what it retrieved and takes each time from the log (`python scripts/investigate.py ALR-…`, or the report page in the UI).

## Test case
The incident on the account `laura.ferrer2` is our test at every level (`laura.ferrer` is someone else with the same display name): a fake login page, a stolen session, a hidden inbox rule, then a fake IBAN change for 148,320 euros. Alerts `ALR-20261007-011785`, `-011786`, `-011787`, `-011788` and `ALR-20261008-011789`.

## More
- `docs/decisions.md`: what's decided and what's still open
- `docs/data_traps.md`: what the analysis found in the data

Code comments and the notebook name work areas such as `data/search-logs` and `agent/triage`. The branches are `data/tools` and `agent/core`.
