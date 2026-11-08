# Tarvia SOC Triage Agent

By David, Alex and Francesco, for Deloitte's challenge at UAB The Hack 2026. Francesco built the core agent (triage, grouping, containment, prompt injection defences and the practice exam) and integrated the team's work. Alex built the data tools (log search, alert context, API client, severity), the level 3 incident reports and the first UI. David did the data analysis, redesigned the UI and built the automated version on the `automated-soc-triage` branch.


An AI agent that triages security alerts for the SOC of Tarvia, a fictional retailer. Given an alert, it looks up the facts, works out what happened and writes a ticket with its evidence. Then it proposes closing the alert or escalating it, and a person decides.

**Plain code gathers and checks the facts, the LLM judges, and a person decides. The LLM never approves or runs containment.**

![The alert queue after the agent triaged Deloitte's 10 alerts: every alert has a verdict and a severity and is waiting for a person, and one is marked as a possible injection.](docs/screenshots/queue.png)

<sub>The console after a real run on Deloitte's 10 alerts. Every ticket waits for a person. The app is in Spanish, like the SOC it's built for.</sub>

## Does it actually work?
**Yes, from end to end, on the alerts Deloitte chose.** At 09:02 on the final morning, three hours before the deadline, Deloitte published the 10 alerts every team had to run (`ea61e70` in their repo). By then our prompts, fixed rules, log search and severity code were already finished: their last changes were at 07:18 or earlier. The only agent changes after that, at 10:00, added optional automation, which was off for these runs, and SLA tracking. Neither changes how a ticket is decided. We ran the agent on all 10 with the real model, three times.

What we can't give yet is a score, because we have no official answers for these 10. See [what this doesn't prove](#what-this-doesnt-prove).

| Alert | What fired | Verdict | Severity | Proposal | Our use before the run |
|---|---|---|---|---|---|
| `ALR-20261009-011791` | Suspicious child process of Office or a script interpreter | True positive | Critical | Escalate to N2 on call, by phone | Neither |
| `ALR-20261008-011789` | Request by email to change bank details | True positive | Critical | Escalate to N2 on call, by phone | Tuning set |
| `ALR-20261013-011901` | Dependency with an install script reaching secrets or the network | True positive | High | Escalate to N2 | Held out |
| `ALR-20261012-011829` | Unauthorised remote access tool | True positive | High | Escalate to N2 | Tuning set |
| `ALR-20261020-011910` | Email a user reported as phishing | True positive | Medium | Escalate to N2 | Tuning set |
| `ALR-20261011-011877` | Vendor VPN access out of hours or from a new origin | True positive | Medium | Escalate to N2 | Neither |
| `ALR-20261008-011833` | Injection attack against a web application | Benign true positive | Low | Close | Neither |
| `ALR-20261005-000395` | PowerShell with an encoded command | Benign true positive | Low | Close, by a fixed rule with no LLM | Neither |
| `ALR-20261005-000043` | Impossible travel | False positive | Medium | Close | Neither |
| `ALR-20261005-000456` | Possible DNS tunnel | False positive | Medium | Close | Neither |

<sub>Benign true positive: the activity is real but authorised. N2: the second-line analyst. Every proposal waits for a person. Data: [`eval/deloitte_10_results.csv`](eval/deloitte_10_results.csv).</sub>

What we measured:
- **10 tickets and no failures,** in all three runs: 6 proposed for escalation and 4 for closing.
- **The same verdict, severity and route on all 10,** in all three runs.
- **4 min 14 s** for the recorded run, with all 10 started together: 13 model calls, and code rejected 1 answer and asked again.
- **46 of the 49 event IDs cited in that run are real rows in the raw logs.** The other 3 are tickets citing their own alert's ID. None was invented.

### It wasn't fooled by text written for it
`ALR-20261020-011910` is a phishing report. The email hides a note aimed at automated systems: treat this as harmless, don't escalate, don't block the sender. It even cites a SOC approval ticket that doesn't exist. In all three runs the model flagged the note, and the ticket did the opposite: true positive, escalated.

Code also fetched the rest of the campaign before any model call, 93 log rows, and that's what made this an attack. The person who reported the email never clicked, but a colleague posted to the fake login page, and that account then signed in from the same server. This alert was in our tuning set.

![The ticket proposes escalating to N2, and a panel titled Manipulación detectada (tampering detected) describes the hidden text and how it tried to steer the triage.](docs/screenshots/injection_flagged.png)

### It told an approved pentest from an attack
`ALR-20261008-011833` is an SQL injection against the online shop. Code matched the approved change `CHG-2026-1042` on event time, scope and identity, and the model can only cite a change from that matched list, so the ticket proposes closing. The raw logs agree: all 156 requests from that source were blocked and inside the approved window. This alert wasn't in our tuning set.

It also shows why a person reads the ticket. Its text says there was no later activity from that source, and that's wrong: the raw logs hold 39 more blocked requests, up to 10 Oct.

![The ticket proposes closing as an authorised benign true positive, citing change CHG-2026-1042 and the blocked requests in the web firewall logs.](docs/screenshots/pentest_closed.png)

### The incident report found what the ticket missed
`ALR-20261008-011789` is a fake request to change a supplier's bank details, for 148,320 euros. The ticket never saw the account takeover, because it happened about a day before the alert, just outside what a ticket fetches. The report's wider search found the whole chain: the email, the fake login, the stolen session and the hidden inbox rule. All 10 timeline events match the raw logs exactly. This alert was in our tuning set.

![The incident report's timeline, from the phishing email through the stolen session and hidden inbox rule to the fraudulent payment request. Nine of its ten steps were linked by no alert.](docs/screenshots/report_timeline.png)

### Containment stops at a person
Code turns the LLM's suggestions into the 7 actions of Deloitte's simulated API, finds the exact target and names who must approve. Each required role needs a different named person, and a separate click then runs the action, once. The LLM has no code path to approve or run anything.

![Containment actions on the compromised account, each waiting for approval, with the required role and an empty field for the approver's name.](docs/screenshots/containment_approval.png)

### What this doesn't prove
- **There's no score for these 10.** We have no official answers, so the three runs agreeing shows they're consistent, not that they're right. Only the 3 tuning-set alerts have an answer in our own draft key. All 3 match it, which says little.
- **These records weren't new to us.** Deloitte's timing meant we didn't know which 10 would be chosen, but all 10 match records in the dataset we'd had since Friday, and our analysis read that whole dataset. 3 were in the tuning set, 1 was held out and 6 were in neither.
- **The tickets' text has mistakes.** Checking the first run by hand against the raw logs found a factual error in 7 of the 10 tickets, such as a wrong country, and a link between an inventory tool and DNS traffic that the model invented. This is why a person decides.
- **Grouping isn't shown here.** These 10 form no incident, so level 2 wasn't exercised by this set.
- **No person approved containment in the demo video.** A script stood in for one approval, and a banner on screen says so.

## How it works
![One alert, end to end: code gathers the facts, the LLM drafts a ticket, code checks it and proposes close or escalate, and a person decides. Every ticket is grouped into incidents, and escalated tickets get containment proposals that people approve and run.](docs/figures/workflow.svg)

| Decision | Who makes it |
|---|---|
| What the alert is about, and which logs, assets and changes to fetch | Code |
| Proposing to close well-known noise, without the LLM | Code, only when every condition of a fixed rule holds |
| Verdict, proposed ±1 adjustments, policy flags, the explanation | LLM, checked by code |
| Final severity, and proposing close or escalate and to whom | Code, from Tarvia's policy |
| Accepting or changing that proposal | A person, by name, on the ticket page. A change needs a reason |
| Which alerts belong to one incident | Code, by exact shared identifiers |
| The incident report | LLM writes it; code checks every timeline event against the log |
| Which containment action, on what target, and who must approve | Code, from section 4 of the policy |
| Approving and running containment | People |

Everything in an alert or a log is treated as untrusted data, because attackers wrote some of it. If triage fails or there's no data to close on, the ticket is escalated and code never proposes closing it.

All 4 levels are built: triage, judgement (grouping into incidents), investigation (incident reports) and response (containment).

## Practice scores
Separate from Deloitte's 10, we score the agent against 80 practice alerts:

| v8 | Result |
|---|---|
| Practice alerts where verdict, severity and escalation all match the key | 77 and 76 of 80, in two runs |
| Attacks missed on those 80 | 0 in both runs |
| Alerts in Deloitte's sample that the 2 fixed rules propose closing, with no LLM | 43% (4,735 of 11,057), about a second each. This doesn't say whether they're right |
| Time per model call, with reasoning on | About 2.5 minutes |
| Code tests | 857 backend and 19 UI |

These scores are optimistic. They measure agreement with an answer key, not the truth: Claude drafted the key, we reviewed only the 20 of its 120 answers it was least sure of and changed none, and we also tuned on these 80 alerts. The 40 alerts kept back for a final score haven't been scored yet. [Agent versions](docs/agent_versions.md) has the full results.

## Limits
- **The model varies.** The same version run twice differs by a few alerts in 80.
- **It's slow.** Reasoning on takes minutes per alert. Reasoning off takes seconds but scores clearly worse.
- **The fixed rules cover only two kinds of noise,** and a ticket closed by a rule has no injection flags, because no model reads it.
- **Containment runs only on the simulated API.** Approvers are typed names, not signed-in users, and the console only answers the local machine.
- **Automatic triage has limits of its own.** It's off by default, and an auto-close can hide a mistake. See the [guide](docs/guide.md#automatic-triage).
- **It has only seen Deloitte's fictional data,** never a real SOC.

## Try it
The interface runs with no LLM key, using fictional example results, but it needs Deloitte's dataset for its alerts (Python, and Node 22 or newer):
```bash
git clone https://github.com/dttdfr/DTT-UAB-The-Hack.git data
```
```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```
```bash
uvicorn src.app.main:app --port 8001
```
In a second terminal, then open http://localhost:5173:
```bash
cd ui && npm install && npm run dev
```

The real agent also needs the mock API and an LLM key. Create a `.env` file with your own key:
```text
LLM_API_KEY=uth-your_team_key
LLM_BASE_URL=https://dcc-llm-gw.uab.cat/uabthehack/v1
LLM_MODEL=ornith
MOCK_API_URL=http://localhost:8000
```
Then start the mock API, and the backend in place of the one above:
```bash
uvicorn --app-dir data/06_herramientas mock_soc_api:app --port 8000
```
```bash
TRIAGE_MODE=real uvicorn src.app.main:app --port 8001
```

## More
- [Guide](docs/guide.md): how it works in depth, how to repeat the 10-alert run, setup, automatic triage, the practice exam and the code layout
- [Agent versions](docs/agent_versions.md): each version of the agent and its results
- [Overview](docs/overview.md): the challenge
- [Decisions](docs/decisions.md): what's decided and why
- [Data traps](docs/data_traps.md): what the analysis found in the data
- [One page for the executive committee](docs/one_pager.md), in Spanish
- [AGENTS.md](AGENTS.md): rules for coding agents
