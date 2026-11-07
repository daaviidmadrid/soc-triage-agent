# Example tickets and trace events

**Everything here is hand-written and fictional.** These files exist so the UI can be built and
tested before the real agent is connected. They are not findings about the dataset, and the
alert IDs, users, hosts, event IDs and indicators in them don't exist in `data/`.
IPs are from the RFC 5737 documentation ranges and domains end in `.example`.

They follow `Ticket` and `TraceEvent` in `contracts/models.py` on the `agent/core` branch.

| Scenario | Ticket | What it shows |
|---|---|---|
| `escalated` | `TKT-EXAMPLE-ESC-0001` | `true_positive`, severity raised by +1, mandatory escalation, actions waiting for approval |
| `closed_authorised` | `TKT-EXAMPLE-AUT-0002` | `benign_true_positive`, two alerts grouped, `authorised_by` a change, closed, one extra log search |
| `needs_more_info` | `TKT-EXAMPLE-NMI-0003` | truncated log result, LLM quota limit, error event, fallback ticket for a person |
| `injection` | `TKT-EXAMPLE-INJ-0004` | email text with hidden HTML and instructions, `injection_flags`, a rejected first answer and a retry |

Each scenario has two files: `<scenario>.trace.json` (the events, the last one `ticket_ready`)
and `<scenario>.ticket.json` (the ticket that event carries). `src/app/runner.py` replays them
when `TRIAGE_MODE` is unset or `example`, filling in `run_id`, `seq`, `at` and the ticket.

The `injection` ticket deliberately contains HTML and instructions as text. The UI must show
it as plain text and must not obey it.
