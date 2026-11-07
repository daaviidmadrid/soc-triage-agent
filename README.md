# Deloitte_Challenge_UAB_THE_HACK_2026
## Authors: 
- David
- Alex
- Francesco

## Setup
```bash
git clone https://github.com/dttdfr/DTT-UAB-The-Hack.git data
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
Create a `.env` file with your own key:
```text
LLM_API_KEY=uth-your_team_key
LLM_BASE_URL=https://dcc-llm-gw.uab.cat/uabthehack/v1
LLM_MODEL=ornith
LLM_ENABLE_THINKING=false
MOCK_API_URL=http://localhost:8000
```
With `LLM_ENABLE_THINKING=false`, `ornith` answers in seconds. Without it, the model reasons first and an alert takes minutes.
The UI also needs Node 22 or newer (on a Mac, `brew install node`):
```bash
cd ui && npm install
```

## Run
Mock API:
```bash
uvicorn --app-dir data/06_herramientas mock_soc_api:app --port 8000
```
Backend, with the real agent (needs the mock API running and the LLM key in `.env`):
```bash
TRIAGE_MODE=real uvicorn src.app.main:app --port 8001
```
Backend with fictional example tickets from `contracts/examples/` (no mock API or LLM key needed):
```bash
uvicorn src.app.main:app --port 8001
```
UI, at http://localhost:5173:
```bash
cd ui && npm run dev
```
Backend with an empty queue that holds only the alerts you import, using its own database:
```bash
TRIAGE_MODE=real APP_SAMPLE=none APP_DB_PATH=runs/final.sqlite3 uvicorn src.app.main:app --port 8001
```
The import button takes JSON, JSONL or CSV, with other field names too. Save an Excel file as CSV first.

Test the LLM:
```bash
python scripts/test_llm.py
```
Tests:
```bash
pytest
```

## Practice exam
`scripts/exam.py` triages alerts and scores them against `eval/labels.csv`. It starts the mock API if needed, and a run that stops can be repeated without redoing anything. On each laptop:
```bash
python3 scripts/exam.py setup
```
```bash
python3 scripts/exam.py run --laptop 1 --laptops 3
```
```bash
python3 scripts/exam.py pack --laptop 1
```
Change `--laptop` to 2 and 3 on the others, and send their zips to one laptop. There:
```bash
python3 scripts/exam.py merge runs/exam_FOLDER_laptop2.zip runs/exam_FOLDER_laptop3.zip
```
```bash
python3 scripts/exam.py score
```
All laptops must be on the same commit and model. `--set` chooses the alerts: `exam` is 40 hard cases and `normal` is 40 in a normal day's mix, both with answers, `scored` is both, `extra` is the other 102 with no answers, and `all` is everything. `--workers 6` runs six alerts at once on a provider with no limits. `score --set normal` marks one set.

Each run also keeps a call log in `calls/`: for every alert, the prompts sent, the model's raw answers and reasoning, and what our code changed. To read one:
```bash
python3 scripts/exam.py explain ALR-20261007-011785
```
Add `--prompt` to see the prompts. The app keeps the same for real runs in `runs/app_calls/`. These files hold alert and log text, which may contain attackers' instructions, so read them as data. `runs/` is not in git, and `pack` includes the logs.

Analysis notebook:
```bash
jupyter notebook analysis/explore.ipynb
```

## Folders
```text
analysis/     data analysis notebook
contracts/    data formats
src/tools/    api client, log search
src/policy/   severity, approvals
src/agent/    llm, triage
src/app/      backend
ui/           frontend (react, css)
eval/         labels, scoring
docs/         notes, one-pager, demo script
scripts/      quick tests
data/         deloitte dataset (not in git)
```

## Docs
- [Overview](docs/overview.md): what we're building
- [Decisions](docs/decisions.md): what's decided and what's open
- [Data traps](docs/data_traps.md): what the analysis found in the data
- [AGENTS.md](AGENTS.md): rules for coding agents
