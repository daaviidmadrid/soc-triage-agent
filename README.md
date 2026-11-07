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
cp .env.example .env
```
Put your API key in `.env`.

## Run
Mock API:
```bash
uvicorn --app-dir data/06_herramientas mock_soc_api:app --port 8000
```
Test the LLM:
```bash
python scripts/test_llm.py
```

## Folders
```text
contracts/    data formats
src/tools/    api client, log search
src/policy/   severity, approvals
src/agent/    llm, triage
src/app/      backend
ui/           frontend
eval/         labels, scoring
docs/         one-pager, demo script
scripts/      quick tests
data/         deloitte dataset (not in git)
```
