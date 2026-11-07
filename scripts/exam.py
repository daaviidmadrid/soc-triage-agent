#!/usr/bin/env python3
"""Runs the practice exam on one laptop or splits it across several. Start from the repo root.

    python3 scripts/exam.py setup                        prepares this laptop
    python3 scripts/exam.py check                        says what is ready and how to fix what isn't
    python3 scripts/exam.py run --laptop 1 --laptops 3   triages this laptop's share of the alerts
    python3 scripts/exam.py status                       shows what is done and what is missing
    python3 scripts/exam.py pack --laptop 1              makes a zip to send to the laptop that merges
    python3 scripts/exam.py merge FILE.zip [FILE.zip]    adds other laptops' results to this one
    python3 scripts/exam.py score                        marks the tickets against eval/labels.csv

--set chooses the alerts: exam (40 hard cases with answers, the default), normal (40 alerts in a normal
day's mix, with answers), scored (both), extra (the other test alerts, with no answers), all (everything)
or the path of a file with one alert ID per line.

If a run stops for any reason, run the same command again. Saved tickets are never redone.
The .env file is read only by the program, and neither its key nor its contents are ever printed.
"""
import argparse
import collections
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = ROOT / "runs"
VENV = ROOT / ".venv"
VENV_PYTHON = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
DATA_REPO = "https://github.com/dttdfr/DTT-UAB-The-Hack.git"
ALERTS_FILE = ROOT / "data" / "03_alertas" / "alertas.jsonl"
EXAM_FILE = ROOT / "eval" / "key40_alerts.txt"
NORMAL_FILE = ROOT / "eval" / "key_normal40_alerts.txt"
LABELS_FILE = ROOT / "eval" / "labels.csv"
MOCK_FILE = ROOT / "data" / "06_herramientas" / "mock_soc_api.py"
ENV_TEMPLATE = """LLM_API_KEY=
LLM_BASE_URL=https://dcc-llm-gw.uab.cat/uabthehack/v1
LLM_MODEL=ornith
LLM_ENABLE_THINKING=false
MOCK_API_URL=http://localhost:8000
"""
MIN_PYTHON = (3, 11)
MOCK_START_SECONDS = 180
# The provider's daily limit stops a run by itself, so this only guards against a runaway loop.
MAX_CALLS = 2000
SECONDS_PER_ALERT = 4
EXTRA_PASSES = 2
TICKET_NAME = re.compile(r"[A-Za-z0-9_-]+\.json")
FOLDER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class Problem(Exception):
    """Something the person has to fix. The message says how."""


def _use_project():
    os.chdir(ROOT)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))


def _load_env():
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")


def _model():
    """The one model this run uses. Fallback is turned off so a run's tickets all come from the same model."""
    _load_env()
    model = os.environ.get("LLM_MODEL", "").strip()
    if not model:
        raise Problem("LLM_MODEL isn't set in .env. Run: python3 scripts/exam.py check")
    os.environ["LLM_BACKUP_MODEL"] = model
    return model


def results_folder(model=None):
    """Tickets from different models, prompts or reasoning settings must never mix, so each gets its own folder."""
    from src.agent.prompts import PROMPT_VERSION

    thinking = "-nothink" if os.environ.get("LLM_ENABLE_THINKING", "").strip().lower() == "false" else ""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", f"{PROMPT_VERSION}-{model or _model()}{thinking}")
    return RUNS_DIR / name


def split(ids, laptop, laptops):
    """This laptop's share. Every alert goes to exactly one laptop, and the order comes from the list, not the ID."""
    if laptops < 1 or not 1 <= laptop <= laptops:
        raise Problem(f"--laptop must be between 1 and {max(laptops, 1)}.")
    return ids[laptop - 1::laptops]


def choose_ids(name):
    """The alert IDs of a set, in order, never with held-out alerts."""
    from eval import score

    exam = score._read_ids(EXAM_FILE)
    normal = score._read_ids(NORMAL_FILE)
    if name == "exam":
        ids = exam
    elif name == "normal":
        ids = normal
    elif name == "scored":
        ids = exam + normal
    elif name in ("extra", "all"):
        chosen = set(exam + normal)
        extra = [alert["alert_id"] for alert in score.load_test_set() if alert["alert_id"] not in chosen]
        ids = extra if name == "extra" else exam + normal + extra
    else:
        path = Path(name)
        if not path.exists():
            raise Problem(f"There's no set or file called {name}. Use exam, extra, all or a file of alert IDs.")
        ids = score._read_ids(path)
    held_out = set(score._read_ids(score.HELDOUT_FILE))
    return [alert_id for alert_id in dict.fromkeys(ids) if alert_id not in held_out]


# --- the mock API -----------------------------------------------------------------------------

def mock_url():
    _load_env()
    return os.environ.get("MOCK_API_URL", "http://localhost:8000").rstrip("/")


def mock_is_up(url=None):
    try:
        with urllib.request.urlopen(f"{url or mock_url()}/alerts?limit=1", timeout=5) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


@contextlib.contextmanager
def running_mock():
    """Uses the mock API if it is already running. If not, starts it for this command and stops it after."""
    url = mock_url()
    if mock_is_up(url):
        yield
        return
    found = re.search(r":(\d+)$", url)
    port = found.group(1) if found else "8000"
    print(f"Starting the mock API on port {port}. Loading the logs can take a minute.", flush=True)
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "--app-dir", str(MOCK_FILE.parent), "mock_soc_api:app", "--port", port, "--log-level", "warning"],
        cwd=ROOT, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    try:
        deadline = time.monotonic() + MOCK_START_SECONDS
        while not mock_is_up(url):
            if process.poll() is not None:
                raise Problem(f"The mock API didn't start. Is another program using port {port}?")
            if time.monotonic() > deadline:
                raise Problem("The mock API took too long to start.")
            time.sleep(1)
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


# --- setup and check --------------------------------------------------------------------------

def command_setup(_args):
    os.chdir(ROOT)
    if sys.version_info < MIN_PYTHON:
        raise Problem(f"Python {'.'.join(map(str, MIN_PYTHON))} or newer is needed, and this is {sys.version.split()[0]}.")
    if not VENV_PYTHON.exists():
        print("Creating .venv ...", flush=True)
        subprocess.check_call([sys.executable, "-m", "venv", str(VENV)])
    print("Installing the requirements ...", flush=True)
    subprocess.check_call([str(VENV_PYTHON), "-m", "pip", "install", "--quiet", "-r", "requirements.txt"])
    if not ALERTS_FILE.exists():
        if (ROOT / "data").exists() and any((ROOT / "data").iterdir()):
            raise Problem("data/ exists but has no alerts. Move it away and run setup again.")
        print("Downloading Deloitte's dataset into data/ ...", flush=True)
        subprocess.check_call(["git", "clone", DATA_REPO, "data"])
    env_file = ROOT / ".env"
    if not env_file.exists():
        env_file.write_text(ENV_TEMPLATE, encoding="utf-8")
        print("Created .env. Open it and put your own key after LLM_API_KEY=")
    return subprocess.call([str(VENV_PYTHON), str(Path(__file__).resolve()), "check"])


def _checks():
    """Yields (passed, what was checked, how to fix it)."""
    version = ".".join(map(str, sys.version_info[:3]))
    yield sys.version_info >= MIN_PYTHON, f"Python {version}", "Install a newer Python, then run setup."
    missing = []
    for module in ("dotenv", "fastapi", "httpx", "openai", "pydantic"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    yield not missing, "Python packages", "Run: python3 scripts/exam.py setup"
    if missing:
        return
    for path, name in ((ALERTS_FILE, "alerts"), (MOCK_FILE, "mock API"), (EXAM_FILE, "exam list"), (LABELS_FILE, "answer key")):
        yield path.exists(), f"{name} file", "Run: python3 scripts/exam.py setup, and update this branch with git pull."
    _load_env()
    yield bool(os.environ.get("LLM_API_KEY", "").strip()), "LLM key is set", "Put your own key after LLM_API_KEY= in .env"
    yield bool(os.environ.get("LLM_BASE_URL", "").strip()), "LLM address is set", "Copy LLM_BASE_URL from the README into .env"
    model = os.environ.get("LLM_MODEL", "").strip()
    yield bool(model), f"model: {model or 'not set'}", "Put LLM_MODEL=ornith in .env"
    print(f"  --  reasoning: {'off' if os.environ.get('LLM_ENABLE_THINKING', '').strip().lower() == 'false' else 'on, which takes minutes per alert'}")


def _commit():
    try:
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT, text=True).strip()
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, text=True, capture_output=True).stdout.strip()
    return f"{branch} at {commit}" + (" with uncommitted changes" if dirty else "")


def _ping():
    from src.agent.llm import LLMError, complete

    _model()

    started = time.monotonic()
    try:
        result = complete("Reply with this JSON only: {\"ok\": true}", "Are you there?")
    except LLMError as error:
        return False, f"LLM call failed: {error}"
    return True, f"LLM answered in {time.monotonic() - started:.1f} s from {result.model}"


def command_check(args):
    os.chdir(ROOT)
    failed = 0
    for passed, label, fix in _checks():
        print(f"  {'ok ' if passed else 'NO '} {label}" + ("" if passed else f"\n       Fix: {fix}"))
        failed += not passed
    if failed:
        print(f"{failed} thing(s) to fix before running.")
        return 1
    _use_project()
    print(f"  ok  code: {_commit()}")
    with running_mock():
        from src.tools.context import build_context
        from eval import score

        alert = score._read_jsonl(score.SAMPLE)[0]
        started = time.monotonic()
        rows = sum(len(items) for items in build_context(alert).logs.values())
        print(f"  ok  mock API answers: {rows} log rows for a test alert in {time.monotonic() - started:.1f} s")
    print(f"  ok  {len(choose_ids('exam'))} exam alerts, {len(choose_ids('normal'))} normal-day alerts, {len(choose_ids('extra'))} extra alerts")
    if args.ping:
        passed, message = _ping()
        print(f"  {'ok ' if passed else 'NO '} {message}")
        if not passed:
            return 1
    print("Ready. Other laptops must be on the same commit, so that results can be compared.")
    return 0


# --- run ---------------------------------------------------------------------------------------

def _unreviewed_answers():
    from eval import score

    return sum(row.get("labelled_by") == "claude-draft" for row in score.load_labels())


class _PlainBar:
    """Stands in for tqdm on a laptop that hasn't installed it yet, so a run never fails for lack of a bar."""

    def __init__(self, total):
        self.n, self.total = 0, total

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def update(self, step=1):
        self.n += step
        print(f"  {self.n}/{self.total}", flush=True)

    def set_postfix(self, **_):
        pass

    def write(self, text):
        print(text, flush=True)


def progress_bar(total):
    """Returns (bar, on_result). The bar counts saved alerts. Failures are named above it, and they are tried again."""
    try:
        from tqdm import tqdm

        bar = tqdm(total=total, unit="alert", smoothing=0.1)
    except ImportError:
        bar = _PlainBar(total)
    failed = {"count": 0}

    def show(alert_id, status, seconds):
        if status == "done":
            bar.update(1)
        elif status == "failed":
            failed["count"] += 1
            bar.set_postfix(failed=failed["count"])
            bar.write(f"  {alert_id} failed, and will be tried again")
        elif status == "not_found":
            bar.write(f"  {alert_id} isn't in the dataset")

    return bar, show


def command_run(args):
    _use_project()
    if args.no_thinking:
        os.environ["LLM_ENABLE_THINKING"] = "false"
    model = _model()
    ids = split(choose_ids(args.set), args.laptop, args.laptops)
    folder = results_folder(model)
    pending = [alert_id for alert_id in ids if not (folder / f"{alert_id}.json").exists()]
    print(f"Laptop {args.laptop} of {args.laptops}: {len(ids)} alerts from '{args.set}', {len(ids) - len(pending)} already done. Model {model}.")
    print(f"Results go to runs/{folder.name}. About {max(1, round(len(pending) * (SECONDS_PER_ALERT + args.pace) / 60))} min.")
    if args.limit:
        pending = pending[:args.limit]
        print(f"Only the next {len(pending)}, because of --limit.")
    if args.set == "exam" and _unreviewed_answers():
        print(f"Note: {_unreviewed_answers()} answers in eval/labels.csv are still unreviewed drafts. Don't edit them after seeing results without noting why.")
    if not pending:
        print("Nothing to do.")
        return 0

    from src.agent.batch import load_alerts, run_batch

    alerts = load_alerts(pending)
    missing = [alert_id for alert_id in pending if alert_id not in alerts]
    bar, show = progress_bar(len(pending))

    report = {}
    with running_mock(), bar:
        for attempt in range(EXTRA_PASSES + 1):
            todo = [alert_id for alert_id in pending if not (folder / f"{alert_id}.json").exists() and alert_id in alerts]
            if not todo:
                break
            if attempt:
                print(f"Trying {len(todo)} failed alert(s) again in 30 s.", flush=True)
                time.sleep(30)
            report = run_batch(todo, alerts=alerts, out_dir=folder, pace_seconds=args.pace, max_calls=MAX_CALLS, on_result=show, workers=args.workers)
            if report["quota_exhausted"]:
                break

    left = [alert_id for alert_id in ids if not (folder / f"{alert_id}.json").exists()]
    print(f"Finished: {len(ids) - len(left)} of {len(ids)} saved, {len(left)} left.")
    if missing:
        print(f"{len(missing)} alert(s) aren't in the dataset: {', '.join(missing[:5])}")
    if report.get("quota_exhausted"):
        print("Google's daily limit was reached on this key. It resets at about 09:00 Madrid. Saved tickets are safe.")
    if left:
        print("Run the same command again to carry on.")
        return 1
    print(f"Next: python3 scripts/exam.py pack --laptop {args.laptop}" if args.laptops > 1 else "Next: python3 scripts/exam.py score")
    return 0


# --- status, pack and merge --------------------------------------------------------------------

def _folder(args):
    if getattr(args, "folder", None):
        return Path(args.folder)
    return results_folder()


def command_status(args):
    _use_project()
    folder = _folder(args)
    print(f"Results in {folder}")
    names = ("exam", "normal", "extra")
    for name in names:
        ids = choose_ids(name)
        done = sum((folder / f"{alert_id}.json").exists() for alert_id in ids)
        print(f"  {name}: {done} of {len(ids)} done")
        if name == "exam" and done < len(ids):
            for laptop in range(1, args.laptops + 1):
                share = split(ids, laptop, args.laptops)
                print(f"    laptop {laptop}: {sum((folder / f'{i}.json').exists() for i in share)} of {len(share)}")
    return 0


def command_pack(args):
    _use_project()
    folder = _folder(args)
    tickets = sorted(folder.glob("*.json"))
    if not tickets:
        raise Problem(f"There are no results in {folder} yet.")
    target = RUNS_DIR / f"exam_{folder.name}_laptop{args.laptop}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in tickets + sorted((folder / "traces").glob("*.json")):
            archive.write(path, Path(folder.name) / path.relative_to(folder))
    print(f"Made {target} with {len(tickets)} tickets. Send it to the laptop that merges, for example by AirDrop.")
    return 0


def merge_zip(path, runs_dir=RUNS_DIR):
    """Adds a pack to runs/. Refuses anything that isn't a ticket or a trace. Returns (folder name, new, same, different)."""
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        raise Problem(f"{path} isn't a results pack made by this script.") from None
    with archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        folders = {name.split("/")[0] for name in names}
        if len(folders) != 1:
            raise Problem(f"{path} isn't a results pack made by this script.")
        folder_name = folders.pop()
        # Everything is checked before anything is written, so a bad pack changes nothing.
        contents = {}
        for name in names:
            inside = name.split("/")[1:]
            valid = (len(inside) == 1 and TICKET_NAME.fullmatch(inside[0])) or (len(inside) == 2 and inside[0] == "traces" and TICKET_NAME.fullmatch(inside[1]))
            if not valid or not FOLDER_NAME.fullmatch(folder_name):
                raise Problem(f"{path} holds an unexpected file, so nothing was merged from it.")
            contents[tuple(inside)] = archive.read(name)
            try:
                json.loads(contents[tuple(inside)])
            except ValueError:
                raise Problem(f"{path} holds a damaged file, so nothing was merged from it.") from None
    new = same = different = 0
    for inside, content in contents.items():
        target = runs_dir / folder_name / Path(*inside)
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_bytes(content)
            new += len(inside) == 1
        elif target.read_bytes() == content:
            same += len(inside) == 1
        else:
            different += len(inside) == 1
    return folder_name, new, same, different


def command_merge(args):
    _use_project()
    folders = set()
    for name in args.files:
        path = Path(name)
        if not path.exists():
            raise Problem(f"There's no file called {name}.")
        folder, new, same, different = merge_zip(path)
        folders.add(folder)
        print(f"{path.name}: {new} new tickets, {same} already here" + (f", {different} DIFFERENT and not replaced" if different else "") + f", in runs/{folder}")
    if len(folders) > 1:
        print(f"Warning: these packs come from different models or prompts: {', '.join(sorted(folders))}. Don't mix them in one score.")
    print("Next: python3 scripts/exam.py status, then python3 scripts/exam.py score --folder runs/" + sorted(folders)[0])
    return 0


# --- score -------------------------------------------------------------------------------------

def _trace_facts(folder):
    models, seconds = collections.Counter(), []
    for path in (folder / "traces").glob("*.json"):
        events = json.loads(path.read_text(encoding="utf-8"))
        for event in events:
            args = event.get("args") or {}
            if event.get("tool") == "llm" and args.get("model"):
                models[args["model"]] += 1
                seconds.append(args.get("seconds") or 0)
    return models, seconds


def _print_mistakes(report):
    """Where the AI and the key disagree. The key can be wrong too, so each of these is worth a look."""
    rows = []
    for row in report["per_alert"]:
        wrong = [f"{field}: AI {row[field][0]}, key {row[field][1]}" for field in ("verdict", "severity", "escalate") if field in row and row[field][0] != row[field][1]]
        if wrong:
            rows.append(f"  {row['alert_id']}  " + "; ".join(wrong))
    if rows:
        print(f"Disagreements with the key: {len(rows)}")
        print("\n".join(rows))


def command_score(args):
    _use_project()
    from eval import score

    folder = _folder(args)
    tickets = []
    for path in sorted(folder.glob("*.json")):
        tickets += score.load_tickets(path)
    if not tickets:
        raise Problem(f"There are no tickets in {folder} yet.")
    labels = score.load_labels()
    labelled = {label["alert_id"] for label in labels}
    if args.set:
        wanted = set(choose_ids(args.set))
        labels = [label for label in labels if label["alert_id"] in wanted]
    report = score.score(tickets, labels)
    print(f"Tickets read: {len(tickets)} from {folder}" + (f". Marking only '{args.set}'." if args.set else ""))
    if report["no_ticket"]:
        print(f"Note: {len(report['no_ticket'])} labelled alerts have no ticket yet, and they count as missed below. Run or merge the rest first.")
    score._print(report)
    _print_mistakes(report)
    other = [ticket for ticket in tickets if not set(ticket.get("alert_ids") or []) & labelled]
    if other:
        verdicts = collections.Counter(ticket.get("verdict") for ticket in other)
        escalated = sum(bool((ticket.get("escalation") or {}).get("escalate")) for ticket in other)
        print(f"Tickets with no answer to compare: {len(other)}. Verdicts {dict(verdicts)}, {escalated} escalated. These show it runs, not that it's right.")
    automatic = [ticket for ticket in tickets if ticket.get("confidence") == 0.0 and not ticket.get("evidence")]
    print(f"Tickets that fell back to a person because triage failed: {len(automatic)}")
    models, seconds = _trace_facts(folder)
    if seconds:
        print(f"Models: {dict(models)}. Average model call: {sum(seconds) / len(seconds):.1f} s.")
    return 0


# --- entry point -------------------------------------------------------------------------------

def parser():
    main_parser = argparse.ArgumentParser(description="Runs the practice exam on one or more laptops.")
    commands = main_parser.add_subparsers(dest="command", required=True)
    commands.add_parser("setup", help="prepare this laptop").set_defaults(run=command_setup)
    check = commands.add_parser("check", help="say what is ready")
    check.add_argument("--ping", action="store_true", help="also make one real LLM call, which uses up one of the day's calls")
    check.set_defaults(run=command_check)
    run = commands.add_parser("run", help="triage this laptop's share")
    run.add_argument("--set", default="exam", help="exam, extra, all or a file of alert IDs")
    run.add_argument("--laptop", type=int, default=1)
    run.add_argument("--laptops", type=int, default=1)
    run.add_argument("--limit", type=int, default=0, help="only do this many alerts")
    run.add_argument("--pace", type=float, default=2.0, help="seconds to wait between alerts when --workers is 1")
    run.add_argument("--workers", type=int, default=1, help="how many alerts to run at once")
    run.add_argument("--no-thinking", action="store_true", help="turn off reasoning, on models that support it")
    run.set_defaults(run=command_run)
    status = commands.add_parser("status", help="show what is done")
    status.add_argument("--laptops", type=int, default=3)
    status.add_argument("--folder")
    status.set_defaults(run=command_status)
    pack = commands.add_parser("pack", help="zip results to send to another laptop")
    pack.add_argument("--laptop", type=int, default=1)
    pack.add_argument("--folder")
    pack.set_defaults(run=command_pack)
    merge = commands.add_parser("merge", help="add other laptops' results")
    merge.add_argument("files", nargs="+")
    merge.set_defaults(run=command_merge)
    score = commands.add_parser("score", help="mark the tickets")
    score.add_argument("--folder")
    score.add_argument("--set", help="mark only this set, such as exam or normal")
    score.set_defaults(run=command_score)
    return main_parser


def _running_from_venv():
    return Path(sys.prefix).resolve() == VENV.resolve()


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    options = parser().parse_args(arguments)
    if options.command != "setup" and VENV_PYTHON.exists() and not _running_from_venv():
        return subprocess.call([str(VENV_PYTHON), str(Path(__file__).resolve()), *arguments])
    try:
        return options.run(options)
    except Problem as problem:
        print(f"Stopped: {problem}")
        return 1
    except KeyboardInterrupt:
        print("\nStopped. Saved tickets are safe: run the same command again to carry on.")
        return 130
    except subprocess.CalledProcessError as error:
        print(f"Stopped: a setup step failed ({error}). Check your internet connection and try again.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
