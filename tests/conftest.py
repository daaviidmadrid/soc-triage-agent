"""Starts a copy of the mock API outside data/ for the whole test session.

The mock writes containment_log.jsonl next to itself, so we copy mock_soc_api.py into a
temp folder and symlink the read-only data folders beside it. MOCK_API_URL points at it.
"""
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
sys.path.insert(0, str(ROOT))

DATA_DIRS = ["01_contexto", "02_inventario", "03_alertas", "04_logs", "05_inteligencia"]


@pytest.fixture(autouse=True)
def manual_defaults_for_existing_tests(monkeypatch):
    """Legacy tests exercise manual routes. Automation tests opt in with an explicit Config."""
    monkeypatch.setenv("AUTO_TRIAGE", "0")
    monkeypatch.setenv("AUTO_INVESTIGATE", "0")
    monkeypatch.setenv("AUTO_CLOSE_LOW_RISK", "0")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def mock_dir(tmp_path_factory):
    base = tmp_path_factory.mktemp("mock")
    tools = base / "06_herramientas"
    tools.mkdir()
    shutil.copy(DATA / "06_herramientas" / "mock_soc_api.py", tools / "mock_soc_api.py")
    for d in DATA_DIRS:
        (base / d).symlink_to(DATA / d, target_is_directory=True)
    return base


@pytest.fixture(scope="session", autouse=True)
def mock_api(mock_dir):
    port = _free_port()
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "--app-dir", str(mock_dir / "06_herramientas"),
         "mock_soc_api:app", "--port", str(port), "--log-level", "warning"],
        env=env, cwd=str(mock_dir),
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 60
    while True:
        try:
            httpx.get(url + "/alerts", params={"limit": 1}, timeout=2)
            break
        except httpx.HTTPError:
            if proc.poll() is not None or time.time() > deadline:
                proc.kill()
                raise RuntimeError("mock API did not start")
            time.sleep(0.3)
    old = os.environ.get("MOCK_API_URL")
    os.environ["MOCK_API_URL"] = url
    yield url
    proc.terminate()
    proc.wait(timeout=10)
    if old is None:
        os.environ.pop("MOCK_API_URL", None)
    else:
        os.environ["MOCK_API_URL"] = old
