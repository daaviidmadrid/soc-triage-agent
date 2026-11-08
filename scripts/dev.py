"""Start the local mock, backend and UI together. No provider request is made at startup."""
import argparse
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DATA_DIRS = ("01_contexto", "02_inventario", "03_alertas", "04_logs", "05_inteligencia")


def prepare_mock(destination):
    """The mock writes its containment log beside itself, so run a copy outside data/."""
    destination = Path(destination)
    tools = destination / "06_herramientas"
    tools.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "data" / "06_herramientas" / "mock_soc_api.py", tools / "mock_soc_api.py")
    for name in DATA_DIRS:
        link = destination / name
        if not link.exists():
            link.symlink_to(ROOT / "data" / name, target_is_directory=True)
    return tools


def wait_port(port, process, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"El servicio del puerto {port} terminó al arrancar.")
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(.15)
    raise RuntimeError(f"El servicio del puerto {port} no arrancó a tiempo.")


def main():
    parser = argparse.ArgumentParser(description="Arranca la aplicación local completa.")
    parser.add_argument("--example", action="store_true", help="Usar tickets ficticios sin llamar al LLM")
    parser.add_argument("--mock-port", type=int, default=8000)
    parser.add_argument("--backend-port", type=int, default=8001)
    parser.add_argument("--ui-port", type=int, default=5173)
    args = parser.parse_args()
    for port in (args.mock_port, args.backend_port, args.ui_port):
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                raise SystemExit(f"El puerto {port} ya está ocupado. Detén las terminales anteriores con Ctrl+C y vuelve a ejecutar python scripts/dev.py.")
    if not (ROOT / "ui" / "node_modules").exists():
        raise SystemExit("Faltan las dependencias web. Ejecuta: cd ui && npm install")
    mock_dir = prepare_mock(ROOT / "runs" / "dev-mock")
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1",
           "TRIAGE_MODE": "example" if args.example else "real", "APP_SAMPLE": "none",
           "AUTO_TRIAGE": "1", "AUTO_INVESTIGATE": "1",
           "APP_DB_PATH": os.environ.get("APP_DB_PATH") or str(ROOT / "runs" / "demo.sqlite3"),
           "MOCK_API_URL": f"http://127.0.0.1:{args.mock_port}",
           "API_PROXY_TARGET": f"http://127.0.0.1:{args.backend_port}"}
    commands = [
        ([sys.executable, "-m", "uvicorn", "--app-dir", str(mock_dir), "mock_soc_api:app", "--host", "127.0.0.1", "--port", str(args.mock_port)], ROOT, args.mock_port),
        ([sys.executable, "-m", "uvicorn", "src.app.main:app", "--host", "127.0.0.1", "--port", str(args.backend_port)], ROOT, args.backend_port),
        (["npm", "run", "dev", "--", "--host", "127.0.0.1", "--port", str(args.ui_port), "--strictPort"], ROOT / "ui", args.ui_port),
    ]
    children = []
    def stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        for command, cwd, port in commands:
            process = subprocess.Popen(command, cwd=cwd, env=env)
            children.append(process)
            wait_port(port, process)
        print(f"\nAplicación lista: http://127.0.0.1:{args.ui_port}\nSube las alertas y pulsa Iniciar flujo. Ctrl+C detiene los tres servicios.\n", flush=True)
        while all(p.poll() is None for p in children):
            time.sleep(.3)
    except KeyboardInterrupt:
        pass
    except (OSError, RuntimeError) as error:
        print(f"No se pudo arrancar: {error}", file=sys.stderr)
        return 1
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
        for child in reversed(children):
            child.wait()
    return 0


if __name__ == "__main__":
    project_python = ROOT / ".venv" / "bin" / "python"
    if project_python.exists() and Path(sys.prefix).resolve() != (ROOT / ".venv").resolve():
        os.execv(str(project_python), [str(project_python), __file__, *sys.argv[1:]])
    raise SystemExit(main())
