import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
HEALTH_URL = "http://127.0.0.1:8000/api/health"
STARTUP_TIMEOUT = 30


def _wait_for_app(process: subprocess.Popen, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"The web app exited during startup (exit code {process.returncode}).")
        try:
            with urllib.request.urlopen(HEALTH_URL, timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.25)
    raise RuntimeError(f"The web app did not become healthy within {timeout:g} seconds.")


def _stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main() -> int:
    if sys.prefix == sys.base_prefix:
        print("Activate the project virtual environment first: source .venv/bin/activate", file=sys.stderr)
        return 2
    if not os.getenv("XSS_SENTINEL_FRONTIER_KEY", "").strip():
        print("Set the saved XSS_SENTINEL_FRONTIER_KEY in this shell before starting the local app.", file=sys.stderr)
        return 2
    try:
        from xss_sentinel.frontier import frontier_cipher

        frontier_cipher()
    except (ImportError, ValueError) as exc:
        print(f"Frontier key or project dependencies are invalid ({type(exc).__name__}).", file=sys.stderr)
        return 2

    os.chdir(PROJECT_ROOT)
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 8000))
    except OSError:
        print("Port 8000 is already in use. Stop the existing app before running this launcher.", file=sys.stderr)
        return 1

    env = os.environ.copy()
    app = None
    worker = None
    try:
        app = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "xss_sentinel.main:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=PROJECT_ROOT,
            env=env,
        )
        _wait_for_app(app, STARTUP_TIMEOUT)
        print("Dashboard ready at http://127.0.0.1:8000")

        worker = subprocess.Popen(
            [sys.executable, "-m", "xss_sentinel.worker"],
            cwd=PROJECT_ROOT,
            env=env,
        )
        print("Worker started with the same database and frontier key. Press Ctrl+C to stop both.")

        while True:
            if app.poll() is not None:
                raise RuntimeError(f"The web app exited (exit code {app.returncode}).")
            if worker.poll() is not None:
                raise RuntimeError(f"The crawl worker exited (exit code {worker.returncode}).")
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("Stopping the local app and worker.")
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        _stop_process(worker)
        _stop_process(app)


if __name__ == "__main__":
    raise SystemExit(main())
