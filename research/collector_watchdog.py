"""Independent Windows Task Scheduler watchdog; one short, local-only check.

Schedule every minute. It controls only this project's existing collector task,
never signs in, and never treats an old location alone as a hung process.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from location_ledger import store
from . import auth_cooldown
from .collector import collector_lock, prerequisite, write_status
from .windows_secrets import load

HEARTBEAT_TIMEOUT = 180
STARTUP_GRACE = 180
STOP_GRACE = 20
STABLE_SECONDS = 600


def task_name(root):
    return "FindMyLedger-" + hashlib.sha256(str(Path(root).resolve()).lower().encode()).hexdigest()[:8].upper()


def integer(value, default=0):
    return value if type(value) is int and value >= 0 else default


def read_status(path):
    if not path.exists():
        return {}
    if path.stat().st_size > 65536:
        raise ValueError("Oversized local status")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Invalid local status")
    return value


def decide(task, status, saved, *, now, manual_stop=False, participant_active=True, cooldown_until=0):
    """Pure recovery policy. Deliberate stops/auth/validation failures stay stopped."""
    state = task.get("state")
    if manual_stop:
        return "none", "manual_stop"
    if not participant_active:
        return ("stop" if state == "Running" else "none"), "participant_paused_or_unselected"
    if state not in ("Running", "Ready"):
        return "none", "task_unavailable_or_disabled"
    started = integer(task.get("last_run_unix"))
    heartbeat = integer(status.get("heartbeat_unix"))
    # Ignore status left by a previous process while its replacement boots.
    current_status = heartbeat >= started - 2
    if state == "Running":
        if now - started < STARTUP_GRACE:
            return "none", "worker_starting"
        if current_status and now - HEARTBEAT_TIMEOUT <= heartbeat <= now + 30:
            return "none", "worker_responsive"
        requested = integer(saved.get("restart_requested_unix"))
        if requested < started:
            requested = 0
        if requested and now - requested >= STOP_GRACE:
            return "force_stop", "worker_unresponsive"
        return ("none", "waiting_for_graceful_stop") if requested else ("request_stop", "worker_heartbeat_stale")
    if current_status and status.get("state") == "paused":
        return "none", "worker_paused"
    if current_status and status.get("state") == "stopped" and status.get("reason") != "watchdog_restart":
        return "none", "worker_stopped_intentionally"
    if current_status and status.get("state") == "needs_attention" and status.get("automatic_recovery") is not True:
        return "none", "manual_attention_required"
    if max(cooldown_until, integer(saved.get("next_restart_unix")), integer(status.get("next_connect_unix"))) > now:
        return "none", "recovery_backoff"
    return "start", "recoverable_worker_exit" if status.get("automatic_recovery") else "worker_exited_unexpectedly"


class WindowsTask:
    def __init__(self, root, name):
        self.root = Path(root).resolve()
        self.name = name
        if name != task_name(self.root):
            raise ValueError("Watchdog task identity must match this project")

    def command(self, source):
        powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        completed = subprocess.run([str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", source],
            capture_output=True, text=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        if completed.returncode or len(completed.stdout) > 16384:
            raise RuntimeError("Windows task control failed")
        return completed.stdout

    def query(self):
        # name is a derived fixed-prefix hex identifier, never shell input.
        source = "$ErrorActionPreference='Stop'\n" + f"$ledgerTask=Get-ScheduledTask -TaskName '{self.name}' -ErrorAction SilentlyContinue\n"
        source += "if (-not $ledgerTask) { @{state='absent'} | ConvertTo-Json -Compress; exit }\n"
        source += f"$ledgerInfo=Get-ScheduledTaskInfo -TaskName '{self.name}'\n"
        source += "@{state=[string]$ledgerTask.State; last_run_unix=([DateTimeOffset]$ledgerInfo.LastRunTime).ToUnixTimeSeconds(); working_directory=$ledgerTask.Actions[0].WorkingDirectory; arguments=$ledgerTask.Actions[0].Arguments} | ConvertTo-Json -Compress"
        result = json.loads(self.command(source))
        if result["state"] != "absent":
            if (Path(result.pop("working_directory")).resolve() != self.root
                    or "research.live_collector" not in result.pop("arguments", "")):
                raise ValueError("Collector task definition does not match this project")
        return result

    def start(self):
        self.command(f"$ErrorActionPreference='Stop'; Start-ScheduledTask -TaskName '{self.name}'")

    def stop(self):
        self.command(f"$ErrorActionPreference='Stop'; Stop-ScheduledTask -TaskName '{self.name}'")


def check(directory, database, control, *, now=None, participant_check=None, bootstrap_check=None):
    now = int(time.time()) if now is None else now
    path = directory / "watchdog-status.json"
    saved = read_status(path)
    status = read_status(directory / "collector-status.json")
    task = control.query()
    if participant_check is None:
        selection = load(directory / "selected-person.dpapi")
        with store.connect(database) as db:
            participant_active = bool(store.subject(db, selection["alias"])["active"])
    else:
        participant_active = participant_check()
    cooldown = auth_cooldown.active(directory, now=now)
    action, reason = decide(task, status, saved, now=now,
        manual_stop=(directory / "live-stop.request").exists(), participant_active=participant_active,
        cooldown_until=now + cooldown["seconds_remaining"] if cooldown else 0)
    result = {**saved, "stage": "collector_watchdog", "checked_at_unix": now, "check_interval_seconds": 60,
              "heartbeat_timeout_seconds": HEARTBEAT_TIMEOUT, "action": action, "reason": reason,
              "worker_task_state": task["state"], "network_requests": 0,
              "restart_count": integer(saved.get("restart_count")),
              "consecutive_restarts": integer(saved.get("consecutive_restarts"))}
    if reason == "worker_responsive" and now - integer(task.get("last_run_unix")) >= STABLE_SECONDS:
        result["consecutive_restarts"] = 0
        result["next_restart_unix"] = 0
    restart_file = directory / "live-restart.request"
    if action == "request_stop":
        restart_file.touch()
        result["restart_requested_unix"] = now
    elif action in ("force_stop", "stop"):
        # Stop the named task, never a guessed/reused process ID. A manual stop
        # marker remains untouched, so this cannot restart an intentional stop.
        control.stop()
        result["next_restart_unix"] = max(integer(saved.get("next_restart_unix")), now + 30)
    elif action == "start":
        gate = bootstrap_check() if bootstrap_check else prerequisite(directory, database)
        if not gate.get("ready"):
            result.update(action="none", reason="bootstrap_or_selection_not_ready")
        elif (directory / "live-stop.request").exists():
            result.update(action="none", reason="manual_stop")
        else:
            try:
                # A foreground diagnostic may own the same collector outside
                # Task Scheduler. Respect its OS lock before starting the task.
                with collector_lock(directory / "collector.lock"):
                    pass
            except (RuntimeError, OSError):
                result.update(action="none", reason="collector_already_running")
                write_status(path, result)
                return result
            failures = min(20, result["consecutive_restarts"] + 1)
            result.update(consecutive_restarts=failures, restart_count=result["restart_count"] + 1,
                          next_restart_unix=now + min(900, 30 * 2 ** min(failures - 1, 5)),
                          last_restart_unix=now, last_restart_reason=reason, restart_requested_unix=0)
            write_status(path, result)  # Reserve restart/backoff before mutation.
            restart_file.unlink(missing_ok=True)
            control.start()
    write_status(path, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--task-name", required=True)
    args = parser.parse_args()
    directory, database = args.state_dir.resolve(), args.db.resolve()
    root = Path(__file__).resolve().parents[1]
    try:
        control = WindowsTask(root, args.task_name)
        with collector_lock(directory / "watchdog.lock"):
            result = check(directory, database, control)
    except Exception as error:
        # Never print exception strings, credentials, coordinates or shell output.
        result = {"stage": "collector_watchdog", "action": "none", "reason": "watchdog_check_failed",
                  "error_type": type(error).__name__, "checked_at_unix": int(time.time()), "network_requests": 0}
        try:
            write_status(directory / "watchdog-error.json", result)
        except OSError:
            pass
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
