"""Local recovery classification; no raw exception text in diagnostics."""
import errno
import sqlite3
import time


def storage_failure(error):
    code = getattr(error, "sqlite_errorcode", None)
    code = code if type(code) is int else None
    base = code & 255 if code is not None else None
    transient = {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_IOERR,
                 sqlite3.SQLITE_FULL, sqlite3.SQLITE_CANTOPEN, sqlite3.SQLITE_READONLY}
    recoverable = False
    if isinstance(error, sqlite3.Error):
        reason = "sqlite_write_error"
        recoverable = base in transient
    elif isinstance(error, OSError):
        reason = "filesystem_write_error"
        recoverable = error.errno in {errno.EAGAIN, errno.EBUSY, errno.EINTR, errno.ENOSPC} or getattr(error, "winerror", None) in {32, 33, 112}
    elif isinstance(error, ValueError) and str(error) == "History changed outside the collector; restart before writing":
        reason = "history_changed_outside_collector"
    else:
        reason = "history_validation_failed"
    return {"reason": reason, "automatic_recovery": recoverable,
            "error_type": type(error).__name__, "sqlite_errorcode": code}


def save_failure(directory, details, *, phase):
    from .collector import write_status
    # A single small last-failure file survives healthy status updates/restarts.
    event = {"stage": "collector_failure", "at_unix": int(time.time()), "phase": phase,
             **{k: details[k] for k in ("reason", "automatic_recovery", "error_type", "sqlite_errorcode") if k in details}}
    write_status(directory / "collector-last-failure.json", event)
    return event
