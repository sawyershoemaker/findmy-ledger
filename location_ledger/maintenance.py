"""Consistent SQLite snapshots and explicit participant-scoped history maintenance."""
from contextlib import closing
import os
from pathlib import Path
import re
import sqlite3
import time
from uuid import uuid4

from . import store


def backup(source, destination):
    """Snapshot the live database, including committed WAL data; never overwrite a file."""
    source, destination = Path(source).resolve(), Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Backup destination already exists")
    if source == destination.resolve():
        raise ValueError("Backup destination must differ from the source")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name("." + destination.name + "." + uuid4().hex + ".tmp")
    try:
        with temporary.open("xb"):
            pass
        with store.connect(source) as original, closing(sqlite3.connect(temporary)) as snapshot:
            original.backup(snapshot, pages=256, sleep=0.05)
            snapshot.execute("PRAGMA journal_mode=DELETE")
            snapshot.execute("PRAGMA synchronous=FULL")
            if snapshot.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ValueError("Snapshot integrity check failed")
            if snapshot.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise ValueError("Snapshot has inconsistent references")
            measured = store.statistics(snapshot)
            count = measured['samples']
            snapshot.commit()
        with temporary.open("r+b") as stream:
            os.fsync(stream.fileno())
        # Publish only a finished standalone snapshot. link() fails atomically if
        # another process created the destination; both files are on one volume.
        os.link(temporary, destination)
        return {"backup_created": str(destination), "samples": count, 'stored_rows': measured['stored_rows'], "bytes": destination.stat().st_size,
                "integrity_checked": True, "includes_committed_wal": True, "credentials_included": False}
    finally:
        temporary.unlink(missing_ok=True)


def retain(db, participant, before, *, apply=False):
    """Remove observations strictly older than a cutoff, for exactly one participant."""
    cutoff = store.epoch(before)
    sid = store.subject(db, participant)["id"]
    from .history import Run, predecessor, write_run
    version = db.execute('PRAGMA user_version').fetchone()[0]
    total = 'COALESCE(sum(fix_count),0)' if version == 2 else 'count(*)'
    count = db.execute(f'SELECT {total} FROM samples WHERE subject_id=? AND observed_at<?', (sid, cutoff)).fetchone()[0]
    crossing = predecessor(db, sid, cutoff - 1)
    survivor = Run.from_row(crossing).slice(cutoff, 4102444801) if crossing is not None else None
    if survivor is not None:
        count -= survivor.times.count
    if apply:
        db.execute("DELETE FROM samples WHERE subject_id=? AND observed_at<?", (sid, cutoff))
        if survivor is not None:
            write_run(db, sid, survivor)
        db.execute("DELETE FROM sources WHERE id NOT IN (SELECT source_id FROM samples)")
    return {"participant": participant, "before_exclusive": store.iso(cutoff), "eligible_samples": count,
            "deleted_samples": count if apply else 0, "applied": apply}


def rotate_backups(directory, *, keep=7):
    """Keep the newest collector snapshots; never follow links or remove other files."""
    if type(keep) is not int or not 1 <= keep <= 365:
        raise ValueError("Keep must be 1-365 backups")
    root = Path(directory).resolve(strict=True)
    snapshots = []
    for entry in root.iterdir():
        match = re.fullmatch(r"ledger-([0-9]{10,12})-([a-f0-9]{8})\.sqlite", entry.name)
        if match and not entry.is_symlink() and entry.is_file() and entry.resolve().parent == root:
            snapshots.append((int(match[1]), entry.name, entry))
    snapshots.sort(reverse=True)
    removed = 0
    for _, _, entry in snapshots[keep:]:
        # Resolve again immediately before removal; deletion stays in this named directory.
        if entry.is_symlink() or entry.resolve().parent != root:
            raise ValueError("Backup path changed during rotation")
        entry.unlink()
        removed += 1
    return {"backups_removed": removed, "backups_retained": min(len(snapshots), keep)}


def forget(db, participant, *, apply=False):
    """Delete stored history/places but keep an inactive participant row to block recollection."""
    sid = store.subject(db, participant)["id"]
    total = 'COALESCE(sum(fix_count),0)' if db.execute('PRAGMA user_version').fetchone()[0] == 2 else 'count(*)'
    samples = db.execute(f'SELECT {total} FROM samples WHERE subject_id=?', (sid,)).fetchone()[0]
    places = db.execute("SELECT count(*) FROM places WHERE subject_id=?", (sid,)).fetchone()[0]
    if apply:
        db.execute("PRAGMA secure_delete=ON")
        db.execute("UPDATE subjects SET active=0 WHERE id=?", (sid,))
        db.execute("DELETE FROM samples WHERE subject_id=?", (sid,))
        db.execute("DELETE FROM places WHERE subject_id=?", (sid,))
        db.execute("DELETE FROM sources WHERE id NOT IN (SELECT source_id FROM samples)")
    return {"participant": participant, "eligible_samples": samples, "eligible_places": places,
            "applied": apply, "collection_paused": bool(apply), "backups_modified": False,
            "apple_credentials_modified": False}


def compact(path):
    with store.connect(path, write=True) as db:
        before = store.statistics(db)["database_bytes"]
        checkpoint = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint[0]:
            raise ValueError("Database is busy; stop the collector and close readers before compacting")
        db.execute("VACUUM")
        db.execute('PRAGMA optimize')
        after = store.statistics(db)["database_bytes"]
        checkpoint = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        return {"database_bytes_before": before, "database_bytes_after": after,
                "wal_checkpoint_complete": checkpoint[0] == 0}


def joined_runs(db, sid, policy):
    from .history import Run
    current = None
    previous_end = None
    for row in db.execute('SELECT * FROM samples WHERE subject_id=? ORDER BY observed_at', (sid,)):
        incoming = Run.from_row(row)
        if previous_end is not None and incoming.times.first <= previous_end:
            raise ValueError('Overlapping history records require inspection')
        previous_end = incoming.times.last
        merged = current.join(incoming, policy) if current is not None else None
        if merged is None:
            if current is not None:
                yield current
            current = incoming
        else:
            current = merged
    if current is not None:
        yield current


def optimize(path, participant, *, policy=None, apply=False, backup_path=None):
    """Preview, or backup and atomically migrate/compact one participant's history.

    Stop the collector first. Reads still support v1 backups; v2 stores points
    and stationary runs in the same primary-key B-tree, without a second index.
    """
    from .history import StayPolicy, row_values, Run
    policy = policy or StayPolicy()
    path = Path(path).resolve()
    with store.connect(path) as db:
        sid = store.subject(db, participant)['id']
        old = store.statistics(db)
        before_rows = db.execute('SELECT count(*) FROM samples WHERE subject_id=?', (sid,)).fetchone()[0]
        rows, count = 0, 0
        for run in joined_runs(db, sid, policy):
            rows += 1
            count += run.times.count
    result = {'participant': participant, 'applied': False, 'observations': count,
              'rows_before': before_rows, 'rows_after': rows, 'rows_removed': before_rows - rows,
              'radius_m': policy.radius_m, 'max_gap_seconds': policy.gap_seconds,
              'source_times_preserved': True, 'coordinates_within_stays': 'representative anchor and uncertainty envelope'}
    if not apply:
        return result
    backup_path = Path(backup_path) if backup_path else path.parent / 'backups' / (
        'before-stays-' + str(int(time.time())) + '-' + uuid4().hex[:8] + '.sqlite')
    saved = backup(path, backup_path)
    with store.connect(path, write=True) as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('PRAGMA user_version').fetchone()[0] == 1:
            db.execute('ALTER TABLE samples ADD COLUMN span_seconds INTEGER NOT NULL DEFAULT 0 CHECK(span_seconds >= 0)')
            db.execute('ALTER TABLE samples ADD COLUMN fix_count INTEGER NOT NULL DEFAULT 1 CHECK(fix_count >= 1)')
            db.execute('ALTER TABLE samples ADD COLUMN detail BLOB')
            db.execute('PRAGMA user_version=2')
        sid = store.subject(db, participant)['id']
        before_rows, expected = db.execute('SELECT count(*),COALESCE(sum(fix_count),0) FROM samples WHERE subject_id=?', (sid,)).fetchone()
        db.execute('CREATE TEMP TABLE compacted_history AS SELECT * FROM samples WHERE 0')
        rows = count = 0
        for run in joined_runs(db, sid, policy):
            db.execute('INSERT INTO compacted_history VALUES(?,?,?,?,?,?,?,?,?,?)', row_values(sid, run))
            rows += 1
            count += run.times.count
        if count != expected:
            raise ValueError('Compaction changed the number of source observations')
        db.execute('DELETE FROM samples WHERE subject_id=?', (sid,))
        db.execute('INSERT INTO samples SELECT * FROM compacted_history')
        db.execute('DROP TABLE compacted_history')
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok' or db.execute('PRAGMA foreign_key_check').fetchone() is not None:
            raise ValueError('History integrity validation failed')
    reclaimed = compact(path)
    with store.connect(path) as db:
        measured = store.statistics(db)
        for row in db.execute('SELECT * FROM samples WHERE subject_id=?', (sid,)):
            Run.from_row(row)  # Decode every new payload before reporting success.
    result.update(applied=True, observations=count, rows_before=before_rows, rows_after=rows,
        rows_removed=before_rows-rows, backup_created=saved['backup_created'],
        database_bytes_before=old['database_bytes'], database_bytes_after=measured['database_bytes'],
        wal_checkpoint_complete=reclaimed['wal_checkpoint_complete'], schema_version=2)
    return result
