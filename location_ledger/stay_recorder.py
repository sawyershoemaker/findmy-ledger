"""Transactional stationary aggregation for the single live writer."""
from dataclasses import asdict
import time

from . import store
from .history import ConflictingObservationError, Run, StayPolicy, insert_exact, require_active_writer, source_id, write_run


def outcome(reason, *, inserted=0, updated=0, duplicate=False, coalesced=False):
    return {'reason': reason, 'inserted': inserted, 'updated': updated,
            'duplicates': int(duplicate), 'coalesced': coalesced}


class StayRecorder:
    def __init__(self, database, alias, policy=None):
        self.database, self.alias = database, alias
        self.policy = policy or StayPolicy()
        self.current = self.persisted = None
        self.last_checkpoint = time.monotonic()
        self.reload()

    def reload(self):
        if self.current != self.persisted:
            raise ValueError('Flush history before reloading the active stay')
        with store.connect(self.database) as db:
            if db.execute('PRAGMA user_version').fetchone()[0] != 2:
                raise ValueError('Upgrade history with the optimize command before starting stay collection')
            sid = store.subject(db, self.alias, require_active=True)['id']
            row = db.execute('SELECT * FROM samples WHERE subject_id=? ORDER BY observed_at DESC LIMIT 1', (sid,)).fetchone()
            self.current = self.persisted = Run.from_row(row) if row else None

    def _check_tail(self, db, sid, expected):
        row = db.execute('SELECT * FROM samples WHERE subject_id=? ORDER BY observed_at DESC LIMIT 1', (sid,)).fetchone()
        actual = Run.from_row(row) if row else None
        if actual != expected:
            raise ValueError('History changed outside the collector; restart before writing')

    def _write(self, db, sid, current, persisted):
        if current == persisted:
            return 0
        require_active_writer(db, sid)
        self._check_tail(db, sid, persisted)
        write_run(db, sid, current)
        return 1

    def accept(self, observation, *, received_at=None):
        values = store.normalize_observation(observation, received_at=received_at)
        current, persisted = self.current, self.persisted
        checkpoint = self.last_checkpoint
        with store.connect(self.database, write=True, timeout=1) as db:
            sid = store.subject(db, self.alias, require_active=True)['id']
            source = source_id(db, values[5])
            incoming = Run.point(values, source)
            if current is None:
                require_active_writer(db, sid)
                self._check_tail(db, sid, None)
                added = insert_exact(db, sid, values, source)
                current = persisted = incoming
                checkpoint = time.monotonic()
                result = outcome('first_observation', inserted=int(added), duplicate=not added)
            elif values[0] <= current.times.last:
                if current.times.contains(values[0]):
                    if not current.matches(values, source):
                        raise ConflictingObservationError('Conflicting location at the same source timestamp; inspect the adapter')
                    return outcome('duplicate', duplicate=True)
                self._write(db, sid, current, persisted)
                added = insert_exact(db, sid, values, source)
                row = db.execute('SELECT * FROM samples WHERE subject_id=? ORDER BY observed_at DESC LIMIT 1', (sid,)).fetchone()
                current = persisted = Run.from_row(row)
                checkpoint = time.monotonic()
                result = outcome('out_of_order', inserted=int(added), duplicate=not added)
            else:
                merged = current.join(incoming, self.policy)
                if merged is not None:
                    current = merged
                    updated = 0
                    if (time.monotonic() - checkpoint >= self.policy.checkpoint_seconds or
                            current.times.last - persisted.times.last >= self.policy.checkpoint_seconds):
                        updated = self._write(db, sid, current, persisted)
                        persisted = current
                        checkpoint = time.monotonic()
                    result = outcome('stay_extended', updated=updated, coalesced=True)
                else:
                    updated = self._write(db, sid, current, persisted)
                    require_active_writer(db, sid)
                    self._check_tail(db, sid, current)
                    write_run(db, sid, incoming)
                    current = persisted = incoming
                    checkpoint = time.monotonic()
                    result = outcome('new_segment', inserted=1, updated=updated)
        # The transaction must commit before advancing state.
        self.current, self.persisted, self.last_checkpoint = current, persisted, checkpoint
        return result

    def flush(self):
        with store.connect(self.database, write=True, timeout=1) as db:
            sid = store.subject(db, self.alias, require_active=True)['id']
            updated = self._write(db, sid, self.current, self.persisted) if self.current is not None else 0
        self.persisted = self.current
        self.last_checkpoint = time.monotonic()
        return outcome('stay_checkpoint' if updated else 'nothing_pending', updated=updated)

    def checkpoint(self):
        if self.current != self.persisted and time.monotonic() - self.last_checkpoint >= self.policy.checkpoint_seconds:
            return self.flush()
        return outcome('nothing_pending')

    def discard(self):
        self.current = self.persisted

    def configuration(self):
        return {'storage': 'stationary_runs', 'exact_source_timestamps': True, **asdict(self.policy)}
