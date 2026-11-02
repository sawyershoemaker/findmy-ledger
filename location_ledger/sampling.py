"""Compact frequent fixes while preserving source times and uncertainty.

This consumes validated observations; it does not acquire or authenticate Apple
messages. Only one uncommitted stationary endpoint is held in memory. An abrupt
exit can lose that endpoint, never a previously committed observation.
"""
from copy import copy
from dataclasses import asdict, dataclass

from . import store


@dataclass(frozen=True)
class SamplingPolicy:
    movement_m: float = 10
    stationary_seconds: int = 300
    gap_seconds: int = 60
    max_accuracy_m: float = 100

    def __post_init__(self):
        store.number(self.movement_m, 1, 10000, "Movement threshold")
        store.number(self.max_accuracy_m, 1, 10000, "Accuracy threshold")
        for value in (self.stationary_seconds, self.gap_seconds):
            if type(value) is not int or not 1 <= value <= 86400:
                raise ValueError("Sampling intervals must be integer seconds from 1 to 86400")


@dataclass(frozen=True)
class Fix:
    observed_at: int
    received_at: int
    lat_e6: int
    lon_e6: int
    accuracy_dm: int
    source: str

    @classmethod
    def parse(cls, observation, received_at=None):
        return cls(*store.normalize_observation(observation, received_at=received_at))

    def observation(self):
        return {"observed_at": self.observed_at, "latitude": self.lat_e6 / 1e6,
                "longitude": self.lon_e6 / 1e6, "accuracy_m": self.accuracy_dm / 10,
                "source": self.source}

    def identity(self):
        # A later receipt of the same source fix is not a new observation.
        return self.observed_at, self.lat_e6, self.lon_e6, self.accuracy_dm, self.source


@dataclass(frozen=True)
class Decision:
    fixes: tuple[Fix, ...]
    reason: str


class AdaptiveSampler:
    def __init__(self, policy=None, *, previous=None):
        self.policy = policy or SamplingPolicy()
        self.anchor = previous
        self.latest = previous

    @classmethod
    def from_database(cls, db, alias, policy=None):
        sid = store.subject(db, alias, require_active=True)["id"]
        row = db.execute("SELECT s.*,o.name AS source FROM samples s JOIN sources o ON o.id=s.source_id "
                         "WHERE subject_id=? ORDER BY observed_at DESC LIMIT 1", (sid,)).fetchone()
        from .history import Run
        tail = Run.from_row(row) if row else None
        previous = (Fix(tail.times.last, tail.last_received_at, tail.last_lat_e6, tail.last_lon_e6,
                        tail.last_accuracy_dm, row['source']) if tail else None)
        return cls(policy, previous=previous)

    def accept(self, observation, *, received_at=None):
        fix = Fix.parse(observation, received_at)
        anchor, latest, policy = self.anchor, self.latest, self.policy
        if latest is None:
            self.anchor = self.latest = fix
            return Decision((fix,), "first_observation")
        if fix.observed_at == latest.observed_at:
            if fix.identity() != latest.identity():
                raise ValueError("Conflicting location at the same source timestamp; inspect the adapter")
            return Decision((), "duplicate")
        if fix.observed_at < latest.observed_at:
            # Backfill never moves the current anchor or pending endpoint backward.
            return Decision((fix,), "out_of_order")

        accurate = fix.accuracy_dm <= policy.max_accuracy_m * 10
        was_accurate = anchor.accuracy_dm <= policy.max_accuracy_m * 10
        accuracy_delta = abs(fix.accuracy_dm - anchor.accuracy_dm)
        accuracy_ratio = max(fix.accuracy_dm, anchor.accuracy_dm) / max(1, min(fix.accuracy_dm, anchor.accuracy_dm))
        distance = store.distance_m(anchor.lat_e6 / 1e6, anchor.lon_e6 / 1e6,
                                    fix.lat_e6 / 1e6, fix.lon_e6 / 1e6)
        # Overlapping accuracy circles are not sufficient evidence of movement.
        movement_threshold = max(policy.movement_m, (anchor.accuracy_dm + fix.accuracy_dm) / 10)
        reason = None
        if fix.source != anchor.source:
            reason = "source_changed"
        elif (fix.observed_at - latest.observed_at > policy.gap_seconds or
              fix.received_at - latest.received_at > policy.gap_seconds):
            reason = "gap_boundary"
        elif accurate != was_accurate or (accuracy_delta >= 100 and accuracy_ratio >= 2):
            reason = "accuracy_changed"
        elif accurate and was_accurate and distance >= movement_threshold:
            reason = "movement_change"
        elif fix.observed_at - anchor.observed_at >= policy.stationary_seconds:
            reason = "periodic_sample"

        self.latest = fix
        if reason is None:
            return Decision((), "coalesced")
        # Preserve the last observation before movement, an outage, or a quality
        # change; it bounds the transition without inventing an arrival time.
        endpoint = (latest,) if reason != "periodic_sample" and latest != anchor else ()
        self.anchor = fix
        return Decision(endpoint + (fix,), reason)

    def flush(self):
        if self.latest is None or self.latest == self.anchor:
            return Decision((), "nothing_pending")
        self.anchor = self.latest
        return Decision((self.latest,), "final_endpoint")


def write_decision(db, alias, decision):
    store.subject(db, alias, require_active=True)
    inserted = sum(store.ingest(db, alias, fix.observation(), received_at=fix.received_at)
                   for fix in decision.fixes)
    return {"reason": decision.reason, "inserted": inserted,
            "duplicates": len(decision.fixes) - inserted + (decision.reason == "duplicate"),
            "coalesced": decision.reason == "coalesced"}


class AdaptiveRecorder:
    """Commit retained points atomically, then advance the in-memory sampler.

    Use one recorder per participant and serialize calls. The surrounding
    collector owns the existing OS writer lock. Call flush on an orderly stream
    disconnect; call discard when collection is paused or the selection changes.
    """
    def __init__(self, database, alias, policy=None):
        self.database, self.alias = database, alias
        with store.connect(database) as db:
            self.sampler = AdaptiveSampler.from_database(db, alias, policy)

    def _commit(self, operation):
        candidate = copy(self.sampler)
        decision = operation(candidate)
        with store.connect(self.database, write=True) as db:
            result = write_decision(db, self.alias, decision)
        self.sampler = candidate
        return result

    def accept(self, observation, *, received_at=None):
        return self._commit(lambda sampler: sampler.accept(observation, received_at=received_at))

    def flush(self):
        return self._commit(lambda sampler: sampler.flush())

    def discard(self):
        self.sampler = AdaptiveSampler(self.sampler.policy)

    def configuration(self):
        return asdict(self.sampler.policy)
