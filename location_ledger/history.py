"""Bounded stationary runs: one spatial envelope plus exact delta/RLE source times.

Coordinates inside a run are deliberately lossy; timing, counts and gaps are
exact. A fixed anchor prevents a chain of nearby fixes from swallowing travel.
The (subject_id, observed_at) primary key also serves interval queries: seek
one predecessor, then read the requested range. Runs never overlap.
"""
from dataclasses import dataclass, replace
from math import ceil
import zlib

from . import store

MAX_PAIRS = 1024
MAX_SPAN = 7 * 86400
MAX_COUNT = MAX_SPAN + 1  # Source timestamps have integer-second precision.


class ConflictingObservationError(ValueError):
    """A second value for a source second already represented in history."""


def varint(value):
    if type(value) is not int or not 0 <= value < 1 << 63:
        raise ValueError("Invalid history integer")
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def integers(payload):
    if not isinstance(payload, bytes) or len(payload) > 16384:
        raise ValueError("Invalid history payload size")
    value = shift = 0
    for byte in payload:
        value |= (byte & 127) << shift
        if byte & 128:
            shift += 7
            if shift >= 63:
                raise ValueError("Invalid history integer")
        else:
            if shift and byte == 0:
                raise ValueError("Noncanonical history integer")
            yield value
            value = shift = 0
    if shift:
        raise ValueError("Truncated history payload")


def signed(value):
    return value * 2 if value >= 0 else -value * 2 - 1


def unsigned(value):
    return -(value // 2) - 1 if value & 1 else value // 2


@dataclass(frozen=True)
class Times:
    first: int
    pairs: tuple = ()  # (positive source-time delta, number of repetitions)

    @property
    def count(self):
        return 1 + sum(n for _, n in self.pairs)

    @property
    def last(self):
        return self.first + sum(delta * n for delta, n in self.pairs)

    def append(self, timestamp):
        return self.extend(timestamp - self.last, 1)

    def extend(self, delta, count):
        if count == 0:
            return self
        if delta <= 0 or count < 0:
            raise ValueError("History source times must increase")
        if self.pairs and self.pairs[-1][0] == delta:
            return Times(self.first, self.pairs[:-1] + ((delta, self.pairs[-1][1] + count),))
        return Times(self.first, self.pairs + ((delta, count),))

    def series(self, start, end):
        """Clipped arithmetic progressions; never expand a dense stationary run."""
        if start <= self.first < end:
            yield self.first, 1, 1
        previous = self.first
        for delta, count in self.pairs:
            first = previous + delta
            low = max(0, (start - first + delta - 1) // delta)
            high = min(count, (end - first + delta - 1) // delta)
            if high > low:
                yield first + low * delta, delta, high - low
            previous += delta * count
            if previous >= end:
                break

    def clip(self, start, end):
        result = None
        for first, step, count in self.series(start, end):
            result = Times(first) if result is None else result.append(first)
            result = result.extend(step, count - 1)
        return result

    def contains(self, timestamp):
        return next(self.series(timestamp, timestamp + 1), None) is not None

    def groups(self, max_gap):
        """Source-supported spans, split if a caller wants a stricter gap limit."""
        current = Times(self.first)
        for delta, count in self.pairs:
            if delta <= max_gap:
                current = current.extend(delta, count)
            else:
                for _ in range(count):
                    yield current
                    current = Times(current.last + delta)
        yield current


@dataclass(frozen=True)
class StayPolicy:
    radius_m: float = 25
    gap_seconds: int = 600
    max_accuracy_m: float = 100
    checkpoint_seconds: int = 30
    stationary_seconds: int = 300  # Native quiet-session renewal; not extra rows.

    def __post_init__(self):
        store.number(self.radius_m, 1, 1000, "Stay radius")
        store.number(self.max_accuracy_m, 1, 1000, "Stay accuracy limit")
        for value in (self.gap_seconds, self.stationary_seconds):
            if type(value) is not int or not 1 <= value <= 86400:
                raise ValueError("Invalid stay interval")
        if type(self.checkpoint_seconds) is not int or not 1 <= self.checkpoint_seconds <= 300:
            raise ValueError("Invalid history checkpoint interval")


@dataclass(frozen=True)
class Run:
    times: Times
    received_at: int  # Latest receipt among the observations, not a new source fix.
    lat_e6: int
    lon_e6: int
    accuracy_dm: int  # Envelope covering anchor displacement + each source accuracy.
    source_id: int
    anchor_accuracy_dm: int
    max_accuracy_dm: int
    spread_dm: int
    last_lat_e6: int
    last_lon_e6: int
    last_accuracy_dm: int
    last_received_at: int
    first_received_at: int
    exact_endpoints: int = 3  # first=1, last=2; trimming may remove exact endpoints.

    @classmethod
    def point(cls, values, source_id):
        timestamp, received, lat, lon, accuracy = values[:5]
        return cls(Times(timestamp), received, lat, lon, accuracy, source_id,
                   accuracy, accuracy, 0, lat, lon, accuracy, received, received)

    @classmethod
    def from_row(cls, row):
        row = dict(row)
        result = cls.point((row['observed_at'], row['received_at'], row['lat_e6'], row['lon_e6'],
                            row['accuracy_dm']), row['source_id'])
        payload = row.get('detail')
        if payload is None:
            if row.get('span_seconds', 0) or row.get('fix_count', 1) != 1:
                raise ValueError("Incomplete stationary history")
            return result
        if not payload or payload[0] not in (1, 2) or len(payload) > 16384:
            raise ValueError("Unsupported stationary history encoding")
        raw = payload[1:]
        if payload[0] == 2:
            decoder = zlib.decompressobj()
            try:
                raw = decoder.decompress(raw, 16385)
            except zlib.error as error:
                raise ValueError('Invalid compressed stationary evidence') from error
            if len(raw) > 16384 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise ValueError('Invalid compressed stationary evidence size')
        fields = list(integers(raw))
        if len(fields) < 9 or (len(fields) - 9) % 2 or len(fields) > 9 + MAX_PAIRS * 2:
            raise ValueError("Invalid stationary history encoding")
        pairs = tuple(zip(fields[9::2], fields[10::2]))
        if any(delta <= 0 or count <= 0 for delta, count in pairs):
            raise ValueError("Invalid stationary timing evidence")
        times = Times(row['observed_at'], pairs)
        if (times.count != row['fix_count'] or times.last - times.first != row['span_seconds']
                or times.count > MAX_COUNT or times.last - times.first > MAX_SPAN or fields[7] > 3):
            raise ValueError("Inconsistent stationary timing evidence")
        result = replace(result, times=times, anchor_accuracy_dm=fields[0], max_accuracy_dm=fields[1],
            spread_dm=fields[2], last_lat_e6=result.lat_e6 + unsigned(fields[3]),
            last_lon_e6=result.lon_e6 + unsigned(fields[4]), last_accuracy_dm=fields[5],
            last_received_at=times.first + unsigned(fields[6]), exact_endpoints=fields[7],
            first_received_at=times.first + unsigned(fields[8]))
        if (not -90000000 <= result.last_lat_e6 <= 90000000 or not -180000000 <= result.last_lon_e6 <= 180000000
                or result.max_accuracy_dm > result.accuracy_dm or result.spread_dm > result.accuracy_dm
                or result.anchor_accuracy_dm > result.max_accuracy_dm or result.last_accuracy_dm > result.accuracy_dm):
            raise ValueError("Invalid stationary spatial envelope")
        return result

    def payload(self):
        if self.times.count == 1 and self.exact_endpoints == 3 and self.spread_dm == 0:
            return None
        fields = (self.anchor_accuracy_dm, self.max_accuracy_dm, self.spread_dm,
            signed(self.last_lat_e6 - self.lat_e6), signed(self.last_lon_e6 - self.lon_e6),
            self.last_accuracy_dm, signed(self.last_received_at - self.times.first), self.exact_endpoints,
            signed(self.first_received_at - self.times.first))
        raw = b''.join(varint(n) for n in fields) + b''.join(
            varint(delta) + varint(count) for delta, count in self.times.pairs)
        if len(raw) >= 96:
            compressed = zlib.compress(raw, 6)
            if len(compressed) < len(raw):
                return b'\x02' + compressed
        return b'\x01' + raw

    def distance(self, lat, lon):
        return store.distance_m(self.lat_e6 / 1e6, self.lon_e6 / 1e6, lat / 1e6, lon / 1e6)

    def join(self, other, policy):
        delta = other.times.first - self.times.last
        distance = self.distance(other.lat_e6, other.lon_e6)
        if (self.source_id != other.source_id or not 0 < delta <= policy.gap_seconds
                or other.first_received_at - self.last_received_at > policy.gap_seconds
                or max(self.max_accuracy_dm, other.max_accuracy_dm) > policy.max_accuracy_m * 10
                or distance + other.spread_dm / 10 > policy.radius_m
                or other.times.last - self.times.first > MAX_SPAN):
            return None
        times = self.times.append(other.times.first)
        for step, count in other.times.pairs:
            times = times.extend(step, count)
        if len(times.pairs) > MAX_PAIRS:
            return None
        return replace(self, times=times, received_at=max(self.received_at, other.received_at),
            accuracy_dm=max(self.accuracy_dm, ceil(distance * 10 + other.accuracy_dm)),
            max_accuracy_dm=max(self.max_accuracy_dm, other.max_accuracy_dm),
            spread_dm=max(self.spread_dm, ceil(distance * 10 + other.spread_dm)),
            last_lat_e6=other.last_lat_e6, last_lon_e6=other.last_lon_e6,
            last_accuracy_dm=other.last_accuracy_dm, last_received_at=other.last_received_at,
            exact_endpoints=(self.exact_endpoints & 1) | (other.exact_endpoints & 2))

    def slice(self, start, end):
        times = self.times.clip(start, end)
        if times is None:
            return None
        flags = self.exact_endpoints
        if times.first != self.times.first:
            flags &= ~1
        first_receipt = self.first_received_at if times.first == self.times.first else self.received_at
        if times.last != self.times.last:
            flags &= ~2
            return replace(self, times=times, exact_endpoints=flags, last_lat_e6=self.lat_e6,
                last_lon_e6=self.lon_e6, last_accuracy_dm=self.accuracy_dm, last_received_at=self.received_at,
                first_received_at=first_receipt)
        return replace(self, times=times, exact_endpoints=flags, first_received_at=first_receipt)

    def matches(self, values, source_id):
        timestamp, _, lat, lon, accuracy = values[:5]
        if self.source_id != source_id:
            return False
        if timestamp == self.times.last and self.exact_endpoints & 2:
            return (lat, lon, accuracy) == (self.last_lat_e6, self.last_lon_e6, self.last_accuracy_dm)
        if timestamp == self.times.first and self.exact_endpoints & 1:
            return (lat, lon, accuracy) == (self.lat_e6, self.lon_e6, self.anchor_accuracy_dm)
        # Interior jitter was deliberately discarded. Only accept a replay
        # consistent with the saved envelope; never increase count or duration.
        return (self.distance(lat, lon) * 10 <= self.spread_dm + 2
                and accuracy <= self.max_accuracy_dm)


def source_id(db, name):
    row = db.execute('SELECT id FROM sources WHERE name=?', (name,)).fetchone()
    if row is not None:
        return row[0]
    db.execute('INSERT OR IGNORE INTO sources(name) VALUES(?)', (name,))
    return db.execute('SELECT id FROM sources WHERE name=?', (name,)).fetchone()[0]


def require_active_writer(db, sid):
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    row = db.execute('SELECT active FROM subjects WHERE id=?', (sid,)).fetchone()
    if row is None or not row[0]:
        raise ValueError('Collection is paused for this participant')


def row_values(sid, run):
    return (sid, run.times.first, run.received_at, run.lat_e6, run.lon_e6, run.accuracy_dm,
            run.source_id, run.times.last - run.times.first, run.times.count, run.payload())


def write_run(db, sid, run):
    db.execute('INSERT INTO samples(subject_id,observed_at,received_at,lat_e6,lon_e6,accuracy_dm,source_id,'
        'span_seconds,fix_count,detail) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(subject_id,observed_at) '
        'DO UPDATE SET received_at=excluded.received_at,lat_e6=excluded.lat_e6,lon_e6=excluded.lon_e6,'
        'accuracy_dm=excluded.accuracy_dm,source_id=excluded.source_id,span_seconds=excluded.span_seconds,'
        'fix_count=excluded.fix_count,detail=excluded.detail', row_values(sid, run))


def predecessor(db, sid, timestamp):
    return db.execute('SELECT * FROM samples WHERE subject_id=? AND observed_at<=? '
                      'ORDER BY observed_at DESC LIMIT 1', (sid, timestamp)).fetchone()


def range_rows(db, sid, start, end):
    """At most one overlapping predecessor, then a primary-key range scan."""
    before = db.execute('SELECT * FROM samples WHERE subject_id=? AND observed_at<? '
                        'ORDER BY observed_at DESC LIMIT 1', (sid, start)).fetchone()
    if before is not None and Run.from_row(before).times.last >= start:
        yield before
    yield from db.execute('SELECT * FROM samples WHERE subject_id=? AND observed_at>=? AND observed_at<? '
                          'ORDER BY observed_at', (sid, start, end))


def insert_exact(db, sid, values, source):
    require_active_writer(db, sid)
    row = predecessor(db, sid, values[0])
    previous = Run.from_row(row) if row else None
    if previous and previous.times.last >= values[0]:
        if previous.times.contains(values[0]):
            if not previous.matches(values, source):
                raise ConflictingObservationError('Conflicting location at the same source timestamp; inspect the adapter')
            return False
        # Unexpected backfill is retained exactly. Split the old interval so it
        # cannot assert a stationary span across a contradictory observation.
        db.execute('DELETE FROM samples WHERE subject_id=? AND observed_at=?', (sid, previous.times.first))
        for part in (previous.slice(previous.times.first, values[0]), previous.slice(values[0]+1, previous.times.last+1)):
            if part is not None:
                write_run(db, sid, part)
    write_run(db, sid, Run.point(values, source))
    return True
