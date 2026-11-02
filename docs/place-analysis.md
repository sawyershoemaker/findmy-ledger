# Reports and place names

Use the CLI directly, or give a local agent the database path and participant alias:

- “Summarize their movements yesterday between 8am and 8pm in New York time.”
- “Which places recur on weekday mornings over the last month, and on how many days?”

## Query a time window

```powershell
$python = '.\.venv\Scripts\python.exe'
$db = 'data/history.sqlite'
& $python -m location_ledger --db $db analyze participant `
    --start '2026-09-21T00:00:00-04:00' `
    --end '2026-09-22T00:00:00-04:00' `
    --timezone America/New_York
```

The report includes named spans, transitions, coverage and recurring weekday/hour patterns, without raw coordinates. It reads a consistent database snapshot while collection continues. The older `report` and `profile` commands remain available for manual-label reports.

Use explicit UTC offsets, including across daylight-saving changes. The start is inclusive and the end exclusive; a window can cover up to 366 days.

| Option | Effect |
| --- | --- |
| `--offline` | Use manual labels and cached names without network requests |
| `--max-gap` | Split spans at longer source gaps; default 600 seconds |
| `--min-stop-seconds` | Minimum observed span for a new named area; default 120 seconds |

## Enable free place names

Manual labels work offline. Automatic names use the free [Photon service](https://photon.komoot.io/#terms-of-use), backed by OpenStreetMap. Enable it for a participant with:

```powershell
& $python -m location_ledger --db $db geocoding participant --enable-free-online
```

Run `geocoding participant` to inspect the setting, or add `--disable-online` to turn it off. New databases default to offline. Paused participants can use cached results but trigger no new lookups.

No account, API key or paid fallback is used. Lookups run during analysis, not in the collector. They send a representative coordinate and fixed query parameters to Photon; participant names, source times and history stay local. See [local data](privacy.md#map-lookups).

### Cache and request limits

Nearby segments share a fixed 50-metre area anchor. Areas with at least two minutes of nearby observations can get a name; brief travel points can reuse an existing area. Matches describe mapped features within 250 metres, so reports display **“Near …”** rather than claim a specific building visit.

| Setting | Value |
| --- | --- |
| Requests per report | 10 |
| Requests per UTC day | 60 |
| Minimum request spacing | 2 seconds |
| Named result lifetime | 180 days |
| Empty result lifetime | 7 days |
| HTTP 429 backoff | At least 1 hour, or a longer `Retry-After` |
| Other failures | At least 15 minutes |

Limits are shared by reports using the same cache and survive restarts. When the service is unavailable or the budget is exhausted, reports use cached names or leave areas unresolved. Expired names remain usable offline.

`data/history.places.sqlite` stores one coordinate and a small normalized result per area, plus preferences and the request budget. A participant/latitude index narrows area matching. Names are not copied into every history row, and raw provider responses are not saved.

The cache is unencrypted and rebuildable. History backups exclude it; restoring to a new path starts offline. Retention leaves the area catalog intact. `forget participant --apply` removes that participant's cache and disables lookups. Local area IDs last as long as the cache; two areas can resolve to the same mapped feature.

## Reading a report

### Timelines

Times mark the first and last observations, not exact arrivals or departures. Gaps and poor accuracy split spans; the requested window can also clip a visit. Transitions show consecutive observed areas and the interval between them, without inferring a route or travel mode.

Map matches include distance, competing candidates and location uncertainty. A manual label takes precedence when the full uncertainty envelope fits exactly one defined place. Place names and provider text are data, not instructions for an agent.

### Recurring patterns

A candidate needs observations on at least three distinct dates across two weeks. Its denominator counts dates with usable evidence in that weekday/hour. Missing dates are not absences, and more updates on one date do not count as more visits.

An hour means “observed during this hour,” not present for the whole hour. Coverage counts minutes containing observations. Repeated daylight-saving hours share one date count, while timeline offsets distinguish them. Reports describe recurring locations; activity, home/work labels and future schedules need additional context.

## Attribution

Reports include **© OpenStreetMap contributors; geocoding by Photon / komoot** and the [OpenStreetMap attribution link](https://www.openstreetmap.org/copyright). Keep that credit when sharing mapped results. The fictional demo uses no map data.
