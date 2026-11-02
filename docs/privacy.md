# Local data and collection controls

Ledger records the selected participant. It does not collect other shared contacts.

## Stored data

| Data | Where it lives |
| --- | --- |
| Apple password and 2FA | Entered in a local terminal; the password is not saved |
| Session tokens, device identity and sharing keys | Files protected by Windows current-user DPAPI |
| History, labels and backups | Unencrypted SQLite files |
| Place-name cache | Unencrypted SQLite sidecar with representative coordinates and map results |
| Diagnostics | Status files replaced on update; no routine packet capture |

DPAPI protects the saved account state, not the history database. It also permits access by other processes running as the same Windows user. Use Windows file permissions and disk encryption to protect local files and backups.

## Map lookups

Online geocoding is off by default. When enabled, Photon receives a representative coordinate and sees the connection IP and request time. Ledger does not send participant names, Apple identifiers, source timestamps or history. Results are cached locally. See [place names](place-analysis.md) for limits and attribution.

## Pause and deletion

`pause ALIAS` blocks new writes. Removed Find My sharing is detected at the next relationship refresh, normally within five minutes.

`forget ALIAS --apply` deletes the participant's history, labels and cached areas, disables online lookups and keeps an inactive participant record. Retention and forgetting leave existing backups and Apple session files in place; they do not securely erase disk contents. See [maintenance commands](operations.md#history-maintenance).

Public examples use fictional data. Keep `data/`, credentials, real reports and captures out of public repositories; use the [source exporter](public-release.md) to prepare a release.
