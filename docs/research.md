# Development notes

Native collection follows this path:

```text
Apple sign-in → IDS / APNs registration → sharing key
    → Live relay → authenticated locations → SQLite history
```

Windows testing has covered sign-in with 2FA, encrypted session restoration, participant selection, key delivery, Live startup, session renewal and watchdog recovery. Startup and quiet-session renewal have worked with Find My closed on the viewing phone.

## Open work

| Area | Next step |
| --- | --- |
| Fresh installation | Repeat the full runtime setup on a clean Windows machine |
| Movement | Verify sustained high-frequency delivery while moving, with the viewing app closed |
| Account lifetime | Handle token expiry, reauthentication and machine resynchronization over extended operation |
| Sharing changes | Test real key rotation and revocation; current tests use synthetic events |
| Boot startup | Verify the optional pre-sign-in task after a reboot |
| Distribution | Resolve runtime licensing before packaging a combined installer |

The current authentication wrapper does not implement unattended token renewal or machine resynchronization. The integration uses unofficial Apple protocols, so service changes may require code updates.

## Other tools

The snapshot collector and single-report probe are available for diagnostics. Stop the Live receiver before using them; they share the same writer and receiver locks.

CloudKit and device-passcode recovery experiments are disabled for collection. The identified SharedSecrets records concern nearby finding; their role in map-location key recovery was not established. Native Live bootstrap does not use this route.

The optional [request-format probe](native-capture.md) records HTTP field shapes for protocol research. It is not part of installation.

## References

- [Windows setup](windows-emulator.md): runtime files, pinned revisions and bootstrap commands.
- [Live protocol](live-protocol.md): invitation, relay, encryption and report handling.
- [Storage](storage.md): compaction rules and reproducible synthetic benchmarks.
- [Third-party notices](../THIRD_PARTY_NOTICES.md): component sources and licenses.
