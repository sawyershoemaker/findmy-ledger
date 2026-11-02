# Native Live protocol

The receiver establishes an IDS session with the selected participant's device, opens a relay transport and stores authenticated location reports. The publisher controls GPS cadence and availability.

## Invitations

The session uses `com.apple.private.alloy.fmd`. NGM command 232 carries the device-scoped invitation; command 233 accepts it and 235 cancels it. Each outgoing NGM message durably reserves its replay counter before sending. Directory identity signatures, selected sender/token, recipient, and session UUID are checked.

## Relay and control channels

QuickRelay command 200 provides an authenticated UDP binding. STUN messages use the relay key; GlobalLink control messages use the session UUID key and unpadded TLVs. The classic channel payload is UTun directly. A bounded virtual TCP stream on port 1024 carries length-prefixed control frames, authenticates the selected peer's legacy pair-v2 signatures, and negotiates two UDP data channels. Packet loss uses cumulative acknowledgements and bounded retransmission. No local TCP server or firewall listener is opened.

## Encryption and reports

The native IDS stream KDF uses AES-128-CBC to derive an AES-256-CTR key. Directional material is formed by XORing both sides' random setup bytes and ordering GUIDs. Each direction has its own SSRC, rollover counter, and sequence. Native `IDSStreamEncryption` initializes last-sequence to zero separately from the advertised random start. Starts at or above 32768 therefore use initial wire ROC `0xffffffff`, then zero after the first sequence wrap. The implementation keeps chronological replay indices separate from that nonce rule. Outgoing counters are reserved before sending.

This layer has **no authentication tag**: a valid UDP checksum never authorizes history. Replay state for reports advances only after inner authentication.

Application datagrams carry binary plist keys `T`, `V`, `I`, and `P`. Location type 0 contains selected identifier bytes and encrypted `locationInfo` entries. The inner P-224 ECDH / AES-GCM report must authenticate and contain the exact selected Find My identifier. Original source time and accuracy are retained. Heartbeats -1/-2 and shutdown -3 never create observations.

## Session lifecycle

`research.live_collector` owns the writer and push-receiver locks and uses the session engine in `research.live_probe`. Routine collection disables raw captures. Status files contain counters, source times, accuracy and selected protocol fields; diagnostic captures require current-user DPAPI encryption.

| Event | Timing |
| --- | --- |
| Application heartbeat | Every 30 seconds |
| Setup timeout | 90 seconds |
| Timeout without application responses | 210 seconds |
| Transport reconnect | 5–300 seconds |
| Normal renewal | Every 30 minutes |
| Quiet renewal | Default 300 seconds without a newer source time; configurable from 60–1800 |

Renewal performs a fresh directory lookup and obtains new session keys. It creates a new Live subscription, not a SearchParty snapshot. Heartbeats do not count as locations.

Orderly shutdown sends native `T=-3` before cancelling IDS. A minimum 30-second delay before another invitation allows account-scoped publisher cleanup; this deadline survives restarts. HTTP 429 also saves an account cooldown. Authentication rejection and unknown protocol errors require attention.

Each accepted report checks the local participant state. Selection changes or pause stop collection and discard pending updates. Sharing is refreshed every five minutes; a removed relationship pauses ingestion. Authenticated key updates use the same APNs connection and are saved atomically.

Older authenticated reports can backfill history without moving current-location status backward. The `publishReason` field can identify Live publication. See [operations](operations.md) for recovery and [storage](storage.md) for compaction.

## Sources

The primary references are decompiled Apple build 23B85 at commit `90aa0cfe59d9682b4265e1354c8b19ec3c7823ab` and matching firmware inspected during development.

- [findmylocated_10.mm](https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/90aa0cfe59d9682b4265e1354c8b19ec3c7823ab/usr/libexec/findmylocated/findmylocated_10.mm): creates `InternetMessaging.makeSession` with `BeaconSharingSessionContext`, accepts authorized incoming requests, and starts location publishing.
- [FindMyMessaging_02.mm](https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/90aa0cfe59d9682b4265e1354c8b19ec3c7823ab/System/Library/PrivateFrameworks/FindMyMessaging.framework/FindMyMessaging/FindMyMessaging_02.mm): IDSSession transport 0, NWDatagramConnection, session plist coding, and heartbeat behavior.
- [IDSDSessionInvitationManager.mm](https://github.com/EthanArbuckle/iPhone18-3_26.1_23B85_Restore/blob/90aa0cfe59d9682b4265e1354c8b19ec3c7823ab/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/IDS/IDSDSessionInvitationManager.mm): encrypted invitations and cancellation.
- [RustPush identity cryptography](https://github.com/OpenBubbles/rustpush/blob/b3c96c23e1aae78d1229ebaccb12027624f1eaff/src/ids/user.rs) and [relay transport](https://github.com/OpenBubbles/rustpush/blob/b3c96c23e1aae78d1229ebaccb12027624f1eaff/src/ids/link.rs) were cross-checks. Its SSPL runtime is not installed or copied into this implementation. Its group-relay packet header differs from the classic UTun transport used here.

[Development notes](research.md) track remaining integration tests.
