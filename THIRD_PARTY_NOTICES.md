# Third-party notices

Original Ledger code and documentation use [Apache 2.0](LICENSE). Adapted Onitrack material retains the MIT notice below and in [licenses/Onitrack-MIT.txt](licenses/Onitrack-MIT.txt). Package metadata lists `Apache-2.0 AND MIT`.

External runtimes are obtained separately and keep their own licenses. Apple binaries and the pinned encoder source have no redistribution permission established here. This source package does not bundle them or the emulator checkouts.

## Components

| Component | Version / license | Used for |
| --- | --- | --- |
| [FindMy.py](https://github.com/malmeloo/FindMy.py) | 0.10.2 / MIT | Optional authentication dependency |
| [Onitrack](https://github.com/TureBentzin/onitrack/tree/04dd25312643d8c9aa93c883a343488a4b682635) | `04dd253` / MIT | IDS/key verification and adapted Friends requests |
| [os-findmy-e](https://github.com/sacca97/os-findmy-e/tree/d4d2a832baf47d1cf43d989879950ac2aec45f47) | `d4d2a83` / GPL-2.0 | External CoreADI emulator |
| [pypush](https://github.com/JJTech0130/pypush/tree/71aa2e4442061596f75e6b02dfad613330127b5b) | `71aa2e4` / SSPL-1.0 | Optional APNs dependency, with Ledger's verified transport wrappers |
| [pypush legacy NAC](https://github.com/JJTech0130/pypush/tree/8220f3407c96c975d0dd699fd5ab41f56f372c47) | `8220f34` / SSPL-1.0 | External NAC emulator |
| [RustPush / OpenBubbles](https://github.com/OpenBubbles/rustpush/tree/b3c96c23e1aae78d1229ebaccb12027624f1eaff) | `b3c96c2` / SSPL-1.0 | Protocol reference for pair-v2 and relay structures; no source or runtime bundled |
| [apple-gen](https://github.com/Smoothstep/apple-gen/tree/d561c2cc12f889c7117cd81a49993f382eee42eb) | `d561c2c` / no license file at this revision | External IOKit encoder source |
| Apple CoreADI / IMDAppleServices | Proprietary | External Apple routines; the NAC artifact is from a third-party mirror |
| [Apple Root CA G3](https://www.apple.com/certificateauthority/AppleRootCA-G3.cer) | Public trust certificate | Bundled certificate; its DER hash is checked during export |
| [parawanderer/FindMy.py](https://github.com/parawanderer/FindMy.py/tree/8ecfae6cb34b29caf0bd8176ee73155ca81415a8) | `8ecfae6` / MIT | Optional CloudKit research; passcode recovery is disabled |
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) | 12.2.1 / MIT | Optional request-format probe |

Full revisions and artifact hashes are in [Windows setup](docs/windows-emulator.md). Apple protocol references are listed in [Live protocol](docs/live-protocol.md). A combined runtime distribution needs review under all applicable terms, even when components run in separate processes.

Map results carry [OpenStreetMap attribution](https://www.openstreetmap.org/copyright). The demo and README visuals use fictional data and no map tiles. FindMy Ledger is not endorsed by Apple or the upstream projects.

## Onitrack MIT license

Copyright 2026 Ture Bentzin

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
