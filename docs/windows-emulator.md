# Windows setup

Native collection runs selected Apple x86_64 routines under Unicorn in Windows Python. It needs manual account setup and the separate runtime files below. Once running, it does not require a viewing iPhone or Mac to stay online.

Use the same Windows account for setup and collection: saved session and device state belong to that user through DPAPI. Runtime components have their own [licenses](../THIRD_PARTY_NOTICES.md) and are not included in this source package.

## 1. Create the environment

```powershell
py -3.13 -m venv .venv
$python = '.\.venv\Scripts\python.exe'
& $python -m pip install -e '.[auth,mac-emulator,push-research]'
```

You will also need Git, a DMG/XAR-capable 7-Zip executable and LLVM for the encoder build. Keep external checkouts and binaries in a separate directory, such as `C:/your-runtime`. Local configuration and encrypted state go in `data/apple-auth`.

Launchers find Python through `-Python`, `FINDMY_LEDGER_PYTHON`, `data/python-path.txt`, then `.venv`. Use Ledger's launchers for verified TLS and encrypted persistence.

## 2. Prepare authentication

1. Clone [os-findmy-e at the pinned revision](https://github.com/sacca97/os-findmy-e/tree/d4d2a832baf47d1cf43d989879950ac2aec45f47) into the runtime directory. Keep it unmodified. Its requirements target a different FindMy.py fork; use this project's extras instead.
2. Download [iTunes 12.8.3 for Mac](https://support.apple.com/en-us/106374) from Apple and check its hash against the artifact list below.
3. Extract `iTunes/Install iTunes.pkg`, then `CoreADI.pkg/Payload`. These are archive operations; the installer is not run on Windows.
4. Extract the pinned x86_64 slice:

```powershell
& $python -m research.extract_coreadi `
    --payload PATH_TO_PAYLOAD --output PATH_TO_CoreADI.x86_64
```

The extractor reads one archive member through Windows `tar.exe` and checks the binary hash.

Create `data/apple-auth/mac-helper-config.json` with absolute paths:

```json
{
  "upstream_path": "C:/your-runtime/os-findmy-e",
  "coreadi_binary": "C:/your-runtime/CoreADI.x86_64",
  "upstream_commit": "d4d2a832baf47d1cf43d989879950ac2aec45f47"
}
```

Provision the machine and check that its state can be restored:

```powershell
& $python -m research.mac_helper prepare `
    --config data/apple-auth/mac-helper-config.json --state-dir data/apple-auth
& .\scripts\test-login.ps1 -Command prepare
```

Provisioning contacts Apple without an account password and saves encrypted machine state. Repeating it reuses the provisioned identity.

## 3. Prepare push and IDS

The push extras install the modern pypush dependency. Obtain these additional files separately:

| Component | Pinned source |
| --- | --- |
| APNs dependency | [pypush `71aa2e4`](https://github.com/JJTech0130/pypush/tree/71aa2e4442061596f75e6b02dfad613330127b5b) |
| NAC emulator | [pypush legacy `8220f34`](https://github.com/JJTech0130/pypush/tree/8220f3407c96c975d0dd699fd5ab41f56f372c47), including `emulated/` and its license |
| NAC binary | [IMDAppleServices](https://github.com/JJTech0130/nacserver/blob/main/IMDAppleServices), a third-party mirror of an Apple binary |
| IDS and key verifier | [Onitrack `04dd253`](https://github.com/TureBentzin/onitrack/tree/04dd25312643d8c9aa93c883a343488a4b682635) |
| IOKit encoder | [apple-gen `d561c2c`](https://github.com/Smoothstep/apple-gen/tree/d561c2cc12f889c7117cd81a49993f382eee42eb) |

Build only `src/asm/amd64/encrypt.s` from the encoder source:

```powershell
& 'C:\Program Files\LLVM\bin\clang.exe' `
    -c PATH_TO_ENCRYPT_S -o PATH_TO_IO_ENCODE_OBJ
& 'C:\Program Files\LLVM\bin\lld-link.exe' `
    /dll /noentry /nodefaultlib /timestamp:0 `
    /export:sub_ffffff8000ec7320 /out:PATH_TO_IO_ENCODE_DLL PATH_TO_IO_ENCODE_OBJ
```

Check the output hash below. Different toolchains may produce different DLLs; inspect differences before changing the pin. Ledger maps this DLL into Unicorn rather than loading it into the Windows process.

Create `data/apple-auth/push-helper-config.json`:

```json
{
  "nac_source_path": "C:/your-runtime/pypush-nac-legacy",
  "nac_binary": "C:/your-runtime/IMDAppleServices",
  "onitrack_path": "C:/your-runtime/onitrack",
  "pypush_commit": "71aa2e4442061596f75e6b02dfad613330127b5b",
  "nac_emulator_commit": "8220f3407c96c975d0dd699fd5ab41f56f372c47",
  "onitrack_commit": "04dd25312643d8c9aa93c883a343488a4b682635",
  "io_encoder_binary": "C:/your-runtime/io-encode.dll",
  "io_encoder_commit": "d561c2cc12f889c7117cd81a49993f382eee42eb"
}
```

The wrapper builds NAC validation from the persistent authentication identity, including matching encoded serial and platform UUID values. APNs and IDS use verified TLS; APNs has a separate TLS context for its ALPN settings.

## 4. Sign in and select a participant

```powershell
& .\scripts\test-login.ps1 -Command doctor
& .\scripts\test-login.ps1
& .\scripts\select-person.ps1 -Command discover
& .\scripts\select-person.ps1
```

Enter the Apple password and any 2FA code in the local terminal. The password is not saved. Participant names and contact details appear only in that terminal; the selected identity is saved encrypted. The local alias is `participant`.

## 5. Register the receiver and receive a key

```powershell
& $python -m research.apns_probe --state-dir data/apple-auth
& .\scripts\register-device.ps1 -Doctor
& .\scripts\register-device.ps1
& .\scripts\acquire-key.ps1
```

Registration refreshes sign-in to use a short-lived IDS credential; valid existing registration is reused. Key delivery needs a response from the participant's device. A timeout does not call for repeated account registration.

## 6. Check collection and install the task

```powershell
& $python -m location_ledger --db data/history.sqlite init
& $python -m location_ledger --db data/history.sqlite register participant
& $python -m research.location_probe `
    --state-dir data/apple-auth --db data/history.sqlite
& .\scripts\install-collector.ps1 -Command doctor
```

The probe checks for an authenticated, recent source location. Once `doctor` reports readiness, follow [collector operations](operations.md) to install the background tasks and configure backups.

## Troubleshooting

Authentication headers use a fresh worker with up to 30 seconds of caching. The emulator needs real time; freezing its clock invalidates later authentication material. A file lock allows only one process to update machine state.

Keep the existing machine directory when resolving authentication failures. Tokens depend on that identity. Sign-in HTTP 429 responses save a minimum 45-minute cooldown, extended by a longer server `Retry-After`; the launchers do not retry sign-in automatically.

Unattended token renewal and machine resynchronization remain [open work](research.md). CloudKit passcode recovery and phone proxy tests are not part of this setup.

## Artifact checksums

<details>
<summary>SHA-256 hashes and development versions</summary>

The wrappers check the pinned runtime binaries. To check a downloaded file in PowerShell, use `Get-FileHash PATH -Algorithm SHA256`.

| Artifact | SHA-256 |
| --- | --- |
| iTunes 12.8.3 DMG | `dd08b9967db3e5847955fa168ce880303abf5f36de12abb2061e7ef1a25be214` |
| CoreADI x86_64, 1,676,560 bytes | `2eafc3c79c7f41a8afbfbeaaf23ee5dab5ad5bda55ec8e54dbc0ddf1d20ce630` |
| IMDAppleServices, 6,222,784 bytes | `74c2a8fe826a478f14f6e17b3709a8b315e8c0e0e34e3fba6b9c4eee2f4516e9` |
| Encoder `encrypt.s` | `a461d8fed3b0ab2cd7b607945c63334563c292a9bfa785881efa70118e295513` |
| Encoder DLL | `e92aa56b157ac6e914fe008a1248bf098bd48b8d0fcba3747124f25e2dcb55cf` |
| Apple Root CA G3, DER | `63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179` |
| 7-Zip 26.05 x64 MSI | `3fe4ab99fa15629c652944309a2b2bc6e41fc933fc6b63f5df1ebcf3aea68263` |

`research/certificates/apple-root-g3.pem` is converted from [Apple's public Root CA G3](https://www.apple.com/certificateauthority/AppleRootCA-G3.cer). The development setup used FindMy.py 0.10.2, Unicorn 2.1.4, pypush 2.0.2, HTTPX 0.28.1, AnyIO 4.15.1 and Requests 2.34.2. The 7-Zip files were extracted from the official MSI without a global installation.

</details>
