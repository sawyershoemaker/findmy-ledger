# Request-format probe

This optional diagnostic compares Find My's HTTPS request formats. It is not needed for installation and does not recover sharing keys; People reports also use application-level encryption.

## Start a probe

Use a separate Python environment:

```powershell
py -3.13 -m venv .capture-venv
& .\.capture-venv\Scripts\python.exe -m pip install mitmproxy==12.2.1
& .\.capture-venv\Scripts\python.exe -m research.native_capture `
    --bind PC_ADDRESS --client-ip PHONE_ADDRESS `
    --port 8877 --seconds 600 --output-dir data/native-probe-NEW
```

Replace the addresses with the current PC and phone private IPv4 addresses. The output directory must be new. The probe stops after ten minutes or Ctrl+C.

Only the specified phone can connect. Interception covers `fmfmobile.icloud.com`, its numbered service hosts, `gateway.icloud.com` and a local test page at `findmy-ledger.invalid`. Other permitted Apple HTTPS connections remain encrypted; other destinations are blocked. The tool makes no system proxy, firewall or trust-store changes on Windows and verifies upstream TLS.

## Configure the phone

1. In the connected Wi-Fi network's settings, set **Configure Proxy → Manual**, using the PC address and port `8877`, with authentication off.
2. In Safari, open `http://PC_ADDRESS:8877` followed by the `certificate_download_path` printed at startup. Allow the profile download.
3. Install **FindMy Ledger Temporary Probe** under **Settings → General → VPN & Device Management**, or **Profile Downloaded**.
4. Enable it under **General → About → Certificate Trust Settings**. This is a [separate trust step](https://support.apple.com/en-ca/102390).
5. Open `https://findmy-ledger.invalid/__findmy_ledger_tls_control__` in Safari. Continue only if it says **FindMy Ledger HTTPS trust check passed**. This page is served locally through the proxy; use this hostname rather than an Apple domain.
6. Open **Find My → People → the selected participant** for 30 seconds.
7. Turn the Wi-Fi proxy **Off** and remove **FindMy Ledger Temporary Probe** from VPN & Device Management.

Avoid unrelated apps during the test. The probe cannot reset phone settings when it exits. Each run creates a new one-day certificate, so a restarted probe needs a fresh download and installation. Its private key exists only in memory.

## Output

The output directory contains the public certificate, public DH parameters and `request-shapes.jsonl`. The log retains field names, types, lengths, limited protocol enums, counts, header-presence flags and HTTP/TLS status categories. It omits arbitrary strings, identifiers, credentials, coordinates and raw requests or responses. The probe does not load Ledger's account state.

The log allows 1,000 events plus a final summary. Repeated downloads and identical TLS failures are sampled at powers of two, with exact totals in the summary. Proxy traffic dumping is disabled.

## Interpreting results

An updating map alone does not confirm interception. Check for both a successful local HTTPS control and recorded request shapes. A TLS trust error alone does not establish certificate pinning. If the control fails, resolve that before testing Find My; the probe does not bypass pinning.

Run the synthetic capture tests with:

```powershell
& .\.capture-venv\Scripts\python.exe -m unittest discover `
    -s tests -p test_native_capture.py -v
```
