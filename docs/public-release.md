# Preparing a source release

Create a clean export before starting a public repository:

```powershell
$python = '.\.venv\Scripts\python.exe'
& $python -m research.public_source --check
& $python -m research.public_source --output ../findmy-ledger-public
```

The destination must not exist. The exporter copies only files listed in `public-files.json` and adds `SOURCE_SHA256.txt`. It checks paths, common secret patterns and the bundled Apple public certificate. It excludes private data, runtime assets and Git history, and does not publish anything.

## Review the export

1. Read the exported diff and check that examples and visuals contain only fictional data.
2. Run the [development checks](../CONTRIBUTING.md#development-checks) from the export.
3. Check Markdown links, SVGs, third-party notices and file checksums.
4. Initialize the public repository from this directory, with fresh Git history.

Add new public files to the manifest deliberately. The pattern scan helps catch mistakes, but exported content still needs review.

## Package contents

The source includes original Apache 2.0 code and adapted MIT material, with both notices. It excludes Apple binaries, external emulator checkouts, the encoder binary, saved accounts and location databases.

A combined runtime installer needs a separate licensing review. Apple artifacts and the pinned encoder source have no redistribution permission established here; other optional components use GPL or SSPL. See [third-party notices](../THIRD_PARTY_NOTICES.md).
