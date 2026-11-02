# Contributing

Start with the [offline demo](README.md#try-the-demo). Use Python 3.12 or newer in a virtual environment; development uses Python 3.13.

## Development checks

```powershell
$python = '.\.venv\Scripts\python.exe'
& $python -m pip install -e '.[protocol]'
& $python -m unittest discover -s tests -v
& $python -m research.demo --output data/demo-review
& $python -m research.public_source --check
```

Choose a new demo output directory each time. Some tests require optional dependencies or Windows APIs and skip when those are unavailable. Include the environment and any skips with your test results.

Tests and public examples use synthetic data. Keep credentials, real histories, captures and runtime assets out of commits. Automated tests should work without Apple sign-in, participant contact or map requests.

## Making changes

Keep reporting usable without Apple dependencies. Before changing storage or compaction, read the [storage guide](docs/storage.md). Preserve source timing, observation counts, gaps and rollback behavior. Reporting changes should cover overlapping stays and time-zone boundaries, including daylight saving time.

Add new public files to `public-files.json`, then run the source check above. Describe the behavior changed and how you checked it. Preserve upstream notices and record the source of adapted code. Original contributions use Apache 2.0; third-party material keeps its own terms.

## Reporting bugs

Include the command, Python and Windows versions, expected result and a synthetic reproduction. For collector problems, include the relevant redacted status fields. Keep account details, locations and credential files out of issues and attachments.
