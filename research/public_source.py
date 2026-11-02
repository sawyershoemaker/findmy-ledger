"""Validate or export an explicit list of public source files; never publish."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import ssl

MANIFEST = "public-files.json"
PUBLIC_CA = "research/certificates/apple-root-g3.pem"
CA_SHA256 = "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"
ROOT_FILES = {".gitignore", "AGENTS.md", "CONTRIBUTING.md", "LICENSE", "NOTICE",
              "MANIFEST.in", "README.md", "THIRD_PARTY_NOTICES.md", "pyproject.toml",
              "requirements-cloudkit.lock", MANIFEST}
ROOTS = {"location_ledger", "research", "tests", "scripts", "docs", "examples", "licenses", ".github"}
SUFFIXES = {".py", ".ps1", ".md", ".svg", ".json", ".jsonl", ".txt", ".yml", ".yaml"}
BLOCKED_PARTS = {"data", "work", "runtime", "upstream", "captures", "secrets", ".git",
                 ".venv", "__pycache__", "node_modules", "build", "dist"}
PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "personal_windows_path": re.compile(r"(?i)[a-z]:[/\\]+Users[/\\]+(?!Public\b|Default\b)[^\s/\\]+"),
}
EMAIL = re.compile(r"[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})")


def safe_path(root, name):
    if not isinstance(name, str) or not name or "\\" in name or ":" in name:
        raise ValueError("Manifest contains an invalid path")
    rel = PurePosixPath(name)
    if rel.is_absolute() or str(rel) != name or any(part in {".", ".."} for part in rel.parts):
        raise ValueError("Manifest paths must be normalized and relative")
    if any(part.casefold() in BLOCKED_PARTS or part.startswith(".env") or part.endswith(".egg-info") for part in rel.parts):
        raise ValueError(f"Private artifact path blocked: {name}")
    if name not in ROOT_FILES:
        if rel.parts[0] not in ROOTS or (name != PUBLIC_CA and rel.suffix.lower() not in SUFFIXES):
            raise ValueError(f"Unapproved source file type: {name}")
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink() or current.is_junction():
            raise ValueError(f"Links are not exportable: {name}")
    if not current.is_file() or not current.resolve().is_relative_to(root):
        raise ValueError(f"Missing or escaped source file: {name}")
    if current.stat().st_size > 2 * 1024 * 1024:
        raise ValueError(f"Oversized source file needs manual review: {name}")
    return current


def inspect_source(root):
    root = Path(root).resolve(strict=True)
    path = safe_path(root, MANIFEST)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    names = manifest.get("files")
    if manifest.get("version") != 1 or not isinstance(names, list) or not names or not all(isinstance(n, str) for n in names):
        raise ValueError("Unsupported public source manifest")
    if len(names) != len({n.casefold() for n in names}) or MANIFEST not in names:
        raise ValueError("Manifest needs unique paths and must include itself")
    # Exact reviewed lines in synthetic URL-rejection tests can resemble emails.
    # Hashing the whole line means edits require a fresh review; other checks
    # (private keys, tokens, paths) are never suppressed by this exception.
    reviewed = {(item["file"], item["line_sha256"]) for item in manifest.get("reviewed_email_fixtures", [])}
    files, findings = {}, []
    for name in sorted(names):
        payload = safe_path(root, name).read_bytes()
        try:
            content = payload.decode("utf-8-sig")
        except UnicodeError as error:
            raise ValueError(f"Binary file is not approved for source export: {name}") from error
        for line_number, line in enumerate(content.splitlines(), 1):
            for category, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append({"file": name, "line": line_number, "category": category})
            for domain in EMAIL.findall(line):
                domain = domain.lower()
                if name.startswith("tests/") and (name, hashlib.sha256(line.encode()).hexdigest()) in reviewed:
                    continue
                if not (domain.endswith((".invalid", ".test", ".example")) or domain in
                        {"example.com", "example.org", "example.net"}):
                    findings.append({"file": name, "line": line_number, "category": "non_example_email"})
        if name.endswith(".svg") and re.search(r"(?i)<script|<foreignObject|\bon\w+\s*=|(?:href|src)\s*=\s*['\"]https?://", content):
            findings.append({"file": name, "category": "active_or_remote_svg_content"})
        if name == PUBLIC_CA:
            der = ssl.PEM_cert_to_DER_cert(content)
            if hashlib.sha256(der).hexdigest() != CA_SHA256:
                findings.append({"file": name, "category": "unexpected_public_certificate"})
        files[name] = payload
    if findings:
        # Never echo matched text, which could be a credential or identity.
        raise ValueError("Public source check failed: " + json.dumps(findings))
    return files


def export_source(root, destination):
    root = Path(root).resolve(strict=True)
    files = inspect_source(root)  # Snapshot reviewed bytes before writing anything.
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink() or destination.is_junction():
        raise FileExistsError("Export destination must not exist")
    for parent in destination.parents:
        if parent.is_symlink() or parent.is_junction():
            raise ValueError("Export destination cannot traverse a link")
    if destination.resolve().is_relative_to(root):
        raise ValueError("Export must be outside the working source directory")
    destination.mkdir(parents=True, exist_ok=False)
    hashes = []
    for name, payload in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        hashes.append(f"{hashlib.sha256(payload).hexdigest()}  {name}\n")
    (destination / "SOURCE_SHA256.txt").write_text("".join(hashes), encoding="utf-8")
    return {"files": len(files), "source_bytes": sum(map(len, files.values())),
            "checksums": "SOURCE_SHA256.txt", "network_requests": 0, "published": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.check:
            files = inspect_source(args.root)
            result = {"passed": True, "files": len(files), "source_bytes": sum(map(len, files.values())),
                      "scope": "Explicit public manifest; pattern checks are not a complete privacy or license audit.",
                      "network_requests": 0, "published": False}
        else:
            result = export_source(args.root, args.output)
    except (ValueError, OSError) as error:
        parser.exit(2, str(error) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
