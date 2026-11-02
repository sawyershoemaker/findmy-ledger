import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from research.public_source import export_source, inspect_source


class PublicSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        (self.root / "README.md").write_text("Synthetic example", encoding="utf-8")
        self.manifest(["README.md", "public-files.json"])

    def manifest(self, files):
        (self.root / "public-files.json").write_text(json.dumps({"version": 1, "files": files}), encoding="utf-8")

    def test_only_allowlisted_bytes_and_matching_hashes_are_exported(self):
        private = self.root / "data"
        private.mkdir()
        (private / "account.dpapi").write_bytes(b"never export this")
        target = self.root.parent / "public"
        result = export_source(self.root, target)
        self.assertEqual(result["files"], 2)
        self.assertFalse((target / "data").exists())
        for line in (target / "SOURCE_SHA256.txt").read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(digest, hashlib.sha256((target / name).read_bytes()).hexdigest())
        with self.assertRaises(FileExistsError):
            export_source(self.root, target)

    def test_private_paths_and_traversal_block_even_when_allowlisted(self):
        for unsafe in ("data/account.json", "docs/../README.md", "C:/private.txt", "research/state.dpapi", "/etc/passwd"):
            with self.subTest(unsafe=unsafe):
                self.manifest(["public-files.json", unsafe])
                with self.assertRaises(ValueError):
                    inspect_source(self.root)

    def test_findings_do_not_echo_secret_value(self):
        value = "ghp_" + "x" * 36
        (self.root / "README.md").write_text(value, encoding="utf-8")
        with self.assertRaises(ValueError) as caught:
            inspect_source(self.root)
        self.assertIn("github_token", str(caught.exception))
        self.assertNotIn(value, str(caught.exception))

    def test_linked_source_is_rejected_when_supported(self):
        target = self.root / "README.md"
        linked = self.root / "CONTRIBUTING.md"
        try:
            linked.symlink_to(target)
        except OSError:
            self.skipTest("Creating symbolic links is unavailable")
        self.manifest(["public-files.json", "CONTRIBUTING.md"])
        with self.assertRaisesRegex(ValueError, "Links"):
            inspect_source(self.root)

    def test_export_inside_working_tree_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            export_source(self.root, self.root / "copy")
