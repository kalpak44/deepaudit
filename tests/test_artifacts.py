import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deepaudit.artifacts import check_integrity, make_run_dir, run_verifiers, write_artifacts
from deepaudit.policy import PolicyError, Target
from deepaudit.tools import AuditTools
from tests.helpers import FakeProbes


def make_bundle(root, *, real_verification=False):
    tools = AuditTools(FakeProbes())
    tools.complete()
    folder = make_run_dir(root, "audits", tools.probes.scope.target)
    fake = {"verifier": "test setup only", "cases": [], "reproduced": 5, "total": 5, "all_reproduced": True}
    if real_verification:
        manifest = write_artifacts(folder, tools, {"status": "baseline", "summary": "", "fallback_used": False},
                                   "2026-09-18T00:00:00+00:00")
    else:
        with patch("deepaudit.artifacts.run_verifiers", return_value=fake):
            manifest = write_artifacts(folder, tools, {"status": "baseline", "summary": "", "fallback_used": False},
                                       "2026-09-18T00:00:00+00:00")
    return folder, manifest


class ArtifactTests(unittest.TestCase):
    def test_real_subprocess_pocs_and_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder, manifest = make_bundle(Path(tmp), real_verification=True)
            self.assertEqual(manifest["offline_verification"]["total"], 5)
            self.assertEqual(manifest["offline_verification"]["reproduced"], 5)
            self.assertTrue(check_integrity(folder)["ok"])
            self.assertTrue(run_verifiers(folder)["all_reproduced"])
            self.assertTrue((folder / "report.md").exists())

    def test_changed_evidence_fails_hash_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder, _ = make_bundle(Path(tmp))
            path = folder / "evidence" / "initial.json"
            path.write_text(path.read_text() + " ", encoding="utf-8")
            self.assertFalse(check_integrity(folder)["ok"])

    def test_modified_poc_never_executes(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder, _ = make_bundle(Path(tmp))
            path = sorted((folder / "pocs").glob("*/poc.py"))[0]
            path.write_text("raise RuntimeError('must never execute')\n", encoding="utf-8")
            with self.assertRaises(PolicyError):
                run_verifiers(folder)

    def test_output_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for output in ("../outside", "/tmp/outside", ".git/hooks", "audits/../oops", ".", "a b"):
                with self.subTest(output=output), self.assertRaises(PolicyError):
                    make_run_dir(Path(tmp), output, Target.parse("example.test"))

    def test_output_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "outside").mkdir()
            try:
                (root / "audits").symlink_to(root / "outside", target_is_directory=True)
            except OSError:
                self.skipTest("Symlink privileges unavailable")
            with self.assertRaises(PolicyError):
                make_run_dir(root, "audits", Target.parse("example.test"))

    def test_unique_run_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            one = make_run_dir(Path(tmp), "audits", Target.parse("example.test"))
            two = make_run_dir(Path(tmp), "audits", Target.parse("example.test"))
            self.assertNotEqual(one, two)

    def test_poc_detects_changed_observation_independently(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder, _ = make_bundle(Path(tmp))
            path = folder / "evidence" / "recheck.json"
            value = json.loads(path.read_text())
            value["http"]["signals"]["csp_present"] = True
            path.write_text(json.dumps(value), encoding="utf-8")
            outcomes = run_verifiers(folder)
            csp = next(item for item in outcomes["cases"] if item["rule_id"] == "HTML_CSP_ABSENT")
            self.assertEqual(csp["status"], "not_reproduced")
            self.assertEqual(csp["exit_code"], 1)

    def test_unlisted_artifact_fails_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder, _ = make_bundle(Path(tmp))
            (folder / "unexpected.txt").write_text("not listed", encoding="utf-8")
            self.assertFalse(check_integrity(folder)["ok"])

    def test_duplicate_hash_entry_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder, _ = make_bundle(Path(tmp))
            manifest = folder / "SHA256SUMS"
            content = manifest.read_text()
            manifest.write_text(content + content.splitlines()[0] + "\n", encoding="utf-8")
            with self.assertRaises(PolicyError):
                check_integrity(folder)
