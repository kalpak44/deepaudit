import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from deepaudit import deps
from deepaudit.artifacts import check_integrity
from deepaudit.sbom import cyclonedx


def arguments(repo, **overrides):
    values = {"repo": repo, "out": "audits", "allow_advisory_fetch": False,
              "max_advisory_requests": 16, "timeout": 5}
    values.update(overrides)
    return argparse.Namespace(**values)


def run_quietly(args):
    """The pipeline reports to stdout; tests assert on artifacts, not on that."""
    with redirect_stdout(io.StringIO()):
        return deps.run_deps(args)


def fixture(root: Path) -> None:
    (root / "requirements.txt").write_text("Flask==2.0.1\nrequests>=2.0\n")
    (root / "package-lock.json").write_text(json.dumps(
        {"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.11"}}}))


ADVISORY = {"id": "GHSA-x", "summary": "Test advisory", "aliases": ["CVE-2026-9"],
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "PyPI", "name": "flask"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "2.1.0"}]}]}]}


class OfflineRun(unittest.TestCase):
    def test_writes_every_artifact_and_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root)
            run_dir, manifest, code = run_quietly(arguments(root))
            self.assertEqual(code, 3, "no advisory source consulted is not a complete audit")
            for name in ("inventory.json", "sbom.json", "advisories.json",
                         "applicability.json", "report.md", "manifest.json", "SHA256SUMS"):
                self.assertTrue((run_dir / name).is_file(), name)
            self.assertFalse(manifest["advisory_consulted"])
            self.assertFalse(manifest["complete"])

    def test_report_says_zero_findings_is_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root)
            run_dir, _, _ = run_quietly(arguments(root))
            report = (run_dir / "report.md").read_text()
            self.assertIn("No advisory source was consulted", report)
            self.assertIn("not a clean result", report)

    def test_artifacts_are_self_verifying(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root)
            run_dir, _, _ = run_quietly(arguments(root))
            self.assertTrue(check_integrity(run_dir)["ok"])

    def test_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root)
            run_dir, _, _ = run_quietly(arguments(root))
            (run_dir / "report.md").write_text("rewritten")
            self.assertFalse(check_integrity(run_dir)["ok"])


class AssessedRun(unittest.TestCase):
    def _run(self, root, **overrides):
        original = deps.fetch
        key = "PyPI|flask|2.0.1"
        deps.fetch = lambda components, client: {
            "advisories": {"GHSA-x": __import__("deepaudit.advisories", fromlist=["normalize"]).normalize(ADVISORY)},
            "by_component": {key: ["GHSA-x"]}, "requests": 2, "incomplete": False, "error": None}
        try:
            return run_quietly(arguments(root, allow_advisory_fetch=True, **overrides))
        finally:
            deps.fetch = original

    def test_finding_reaches_the_report_as_potential(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root)
            run_dir, manifest, code = self._run(root)
            assessment = json.loads((run_dir / "applicability.json").read_text())
            self.assertEqual(assessment["counts"]["POTENTIAL"], 1)
            self.assertEqual(assessment["findings"][0]["advisory_id"], "GHSA-x")
            report = (run_dir / "report.md").read_text()
            self.assertIn("GHSA-x", report)
            self.assertIn("CVE-2026-9", report)
            self.assertIn("VERSION_MATCH", report)
            # An unpinned requirement remains a coverage gap, so the run is not complete.
            self.assertEqual(code, 3)
            self.assertTrue(manifest["advisory_consulted"])

    def test_unresolved_component_is_listed_as_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root)
            run_dir, _, _ = self._run(root)
            assessment = json.loads((run_dir / "applicability.json").read_text())
            names = {item["name"] for item in assessment["unresolved_components"]}
            self.assertIn("requests", names)
            self.assertIn("Coverage gaps", (run_dir / "report.md").read_text())

    def test_data_sharing_is_disclosed_in_the_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture(root)
            run_dir, _, _ = self._run(root)
            self.assertIn("Data sharing", (run_dir / "report.md").read_text())


class Sbom(unittest.TestCase):
    def test_only_resolved_versions_become_components(self):
        inventory = {"root": "r", "components": [
            {"ecosystem": "PyPI", "name": "flask", "raw_name": "Flask", "version": "2.0.1",
             "purl": "pkg:pypi/flask@2.0.1", "source": "r.txt", "direct": True, "resolution": "pinned"},
            {"ecosystem": "PyPI", "name": "requests", "raw_name": "requests", "version": None,
             "purl": None, "source": "r.txt", "direct": True, "resolution": "declared_range"}]}
        document = cyclonedx(inventory, "2026-09-18T00:00:00+00:00")
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(len(document["components"]), 1)
        self.assertEqual(document["components"][0]["purl"], "pkg:pypi/flask@2.0.1")


if __name__ == "__main__":
    unittest.main()
