import unittest

from deepaudit.advisories import AdvisoryError, OSVClient, component_key, fetch, normalize


class FakeClient(OSVClient):
    """Replaces only the transport, so budget and orchestration logic stay under test."""

    def __init__(self, batch=None, vulns=None, fail_on=None, **kwargs):
        super().__init__(**kwargs)
        self.batch = batch or []
        self.vulns = vulns or {}
        self.fail_on = fail_on
        self.calls = []

    def _call(self, method, path, payload):
        if self.requests >= self.max_requests:
            raise AdvisoryError("Advisory request budget exhausted")
        self.requests += 1
        self.calls.append((method, path))
        if self.fail_on and self.fail_on in path and payload and "package" in payload:
            raise AdvisoryError("boom")
        if path.endswith("querybatch"):
            return self.batch.pop(0) if self.batch else {"results": []}
        name = payload["package"]["name"]
        if self.fail_on == name:
            raise AdvisoryError("boom")
        return {"vulns": self.vulns.get(name, [])}


def component(name="pkg", version="1.0.0", ecosystem="npm"):
    return {"ecosystem": ecosystem, "name": name, "version": version}


class Normalization(unittest.TestCase):
    def test_extracts_cves_from_aliases(self):
        result = normalize({"id": "GHSA-1", "aliases": ["CVE-2026-1", "GHSA-2"]})
        self.assertEqual(result["cve"], ["CVE-2026-1"])

    def test_keeps_severity_label_and_vectors(self):
        result = normalize({"id": "x", "database_specific": {"severity": "HIGH"},
                            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}]})
        self.assertEqual(result["severity_label"], "HIGH")
        self.assertEqual(result["severity"][0]["score"], "CVSS:3.1/AV:N")

    def test_tolerates_missing_and_malformed_sections(self):
        result = normalize({"id": "x", "affected": [None, {"package": "notadict"}],
                            "references": ["notadict"], "severity": ["bad"]})
        self.assertEqual(result["affected"], [])
        self.assertEqual(result["references"], [])
        self.assertEqual(result["severity"], [])

    def test_summary_is_truncated(self):
        self.assertEqual(len(normalize({"id": "x", "summary": "a" * 900})["summary"]), 500)

    def test_carries_ranges_through(self):
        raw = {"id": "x", "affected": [{"package": {"ecosystem": "npm", "name": "p"},
                                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
        self.assertEqual(normalize(raw)["affected"][0]["ranges"][0]["type"], "SEMVER")


class Fetching(unittest.TestCase):
    def test_two_stage_lookup_queries_only_flagged_components(self):
        client = FakeClient(
            batch=[{"results": [{"vulns": [{"id": "GHSA-1"}]}, {}]}],
            vulns={"a": [{"id": "GHSA-1", "affected": []}]})
        result = fetch([component("a"), component("b")], client)
        self.assertEqual(result["advisories"]["GHSA-1"]["id"], "GHSA-1")
        self.assertEqual(result["by_component"], {component_key(component("a")): ["GHSA-1"]})
        # One batch call plus one query for the single flagged component.
        self.assertEqual(len(client.calls), 2)
        self.assertFalse(result["incomplete"])

    def test_components_without_a_version_are_never_queried(self):
        client = FakeClient()
        result = fetch([{"ecosystem": "npm", "name": "a", "version": None}], client)
        self.assertEqual(client.calls, [])
        self.assertEqual(result["advisories"], {})

    def test_budget_exhaustion_keeps_partial_results(self):
        client = FakeClient(
            batch=[{"results": [{"vulns": [{"id": "G1"}]}, {"vulns": [{"id": "G2"}]}]}],
            vulns={"a": [{"id": "G1", "affected": []}], "b": [{"id": "G2", "affected": []}]},
            max_requests=2)
        result = fetch([component("a"), component("b")], client)
        self.assertTrue(result["incomplete"], "a drained budget must be reported, not hidden")
        self.assertIn("G1", result["advisories"], "already-retrieved data is kept")
        self.assertIsNotNone(result["error"])

    def test_batch_failure_reports_incomplete_with_no_data(self):
        client = FakeClient(fail_on="querybatch")
        client.batch = []

        def explode(method, path, payload):
            raise AdvisoryError("network down")
        client._call = explode
        result = fetch([component("a")], client)
        self.assertTrue(result["incomplete"])
        self.assertEqual(result["advisories"], {})

    def test_invalid_budget_is_rejected(self):
        with self.assertRaises(AdvisoryError):
            OSVClient(max_requests=0)
        with self.assertRaises(AdvisoryError):
            OSVClient(max_requests=10_000)

    def test_pagination_is_followed(self):
        client = FakeClient(batch=[
            {"results": [{"vulns": [{"id": "G1"}]}], "next_page_token": "t"},
            {"results": [{"vulns": [{"id": "G2"}]}]}],
            vulns={"a": [{"id": "G1", "affected": []}, {"id": "G2", "affected": []}]})
        result = fetch([component("a")], client)
        self.assertEqual(sorted(result["by_component"][component_key(component("a"))]), ["G1", "G2"])


if __name__ == "__main__":
    unittest.main()
