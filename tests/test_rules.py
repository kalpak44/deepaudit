from copy import deepcopy
import unittest
from deepaudit.poc_template import observe
from deepaudit.rules import RULES, evaluate, verify_observations
from tests.helpers import snapshot


class RuleTests(unittest.TestCase):
    def ids(self, value):
        return {finding["id"] for finding in evaluate(value)}

    def test_demo_has_five_observations(self):
        self.assertEqual(len(evaluate(snapshot())), 5)

    def test_hardened_http_retains_only_plaintext(self):
        self.assertEqual(self.ids(snapshot(hardened=True)), {"HTTP_PLAINTEXT_RESPONSE"})

    def test_json_has_no_html_findings(self):
        self.assertFalse({"HTML_CSP_ABSENT", "HTML_FRAME_GUARD_ABSENT"} & self.ids(snapshot(html=False)))

    def test_redirect_has_no_html_findings(self):
        value = snapshot()
        value["http"]["status_code"] = 302
        self.assertEqual(evaluate(value), [])

    def test_error_is_not_a_missing_header(self):
        value = snapshot()
        value["http"] = {"status": "error", "error": "timeout"}
        self.assertEqual(evaluate(value), [])

    def test_hsts_only_https_hostname(self):
        self.assertIn("HTTPS_HSTS_ABSENT", self.ids(snapshot(url="https://example.test/")))
        self.assertNotIn("HTTPS_HSTS_ABSENT", self.ids(snapshot(url="https://1.1.1.1/")))
        self.assertNotIn("HTTPS_HSTS_ABSENT", self.ids(snapshot()))

    def test_cookie_review_is_info_not_session_compromise(self):
        result = next(f for f in evaluate(snapshot()) if f["id"] == "COOKIE_FLAGS_REVIEW")
        self.assertEqual(result["severity"], "info")
        self.assertNotIn("cookie_value", result["evidence"])

    def test_certificate_failure(self):
        value = snapshot(url="https://example.test/", hardened=True)
        value["tls"] = {"status": "error", "error": "certificate_verification_failed", "verify_code": 18}
        self.assertIn("TLS_CERTIFICATE_REJECTED", self.ids(value))
        self.assertTrue(observe("TLS_CERTIFICATE_REJECTED", value))

    def test_expiring_certificate(self):
        value = snapshot(url="https://example.test/", hardened=True)
        value["tls"] = {"status": "ok", "observed_at": "2026-09-18T00:00:00+00:00",
                        "not_after": "2026-10-01T00:00:00+00:00"}
        self.assertEqual(self.ids(value), {"TLS_CERTIFICATE_EXPIRING"})
        self.assertTrue(observe("TLS_CERTIFICATE_EXPIRING", value))

    def test_reproduced_independent_rule_conditions(self):
        for value in (snapshot(), snapshot(hardened=True), snapshot(url="https://example.test/"), snapshot(html=False)):
            hits = self.ids(value)
            for rule_id in RULES:
                if rule_id.startswith("TLS_"):
                    continue
                with self.subTest(rule=rule_id, target=value["scope"]["target"]):
                    self.assertEqual(observe(rule_id, value), rule_id in hits)

    def test_recheck_success(self):
        self.assertTrue(all(f["verification"] == "reproduced" for f in verify_observations(snapshot(), snapshot())))

    def test_recheck_hardened_not_reproduced(self):
        findings = verify_observations(snapshot(), snapshot(hardened=True))
        self.assertEqual(sum(f["verification"] == "not_reproduced" for f in findings), 4)

    def test_recheck_error_inconclusive(self):
        second = snapshot()
        second["http"] = {"status": "error", "error": "timeout"}
        self.assertTrue(all(f["verification"] == "inconclusive" for f in verify_observations(snapshot(), second)))
