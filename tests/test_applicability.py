import unittest

from deepaudit.applicability import (CONDITIONS_MATCH, CONFIRMED, CONFIRMED_APPLICABLE,
                                     EXTERNALLY_REACHABLE, INSUFFICIENT_EVIDENCE, LADDER,
                                     LIKELY_APPLICABLE, NOT_APPLICABLE, NOT_EVALUATED,
                                     POTENTIAL, REACHABLE, REFUTED, REPRODUCED,
                                     VERSION_MATCH, assess, assess_version_match, pending,
                                     state, status_for)


def component(version="1.0.0", ecosystem="npm", name="pkg"):
    return {"ecosystem": ecosystem, "name": name, "version": version,
            "purl": f"pkg:npm/{name}@{version}", "source": "package-lock.json",
            "direct": True, "resolution": "locked"}


def advisory(ranges=None, versions=None, ecosystem="npm", name="pkg", **extra):
    return {"id": "GHSA-test", "cve": ["CVE-2026-1"], "summary": "s", "affected": [
        {"ecosystem": ecosystem, "name": name, "ranges": ranges or [], "versions": versions or []}],
        **extra}


class StatusDerivation(unittest.TestCase):
    def _states(self, **results):
        return [state(name, results.get(name, NOT_EVALUATED), "r") for name in LADDER]

    def test_version_match_refuted_is_not_applicable(self):
        self.assertEqual(status_for(self._states(VERSION_MATCH=REFUTED)), NOT_APPLICABLE)

    def test_version_match_unevaluated_is_insufficient(self):
        self.assertEqual(status_for(self._states()), INSUFFICIENT_EVIDENCE)

    def test_version_match_alone_is_potential(self):
        self.assertEqual(status_for(self._states(VERSION_MATCH=CONFIRMED)), POTENTIAL)

    def test_reachability_promotes_to_likely(self):
        self.assertEqual(
            status_for(self._states(VERSION_MATCH=CONFIRMED, REACHABLE=CONFIRMED)),
            LIKELY_APPLICABLE)
        self.assertEqual(
            status_for(self._states(VERSION_MATCH=CONFIRMED, CONDITIONS_MATCH=CONFIRMED)),
            LIKELY_APPLICABLE)

    def test_reproduction_is_the_only_route_to_confirmed(self):
        self.assertEqual(
            status_for(self._states(VERSION_MATCH=CONFIRMED, REPRODUCED=CONFIRMED)),
            CONFIRMED_APPLICABLE)

    def test_a_refuted_higher_rung_rules_it_out(self):
        for name in (CONDITIONS_MATCH, REACHABLE, EXTERNALLY_REACHABLE):
            self.assertEqual(
                status_for(self._states(**{VERSION_MATCH: CONFIRMED, name: REFUTED})),
                NOT_APPLICABLE, name)

    def test_reproduction_outranks_a_refuted_rung(self):
        self.assertEqual(
            status_for(self._states(VERSION_MATCH=CONFIRMED, REACHABLE=REFUTED,
                                    REPRODUCED=CONFIRMED)),
            CONFIRMED_APPLICABLE)

    def test_unevaluated_never_counts_as_ruled_out(self):
        # The whole point of the ladder: an unimplemented check must not read as a pass.
        self.assertNotEqual(status_for(self._states(VERSION_MATCH=CONFIRMED)), NOT_APPLICABLE)

    def test_pending_rungs_are_marked_not_evaluated(self):
        self.assertEqual(pending(REACHABLE)["result"], NOT_EVALUATED)


class VersionMatchEvidence(unittest.TestCase):
    def test_explicit_version_list(self):
        result = assess_version_match(component("1.0.0"), advisory(versions=["1.0.0"]))
        self.assertEqual(result["result"], CONFIRMED)
        self.assertEqual(result["evidence"]["matched_by"], "versions")

    def test_range_hit_and_miss(self):
        ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
        self.assertEqual(assess_version_match(component("1.0.0"), advisory(ranges=ranges))["result"],
                         CONFIRMED)
        # A clean miss is a disagreement with the source, so it stays undecided.
        self.assertEqual(assess_version_match(component("3.0.0"), advisory(ranges=ranges))["result"],
                         NOT_EVALUATED)

    def test_withdrawn_advisory_is_refuted(self):
        result = assess_version_match(component(), advisory(withdrawn="2026-01-01T00:00:00Z"))
        self.assertEqual(result["result"], REFUTED)

    def test_unparseable_range_is_not_evaluated(self):
        ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "junk"}]}]
        self.assertEqual(assess_version_match(component("1.0.0"), advisory(ranges=ranges))["result"],
                         NOT_EVALUATED)

    def test_git_ranges_cannot_be_evaluated(self):
        ranges = [{"type": "GIT", "events": [{"introduced": "abc123"}]}]
        self.assertEqual(assess_version_match(component("1.0.0"), advisory(ranges=ranges))["result"],
                         NOT_EVALUATED)

    def test_pypi_names_match_after_normalization(self):
        ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]
        subject = component("1.0", ecosystem="PyPI", name="flask-login")
        entry = advisory(ranges=ranges, ecosystem="PyPI", name="Flask_Login")
        self.assertEqual(assess_version_match(subject, entry)["result"], CONFIRMED)

    def test_other_package_in_the_same_advisory_is_ignored(self):
        ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
        entry = advisory(ranges=ranges, name="different")
        self.assertEqual(assess_version_match(component(), entry)["result"], NOT_EVALUATED)

    def test_component_without_a_version_is_not_evaluated(self):
        self.assertEqual(assess_version_match(component(None), advisory())["result"], NOT_EVALUATED)


class Assessment(unittest.TestCase):
    def _inventory(self, components):
        return {"schema_version": 1, "root": "r", "manifests": [], "components": components,
                "counts": {"total": len(components), "with_version": 1, "undetermined_version": 0}}

    def test_pairs_components_with_their_advisories(self):
        item = component("1.0.0")
        data = {"advisories": {"GHSA-test": advisory(versions=["1.0.0"])},
                "by_component": {"npm|pkg|1.0.0": ["GHSA-test"]}}
        result = assess(self._inventory([item]), data)
        self.assertEqual(result["counts"]["total"], 1)
        self.assertEqual(result["findings"][0]["status"], POTENTIAL)
        self.assertEqual(result["findings"][0]["cve"], ["CVE-2026-1"])

    def test_unresolved_components_are_reported_as_gaps(self):
        result = assess(self._inventory([component(None)]), {"advisories": {}, "by_component": {}})
        self.assertEqual(result["counts"]["unresolved_components"], 1)
        self.assertEqual(result["counts"]["total"], 0)

    def test_no_advisory_data_produces_no_findings(self):
        result = assess(self._inventory([component("1.0.0")]), {"advisories": {}, "by_component": {}})
        self.assertEqual(result["findings"], [])

    def test_every_rung_is_present_on_each_finding(self):
        item = component("1.0.0")
        data = {"advisories": {"GHSA-test": advisory(versions=["1.0.0"])},
                "by_component": {"npm|pkg|1.0.0": ["GHSA-test"]}}
        states = assess(self._inventory([item]), data)["findings"][0]["states"]
        self.assertEqual([entry["state"] for entry in states], list(LADDER))


if __name__ == "__main__":
    unittest.main()
