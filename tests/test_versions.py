import unittest

from deepaudit.versions import (PEP440, SEMVER, compare, in_range, normalize_pypi,
                                parse_pep440, parse_semver)


class Pep440Ordering(unittest.TestCase):
    def test_release_equivalence_and_padding(self):
        self.assertEqual(compare(PEP440, "1.0", "1.0.0"), 0)
        self.assertEqual(compare(PEP440, "1.0.0.0", "1.0"), 0)

    def test_numeric_not_lexicographic(self):
        self.assertEqual(compare(PEP440, "2.0.0", "10.0.0"), -1)

    def test_prerelease_sorts_below_release(self):
        for value in ("1.0a1", "1.0b1", "1.0rc1", "1.0.dev1"):
            self.assertEqual(compare(PEP440, value, "1.0"), -1, value)

    def test_post_sorts_above_release(self):
        self.assertEqual(compare(PEP440, "1.0", "1.0.post1"), -1)

    def test_dev_sorts_below_prerelease(self):
        self.assertEqual(compare(PEP440, "1.0.dev1", "1.0a1"), -1)

    def test_spelling_aliases_are_equal(self):
        self.assertEqual(compare(PEP440, "1.0beta2", "1.0b2"), 0)
        self.assertEqual(compare(PEP440, "1.0-1", "1.0.post1"), 0)

    def test_epoch_dominates(self):
        self.assertEqual(compare(PEP440, "1!0.1", "99.9"), 1)

    def test_local_version_outranks_bare(self):
        self.assertEqual(compare(PEP440, "1.0+local", "1.0"), 1)

    def test_unparseable_is_none_never_false(self):
        self.assertIsNone(parse_pep440("not a version"))
        self.assertIsNone(compare(PEP440, "not a version", "1.0"))


class SemverOrdering(unittest.TestCase):
    def test_prerelease_below_release(self):
        self.assertEqual(compare(SEMVER, "1.0.0-alpha", "1.0.0"), -1)

    def test_prerelease_identifier_precedence(self):
        self.assertEqual(compare(SEMVER, "1.0.0-alpha.1", "1.0.0-alpha.beta"), -1)
        self.assertEqual(compare(SEMVER, "1.0.0-beta", "1.0.0-beta.2"), -1)

    def test_numeric_identifier_below_alphanumeric(self):
        self.assertEqual(compare(SEMVER, "1.0.0-1", "1.0.0-alpha"), -1)

    def test_build_metadata_ignored(self):
        self.assertEqual(compare(SEMVER, "1.0.0+build", "1.0.0"), 0)

    def test_partial_version_is_not_semver(self):
        self.assertIsNone(parse_semver("1.0"))


class RangeEvaluation(unittest.TestCase):
    def test_introduced_zero_then_fixed(self):
        events = [{"introduced": "0"}, {"fixed": "1.2.3"}]
        self.assertIs(in_range(SEMVER, "1.0.0", events), True)
        self.assertIs(in_range(SEMVER, "1.2.3", events), False)
        self.assertIs(in_range(SEMVER, "1.2.4", events), False)

    def test_multiple_disjoint_intervals(self):
        events = [{"introduced": "1.0.0"}, {"fixed": "1.5.0"},
                  {"introduced": "2.0.0"}, {"fixed": "2.1.0"}]
        self.assertIs(in_range(SEMVER, "0.9.0", events), False)
        self.assertIs(in_range(SEMVER, "1.4.0", events), True)
        self.assertIs(in_range(SEMVER, "1.9.0", events), False)
        self.assertIs(in_range(SEMVER, "2.0.5", events), True)
        self.assertIs(in_range(SEMVER, "3.0.0", events), False)

    def test_last_affected_is_inclusive(self):
        events = [{"introduced": "0"}, {"last_affected": "1.2.3"}]
        self.assertIs(in_range(SEMVER, "1.2.3", events), True)
        self.assertIs(in_range(SEMVER, "1.2.4", events), False)

    def test_unreadable_bound_reports_none_not_false(self):
        self.assertIsNone(in_range(SEMVER, "1.0.0", [{"introduced": "0"}, {"fixed": "junk"}]))

    def test_unreadable_version_reports_none_not_false(self):
        self.assertIsNone(in_range(SEMVER, "not-a-version", [{"introduced": "0"}]))

    def test_pep440_range(self):
        events = [{"introduced": "3.2"}, {"fixed": "3.2.13"}]
        self.assertIs(in_range(PEP440, "3.2.4", events), True)
        self.assertIs(in_range(PEP440, "3.2.13", events), False)


class NameNormalization(unittest.TestCase):
    def test_pep503_equivalence(self):
        self.assertEqual(normalize_pypi("Flask_Login"), "flask-login")
        self.assertEqual(normalize_pypi("zope.interface"), "zope-interface")
        self.assertEqual(normalize_pypi("A--B"), "a-b")


if __name__ == "__main__":
    unittest.main()
