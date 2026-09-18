import json
import tempfile
import unittest
from pathlib import Path

from deepaudit.inventory import (DECLARED_RANGE, LOCKED, NPM, PINNED, PYPI, collect,
                                 parse_package_json, parse_package_lock, parse_pyproject,
                                 parse_requirements)
from deepaudit.policy import PolicyError


class Requirements(unittest.TestCase):
    def test_pinned_versions_are_exact(self):
        parsed = parse_requirements("Flask==2.0.1\n", "requirements.txt")
        self.assertEqual(parsed[0]["name"], "flask")
        self.assertEqual(parsed[0]["version"], "2.0.1")
        self.assertEqual(parsed[0]["resolution"], PINNED)
        self.assertEqual(parsed[0]["purl"], "pkg:pypi/flask@2.0.1")

    def test_ranges_stay_undetermined(self):
        parsed = parse_requirements("requests>=2.0\n", "r.txt")
        self.assertIsNone(parsed[0]["version"])
        self.assertEqual(parsed[0]["resolution"], DECLARED_RANGE)

    def test_wildcard_pin_is_not_exact(self):
        self.assertIsNone(parse_requirements("x==1.*\n", "r.txt")[0]["version"])

    def test_extras_and_markers_are_stripped(self):
        parsed = parse_requirements("Django[bcrypt]==4.2.1 ; python_version>'3.8'\n", "r.txt")
        self.assertEqual(parsed[0]["name"], "django")
        self.assertEqual(parsed[0]["version"], "4.2.1")

    def test_comments_flags_and_vcs_are_ignored(self):
        text = "# note\n-r other.txt\n--index-url https://x\ngit+https://a/b.git\n./local\n\n"
        self.assertEqual(parse_requirements(text, "r.txt"), [])

    def test_inline_comment_is_removed(self):
        parsed = parse_requirements("flask==2.0.1  # pinned\n", "r.txt")
        self.assertEqual(parsed[0]["version"], "2.0.1")

    def test_line_continuation(self):
        parsed = parse_requirements("flask==\\\n2.0.1\n", "r.txt")
        self.assertEqual(parsed[0]["version"], "2.0.1")


class NodeManifests(unittest.TestCase):
    def test_lockfile_v3_flat_map(self):
        text = json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "root"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/@scope/pkg": {"version": "1.0.0"},
            "node_modules/a/node_modules/b": {"version": "2.3.4"},
            "node_modules/linked": {"link": True}}})
        parsed = {item["name"]: item for item in parse_package_lock(text, "package-lock.json")}
        self.assertEqual(parsed["lodash"]["version"], "4.17.20")
        self.assertEqual(parsed["@scope/pkg"]["version"], "1.0.0")
        self.assertIn("b", parsed, "nested node_modules entries are real installs")
        self.assertNotIn("linked", parsed, "workspace links are not installed packages")
        self.assertNotIn("root", parsed)
        self.assertEqual(parsed["lodash"]["resolution"], LOCKED)

    def test_lockfile_v1_nested_tree(self):
        text = json.dumps({"lockfileVersion": 1, "dependencies": {
            "lodash": {"version": "4.17.11", "dependencies": {"inner": {"version": "1.0.0"}}}}})
        parsed = {item["name"]: item["version"] for item in parse_package_lock(text, "p.json")}
        self.assertEqual(parsed, {"lodash": "4.17.11", "inner": "1.0.0"})

    def test_package_json_is_ranges_only(self):
        text = json.dumps({"dependencies": {"express": "^4.0.0"}})
        parsed = parse_package_json(text, "package.json")
        self.assertIsNone(parsed[0]["version"])
        self.assertTrue(parsed[0]["direct"])

    def test_malformed_json_yields_nothing(self):
        self.assertEqual(parse_package_lock("{not json", "p.json"), [])


class Pyproject(unittest.TestCase):
    def test_project_dependencies_are_ranges(self):
        parsed = parse_pyproject('[project]\nname="x"\ndependencies=["Flask>=2","httpx"]\n', "p.toml")
        self.assertEqual({item["name"] for item in parsed}, {"flask", "httpx"})
        self.assertTrue(all(item["version"] is None for item in parsed))

    def test_poetry_section_skips_python_itself(self):
        text = '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.0"\n'
        self.assertEqual([item["name"] for item in parse_pyproject(text, "p.toml")], ["requests"])

    def test_malformed_toml_yields_nothing(self):
        self.assertEqual(parse_pyproject("[[[bad", "p.toml"), [])


class RepositoryScan(unittest.TestCase):
    def test_collect_skips_installed_trees_and_dedupes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("Flask==2.0.1\nrequests>=2.0\n")
            (root / "pyproject.toml").write_text('[project]\nname="x"\ndependencies=["Flask>=2"]\n')
            (root / "node_modules").mkdir()
            (root / "node_modules" / "requirements.txt").write_text("evil==1.0\n")
            (root / ".git").mkdir()
            (root / ".git" / "requirements.txt").write_text("alsoevil==1.0\n")
            inventory = collect(root)
            names = {item["name"] for item in inventory["components"]}
            self.assertNotIn("evil", names)
            self.assertNotIn("alsoevil", names)
            flask = [item for item in inventory["components"] if item["name"] == "flask"]
            self.assertEqual(len(flask), 1, "the pinned entry supersedes the declared range")
            self.assertEqual(flask[0]["version"], "2.0.1")
            self.assertEqual(inventory["counts"]["undetermined_version"], 1)

    def test_nested_directories_are_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = root / "services" / "api"
            service.mkdir(parents=True)
            (service / "requirements.txt").write_text("flask==2.0.1\n")
            inventory = collect(root)
            self.assertEqual(inventory["components"][0]["source"], "services/api/requirements.txt")

    def test_missing_repository_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises((PolicyError, OSError)):
                collect(Path(tmp) / "absent")

    def test_empty_repository_is_empty_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            inventory = collect(Path(tmp))
            self.assertEqual(inventory["counts"]["total"], 0)
            self.assertEqual(inventory["manifests"], [])


if __name__ == "__main__":
    unittest.main()
