from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from deepaudit.gitops import GitError, commit_run, preflight
from tests.test_artifacts import make_bundle


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], text=True, capture_output=True, check=True).stdout.strip()


def initialize(root):
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "DeepAudit Test")
    git(root, "config", "user.email", "test@example.invalid")
    (root / "README.md").write_text("Test repository\n", encoding="utf-8")
    git(root, "add", "README.md")
    git(root, "-c", "commit.gpgsign=false", "commit", "-m", "initial")


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class GitTests(unittest.TestCase):
    def test_commits_only_generated_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            initialize(root)
            (root / "unrelated.txt").write_text("Do not stage\n", encoding="utf-8")
            (root / "README.md").write_text("Uncommitted user edit\n", encoding="utf-8")
            folder, _ = make_bundle(root)
            sha = commit_run(root, folder)
            self.assertEqual(sha, git(root, "rev-parse", "HEAD"))
            paths = git(root, "show", "--format=", "--name-only", "HEAD").splitlines()
            self.assertTrue(paths)
            self.assertTrue(all(path.startswith("audits/" + folder.name + "/") for path in paths))
            status = git(root, "status", "--porcelain")
            self.assertIn("README.md", status)
            self.assertIn("unrelated.txt", status)

    def test_staged_user_changes_refuse_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            initialize(root)
            (root / "user.txt").write_text("Staged user data\n", encoding="utf-8")
            git(root, "add", "user.txt")
            with self.assertRaises(GitError):
                preflight(root)
            self.assertEqual(git(root, "diff", "--cached", "--name-only"), "user.txt")

    def test_secret_like_output_refuses_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            initialize(root)
            folder, _ = make_bundle(root)
            (folder / "AI_NOTES.txt").write_text("sk-" + "x" * 32, encoding="utf-8")
            with self.assertRaises(GitError):
                commit_run(root, folder)
            self.assertEqual(git(root, "diff", "--cached", "--name-only"), "")

    def test_commit_hooks_are_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            initialize(root)
            hook = root / ".git" / "hooks" / "pre-commit"
            hook.write_text("#!/bin/sh\necho should-not-run > hook-ran\nexit 1\n", encoding="utf-8")
            hook.chmod(0o755)
            folder, _ = make_bundle(root)
            commit_run(root, folder)
            self.assertFalse((root / "hook-ran").exists())
