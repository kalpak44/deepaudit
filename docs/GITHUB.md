# GitHub setup

The ZIP is source code, not an already connected GitHub repository. No repository has been
created or pushed on your behalf. The Python pipeline does not need GitHub CLI to run.

## Initial source upload

Review the contents first. Avoid adding real `audits/` output or `.env` files to a public repo.
The bundled `examples/sample-run/` contains only a loopback demo.

```bash
git init -b main
git config user.name "Your Name"
git config user.email "you@example.com"
git add deepaudit tests docs examples .github README.md SECURITY.md LICENSE pyproject.toml Makefile .gitignore .env.example
git commit -m "Initial DeepAudit MVP"
gh auth login
gh repo create deepaudit-mvp --private --source=. --remote=origin --push
```

`gh repo create --source` uses the existing local repository; `--push` publishes its commits.
Choose your own repository name. Skip creation when a remote repository already exists.
Reference: https://cli.github.com/manual/gh_repo_create

## Automatic local commit after an audit

```bash
python -m deepaudit work \
  --target https://your-authorized-host.example/ \
  --authorized --share-with-llm --git-commit
```

Configure `DEEPSEEK_API_KEY` first. The model does not run Git. The application commits only
this run after deterministic rechecks and PoC replay pass. Existing staged changes cause a
preflight failure; other unstaged edits are preserved. No automatic push exists in this MVP.
Review the commit, then publish with your normal Git workflow.

## Included workflows

`Tests` runs standard-library tests and a saved evidence replay on Python 3.11, 3.12, 3.13
and 3.14. It does not use an API key, scan a public host, or run on `pull_request_target`.

`Authorized audit` runs only via `workflow_dispatch` and takes two inputs: one public target
and your confirmation of authorization. Everything else is fixed — it always runs the agent
and always shares target metadata with DeepSeek, so it requires the repository secret
`DEEPSEEK_API_KEY`. Re-consenting on every dispatch is what it exists to avoid; the CLI still
exposes `--mode baseline` and `--share-with-llm` for the cases that need them.

A completed run is committed into `audits/` and pushed, so the workflow holds
`contents: write` and keeps its checkout credentials. A degraded run is not committed, and
the job fails while still publishing what it produced. The run directory is also uploaded as
a zip and linked from the run summary; open `report.html` from it. Inputs reach Python
through environment variables, not shell interpolation. Artifacts are retained for seven
days. Scheduled audits are not enabled.

**Committing an audit publishes it.** In a public repository, the pushed run exposes the
target name, its resolved IPs, the audited path and every observation. Use a private
repository unless you intend that.

An external audit target may be unreachable from GitHub-hosted runners. For a private lab,
run the CLI locally; the workflow intentionally does not expose `--allow-private`.

The workflow files were authored against the official Actions documentation checked on
2026-09-18, using the documented v7 major tags. They have not been executed on your GitHub
account. For production, pin reviewed full commit SHAs and maintain them with Dependabot.

References:
- https://github.com/actions/checkout
- https://github.com/actions/setup-python
- https://github.com/actions/upload-artifact
- https://git-scm.com/docs/git
