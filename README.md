# DeepAudit

## Current architecture

DeepAudit is one Python-supervised audit flow running in GitHub Actions. Roles are employee
playbooks, not nested workflows: each employee gets a short isolated planning session, and
the supervisor carries only its concise plan and completed-tool evidence forward. This keeps
the audit trace visible while avoiding a growing shared model context.

```text
audit.yaml (target) -> Python supervisor -> employee session / plan
                                      -> tool_<name>.yml -> evidence artifact
                                      -> record grounded result -> report.html artifact
```

Every approved workflow tool is generic and available to every employee. The employee prompt
decides which is appropriate; Python only permits a workflow that exists as
`.github/workflows/tool_<name>.yaml`, always pins it to the original target, waits through
`gh`, downloads `evidence-<task_id>`, and prints `AUDIT`, `AGENT`, `TOOL`, `RESULT`, and
`REPORT` events to the Actions console. The final job summary links to the downloadable
artifact bundle containing `report.html`.

Run **Audit** (`.github/workflows/audit.yaml`) with `target` and `authorized=true`. It needs
`DEEPSEEK_API_KEY`, optional `DEEPSEEK_MODEL`, and a `GH_ADMIN_TOKEN` PAT with workflow
dispatch permission.

### Add a tool

Create `.github/workflows/tool_<name>.yaml` with the standard inputs `task_id`, `target`,
`params`, and `run_name`. It may install/run any reviewed application (for example nmap) and
must upload its raw result as artifact `evidence-${{ inputs.task_id }}`. The supervisor
discovers it automatically. Put tool selection guidance in employee `roles/<name>/role.md`;
no Python routing change is required.

---

An authorized web-audit system built as an **agent hierarchy running on GitHub Actions**. You
dispatch one workflow with a target; a root agent decides which checks to run, launches each
as its own parallel workflow, reads their results, and assembles a report. The repository is
almost entirely **role prompts and workflows with real tools** — very little audit logic
lives in code.

This is deliberately not a monolithic scanner. Each capability is a role the root agent can
choose to run, and each role is a battle-tested tool (whatweb, and more to come) wrapped in a
workflow, interpreted by a small agent, and grounded by a deterministic check before anything
it reports reaches the audit.

## How it works

```text
you: dispatch Audit with a target
        |
        v
root agent (audit-root.yml)  -- knows the roster of roles, decides what to run
        |  gh workflow run role-<name>.yml  (authenticated with a PAT)
        |--------------> role-fingerprinter.yml  - runs whatweb - interprets - result artifact
        |--------------> role-<other>.yml         (dispatched in parallel)
        |  <-----------  each role returns a typed result the root downloads
        v
root assembles a report -> deterministic provenance check -> report.html, summary + zipped artifact
```

- **Roles are folders.** `roles/<name>/role.md` is both the documentation and the agent's
  system prompt. Its one-line summary is what the root agent sees in its roster; the whole
  file is the prompt the role runs under. A role named `<name>` is run by
  `.github/workflows/role-<name>.yml`.
- **Root is the tech lead.** It never runs a tool itself. It calls `list_roles`, dispatches
  the roles the evidence justifies (in parallel — each is a separate runner), reads their
  typed results, and calls `finish` with a report.
- **Parallelism is the workflow fan-out.** Each dispatched role is its own GitHub Actions
  job, so independent checks run at the same time on separate runners.

## The safety line that survives being agent-driven

The model orchestrates and interprets; it does not get the last word on what is true.

- **Root cannot conjure a finding.** Every finding it reports must carry the `task_id` of the
  sub-agent that produced it. `lib/provenance.py` re-checks each one against that task's
  stored result and drops any the model invented. This is deterministic, not a prompt.
- **No shell for the model.** A role's tools are its entire capability. Root's only actions
  are `list_roles`, `dispatch_role` (a known role, one target, a validated parameter blob),
  and `finish`. A sub-agent's only action is `emit_result` over evidence its workflow already
  collected. Neither can run arbitrary commands or reach an unapproved host.
- **Results are untrusted data.** Tool output and sub-agent results may contain a target's own
  markup; prompts say so, and every value is escaped before it reaches the report.

## Running it

Dispatch the **Audit** workflow (`workflow_dispatch`) with a `target` and the `authorized`
checkbox. The job runs the root agent and delivers the result two ways only: a table in the
run summary, and a zip of the run attached as a workflow artifact — nothing is committed to
the repository. Open `report.html` from the zip. (`audits/` is where a run is assembled
inside the runner and is gitignored.)

Required in the repository:

- Secret `DEEPSEEK_API_KEY` and variable `DEEPSEEK_MODEL` — every agent runs on DeepSeek
  through the small client in `lib/deepseek.py` (no SDK, standard library only).
- Secret `GH_ADMIN_TOKEN` (PAT, repo + workflow scope) — root dispatches roles with it,
  because a workflow dispatched with the default `GITHUB_TOKEN` never starts a run.

## Repository layout

```text
roles/
  root/role.md            tech-lead system prompt: roster + orchestration policy
  fingerprinter/role.md   interpret whatweb output into a typed stack + findings
.github/workflows/
  audit-root.yml          entrypoint: input target, runs the root agent
  role-fingerprinter.yml  workflow_dispatch: task_id + target + params, runs whatweb
templates/report.template.html   the editable report; lib/report.py fills it
lib/
  deepseek.py             standard-library DeepSeek client + bounded tool-use loop
  roles.py                discover roles from the filesystem
  orchestrator.py         root's dispatch tool (gh workflow run + wait + collect result)
  run_root.py             root entrypoint
  run_role.py             generic sub-agent entrypoint (interpret a tool's evidence)
  provenance.py           the deterministic gate: findings must trace to a task result
  report.py               fill the report template
```

## Adding a role

1. `roles/<name>/role.md` — the prompt. First non-heading line is the roster summary.
2. `.github/workflows/role-<name>.yml` — install and run the role's real tool against the
   dispatched target, write its output to a file, then
   `python -m lib.run_role <name> --task-id ... --target ... --evidence <file> --out result.json`
   and upload `result.json` as `result-<task_id>`.

Root discovers it automatically; no orchestration code changes.

## Status

A working first slice: root plus one real-tool role (`fingerprinter`/whatweb) end to end,
with the provenance gate and the report. The offline logic — the agent loop, dispatch
mechanics, the gate, interpretation, rendering — is covered by tests in `lib/tests/`. The
live cross-workflow run makes billable DeepSeek calls and needs the PAT, so the first real
dispatch is left to the operator.

License: MIT.
