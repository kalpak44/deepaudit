# Security boundary and responsible use

Use DeepAudit only on targets you own or are explicitly authorized to test. The `authorized`
input records your assertion; it does not verify ownership or grant permission. A role runs
real scanning tools against the target, so a dispatch is an active, logged interaction with
that host — treat it as you would running the tool by hand.

This is an audit orchestrator, not a penetration-testing framework and not a production
sandbox. Roles run reviewed tools and interpret their output; no claim of comprehensive
vulnerability coverage is made, and absence of a finding is never proof a target is sound.

## The trust model

The system is agent-driven, and it stays honest by keeping the model away from two things:
the last word on what is true, and a general shell.

- **Findings are grounded, deterministically.** The root agent assembles a report, but every
  finding must carry the `task_id` of the sub-agent that produced it, and `lib/provenance.py`
  re-checks each against that task's stored result. A finding with no task behind it, or one
  citing a task that did not return it, is dropped before the report is written. This is code,
  not a prompt the model could talk its way around.
- **Tools are the only capability.** Root can call `list_roles`, `dispatch_role` (a role from
  the known roster, one target, a size- and charset-validated parameter blob) and `finish`. A
  sub-agent can call `emit_result` over evidence its workflow already collected. There is no
  tool that runs an arbitrary command, names an arbitrary workflow, or reaches an unapproved
  host.
- **Scope is fixed per run.** Only the one authorized target is ever passed to a role. Root is
  instructed never to dispatch against another host and cannot infer authorization for one.
- **Untrusted data stays data.** Tool output and sub-agent results may contain a target's own
  markup or third-party text. Prompts say so explicitly, and `lib/report.py` escapes every
  value before it reaches the HTML report.

## Credentials and egress

Every agent talks to `api.deepseek.com` over HTTPS via the standard-library client in
`lib/deepseek.py`; the key comes from the `DEEPSEEK_API_KEY` secret and is sent only in the
Authorization header, never placed into messages, results, or committed artifacts. Root
dispatches roles with the `GH_ADMIN_TOKEN` PAT, required because a workflow dispatched with
the default `GITHUB_TOKEN` never starts a run. A role's tool reaches the network to scan the
authorized target; that egress is the tool's, and is the point of the audit.

## Reporting a vulnerability

Open a private advisory on the repository, or contact the maintainer. Please do not file
public issues for security reports.
