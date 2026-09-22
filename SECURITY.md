# Security & authorized use

DeepAudit performs active security testing. Running it against a system you are not authorized
to assess may be illegal and is not a supported use of this project.

## Authorized use only

- Dispatch an audit **only** against targets you own or have explicit written permission to
  test. The `authorized` checkbox on the workflow is your attestation of that permission.
- Exactly one target is in scope per run: the dispatched host and its subdomains. The agents
  are instructed never to touch any other host, and the target is validated to resolve only to
  public addresses.
- Prefer a **private repository**. Run summaries and artifacts can contain sensitive details
  about a real target; treat them as confidential. Nothing is committed to the repo by design.

## What the system will and will not do

Permitted against the in-scope target: reconnaissance, fingerprinting, vulnerability scanning,
CVE correlation, and non-destructive proof-of-concept to demonstrate real impact.

Not permitted (instructed against, and to be treated as out of scope): denial-of-service or
volumetric traffic, destroying/altering target data, planting persistence, pivoting or lateral
movement to other systems, and exfiltrating runner secrets. The runner is ephemeral and its
secrets are stripped from tool execution environments.

General code execution is *not* technically confined to the target — scope is enforced by the
agents' instructions and the single-target framing. Review runs and keep the PAT least-privileged.

## Reporting a vulnerability in DeepAudit

Open a private security advisory on the repository, or contact the maintainer directly rather
than filing a public issue.
