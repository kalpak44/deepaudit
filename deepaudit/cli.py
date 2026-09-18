"""Command-line interface. `work` is an alias for a complete, one-shot `run`."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from . import __version__
from .agent import run_agent
from .artifacts import check_integrity, make_run_dir, run_verifiers, write_artifacts
from .demo import create_server, local_demo
from .deps import run_deps
from .gitops import GitError, commit_run, preflight
from .advisories import AdvisoryError
from .applicability import LADDER, STATUS_MEANING
from .llm import APIError, DEFAULT_MODEL, DeepSeekClient
from .policy import PolicyError, Scope, Target
from .rules import RULES
from .tools import AuditTools
from .transport import Budget, ProbeClient, utc_now


def progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def run_pipeline(args: argparse.Namespace) -> tuple[Path, dict, int]:
    started = utc_now()
    target = Target.parse(args.target)
    repo = args.repo.resolve(strict=True)
    budget = Budget(maximum=args.max_connections, timeout=args.timeout, delay=args.min_interval)
    if not 1 <= args.max_steps <= 20:
        raise PolicyError("--max-steps must be between 1 and 20")
    if not args.authorized:
        raise PolicyError("--authorized is required; only audit endpoints you are permitted to test")
    client = None
    if args.mode == "agent":
        if not args.share_with_llm:
            raise PolicyError("Agent mode sends target metadata and normalized observations to DeepSeek; add --share-with-llm")
        client = DeepSeekClient(os.environ.get("DEEPSEEK_API_KEY", ""), args.model,
                                max_requests=args.max_api_requests, max_tokens=args.max_tokens)
    if args.git_commit:
        preflight(repo)
    scope = Scope.resolve(target, authorized=True, allow_private=args.allow_private)
    run_dir = make_run_dir(repo, args.out, target)
    probes = ProbeClient(scope, budget)
    tools = AuditTools(probes, progress=progress)
    tools.event("run_started", mode=args.mode, authorization_asserted=True,
                data_sharing_approved=bool(args.share_with_llm and args.mode == "agent"))
    if client is None:
        tools.complete(origin="baseline")
        agent = {"status": "baseline", "model": None, "summary": "", "error": None,
                 "api_requests": 0, "usage": {}, "tool_calls": 0, "fallback_used": False}
    else:
        agent = run_agent(tools, client, max_steps=args.max_steps)
        key = os.environ.get("DEEPSEEK_API_KEY", "")
        if key:
            agent["summary"] = agent["summary"].replace(key, "[REDACTED]")
    manifest = write_artifacts(run_dir, tools, agent, started)
    complete = (manifest["coverage"]["complete"] and manifest["offline_verification"]["all_reproduced"]
                and agent["status"] in ("baseline", "complete"))
    code = 0 if complete else 3
    if args.git_commit:
        if complete:
            sha = commit_run(repo, run_dir)
            progress("[git] committed only this run: " + sha)
        else:
            progress("[git] not committed: incomplete coverage, agent fallback, or unreproduced observations")
    print("Report: " + str(run_dir / "report.md"))
    print("Observations: " + str(manifest["findings_count"]))
    print("Offline PoC replay: " + str(manifest["offline_verification"]["reproduced"]) +
          "/" + str(manifest["offline_verification"]["total"]))
    print("Coverage complete: " + str(manifest["coverage"]["complete"]))
    print("Agent status: " + agent["status"])
    return run_dir, manifest, code


def _options(parser: argparse.ArgumentParser, *, demo: bool = False) -> None:
    if not demo:
        parser.add_argument("--target", required=True, help="One domain/IP or HTTP(S) URL; no query/credentials")
        parser.add_argument("--authorized", action="store_true", help="Assert permission for read-only checks on this endpoint")
        parser.add_argument("--allow-private", action="store_true", help="Permit private/loopback lab addresses, never link-local/metadata")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Selected repository root (default: current directory)")
    parser.add_argument("--out", default="audits", help="Relative artifact directory inside --repo (default: audits)")
    parser.add_argument("--mode", choices=("agent", "baseline"), default="baseline" if demo else "agent",
                        help="agent uses DeepSeek; baseline uses the same checks without an LLM")
    parser.add_argument("--share-with-llm", action="store_true", help="Consent to send target metadata and normalized findings to DeepSeek")
    parser.add_argument("--model", default=os.environ.get("DEEPSEEK_MODEL", DEFAULT_MODEL))
    parser.add_argument("--max-steps", type=int, default=8)
    parser.add_argument("--max-api-requests", type=int, default=8, help="Includes retries, not just successful calls")
    parser.add_argument("--max-tokens", type=int, default=1500, help="Maximum output tokens per API request")
    parser.add_argument("--max-connections", type=int, default=6, help="Target connection budget; normally 2 HTTP or 4 HTTPS connections")
    parser.add_argument("--timeout", type=float, default=8, help="Target per-operation timeout, not a total wall-clock deadline")
    parser.add_argument("--min-interval", type=float, default=0.25, help="Minimum delay between target connection starts")
    parser.add_argument("--git-commit", action="store_true", help="Commit only a fully verified run; no push, no add-all")


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DeepAudit: scoped autonomous configuration checks with DeepSeek")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", aliases=["work"], help="Complete one bounded autonomous audit")
    _options(run)
    demo = commands.add_parser("demo", help="Start a loopback fixture, audit it, then stop it")
    _options(demo, demo=True)
    demo.add_argument("--hardened", action="store_true", help="Serve most hardening headers; plaintext HTTP observation remains")
    verify = commands.add_parser("verify", help="Check artifact hashes and independently replay static PoCs without network")
    verify.add_argument("run_dir", type=Path)
    verify.add_argument("--json", action="store_true")
    serve = commands.add_parser("serve-demo", help="Serve a persistent loopback-only fixture until Ctrl+C")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--hardened", action="store_true")
    deps = commands.add_parser("deps", help="Inventory dependencies and assess known advisories against them")
    deps.add_argument("--repo", type=Path, default=Path.cwd(), help="Repository root to inventory (default: current directory)")
    deps.add_argument("--out", default="audits", help="Relative artifact directory inside --repo (default: audits)")
    deps.add_argument("--allow-advisory-fetch", action="store_true",
                      help="Consent to send dependency names and versions to api.osv.dev; without it no advisory source is consulted")
    deps.add_argument("--max-advisory-requests", type=int, default=128, help="Advisory API request budget")
    deps.add_argument("--timeout", type=float, default=20, help="Advisory API per-operation timeout")
    commands.add_parser("checks", help="List the eight implemented observation rules")
    commands.add_parser("states", help="List the evidence ladder and what each status means")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    try:
        if args.command in ("run", "work"):
            return run_pipeline(args)[2]
        if args.command == "demo":
            with local_demo(hardened=args.hardened) as target:
                args.target, args.authorized, args.allow_private = target, True, True
                progress("[demo] local fixture: " + target)
                return run_pipeline(args)[2]
        if args.command == "verify":
            directory = args.run_dir.resolve(strict=True)
            integrity = check_integrity(directory)
            if not integrity["ok"]:
                print(json.dumps({"integrity": integrity, "error": "Artifact checksums do not match"}, indent=2))
                return 2
            result = {"integrity": integrity, "replay": run_verifiers(directory)}
            print(json.dumps(result, indent=2 if args.json else None))
            return 0 if result["replay"]["all_reproduced"] else 1
        if args.command == "deps":
            return run_deps(args)[2]
        if args.command == "states":
            print("Evidence ladder (each rung is confirmed, refuted, or not evaluated):")
            for name in LADDER:
                print(f"  {name}")
            print("\nStatuses:")
            for name, meaning in STATUS_MEANING.items():
                print(f"  {name:22} {meaning}")
            return 0
        if args.command == "checks":
            for rule_id, spec in RULES.items():
                print(f"{rule_id:30} {spec['severity']:6} {spec['title']}")
            return 0
        if args.command == "serve-demo":
            if not 1 <= args.port <= 65535:
                raise PolicyError("Invalid demo port")
            server = create_server(args.port, hardened=args.hardened)
            print(f"Loopback fixture: http://127.0.0.1:{args.port}/", flush=True)
            try:
                server.serve_forever()
            finally:
                server.server_close()
            return 0
    except GitError as exc:
        print("Git error: " + str(exc), file=sys.stderr)
        return 4
    except (PolicyError, APIError, AdvisoryError, ValueError, OSError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted. No automatic push was attempted.", file=sys.stderr)
        return 130
    return 2
