#!/usr/bin/env python3
"""Generated read-only PoC. Default: replay normalized evidence with no network.

This is fixed application code, not code written by a language model.
The condition being reproduced is a configuration observation, not exploitability.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import ipaddress
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

RULE_IDS = {
    "HTTP_PLAINTEXT_RESPONSE", "HTML_CSP_ABSENT", "HTML_FRAME_GUARD_ABSENT",
    "NOSNIFF_ABSENT", "HTTPS_HSTS_ABSENT", "COOKIE_FLAGS_REVIEW",
    "TLS_CERTIFICATE_REJECTED", "TLS_CERTIFICATE_EXPIRING",
}


def read_json(path: Path) -> dict:
    if path.is_symlink() or path.stat().st_size > 262144:
        raise ValueError("Unsafe or oversized evidence file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected an evidence object")
    return value


def observe(rule: str, snapshot: dict) -> bool | None:
    """An independent predicate implementation, intentionally separate from rules.py."""
    if rule not in RULE_IDS:
        raise ValueError("Unknown rule")
    target = urlsplit(snapshot["scope"]["target"])
    is_tls = rule.startswith("TLS_")
    probe = snapshot.get("tls" if is_tls else "http", {})
    if is_tls:
        if rule == "TLS_CERTIFICATE_REJECTED":
            if probe.get("error") == "certificate_verification_failed":
                return True
            return False if probe.get("status") == "ok" else None
        if probe.get("status") != "ok":
            return None
        days = (datetime.fromisoformat(probe["not_after"]) -
                datetime.fromisoformat(probe["observed_at"])).total_seconds() / 86400
        return 0 <= days <= 30
    if probe.get("status") != "ok":
        return None
    if not 200 <= probe.get("status_code", 0) <= 299:
        return False
    signals = probe["signals"]
    if rule == "HTTP_PLAINTEXT_RESPONSE":
        return target.scheme == "http"
    if rule == "HTML_CSP_ABSENT":
        return bool(signals["html"] and not signals["csp_present"])
    if rule == "HTML_FRAME_GUARD_ABSENT":
        return bool(signals["html"] and not signals["frame_ancestors_present"] and not signals["xfo_restrictive"])
    if rule == "NOSNIFF_ABSENT":
        return not signals["nosniff"]
    if rule == "HTTPS_HSTS_ABSENT":
        try:
            ipaddress.ip_address(target.hostname or "")
            is_ip = True
        except ValueError:
            is_ip = False
        return target.scheme == "https" and not is_ip and not signals["hsts_present"]
    if rule == "COOKIE_FLAGS_REVIEW":
        return any(not c["httponly"] or c["samesite"] == "absent_or_invalid"
                   or (target.scheme == "https" and not c["secure"])
                   for c in signals["cookies"])
    raise ValueError("Unsupported rule")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Re-check the original URL with fresh read-only requests")
    parser.add_argument("--authorized", action="store_true", help="Confirm authorization for the live target")
    parser.add_argument("--allow-private", action="store_true", help="Explicitly authorize private/loopback lab addressing")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable output")
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    run_dir = base.parent.parent
    try:
        case = read_json(base / "case.json")
        rule = case["rule_id"]
        initial = read_json(run_dir / "evidence" / "initial.json")
        second = read_json(run_dir / "evidence" / "recheck.json")
        if args.live:
            if not args.authorized:
                raise ValueError("--live requires --authorized")
            try:
                from deepaudit.policy import Scope, Target
                from deepaudit.transport import Budget, ProbeClient
            except ImportError as exc:
                raise ValueError("Live mode requires the DeepAudit package: python -m pip install -e .") from exc
            scope = Scope.resolve(Target.parse(initial["scope"]["target"]),
                                  authorized=True, allow_private=args.allow_private)
            probes = ProbeClient(scope, Budget(maximum=2))
            probe = "tls" if rule.startswith("TLS_") else "http"
            second = {"scope": scope.public(), probe: getattr(probes, probe)()}
        first_result = observe(rule, initial)
        second_result = observe(rule, second)
        if first_result is None or second_result is None:
            status, code = "inconclusive", 2
        elif first_result and second_result:
            status, code = "reproduced", 0
        else:
            status, code = "not_reproduced", 1
        result = {"rule_id": rule, "mode": "live" if args.live else "offline",
                  "status": status, "initial_match": first_result, "recheck_match": second_result,
                  "claim": "configuration observation, not an exploit"}
    except (ValueError, OSError, KeyError, TypeError) as exc:
        result, code = {"status": "error", "error_type": type(exc).__name__}, 2
        if not args.json:
            print("Error: " + str(exc), file=sys.stderr)
    print(json.dumps(result, indent=None if args.json else 2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
