"""The arsenal: a curated catalogue of security tools the agent knows about and can install.

An agent that knows the battle-tested toolkit and how to install each tool is far stronger
than one improvising checks from scratch. Each entry carries a category, a one-line "when to
use", and a deterministic install recipe so the `run` capability can set a tool up by name
(`setup: ["nuclei", "httpx"]`) instead of the model guessing package names.

Install recipes assume the standard GitHub `ubuntu-latest` runner: apt, pip, a Go toolchain
(`go install`), npm, and internet access are all present. Recipes are idempotent enough to
re-run cheaply. The agent may still install anything else ad hoc through apt/pip/go — this
catalogue is the fast path for the tools that matter most, not a whitelist.
"""
from __future__ import annotations

GOBIN = "$(go env GOPATH)/bin"

# name -> {category, use, install (list of shell commands), bin (path/name to invoke)}
TOOLS = {
    # ---- fingerprint / discovery -------------------------------------------------
    "httpx": {"category": "probe", "bin": f"{GOBIN}/httpx",
              "use": "Fast HTTP prober: status, title, tech, TLS, CDN across many hosts/ports.",
              "install": ["go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"]},
    "whatweb": {"category": "fingerprint", "bin": "whatweb",
                "use": "Identify web technologies, servers, frameworks and observed versions.",
                "install": ["sudo apt-get install -y -qq whatweb"]},
    "wappalyzer": {"category": "fingerprint", "bin": "wappalyzer",
                   "use": "Tech-stack fingerprinting from response signatures.",
                   "install": ["sudo npm install -g wappalyzer >/dev/null 2>&1 || pip install python-Wappalyzer"]},
    "subfinder": {"category": "recon", "bin": f"{GOBIN}/subfinder",
                  "use": "Passive subdomain enumeration → attack-surface expansion.",
                  "install": ["go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"]},
    "dnsx": {"category": "recon", "bin": f"{GOBIN}/dnsx",
             "use": "Resolve/probe DNS records for enumerated hosts.",
             "install": ["go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"]},
    "katana": {"category": "crawl", "bin": f"{GOBIN}/katana",
               "use": "Modern crawler; extracts endpoints from HTML and JavaScript bundles.",
               "install": ["go install -v github.com/projectdiscovery/katana/cmd/katana@latest"]},
    "gau": {"category": "recon", "bin": f"{GOBIN}/gau",
            "use": "Historical URLs from Wayback/OTX/CommonCrawl for extra endpoints.",
            "install": ["go install -v github.com/lc/gau/v2/cmd/gau@latest"]},
    "ffuf": {"category": "content", "bin": f"{GOBIN}/ffuf",
             "use": "Content/parameter/vhost fuzzing (hidden paths, .git, backups).",
             "install": ["go install -v github.com/ffuf/ffuf/v2@latest"]},
    "feroxbuster": {"category": "content", "bin": "feroxbuster",
                    "use": "Recursive content discovery.",
                    "install": ["sudo apt-get install -y -qq feroxbuster || "
                                "(curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s $HOME/.local/bin)"]},
    # ---- vuln scanning -----------------------------------------------------------
    "nuclei": {"category": "vuln", "bin": f"{GOBIN}/nuclei",
               "use": "Template-driven scanner for CVEs, misconfigs, exposures, default creds. "
                      "The workhorse; run after fingerprinting to target the stack. Update templates first.",
               "install": ["go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                           f"{GOBIN}/nuclei -update-templates -silent 2>/dev/null || true"]},
    "nikto": {"category": "vuln", "bin": "nikto",
              "use": "Classic web-server misconfiguration and dangerous-file scanner.",
              "install": ["sudo apt-get install -y -qq nikto"]},
    "wpscan": {"category": "vuln", "bin": "wpscan",
               "use": "WordPress core/plugin/theme vulnerability scanner (if WP is detected).",
               "install": ["sudo gem install wpscan >/dev/null 2>&1 || sudo apt-get install -y -qq wpscan"]},
    "retire": {"category": "vuln", "bin": "retire",
               "use": "Detect known-vulnerable JavaScript libraries in loaded scripts.",
               "install": ["sudo npm install -g retire >/dev/null 2>&1"]},
    "dalfox": {"category": "vuln", "bin": f"{GOBIN}/dalfox",
               "use": "Parameter-analysis XSS scanner with safe verification.",
               "install": ["go install -v github.com/hahwul/dalfox/v2@latest"]},
    "sqlmap": {"category": "exploit", "bin": "sqlmap",
               "use": "SQL-injection detection and (authorized) exploitation. Use conservative "
                      "flags first (--batch --level 1 --risk 1); it is intrusive.",
               "install": ["sudo apt-get install -y -qq sqlmap"]},
    # ---- ports / network ---------------------------------------------------------
    "nmap": {"category": "network", "bin": "nmap",
             "use": "Port scan and service/version detection on the resolved address.",
             "install": ["sudo apt-get install -y -qq nmap"]},
    "naabu": {"category": "network", "bin": f"{GOBIN}/naabu",
              "use": "Fast SYN/CONNECT port discovery to feed httpx/nmap.",
              "install": ["go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"]},
    # ---- tls ---------------------------------------------------------------------
    "testssl": {"category": "tls", "bin": "/opt/testssl/testssl.sh",
                "use": "Deep TLS/SSL audit: protocols, ciphers, cert, known TLS CVEs.",
                "install": ["sudo rm -rf /opt/testssl && sudo git clone --depth 1 -q "
                            "https://github.com/drwetter/testssl.sh /opt/testssl"]},
    "sslscan": {"category": "tls", "bin": "sslscan",
                "use": "Quick cipher/protocol enumeration.",
                "install": ["sudo apt-get install -y -qq sslscan"]},
    # ---- secrets -----------------------------------------------------------------
    "trufflehog": {"category": "secrets", "bin": "trufflehog",
                   "use": "Find verified leaked secrets in fetched JS/source or a repo.",
                   "install": ["curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh "
                               "| sudo sh -s -- -b /usr/local/bin >/dev/null 2>&1"]},
    "gitleaks": {"category": "secrets", "bin": "gitleaks",
                 "use": "Detect secrets/credentials in exposed source or .git.",
                 "install": ["go install -v github.com/gitleaks/gitleaks/v8@latest && "
                             f"sudo ln -sf {GOBIN}/gitleaks /usr/local/bin/gitleaks"]},
    # ---- waf ---------------------------------------------------------------------
    "wafw00f": {"category": "recon", "bin": "wafw00f",
                "use": "Identify a WAF/CDN in front of the target to calibrate later probes.",
                "install": ["pip install -q wafw00f"]},
}


# The base minimum pre-installed by the workflow before any agent starts, so the toolkit is
# ready on PATH. Chosen for high reuse and slow installs (Go builds, template downloads) where
# pre-installing pays off most. Agents still install anything else on demand.
BASE = ["nmap", "whatweb", "wafw00f", "testssl", "httpx", "subfinder", "katana", "ffuf", "nuclei"]


def base_install_script() -> str:
    """A single bash script that installs the base toolkit. Idempotent enough to re-run."""
    commands = install_commands(BASE)
    header = "set +e\n"
    if any("apt-get install" in c for c in commands):
        header = "set +e\nsudo apt-get update -qq\n"
    return header + "\n".join(commands) + "\n"


def catalog_text() -> str:
    """A compact, model-facing listing grouped by category for the agent's system prompt."""
    order = ["recon", "fingerprint", "probe", "crawl", "content", "vuln",
             "exploit", "network", "tls", "secrets"]
    by_cat: dict[str, list[str]] = {}
    for name, spec in TOOLS.items():
        by_cat.setdefault(spec["category"], []).append(f"{name} — {spec['use']}")
    lines = []
    for cat in order:
        if by_cat.get(cat):
            lines.append(f"[{cat}]")
            lines.extend("  " + row for row in sorted(by_cat[cat]))
    return "\n".join(lines)


def install_commands(names) -> list[str]:
    """Deterministic install commands for named arsenal tools (unknown names ignored)."""
    commands: list[str] = []
    seen: set[str] = set()
    for name in names or []:
        spec = TOOLS.get(name)
        if spec and name not in seen:
            seen.add(name)
            commands.extend(spec["install"])
    return commands


def known(names) -> list[str]:
    return [n for n in (names or []) if n in TOOLS]


def _main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="DeepAudit tool arsenal")
    parser.add_argument("--print-base", action="store_true",
                        help="Print the bash script that installs the base toolkit")
    parser.add_argument("--list", action="store_true", help="Print the tool catalogue")
    args = parser.parse_args(argv)
    if args.print_base:
        print(base_install_script())
    elif args.list:
        print(catalog_text())
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
