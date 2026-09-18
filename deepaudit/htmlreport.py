"""Self-contained HTML rendering for both report pipelines.

Every value is escaped on the way in and the stylesheet is inline: a report is opened
straight from an artifact zip, often from a file:// path, so it must not depend on any
network resource. No script runs in it either, because a report frequently carries
attacker-influenced strings such as an advisory summary or a target hostname.
"""
from __future__ import annotations

import html
import json

STYLE = """
:root { color-scheme: light dark;
  --bg:#ffffff; --fg:#1b1f23; --muted:#5b6570; --line:#d8dee4; --card:#f6f8fa;
  --high:#b42318; --mid:#b54708; --low:#175cd3; --ok:#067647; }
@media (prefers-color-scheme: dark) { :root {
  --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --line:#30363d; --card:#161b22;
  --high:#ff7b72; --mid:#e3b341; --low:#79c0ff; --ok:#3fb950; } }
* { box-sizing:border-box; }
body { margin:0; padding:2rem 1.25rem 4rem; background:var(--bg); color:var(--fg);
  font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; }
main { max-width:56rem; margin:0 auto; }
h1 { font-size:1.75rem; margin:0 0 .25rem; }
h2 { font-size:1.25rem; margin:2.5rem 0 .75rem; padding-bottom:.35rem;
  border-bottom:1px solid var(--line); }
h3 { font-size:1rem; margin:1.75rem 0 .5rem; }
p, li { margin:.5rem 0; }
code, pre { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.85em; }
pre { background:var(--card); border:1px solid var(--line); border-radius:6px;
  padding:.75rem 1rem; overflow-x:auto; }
table { border-collapse:collapse; width:100%; margin:.75rem 0; display:block;
  overflow-x:auto; }
th, td { border:1px solid var(--line); padding:.45rem .6rem; text-align:left;
  vertical-align:top; }
th { background:var(--card); font-weight:600; }
.sub { color:var(--muted); margin:0 0 1.5rem; }
.card { background:var(--card); border:1px solid var(--line); border-radius:6px;
  padding:1rem 1.25rem; margin:1rem 0; }
.tag { display:inline-block; padding:.1rem .5rem; border-radius:999px; font-size:.78rem;
  font-weight:600; border:1px solid currentColor; }
.t-high { color:var(--high); } .t-mid { color:var(--mid); }
.t-low { color:var(--low); } .t-ok { color:var(--ok); } .t-muted { color:var(--muted); }
.note { border-left:3px solid var(--mid); padding-left:1rem; color:var(--muted); }
ul.plain { list-style:none; padding-left:0; }
ul.plain li { border-bottom:1px solid var(--line); padding:.4rem 0; }
"""

# Anything not listed reads as neutral, so an unknown label never renders as reassuring.
TONE = {
    "CONFIRMED_APPLICABLE": "t-high", "LIKELY_APPLICABLE": "t-mid",
    "POTENTIAL": "t-low", "INSUFFICIENT_EVIDENCE": "t-mid", "NOT_APPLICABLE": "t-muted",
    "CRITICAL": "t-high", "HIGH": "t-high", "MODERATE": "t-mid", "MEDIUM": "t-mid",
    "LOW": "t-low", "INFO": "t-muted", "INFORMATIONAL": "t-muted",
    "critical": "t-high", "high": "t-high", "medium": "t-mid", "moderate": "t-mid",
    "low": "t-low", "info": "t-muted",
    "confirmed": "t-high", "refuted": "t-ok", "not evaluated": "t-muted",
    "reproduced": "t-high", "not_reproduced": "t-ok", "inconclusive": "t-mid",
    "not_rechecked": "t-muted",
}


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def tag(label) -> str:
    return f'<span class="tag {TONE.get(str(label), "t-muted")}">{esc(label)}</span>'


def heading(level: int, text: str) -> str:
    return f"<h{level}>{esc(text)}</h{level}>"


def para(text: str, klass: str | None = None) -> str:
    attribute = f' class="{klass}"' if klass else ""
    return f"<p{attribute}>{esc(text)}</p>"


def raw(markup: str) -> str:
    """Emit already-escaped markup assembled by this module."""
    return markup


def bullets(items: list[str], plain: bool = False) -> str:
    klass = ' class="plain"' if plain else ""
    return f"<ul{klass}>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"


def table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{esc(item)}</th>" for item in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
                   for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def code_block(value) -> str:
    text = value if isinstance(value, str) else json.dumps(value, indent=2, ensure_ascii=False)
    return f"<pre><code>{esc(text)}</code></pre>"


def links(urls: list[str]) -> str:
    items = []
    for url in urls:
        # Only http(s) becomes a link; anything else is shown as inert text.
        safe = esc(url)
        if str(url).startswith(("http://", "https://")):
            items.append(f'<a href="{safe}" rel="noreferrer noopener">{safe}</a>')
        else:
            items.append(f"<code>{safe}</code>")
    return bullets(items)


def document(title: str, subtitle: str, parts: list[str]) -> str:
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<meta name=\"referrer\" content=\"no-referrer\">\n"
        f"<title>{esc(title)}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<main>\n"
        f"{heading(1, title)}\n{para(subtitle, 'sub')}\n"
        + "\n".join(parts)
        + "\n</main>\n</body>\n</html>\n"
    )
