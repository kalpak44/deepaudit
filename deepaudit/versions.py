"""Version ordering and OSV range evaluation.

Every function here returns None rather than a guess when a version string cannot be
parsed. A silent "not affected" from an unparseable version is the one failure mode this
module exists to prevent, so callers must treat None as "not evaluated", never as False.
"""
from __future__ import annotations

import re

# OSV names the ordering it wants per range; PyPI ranges are published as ECOSYSTEM.
PEP440 = "pep440"
SEMVER = "semver"

ORDERING = {"PyPI": PEP440, "npm": SEMVER}

_PEP440_RE = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)

_SEMVER_RE = re.compile(
    r"""^\s*v?
    (?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)
    (?:-(?P<pre>[0-9a-z-]+(?:\.[0-9a-z-]+)*))?
    (?:\+(?P<build>[0-9a-z-]+(?:\.[0-9a-z-]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)

_PRE_ALIASES = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}


class _Boundary:
    """Sorts above or below every real value, so absent segments compare correctly."""

    def __init__(self, high: bool):
        self._high = high

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Boundary) and other._high == self._high

    def __lt__(self, other: object) -> bool:
        return not self._high and not self == other

    def __gt__(self, other: object) -> bool:
        return self._high and not self == other

    def __le__(self, other: object) -> bool:
        return self == other or self < other

    def __ge__(self, other: object) -> bool:
        return self == other or self > other

    def __repr__(self) -> str:
        return "HIGH" if self._high else "LOW"


LOW = _Boundary(False)
HIGH = _Boundary(True)


def normalize_pypi(name: str) -> str:
    """PEP 503 normalization. `Flask_Login` and `flask-login` are one project."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def parse_pep440(text: str):
    if not isinstance(text, str):
        return None
    match = _PEP440_RE.match(text)
    if not match:
        return None
    release = tuple(int(part) for part in match.group("release").split("."))
    # Trailing zeros are not significant: 1.2 and 1.2.0 are the same release.
    trimmed = list(release)
    while len(trimmed) > 1 and trimmed[-1] == 0:
        trimmed.pop()

    pre = None
    if match.group("pre_l"):
        letter = match.group("pre_l").lower()
        pre = (_PRE_ALIASES.get(letter, letter), int(match.group("pre_n") or 0))
    post = None
    if match.group("post_n1") is not None:
        post = int(match.group("post_n1"))
    elif match.group("post_l"):
        post = int(match.group("post_n2") or 0)
    dev = int(match.group("dev_n") or 0) if match.group("dev_l") else None

    # A bare release outranks its own pre-releases but loses to its post-releases.
    if pre is None and post is None and dev is not None:
        pre_key = LOW
    elif pre is None:
        pre_key = HIGH
    else:
        pre_key = pre
    local = match.group("local")
    local_key = LOW
    if local:
        local_key = tuple((int(part), "") if part.isdigit() else (-1, part.lower())
                          for part in re.split(r"[-_.]", local))
    return (int(match.group("epoch") or 0), tuple(trimmed), pre_key,
            post if post is not None else LOW, dev if dev is not None else HIGH, local_key)


def parse_semver(text: str):
    if not isinstance(text, str):
        return None
    match = _SEMVER_RE.match(text)
    if not match:
        return None
    core = (int(match.group("major")), int(match.group("minor")), int(match.group("patch")))
    pre = match.group("pre")
    if not pre:
        # No prerelease outranks any prerelease of the same core version.
        return (core, HIGH)
    parts = []
    for item in pre.split("."):
        # Numeric identifiers compare numerically and always rank below alphanumeric ones.
        parts.append((0, int(item), "") if item.isdigit() else (1, 0, item))
    return (core, tuple(parts))


def parse(ordering: str, text: str):
    return parse_pep440(text) if ordering == PEP440 else parse_semver(text)


def compare(ordering: str, left: str, right: str) -> int | None:
    """-1/0/1, or None when either side is unparseable under this ordering."""
    a, b = parse(ordering, left), parse(ordering, right)
    if a is None or b is None:
        return None
    return 0 if a == b else (-1 if a < b else 1)


def in_range(ordering: str, version: str, events: list[dict]) -> bool | None:
    """Evaluate one OSV range against a version.

    Follows the OSV schema's linear scan: `introduced` opens the affected interval and a
    later `fixed`/`last_affected` closes it. Returns None when any bound in the range
    cannot be parsed, so an unreadable range is reported rather than silently cleared.
    """
    if parse(ordering, version) is None:
        return None
    affected = False
    for event in events:
        if not isinstance(event, dict):
            return None
        if "introduced" in event:
            bound = event["introduced"]
            if bound == "0":
                affected = True
                continue
            result = compare(ordering, version, bound)
            if result is None:
                return None
            if result >= 0:
                affected = True
        elif "fixed" in event:
            result = compare(ordering, version, event["fixed"])
            if result is None:
                return None
            if result >= 0:
                affected = False
        elif "last_affected" in event:
            result = compare(ordering, version, event["last_affected"])
            if result is None:
                return None
            if result > 0:
                affected = False
    return affected
