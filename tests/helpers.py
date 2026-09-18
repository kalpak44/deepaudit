from copy import deepcopy
from deepaudit.policy import Scope, Target
from deepaudit.transport import Budget


def http_observation(*, html=True, hardened=False, cookie=True):
    return {"status": "ok", "observed_at": "2026-09-18T00:00:00+00:00", "status_code": 200,
            "signals": {"html": html, "csp_present": hardened,
                        "frame_ancestors_present": hardened, "xfo_restrictive": False,
                        "nosniff": hardened, "hsts_present": hardened, "hsts_max_age": 31536000 if hardened else None,
                        "location_class": "absent", "cookies": ([{"index": 1, "secure": hardened,
                        "httponly": hardened, "samesite": "lax" if hardened else "absent_or_invalid"}] if cookie else []),
                        "cookie_parse_errors": 0, "cookie_headers_truncated": False,
                        "raw_headers_retained": False, "body_retained": False}}


def snapshot(url="http://example.test/", **kwargs):
    return {"schema_version": 1,
            "scope": Scope(Target.parse(url), ("93.184.216.34",)).public(),
            "http": http_observation(**kwargs),
            "tls": {"status": "skipped", "reason": "target_is_http"}}


class FakeProbes:
    def __init__(self, *, url="http://example.test/", first=None, second=None):
        self.scope = Scope(Target.parse(url), ("93.184.216.34",))
        self.budget = Budget()
        self.first = first or http_observation()
        self.second = second or deepcopy(self.first)
        self.http_calls = 0
        self.tls_calls = 0

    def http(self):
        self.http_calls += 1
        self.budget.used += 1
        return deepcopy(self.first if self.http_calls == 1 else self.second)

    def tls(self):
        self.tls_calls += 1
        return {"status": "skipped", "reason": "target_is_http"}


def tool_call(name, identifier="call_1", arguments="{}"):
    return {"id": identifier, "type": "function", "function": {"name": name, "arguments": arguments}}


class FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = 0
        self.model = "mock-not-a-live-model"
        self.usage = {"total_tokens": 0}
        self.history = []

    def complete(self, messages, tools):
        self.requests += 1
        self.history.append(deepcopy(messages))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)
