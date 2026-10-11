"""Executes native reference endpoint publication and checked service bindings.

These operations are pure: deferred dependencies establish actual service
readiness, while this handler validates and publishes the materialized values.
"""

import json
import re
import sys


def endpoints(value):
    """Validates the same bounded optional loopback map as the domain module."""
    if value is None:
        return None
    if not isinstance(value, dict) or len(value) > 1024:
        raise ValueError("invalid bounded endpoint map")
    for name, endpoint in value.items():
        if not isinstance(name, str) or len(name) > 128 or re.fullmatch(r"[A-Za-z0-9._-]+", name) is None:
            raise ValueError("invalid endpoint slot")
        if endpoint is None:
            continue
        if not isinstance(endpoint, dict) or set(endpoint) != {"address", "port", "transport"}:
            raise ValueError("invalid endpoint fields")
        if endpoint["address"] != "127.0.0.1" or endpoint["transport"] != "tcp":
            raise ValueError("endpoint must use loopback TCP")
        if type(endpoint["port"]) is not int or not 1024 <= endpoint["port"] <= 65535:
            raise ValueError("invalid unprivileged endpoint port")
    return value


def execute():
    """Executes a pure native apply, remove, or observation invocation."""
    if len(sys.argv) != 2 or sys.argv[1] not in {"apply", "remove", "observe"}:
        raise ValueError("expected one native action")
    encoded = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(encoded) > 1024 * 1024:
        raise ValueError("invocation exceeds the fixture bound")
    invocation = json.loads(encoded)
    action = sys.argv[1]
    if invocation["action"] not in {"apply", "remove"}:
        raise ValueError("invalid native desired action")
    if action != "observe" and invocation["action"] != action:
        raise ValueError("native action mismatch")
    if not isinstance(invocation["id"], str) or not invocation["id"] or len(invocation["id"]) > 4096:
        raise ValueError("invalid native effect identity")

    inputs = invocation["input"]
    if not isinstance(inputs, dict) or set(inputs) not in ({"service"}, {"endpoints"}, {"service", "endpoints"}):
        raise ValueError("unexpected binding input fields")
    outputs = {"resource": invocation["id"]}
    if "service" in inputs:
        service = inputs["service"]
        if not isinstance(service, str) or len(service) > 255 or re.fullmatch(r"[A-Za-z0-9_.@:-]+\.service", service) is None:
            raise ValueError("binding requires an exact service resource")
        outputs["service"] = service
    if "endpoints" in inputs:
        outputs["endpoints"] = endpoints(inputs["endpoints"])

    if action == "remove":
        return {}
    if action == "observe":
        return {"status": "absent"} if invocation["action"] == "remove" else {"status": "current", "outputs": outputs}
    return outputs


if __name__ == "__main__":
    try:
        json.dump(execute(), sys.stdout, separators=(",", ":"), sort_keys=True)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
