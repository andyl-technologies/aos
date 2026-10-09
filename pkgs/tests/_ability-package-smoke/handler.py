"""Exercises the native handler process protocol without mutating host state."""
import json
import sys

LIMIT = 1048576


def run():
    if len(sys.argv) != 2 or sys.argv[1] not in ("apply", "remove", "observe"):
        raise ValueError("expected a native handler action")
    wire = sys.stdin.buffer.read(LIMIT + 1)
    if len(wire) > LIMIT:
        raise ValueError("invocation exceeds its bound")
    invocation = json.loads(wire)
    purpose = sys.argv[1]
    action = invocation["action"]
    if action not in ("apply", "remove"):
        raise ValueError("invalid invocation action")
    if purpose != "observe" and purpose != action:
        raise ValueError("native action differs from argv")
    value = invocation["input"]
    if set(value) != {"enabled", "label", "maximum", "minimum"}:
        raise ValueError("unexpected fixture inputs")
    if type(value["enabled"]) is not bool or not isinstance(value["label"], str):
        raise ValueError("invalid fixture values")
    for field in ("maximum", "minimum"):
        if type(value[field]) is not int or abs(value[field]) > 9007199254740991:
            raise ValueError("invalid integer boundary")

    if purpose == "remove":
        output = {}
    elif purpose == "observe" and action == "remove":
        output = {"status": "absent"}
    elif purpose == "observe":
        output = {"status": "current", "outputs": value}
    else:
        output = value
    print(json.dumps(output, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except (ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
