"""Runs the native configuration operation using shared durable reconciliation."""

import argparse
import json
import sys

from aos_configuration import ConfigurationHandler, locked_dispatch, read_invocation


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-directory", default="/var/lib/aos/native-service-effects")
    parser.add_argument("action", choices=["apply", "remove", "observe"])
    args = parser.parse_args()
    invocation = read_invocation()
    if invocation["effect"]["identity"][-3:-1] != ["configuration", "file"]:
        raise ValueError("unsupported native configuration operation")

    def dispatch(state_directory):
        return ConfigurationHandler(invocation, state_directory).file(args.action)

    result = locked_dispatch(args.state_directory, dispatch)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("native configuration handler: " + str(error), file=sys.stderr)
        sys.exit(1)
