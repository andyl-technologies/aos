"""Runs a bounded QMP command and retains its complete reply transcript."""

import json
import math
import socket
import sys
import time


def command(socket_path, request, output, timeout=15):
    """Negotiates capabilities and waits for the command's matching reply."""

    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(socket_path)
        with connection.makefile("rb") as stream:
            def receive():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("QMP command exceeded its deadline")
                connection.settimeout(remaining)
                line = stream.readline(1024 * 1024 + 1)
                if not line or len(line) > 1024 * 1024:
                    raise ValueError("QMP reply is missing or exceeds the size limit")
                message = json.loads(line)
                print(json.dumps(message), file=output, flush=True)
                return message

            def execute(value, identifier):
                connection.sendall(
                    (json.dumps(value | {"id": identifier}) + "\r\n").encode()
                )
                while True:
                    message = receive()
                    if message.get("id") != identifier:
                        continue
                    if "error" in message:
                        raise ValueError("QMP rejected the command")
                    if "return" in message:
                        return

            if "QMP" not in receive():
                raise ValueError("QMP greeting is missing")
            execute({"execute": "qmp_capabilities"}, "capabilities")
            execute(request, "request")


if __name__ == "__main__":
    try:
        timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 15
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("QMP timeout must be finite and positive")
        command(sys.argv[1], json.loads(sys.argv[2]), sys.stdout, timeout)
    except (OSError, ValueError) as error:
        print(f"QMP command failed: {error}", file=sys.stderr)
        sys.exit(1)
