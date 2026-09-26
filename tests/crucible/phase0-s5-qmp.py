"""Issue one QMP request after completing the capability handshake."""

import json
import socket
import sys


def response(stream):
    while True:
        line = stream.readline()
        if not line:
            raise ConnectionError("QMP closed before responding")

        message = json.loads(line)
        if "return" in message or "error" in message:
            return message


def main():
    socket_path, request_text = sys.argv[1:]
    request = json.loads(request_text)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(socket_path)

        with connection.makefile("rb") as stream:
            greeting = json.loads(stream.readline())
            if "QMP" not in greeting:
                raise ValueError("QMP greeting is missing")

            connection.sendall(b'{"execute":"qmp_capabilities"}\r\n')
            capabilities = response(stream)
            print(json.dumps(capabilities))
            if "error" in capabilities:
                return 1

            connection.sendall(json.dumps(request).encode() + b"\r\n")
            result = response(stream)
            print(json.dumps(result))
            return int("error" in result)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"QMP request failed: {error}", file=sys.stderr)
        sys.exit(1)
