"""Relays the Nix worker protocol through a private Firecracker vsock endpoint."""

import os
import select
import socket
import sys


def connect_vsock(endpoint, port):
    """Opens a byte stream after checking Firecracker's bounded handshake."""
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stream.settimeout(10)
        stream.connect(str(endpoint))
        stream.sendall(f"CONNECT {port}\n".encode("ascii"))
        response = bytearray()
        while len(response) < 128:
            byte = stream.recv(1)
            if not byte:
                raise ConnectionError("vsock closed during handshake")
            response.extend(byte)
            if byte == b"\n":
                break
        else:
            raise ConnectionError("vsock handshake exceeds its bound")

        fields = response.decode("ascii").strip().split()
        if len(fields) != 2 or fields[0] != "OK" or not fields[1].isdigit():
            raise ConnectionError("vsock refused the requested connection")
        stream.settimeout(None)
        return stream
    except BaseException:
        stream.close()
        raise


def relay_stdio(endpoint):
    """Forwards bounded protocol buffers while preserving the write half-close."""
    with connect_vsock(endpoint, 64) as stream:
        source = sys.stdin.fileno()
        destination = sys.stdout.fileno()
        remote = stream.fileno()
        for descriptor in (source, destination, remote):
            os.set_blocking(descriptor, False)

        to_remote = bytearray()
        to_stdout = bytearray()
        input_closed = remote_closed = write_closed = False
        limit = 1024 * 1024
        while not remote_closed or to_stdout:
            readers = []
            writers = []
            if not input_closed and not remote_closed and len(to_remote) < limit:
                readers.append(source)
            if not remote_closed and len(to_stdout) < limit:
                readers.append(remote)
            if to_remote and not remote_closed:
                writers.append(remote)
            if to_stdout:
                writers.append(destination)

            ready_readers, ready_writers, _ = select.select(readers, writers, [])
            if source in ready_readers:
                data = os.read(source, 65536)
                input_closed = not data
                to_remote.extend(data)
            if remote in ready_readers:
                data = os.read(remote, 65536)
                remote_closed = not data
                to_stdout.extend(data)
            if remote in ready_writers and not remote_closed:
                del to_remote[:os.write(remote, to_remote)]
            if destination in ready_writers:
                del to_stdout[:os.write(destination, to_stdout)]
            if input_closed and not to_remote and not write_closed:
                stream.shutdown(socket.SHUT_WR)
                write_closed = True


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[2] != "--stdio":
        raise SystemExit("expected private endpoint followed by --stdio")
    relay_stdio(sys.argv[1])
