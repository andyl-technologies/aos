"""Transfers complete guest documents without bulky uncompressed RPC stdout."""

import base64
import shlex
import zlib


COMPRESS_STDOUT = (
    "import base64,sys,zlib; "
    "sys.stdout.write(base64.b64encode(zlib.compress(sys.stdin.buffer.read())).decode('ascii'))"
)


def compressed_output(machine, command, *, shell, python, maximum=None):
    """Returns the exact UTF-8 stdout, preserving command errors and read bounds."""
    pipeline = f"({command}) | {shlex.quote(python)} -c {shlex.quote(COMPRESS_STDOUT)}"
    encoded = machine.succeed(f"{shlex.quote(shell)} -o pipefail -c {shlex.quote(pipeline)}")
    compressed = base64.b64decode(encoded, validate=True)
    decoder = zlib.decompressobj()
    contents = decoder.decompress(compressed) + decoder.flush()
    if not decoder.eof or decoder.unused_data:
        raise ValueError("invalid compressed native document")
    if maximum is not None and len(contents) > maximum:
        raise RuntimeError("native fixture document exceeds its read bound")
    return contents.decode("utf-8")
