# SPDX-License-Identifier: Apache-2.0
"""Check direct-I/O payload semantics locally; this is not a virtio DMA run."""

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import selectors
import tempfile


def line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(5), "missing DMA stage milestone"
    return process.stdout.readline().decode().strip()


def send(process, command):
    process.stdin.write(command)
    process.stdin.flush()


@contextmanager
def begin(binary, path):
    path.write_bytes(bytes(65536))
    process = subprocess.Popen([str(binary), "--local-file-control", str(path)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
        assert line(process) == "DMA_WRITER_READY_V1 local-file 8192"
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()


def finish(process, expected):
    process.stdin.close()
    status = process.wait(timeout=5)
    error = process.stderr.read().decode()
    assert status == expected, (status, expected, error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="dma-writer-control-") as temporary:
        path = Path(temporary) / "private-disk.img"
        expected = bytes(((index * 29) ^ (index >> 7) ^ 0x6B) & 255
                         for index in range(8192))
        with begin(args.binary, path) as process:
            send(process, b"W")
            assert line(process) == "DMA_WRITER_READ_READY_V1"
            disk = path.read_bytes()
            assert disk[:4096] == bytes(4096)
            assert disk[4096:12288] == expected
            assert disk[12288:] == bytes(65536 - 12288)
            send(process, b"R")
            assert line(process) == "DMA_WRITER_READ_DONE_V1"
            send(process, b"Q")
            finish(process, 0)

        for failure in ("corrupt", "short-read"):
            with begin(args.binary, path) as process:
                send(process, b"W")
                assert line(process) == "DMA_WRITER_READ_READY_V1"
                if failure == "corrupt":
                    with path.open("r+b") as disk:
                        disk.seek(4096)
                        disk.write(bytes([expected[0] ^ 1]))
                    expected_status = 8
                else:
                    path.write_bytes(b"")
                    expected_status = 7
                send(process, b"R")
                finish(process, expected_status)

        for stage in range(3):
            for command in (None, b"!"):
                with begin(args.binary, path) as process:
                    for previous in range(stage):
                        send(process, (b"W", b"R")[previous])
                        assert line(process) == ("DMA_WRITER_READ_READY_V1",
                                                 "DMA_WRITER_READ_DONE_V1")[previous]
                    if command:
                        send(process, command)
                    finish(process, 5)

        # A regular file can never be silently relabeled as a real DMA device.
        result = subprocess.run([str(args.binary), "--virtio-block", str(path)],
                                capture_output=True, timeout=5)
        assert result.returncode == 2 and not result.stdout

        for after_write in (False, True):
            held = None
            try:
                with begin(args.binary, path) as process:
                    held = process
                    if after_write:
                        send(process, b"W")
                        assert line(process) == "DMA_WRITER_READ_READY_V1"
                    raise RuntimeError("deliberate caller assertion")
            except RuntimeError as error:
                assert str(error) == "deliberate caller assertion"
            assert held.poll() is not None
            assert all(pipe.closed for pipe in (held.stdin, held.stdout, held.stderr))
    print(json.dumps({"positive_cases": 1, "negative_cases": 11,
                      "scope": "local direct vectored I/O only; virtio ring/bounce not executed"}))


if __name__ == "__main__":
    main()
