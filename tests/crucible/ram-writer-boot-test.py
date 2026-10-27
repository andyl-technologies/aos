"""Checks actual guest relay/process ordering locally, without booting a VM."""

import argparse
import errno
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile


def run(arguments):
    child = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    try:
        output, error = child.communicate(timeout=15)
        return child.returncode, output.decode(), error.decode()
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        child.stdout.close()
        child.stderr.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--relay", type=Path, required=True)
    parser.add_argument("--writer", type=Path, required=True)
    parser.add_argument("--production-init", type=Path, required=True)
    args = parser.parse_args()

    # Production PID 1 refuses an ordinary local process before mount or I/O.
    status, output, error = run([str(args.production_init)])
    assert status == 2 and not output and not error

    with tempfile.TemporaryDirectory(prefix="writer-boot-controls-") as directory:
        wire = Path(directory) / "wire.bin"
        status, _, _ = run([str(args.relay), "--wire", str(wire)])
        assert status == 0
        data = wire.read_bytes()
        assert len(data) == 81 + 3 * 128
        registration = data[:81]
        assert struct.unpack_from("<HHH", registration) == (1, 1, 56)
        assert struct.unpack_from("<IQ", registration, 8) == (81, 1)
        assert registration[56:68] == b"flight.ready"
        assert registration[72:81] == b"readiness"
        for stage, instance in enumerate([b"boot", b"w001", b"z001"]):
            request = data[81 + stage * 128:81 + (stage + 1) * 128]
            assert struct.unpack_from("<HHH", request) == (1, 2, 48)
            assert struct.unpack_from("<IQ", request, 8) == (128, 2 + stage)
            assert request[48:60] == b"flight.ready" and request[60:64] == instance
            assert struct.unpack_from("<I", request, 44)[0] == 64
            assert request[64:] == bytes(64)

        reply = bytearray(128)
        struct.pack_into("<HHHHIQ", reply, 0, 1, 3, 96, 0, 97, 2)
        struct.pack_into("<II", reply, 88, 96, 1)
        reply[96] = 1
        reply_file = Path(directory) / "reply.bin"
        reply_file.write_bytes(reply)
        status, _, _ = run([str(args.relay), "--reply", str(reply_file), "0"])
        assert status == 0
        rejected_replies = 0
        for offset in [0, 2, 4, 6, 8, 12, 20, 22, 88, 92, 96, 127]:
            changed = bytearray(reply)
            changed[offset] ^= 1
            reply_file.write_bytes(changed)
            status, _, _ = run([str(args.relay), "--reply", str(reply_file), "0"])
            assert status == 1
            rejected_replies += 1
        reply_file.write_bytes(data[81:81 + 128])
        status, _, _ = run([str(args.relay), "--reply", str(reply_file), "0"])
        assert status == 1  # An unmodified request is never a permission reply.
        rejected_replies += 1

        positives = 0
        refusals = 0
        for stdin in ["normal-stdin", "closed-stdin"]:
            status, output, _ = run([str(args.relay), str(args.writer), "byte-store", "-1", stdin])
            assert status == 0, output
            lines = output.splitlines()
            assert lines[0].startswith("WRITER_READY_V1 byte-store ")
            assert lines[1] == "RAM_WRITER_BOUNDARY_V1 stage=1"
            assert lines[2:6] == ["WRITER_STORED_V1 byte-store", "RAM_WRITER_BOUNDARY_V1 stage=2",
                                  "WRITER_ZEROED_V1 byte-store", "RAM_WRITER_BOUNDARY_V1 stage=3"]
            assert lines[6] == "LOCAL_RELAY_RESULT_V1 outcome=0 cause=0 boundaries=3 children=none"
            positives += 1
            for stage in range(3):
                status, output, _ = run([str(args.relay), str(args.writer), "byte-store", str(stage), stdin])
                assert status == 1
                assert f"cause={errno.EACCES} boundaries={stage + 1} children=none" in output
                assert output.count("RAM_WRITER_BOUNDARY_V1") == stage + 1
                refusals += 1

        for writer, name in [(str(args.writer), "unknown-case"),
                             (str(Path(directory) / "missing-executable"), "byte-store")]:
            status, output, _ = run([str(args.relay), writer, name, "-1", "closed-stdin"])
            assert status == 1 and f"cause={errno.EPIPE} boundaries=0 children=none" in output
            refusals += 1

        # Scripted DMA messages check only the relay's WRQ ordering. This is
        # deliberately not a positive device, driver or DMA execution result.
        scripted_dma = Path(directory) / "scripted-dma"
        scripted_dma.write_text(f"#!{sys.executable}\n" + '''
import sys
assert sys.argv[1:] == ["--virtio-block", "/dev/vda"]
print("DMA_WRITER_READY_V1 virtio-block 8192", flush=True)
assert sys.stdin.buffer.read(1) == b"W"
print("DMA_WRITER_READ_READY_V1", flush=True)
assert sys.stdin.buffer.read(1) == b"R"
print("DMA_WRITER_READ_DONE_V1", flush=True)
assert sys.stdin.buffer.read(1) == b"Q"
''')
        scripted_dma.chmod(0o755)
        status, output, _ = run([str(args.relay), str(scripted_dma), "dma-virtio", "-1", "closed-stdin"])
        assert status == 0 and "boundaries=3 children=none" in output
        for stage in range(3):
            status, output, _ = run([str(args.relay), str(scripted_dma), "dma-virtio", str(stage), "closed-stdin"])
            assert status == 1
            assert f"cause={errno.EACCES} boundaries={stage + 1} children=none" in output
            refusals += 1

        for message, cause in [(b"WRITER_READY_V1 byte-store 9000 1\n", errno.EPROTO),
                               (b"WRITER_READY_V1 byte-store 48 1\0hidden\n", errno.EPROTO),
                               (b"x" * 256, errno.EMSGSIZE)]:
            broken = Path(directory) / "broken-message"
            broken.write_text(f"#!{sys.executable}\nimport sys\n"
                              f"sys.stdout.buffer.write({message!r})\nsys.stdout.buffer.flush()\n"
                              "sys.stdin.buffer.read(1)\n")
            broken.chmod(0o755)
            status, output, _ = run([str(args.relay), str(broken), "byte-store", "-1", "closed-stdin"])
            assert status == 1 and f"cause={cause} boundaries=0 children=none" in output
            refusals += 1

    print(json.dumps({"positive_relays": positives, "refusal_relays": refusals,
                      "scripted_dma_relay_only": True,
                      "rejected_reply_controls": rejected_replies,
                      "production_non_pid1_refused": True, "encoded_wire_checked": True,
                      "scope": "Actual local CPU program and relay/control bytes; no guest kernel, native observer or VM execution"}))


if __name__ == "__main__":
    main()
