# SPDX-License-Identifier: Apache-2.0
"""Run real CPU writer instructions and their stopped-stage error controls.

These controls check guest byte semantics and emitted instruction families.
They do not exercise QEMU dirty notification or substitute for a VM RAM root.
"""

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import re
import selectors
import subprocess


CASES = {
    "byte-store": (48, 1),
    "scalar32": (64, 4),
    "unaligned64": (67, 8),
    "cross-page64": (4093, 8),
    "vector128": (128, 16),
    "unaligned-vector128": (131, 16),
    "cross-page-vector128": (4089, 16),
    "atomic8": (176, 1),
    "atomic16": (178, 2),
    "atomic32": (180, 4),
    "atomic64": (192, 8),
    "atomic128": (208, 16),
    "streaming64": (240, 8),
    "cross-page-rep-stos": (4083, 32),
}


def line(process):
    """Read one milestone under a finite local test deadline."""
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(5):
            raise AssertionError("guest did not reach its next boundary")
    return process.stdout.readline().decode().strip()


@contextmanager
def start(binary, name, option=None):
    command = [str(binary), name]
    if option:
        command.append(option)
    process = subprocess.Popen(command, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        marker = line(process)
        if not marker and process.wait(timeout=5) == 77:
            assert name == "atomic128", process.stderr.read().decode()
            yield None
        else:
            offset, length = CASES[name]
            assert marker == f"WRITER_READY_V1 {name} {offset} {length}", marker
            yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()


def send(process, command):
    process.stdin.write(command)
    process.stdin.flush()


def finish(process, expected):
    process.stdin.close()
    status = process.wait(timeout=5)
    error = process.stderr.read().decode()
    assert status == expected, (status, expected, error)
    if expected == 4:
        assert error == "WRITER_MISMATCH_V1\n", error
    return error


def run_case(binary, name):
    with start(binary, name) as process:
        if process is None:
            return False
        send(process, b"W")
        assert line(process) == f"WRITER_STORED_V1 {name}"
        send(process, b"Z")
        assert line(process) == f"WRITER_ZEROED_V1 {name}"
        send(process, b"Q")
        finish(process, 0)
    return True


def instruction_evidence(binary, objdump):
    result = subprocess.run([objdump, "-d", "--insn-width=16", str(binary)],
                            check=True, text=True, capture_output=True)
    required = {
        "scalar8": r"\bmovb\s+\$0x10",
        "scalar32": r"\bmovl\s+\$0x76543210",
        "scalar64": r"\bmov\s+%[a-z0-9]+,\(%[a-z0-9]+\)",
        "vector128": r"\bmovdqu\s+%xmm0,\(%[a-z0-9]+\)",
        "atomic64": r"\block xadd\s+",
        "atomic8": r"\bxchg\s+%[a-z0-9]+,\(%[a-z0-9]+\)",
        "atomic16": r"\bxchg\s+%[a-z0-9]+,\(%[a-z0-9]+\)",
        "atomic32": r"\bxchg\s+%[a-z0-9]+,\(%[a-z0-9]+\)",
        "atomic128": r"\block cmpxchg16b\s+",
        "streaming64": r"\bmovnti\s+",
        "repeated_bytes": r"\brep stos\s+",
    }
    for name, pattern in required.items():
        body = re.search(rf"^[0-9a-f]+ <{name}>:\n(.*?)(?=\n\n)",
                         result.stdout, re.MULTILINE | re.DOTALL)
        assert body and re.search(pattern, body[1]), (name, pattern)
    assert "sfence" in result.stdout
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--evidence-directory", type=Path)
    args = parser.parse_args()
    instructions = instruction_evidence(args.binary, args.objdump)
    supported = [name for name in CASES if run_case(args.binary, name)]
    assert len(supported) >= len(CASES) - 1

    # Both omissions and one-bit corruptions must fail the independent byte oracle.
    negatives = 0
    for name in supported:
        for option in ("--omit-store", "--corrupt-byte"):
            with start(args.binary, name, option) as process:
                assert process is not None
                send(process, b"W")
                finish(process, 4)
            negatives += 1

    # No next-stage success may follow EOF or a wrong command at any boundary.
    for stage in range(3):
        for command in (None, b"!"):
            with start(args.binary, "cross-page-vector128") as process:
                for previous in range(stage):
                    send(process, (b"W", b"Z")[previous])
                    assert line(process).startswith(("WRITER_STORED_V1", "WRITER_ZEROED_V1")[previous])
                if command:
                    send(process, command)
                finish(process, 5)
            negatives += 1

    for after_store in (False, True):
        held = None
        try:
            with start(args.binary, "cross-page-vector128") as process:
                held = process
                if after_store:
                    send(process, b"W")
                    assert line(process) == "WRITER_STORED_V1 cross-page-vector128"
                raise RuntimeError("deliberate caller assertion")
        except RuntimeError as error:
            assert str(error) == "deliberate caller assertion"
        assert held.poll() is not None
        assert all(pipe.closed for pipe in (held.stdin, held.stdout, held.stderr))
        negatives += 1

    result = {
        "supported": supported,
        "unsupported": [name for name in CASES if name not in supported],
        "positive_cases": len(supported),
        "negative_cases": negatives,
        "scope": "real guest instructions and byte oracle; no native dirty-root observation",
    }
    if args.evidence_directory:
        args.evidence_directory.mkdir(parents=True, exist_ok=True)
        (args.evidence_directory / "instructions.txt").write_text(instructions)
        (args.evidence_directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
