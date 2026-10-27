"""Exercises requested-command coverage with concurrent Rust processes.

Version queries create short-lived compiler threads while linked compilations
exercise the wrapper, compiler, native driver, and linker. Every requested
compiler invocation must appear intact in the independent execution trace.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from inspect_compiler_execution import inspect, parse_execution_trace


QUERY_COUNT = 96
COMPILATION_COUNT = 8
TRACE_FLAGS = [
    "-qq", "-f", "-s", "16777216",
    "-e", "trace=execve,execveat", "-e", "signal=none",
]


def workload(args):
    """Runs and records the compiler requests made by the traced subprocess."""
    requests = []
    with tempfile.TemporaryDirectory(prefix="aos-compiler-trace-") as directory:
        root = Path(directory) / "crates" / "trace_probe"
        source = root / "src" / "main.rs"
        source.parent.mkdir(parents=True)
        source.write_text('fn main() { assert_eq!(std::env::args().count(), 1); }\n')
        commands = [[args.rustc, "--version"] for _ in range(QUERY_COUNT)]
        for index in range(COMPILATION_COUNT):
            commands.append([
                args.rustc, "--crate-name", "trace_probe", str(source),
                "-C", "linker=" + args.cc, "-o", str(root / f"probe-{index}"),
            ])
        for command in commands:
            requests.append({
                "schema_version": 1, "directory": str(root),
                "arguments": command, "environment": {},
            })
        (args.output / "requested.jsonl").write_text(
            "".join(json.dumps(request, sort_keys=True) + "\n" for request in requests)
        )

        def execute(command):
            subprocess.run(command, cwd=root, check=True, stdout=subprocess.DEVNULL)

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(execute, commands))
        for index in range(COMPILATION_COUNT):
            subprocess.run([str(root / f"probe-{index}")], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["strace", "rustc", "rustc-unwrapped", "cc", "gcc", "linker"]:
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workload", action="store_true")
    args = parser.parse_args()
    if args.workload:
        workload(args)
        return

    trace = args.output / "execution.log"
    command = [args.strace, *TRACE_FLAGS, "-o", str(trace), sys.executable,
               str(Path(__file__).resolve()), *sys.argv[1:], "--workload"]
    completed = subprocess.run(command, check=True, capture_output=True)
    (args.output / "tracer-stderr.log").write_bytes(completed.stderr)
    if completed.stderr:
        raise ValueError("compiler capture emitted unexpected diagnostics")

    try:
        receipt = inspect(
            trace, args.output / "requested.jsonl", Path(args.rustc_unwrapped),
            Path(args.gcc), Path(args.linker), retain_unresolved_tasks=True,
        )
    except ValueError:
        for line in trace.read_text().splitlines():
            if "execve(" not in line and "<... execve resumed>" not in line:
                print("Unsupported capture record: " + line[:300], file=sys.stderr)
        raise
    if receipt["compiler_invocations"] != QUERY_COUNT + COMPILATION_COUNT:
        raise ValueError("concurrent compiler execution count differs")
    if receipt["requested_compilation_inventory"]["units"] != COMPILATION_COUNT:
        raise ValueError("linked compilation inventory differs")
    if receipt["execution_capture"]["unresolved_task_records"]:
        try:
            parse_execution_trace(trace.read_text())
        except ValueError:
            pass
        else:
            raise ValueError("strict parser accepted an incomplete execution stream")

    # A detached, undecoded task invalidated the unfiltered Cargo capture.
    # Preserve this exact failure as a negative control for every probe run.
    rejected = "109   ???( <detached ...>\n"
    try:
        parse_execution_trace(rejected)
    except ValueError:
        pass
    else:
        raise ValueError("undecoded detached task was accepted")

    receipt["capture"] = {
        "flags": TRACE_FLAGS, "strace": args.strace,
        "strace_sha256": hashlib.sha256(Path(args.strace).read_bytes()).hexdigest(),
        "concurrent_workers": 8, "version_queries": QUERY_COUNT,
        "linked_compilations_and_runs": COMPILATION_COUNT,
        "undecoded_detached_task_rejected": True,
    }
    (args.output / "evidence.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
