"""Binds Cargo's requested compiler arguments to observed compiler execution.

The source-built tracer observes exec calls inside the build sandbox. Environment
values are deliberately omitted. This evidence exposes wrapper expansion and
native linker commands; it does not establish Bazel/Cargo semantic equivalence.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from verify_compiler_options import cargo_compilation_source


def parse_execution_trace(contents):
    """Reassembles concurrent exec calls and rejects abbreviated or partial data."""
    if not contents or not contents.endswith("\n"):
        raise ValueError("empty or incomplete execution trace")

    decoder = json.JSONDecoder()
    pending = {}
    executions = []
    failed = 0
    for line in contents.splitlines():
        prefix = re.fullmatch(r"(\d+)\s+(.*)", line)
        if prefix is None or int(prefix[1]) == 0:
            raise ValueError("unsupported execution trace prefix")
        pid, message = int(prefix[1]), prefix[2]
        if message.endswith("<unfinished ...>"):
            if pid in pending or not message.startswith("execve("):
                raise ValueError("ambiguous unfinished execution")
            pending[pid] = message.removesuffix("<unfinished ...>").rstrip()
            continue

        if message.startswith("<... execve resumed>"):
            if pid not in pending:
                raise ValueError("execution resumed without its prefix")
            message = pending.pop(pid) + message.removeprefix("<... execve resumed>")
        elif pid in pending:
            raise ValueError("execution interrupted by another call for the same process")

        call = re.fullmatch(r"execve\((.*)\)\s+= (.*)", message)
        if call is None:
            raise ValueError("unsupported execution trace record")
        unsuccessful = re.fullmatch(r"-1 [A-Z][A-Z0-9_]+ \([^\n]*\)", call[2]) is not None
        if call[2] != "0" and not unsuccessful:
            raise ValueError("unknown execution result")

        arguments = call[1]
        executable, end = decoder.raw_decode(arguments)
        tail = arguments[end:]
        if not tail.startswith(", "):
            raise ValueError("missing execution argument vector")
        vector, end = decoder.raw_decode(tail[2:])
        environment = tail[2 + end:]
        if re.fullmatch(r", (?:0x[0-9a-f]+|NULL)(?: /\* \d+ vars \*/)?", environment) is None:
            raise ValueError("unexpected execution environment representation")
        if not isinstance(executable, str) or not executable:
            raise ValueError("missing executable path")
        if not isinstance(vector, list) or not vector or not all(isinstance(arg, str) for arg in vector):
            raise ValueError("incomplete execution argument vector")
        if unsuccessful:
            failed += 1
            continue
        executions.append({"pid": pid, "executable": executable, "arguments": vector})

    if pending:
        raise ValueError("unfinished executions at end of trace")
    if not executions:
        raise ValueError("execution trace contains no successful calls")
    return {"executions": executions, "failed_exec_attempts": failed}


def inspect(trace, cargo_arguments, rustc, gcc, linker):
    """Requires every requested compiler invocation to reach the declared compiler."""
    contents = trace.read_text()
    parsed = parse_execution_trace(contents)
    requested = [json.loads(line) for line in cargo_arguments.read_text().splitlines()]
    if not requested or any(record.get("schema_version") != 1 for record in requested):
        raise ValueError("missing or unsupported requested compiler invocations")

    compiler = [record for record in parsed["executions"] if record["executable"] == str(rustc)]
    expected = Counter(tuple(record["arguments"][1:]) for record in requested)
    actual = Counter(tuple(record["arguments"][1:]) for record in compiler)
    # Upstream build scripts query the compiler directly, bypassing Cargo's
    # wrapper. Admit only the observed noncompiling version queries explicitly.
    direct_queries = actual - expected
    if expected - actual or any(arguments not in {
        ("--version",), ("--verbose", "--version"),
    } for arguments in direct_queries):
        raise ValueError("requested compiler invocations differ from observed unwrapped execution")

    units = []
    for record in requested:
        source = cargo_compilation_source(record)
        if source is not None:
            units.append({**record, "source": source})
    if not units:
        raise ValueError("no observed first-party compiler units")

    native = [record for record in parsed["executions"]
              if record["executable"] in {str(gcc), str(linker)}]
    for tool in [gcc, linker]:
        if not any(record["executable"] == str(tool) for record in native):
            raise ValueError("no observed declared native compiler or linker: " + str(tool))

    return {
        "schema_version": 1,
        "status": "PASS: requested compiler invocations reached the declared unwrapped compiler",
        "compiler_invocations": len(compiler), "requested_invocations": len(requested),
        "direct_version_queries": [{"arguments": list(arguments), "count": count}
                                   for arguments, count in sorted(direct_queries.items())],
        "first_party_units": units,
        "native_executions": native, "failed_exec_attempts": parsed["failed_exec_attempts"],
        "executable_counts": dict(sorted(Counter(record["executable"] for record in parsed["executions"]).items())),
        "tools": {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                  for name, path in [("rustc", rustc), ("gcc", gcc), ("linker", linker)]},
        "inputs_sha256": {"execution": hashlib.sha256(trace.read_bytes()).hexdigest(),
                          "requested": hashlib.sha256(cargo_arguments.read_bytes()).hexdigest()},
        "limits": [
            "This records Cargo compiler and native linker execution, not compiler defaults or Bazel/Cargo semantic equivalence.",
            "The requested and unwrapped compiler arguments must match apart from argv[0]; future wrapper expansion requires an explicit mapping.",
            "Environment values and native linker response-file contents are not expanded here.",
            "This parser accepts the observed execve format; other syscall formats fail closed.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--cargo-arguments", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--gcc", type=Path, required=True)
    parser.add_argument("--linker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    report = inspect(options.trace, options.cargo_arguments, options.rustc, options.gcc, options.linker)
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
