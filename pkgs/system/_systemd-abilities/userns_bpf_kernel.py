"""Checks the selected kernel's typed namespace-retirement attachment contract."""

import argparse
from pathlib import Path
import re


REQUIRED_CONFIG = (
    "BPF",
    "BPF_SYSCALL",
    "BPF_JIT",
    "BPF_LSM",
    "DEBUG_INFO_BTF",
    "FUNCTION_TRACER",
    "DYNAMIC_FTRACE_WITH_DIRECT_CALLS",
    "DYNAMIC_FTRACE_WITH_ARGS",
)
HEADER = re.compile(r"\[(\d+)\] (\w+) '([^']*)'(.*)")
ARGUMENT = re.compile(r"\s+'[^']*' type_id=(\d+)")


def check_kernel(config, btf):
    """Rejects missing trampoline support or a changed retirement signature.

    Inputs are the selected kernel's configuration and bpftool raw BTF dump.
    This checks build compatibility, never installed attachment or readiness.
    """
    config_lines = set(config.splitlines())
    for option in REQUIRED_CONFIG:
        if f"CONFIG_{option}=y" not in config_lines:
            raise ValueError(f"namespace retirement requires CONFIG_{option}=y")

    records = {}
    functions = []
    current = None
    for line in btf:
        header = HEADER.fullmatch(line.rstrip("\n"))
        if header:
            identity, kind, name, fields = header.groups()
            current = None
            if kind not in ("FUNC", "FUNC_PROTO", "PTR", "STRUCT"):
                continue
            identity = int(identity)
            if identity in records:
                raise ValueError("duplicate BTF type identity")
            record = (kind, name, dict(re.findall(r"(\w+)=([^\s]+)", fields)), [])
            records[identity] = record
            if kind == "FUNC_PROTO":
                current = record
            if kind == "FUNC" and name == "retire_userns_sysctls":
                functions.append(record)
        elif current is not None:
            argument = ARGUMENT.fullmatch(line.rstrip("\n"))
            if argument is None:
                raise ValueError("invalid BTF function argument")
            current[3].append(int(argument[1]))

    if len(functions) != 1:
        raise ValueError("expected exactly one retire_userns_sysctls BTF function")

    # Follow actual type references; BTF numeric IDs and argument names are
    # kernel-build details. The attachment must remain void (user_namespace *).
    try:
        prototype = records[int(functions[0][2]["type_id"])]
        if (prototype[0] != "FUNC_PROTO"
                or prototype[2].get("ret_type_id") != "0"
                or prototype[2].get("vlen") != "1"
                or len(prototype[3]) != 1):
            raise ValueError("changed namespace retirement prototype")
        pointer = records[prototype[3][0]]
        if pointer[0] != "PTR":
            raise ValueError("namespace retirement argument is not a pointer")
        pointee = records[int(pointer[2]["type_id"])]
        if pointee[:2] != ("STRUCT", "user_namespace"):
            raise ValueError("namespace retirement argument is not user_namespace *")
    except (KeyError, IndexError) as cause:
        raise ValueError("incomplete namespace retirement BTF graph") from cause


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("btf", type=Path)
    arguments = parser.parse_args()
    try:
        with arguments.btf.open() as btf:
            check_kernel(arguments.config.read_text(), btf)
    except ValueError as cause:
        parser.exit(1, f"userns BPF kernel contract: {cause}\n")
    print("userns BPF kernel contract: typed fentry prerequisites verified")


if __name__ == "__main__":
    main()
