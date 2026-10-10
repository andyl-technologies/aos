# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile actual fixed-root source bodies with independent adverse oracles.

Root and admission predicates in the C models are synthetic. These checks
protect native policy and byte-custody mechanics; they do not qualify a node,
Ready, source roots, callback evaluation, input closure, or process images.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import struct
import subprocess


def exact_function(text, signature):
    """Retain one actual native function through its column-zero closing brace."""
    if text.count(signature) != 1:
        raise SystemExit("native function signature is missing or ambiguous")
    start = text.index(signature)
    end = text.find("\n}\n", start)
    if end < 0:
        raise SystemExit("native function closing brace is missing")
    return text[start:end + 3]


def implementation(source, case):
    if case == "registration":
        text = (source / "accel/tcg/tcg-accel-ops-sim-shmem.c").read_text()
        return exact_function(text,
                              "int qemu_plugin_register_crucible_node_root_policy(\n")

    text = (source / "hw/nvram/fw_cfg.c").read_text()
    first = "struct FWCfgEntry {"
    last = "int fw_cfg_crucible_root_firmware_inventory("
    if text.count(first) != 1:
        raise SystemExit("native FW_CFG entry definition is ambiguous")
    final_function = exact_function(text, last)
    end = text.index(last) + len(final_function)
    return text[text.index(first):end]


def configured_flags(source):
    # Co-retain the complete fixture directory in the derivation. The existing
    # configured-flags helper is a source-independent build adapter.
    path = Path(__file__).with_name("native-observation-model.py")
    specification = importlib.util.spec_from_file_location("native_flags", path)
    if specification is None or specification.loader is None:
        raise SystemExit("co-retained configured-flags helper is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module.configured_flags(source)


def compile_model(source, compiler, output, case, body):
    output.mkdir(parents=True, exist_ok=True)
    name = "native-root-registration-model.c.in" if case == "registration" else "native-fwcfg-roots-model.c.in"
    marker = "@NATIVE_REGISTRATION@" if case == "registration" else "@NATIVE_FWCFG@"
    template = Path(__file__).with_name(name).read_text()
    if template.count(marker) != 1:
        raise SystemExit("native insertion point is ambiguous")
    translation = output / "model.c"
    translation.write_text(template.replace(marker, body))
    directory, flags = configured_flags(source)
    executable = output / "model"
    command = [str(compiler), *flags, str(translation), "-o", str(executable),
               "-lglib-2.0", "-pthread"]
    (output / "compile-command.json").write_text(json.dumps(command, indent=2) + "\n")
    subprocess.run(command, cwd=directory, check=True, timeout=90)
    if not executable.is_file():
        raise SystemExit("native model executable is missing")
    return executable


def exercise(executable, output, case):
    if case == "registration":
        subprocess.run([str(executable)], check=True, timeout=10)
        return

    record = output / "original-digest.bin"
    subprocess.run([str(executable), str(record)], check=True, timeout=10)
    # Independent logical BE encoding of the model's complete 64-entry tables,
    # original file-order entry and eight owned payload bytes.
    preimage = b"CNPFWCFG01" + struct.pack(">3I", 64, 1, 0)
    for arch in range(2):
        for key in range(64):
            present = arch == 0 and key == 32
            preimage += struct.pack(">4I", arch, key, int(present), 8 if present else 0)
            if present:
                preimage += bytes(range(8))
    if record.read_bytes() != hashlib.sha256(preimage).digest():
        raise AssertionError("native FW_CFG digest differs from independent BE oracle")


def mutations(case):
    if case == "registration":
        return [
            ("whole-original-policy", "memcmp(original, &node_root_policy, sizeof(*original))", "false"),
            ("original-process", "node_root_launch_process != getpid()", "false"),
            ("original-pins", "!crucible_node_root_original_pins_match()", "false"),
            ("original-bql", "!bql_locked()", "false"),
            ("no-prior-execution", "if (qemu_plugin_icount_raw() ||", "if (false ||"),
        ]
    return [
        ("sealed-lifetime",
         "if (crucible_firmware_alias.sealed &&\n"
         "        (crucible_firmware_alias.original_process != getpid() ||\n"
         "         owner == crucible_firmware_alias.owner)) {",
         "if (false &&\n"
         "        (crucible_firmware_alias.original_process != getpid() ||\n"
         "         owner == crucible_firmware_alias.owner)) {"),
        ("original-data-owner", "held->data != entry->data", "false"),
        ("original-process", "(crucible_firmware_alias.original_process != getpid() ||\n         crucible_firmware_alias.owner != original ||", "(false ||\n         crucible_firmware_alias.owner != original ||"),
        ("bounded-source", "entry->len > FW_CFG_CRUCIBLE_ROOT_MAX_BYTES - total", "false"),
        ("original-cursor", "inventory.current_offset = original->cur_offset;", "inventory.current_offset = 0;"),
        ("canonical-endian", "uint32_t encoded = cpu_to_be32(value);", "uint32_t encoded = cpu_to_le32(value);"),
        ("canonical-domain", '(const uint8_t *)"CNPFWCFG01", 10', '(const uint8_t *)"CNPFWCFG01", 9'),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=("registration", "fwcfg"))
    parser.add_argument("source", type=Path)
    parser.add_argument("compiler", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--mutations", action="store_true")
    arguments = parser.parse_args()
    source, output = arguments.source.resolve(), arguments.output.resolve()
    body = implementation(source, arguments.case)
    executable = compile_model(source, arguments.compiler, output / "original",
                               arguments.case, body)
    exercise(executable, output / "original", arguments.case)
    count = 0
    if arguments.mutations:
        for name, original, replacement in mutations(arguments.case):
            if body.count(original) != 1:
                raise SystemExit(f"native mutation predicate is ambiguous: {name}")
            mutant = body.replace(original, replacement, 1)
            directory = output / name
            executable = compile_model(source, arguments.compiler, directory,
                                       arguments.case, mutant)
            try:
                exercise(executable, directory, arguments.case)
            except subprocess.CalledProcessError as failure:
                if failure.returncode != -signal.SIGABRT:
                    raise SystemExit(f"mutant did not reach a native assertion: {name}")
                count += 1
            except AssertionError:
                if name not in ("canonical-endian", "canonical-domain"):
                    raise
                count += 1
            else:
                raise SystemExit(f"compiled causal negative survived: {name}")
    print(f"PASS actual fixed-root {arguments.case}: original + {count} compiled negatives; no Ready/effect qualification")


if __name__ == "__main__":
    main()
