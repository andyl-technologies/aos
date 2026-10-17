# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile actual observation implementations and adversarial native models.

Controller and inventory predicates in the C harnesses are synthetic. Socket,
thread, fork and registry effects are real; these tests do not qualify Ready,
callback timing, input closure, capture, or a complete backend profile.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import struct
import subprocess


def configured_flags(source):
    """Retain the configured system API flags, with assertions enabled."""
    commands = json.loads((source / "build/compile_commands.json").read_text())
    entries = [entry for entry in commands
               if entry["file"].endswith("/plugins/api-system.c")]
    if len(entries) != 1:
        raise SystemExit("expected exactly one configured system API command")

    entry = entries[0]
    arguments = iter(shlex.split(entry["command"])[1:])
    flags = ["-I" + str(source / "include"), "-I" + str(source)]
    for argument in arguments:
        if argument in ("-MQ", "-MF", "-o", "-c"):
            next(arguments)
        elif argument not in ("-MD", "-MMD", "-MP"):
            flags.append(argument)
    flags.append("-UNDEBUG")
    return Path(entry["directory"]), flags


def administrative_body(source):
    """Extract the complete administrative registry without other root owners."""
    text = (source / "accel/tcg/tcg-accel-ops-sim-shmem.c").read_text()
    declarations = "static QemuPluginCrucibleNodeAdministrationPolicy node_administration_policy;"
    functions = "static bool node_administration_socket_matches("
    following = "bool crucible_node_initialization_launch_pinned(void)"
    if any(text.count(marker) != 1 for marker in
           (declarations, functions, following)):
        raise SystemExit("administrative registry boundaries changed")

    start = text.index(declarations)
    finish = text.index("\n#endif\n", start) + len("\n#endif\n")
    body_start, body_end = text.index(functions), text.index(following)
    if not start < finish <= body_start < body_end:
        raise SystemExit("administrative declarations/functions are out of order")
    # Root policy owners may be defined between these two independent native
    # spans. The complete administrative declarations and functions remain
    # original source bytes; synthetic root implementations are not substituted.
    return text[start:finish] + "\n" + text[body_start:body_end]


def compile_model(source, compiler, output, case, implementation):
    """Compile the actual implementation; mutation compile failures are errors."""
    directory, flags = configured_flags(source)
    fixtures = Path(__file__).parent
    output.mkdir(parents=True, exist_ok=True)
    implementation_path = output / "production.c"
    implementation_path.write_text(implementation)
    executable = output / "model"

    if case == "finite":
        sources = [fixtures / "native-finite-arm-model.c", implementation_path]
        libraries = ["-lglib-2.0", "-pthread"]
    else:
        template = (fixtures / "native-administration-model.c.in").read_text()
        if template.count("@NATIVE_ADMINISTRATION@") != 1:
            raise SystemExit("expected one native implementation insertion point")
        implementation_path.write_text(template.replace(
            "@NATIVE_ADMINISTRATION@", implementation))
        sources = [implementation_path]
        libraries = ["-pthread"]

    command = [str(compiler), *flags, *(str(path) for path in sources),
               "-o", str(executable), *libraries]
    (output / "compile-command.json").write_text(json.dumps(command, indent=2) + "\n")
    subprocess.run(command, cwd=directory, check=True, timeout=90)
    if not executable.is_file():
        raise SystemExit("model compilation did not produce an executable")
    return executable


def finite_digest(executable, output):
    """Check the production digest using an independent canonical BE oracle."""
    record_path = output / "native-record.bin"
    subprocess.run([str(executable), "digest", str(record_path)], check=True, timeout=10)
    record = record_path.read_bytes()
    if len(record) != 376:
        raise AssertionError("expected one native summary176 and timer200")

    # The native ABI is local. Its logical fields, not its memory layout, are
    # independently encoded in the tagged canonical hash preimage.
    header = struct.unpack_from("=4I6Q", record)
    service = struct.unpack_from("=2Q", record, 160)
    timer = record[176:]
    preimage = b"crucible.qemu-native-timer-selection.v1\0"
    preimage += struct.pack(">4I6Q", *header) + record[64:128]
    preimage += struct.pack(">2Q", *service)
    preimage += struct.pack(">5Q6I5Q", *struct.unpack_from("=5Q6I5Q", timer))
    preimage += timer[104:200]
    if hashlib.sha256(preimage).digest() != record[128:160]:
        raise AssertionError("native digest disagrees with independent logical BE encoding")
    if header[:4] != (1, 176, 3, 1):
        raise AssertionError("native data-only flags/count/version changed")


def exercise(executable, output, case):
    subprocess.run([str(executable)], check=True, timeout=10)
    if case == "finite":
        subprocess.run([str(executable), "bounds"], check=True, timeout=10)
        finite_digest(executable, output)


def mutate(text, original, replacement):
    if text.count(original) != 1:
        raise SystemExit(f"expected one original mutation predicate: {original}")
    return text.replace(original, replacement, 1)


def mutations(case):
    if case == "finite":
        return [
            ("changed-held-generation", "origin->gate_generation != selection->summary.gate_generation", "false"),
            ("first-disposition", "row->status != QEMU_PLUGIN_CRUCIBLE_NODE_TIMER_DISPOSITION_PENDING ||", "false ||"),
            ("original-arm-generation", "row->arm_generation != arm_generation", "false"),
            ("retained-scope", "!memcmp(scope, selection->summary.prepared_scope_hash, 32)", "true"),
            ("published-generation", "qemu_timer_node_selection_publish(inventory.mutation_generation,", "qemu_timer_node_selection_publish(inventory.mutation_generation + 1,"),
            ("logical-hash-endian", "stl_be_p(bytes, value);", "stl_le_p(bytes, value);"),
            ("hash-domain", "g_checksum_update(checksum, (const uint8_t *)tag, sizeof(tag));", "g_checksum_update(checksum, (const uint8_t *)tag, sizeof(tag) - 1);"),
        ]
    return [
        ("original-thread", "node_administration_registration !=\n                node_administration_facts.registration_id ||\n            node_administration_facts.thread_id != thread_id ||", "false ||"),
        ("live-socket", "!node_administration_socket_matches(policy)", "false"),
        ("fork-pre-lock", "if (node_administration_launch_process != getpid()) {", "if (false) {"),
        ("unknown-roots", "QEMU_PLUGIN_CRUCIBLE_NODE_ADMINISTRATION_THREAD_OBSERVED |\n                QEMU_PLUGIN_CRUCIBLE_NODE_ADMINISTRATION_UNKNOWN_ROOTS", "QEMU_PLUGIN_CRUCIBLE_NODE_ADMINISTRATION_THREAD_OBSERVED"),
        ("original-realize", "!memcmp(node_administration_policy.realize_request_digest,\n                node_phase_policy.realize_request_digest, 32)", "true"),
        ("whole-policy", "memcmp(policy, &node_administration_policy, sizeof(*policy))", "false"),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=("finite", "administration"))
    parser.add_argument("source", type=Path)
    parser.add_argument("compiler", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--mutations", action="store_true")
    arguments = parser.parse_args()
    source = arguments.source.resolve()
    output = arguments.output.resolve()
    implementation = ((source / "util/crucible-timer-selection.c").read_text()
                      if arguments.case == "finite" else administrative_body(source))

    executable = compile_model(source, arguments.compiler, output / "original",
                               arguments.case, implementation)
    exercise(executable, output / "original", arguments.case)
    count = 0
    if arguments.mutations:
        for name, original, replacement in mutations(arguments.case):
            mutated = mutate(implementation, original, replacement)
            mutant_output = output / name
            executable = compile_model(source, arguments.compiler, mutant_output,
                                       arguments.case, mutated)
            try:
                exercise(executable, mutant_output, arguments.case)
            except subprocess.CalledProcessError as failure:
                if failure.returncode != -signal.SIGABRT:
                    raise SystemExit(f"negative did not reach a native assertion: {name}")
                count += 1
            except AssertionError:
                # Hash mutants produce an actual changed native record; the
                # independent canonical oracle, rather than a crash, refuses it.
                if name not in ("logical-hash-endian", "hash-domain"):
                    raise
                count += 1
            else:
                raise SystemExit(f"compiled negative survived: {name}")
    print(f"PASS native {arguments.case}: original model; {count} compiled causal negatives; no profile qualification")


if __name__ == "__main__":
    main()
