# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile exact held-source bodies and causal assertion mutants.

The source models protect dormant registration and negative admissions only.
They do not certify a RootSeal, epoch, input closure, Ready or process image.
The complete fixture directory is retained because configured-flags imports
the existing native observation helper.
"""

import argparse
import importlib.util
from pathlib import Path
import signal
import subprocess


def exact_function(text, signature):
    """Extract one actual source function through its native closing brace."""
    if text.count(signature) != 1:
        raise SystemExit("native function signature is missing or ambiguous")
    start = text.index(signature)
    end = text.find("\n}\n", start)
    if end < 0:
        raise SystemExit("native function closing brace is absent")
    return text[start : end + 3]


def configured_flags(source):
    path = Path(__file__).with_name("native-observation-model.py")
    specification = importlib.util.spec_from_file_location("native_flags", path)
    if specification is None or specification.loader is None:
        raise SystemExit("co-retained configured-flags helper is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module.configured_flags(source)


def compile_and_run(source, compiler, output, case, body, mutant):
    template = Path(__file__).with_name(f"native-held-{case}-model.c.in").read_text()
    marker = f"@NATIVE_{case.upper()}@"
    if template.count(marker) != 1:
        raise SystemExit("native template insertion is missing or ambiguous")
    output.mkdir(parents=True, exist_ok=True)
    translation = output / "model.c"
    translation.write_text(template.replace(marker, body))
    directory, flags = configured_flags(source)
    binary = output / "model"
    subprocess.run([str(compiler), *flags, str(translation), "-o", str(binary),
                    "-lglib-2.0", "-pthread"], cwd=directory, check=True,
                   timeout=90)
    if not binary.is_file():
        raise SystemExit("native model executable is absent")
    completed = subprocess.run([str(binary)], capture_output=True, timeout=30)
    expected = -signal.SIGABRT if mutant else 0
    if completed.returncode != expected:
        raise SystemExit(f"native {case} returned {completed.returncode}: "
                         f"{completed.stderr.decode(errors='replace')}")
    if not mutant:
        print(completed.stdout.decode(), end="", flush=True)


def endpoint_body(source):
    text = (source / "util/crucible-endpoint-roots.c").read_text()
    start = text.index("#define ENDPOINT_HELD")
    return text[start:]


def endpoint_mutants(body):
    edits = [
        ("immediate-exit", "    _exit(125);", "    exit(125);"),
        ("persistent-hold", "observed & ENDPOINT_HELD", "false"),
        ("foreign-process", "getpid() != endpoint_original_process ||",
         "false ||"),
        ("history-reply", "return nonempty ? -ENOTSUP : 0;",
         "return nonempty ? 0 : 0;"),
    ]
    for label, original, replacement in edits:
        count = body.count(original)
        expected = 2 if label == "foreign-process" else 1
        if count != expected:
            raise SystemExit(f"native causal predicate changed: {label}")
        yield label, body.replace(original, replacement, 1)


def irq_body(source):
    text = (source / "hw/core/irq.c").read_text()
    start = text.index("#define QEMU_IRQ_NODE_ROOT_MAX")
    end = text.index("static QemuIrqNodeRoot *node_irq_root_find")
    # The real source now includes its separately declared controller9
    # provider. Keep the default provider absent in the legacy template and
    # extract both actual helpers without modeling away the sealed branch.
    header = '#include "qemu/crucible-prefix-writer.h"\n'
    return (header + text[start:end] +
            exact_function(text, "static QemuIrqNodeRoot *node_irq_root_find(") +
            exact_function(text, "static bool node_irq_prefix_delivery(") +
            exact_function(text, "void qemu_set_irq("))


def irq_mutants(body):
    functions = [
        ("delivery", "void qemu_set_irq("),
        ("lifetime", "void qemu_irq_node_root_lifetime_guard("),
        ("cpu", "void qemu_irq_node_root_cpu_mutation_guard("),
    ]
    clauses = [
        ("sealed", "qatomic_load_acquire(&node_irq_roots.sealed)", "false"),
        ("original-process", "node_irq_roots.original_process != getpid()", "false"),
        ("original-thread", "node_irq_roots.original_constructor_thread != qemu_get_thread_id()", "false"),
    ]
    for function_name, signature in functions:
        original_body = exact_function(body, signature)
        for clause_name, original, replacement in clauses:
            if original_body.count(original) != 1:
                raise SystemExit("native writer predicate is missing or ambiguous")
            changed_body = original_body.replace(original, replacement)
            label = function_name + "-" + clause_name
            yield label, body.replace(original_body, changed_body, 1)



def epoch_body(source):
    text = (source / "accel/tcg/tcg-accel-ops-sim-shmem.c").read_text()
    return exact_function(text, "int qemu_plugin_register_crucible_node_root_epoch(")


def epoch_mutants(body):
    edits = [
        ("original-policy", "memcmp(original, &node_root_policy, sizeof(*original))", "false"),
        ("original-process", "node_root_launch_process != getpid()", "false"),
        ("retained-registration", "!node_root_registered", "false"),
        ("original-pins", "!crucible_node_root_original_pins_match()", "false"),
        ("callback-retry", "node_root_epoch.begin == begin", "true"),
        ("userdata-retry", "node_root_epoch.userdata == userdata", "true"),
        ("fresh-raw", "qemu_plugin_icount_raw()", "false"),
    ]
    for label, original, replacement in edits:
        if body.count(original) != 1:
            raise SystemExit(f"native registrar predicate changed: {label}")
        yield label, body.replace(original, replacement, 1)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("compiler", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--case", choices=["endpoint", "irq", "epoch"], default="endpoint")
    arguments = parser.parse_args()
    bodies = {
        "endpoint": endpoint_body,
        "irq": irq_body,
        "epoch": epoch_body,
    }
    body = bodies[arguments.case](arguments.source)
    compile_and_run(arguments.source, arguments.compiler,
                    arguments.output / "original", arguments.case, body, False)
    mutations = {
        "endpoint": endpoint_mutants,
        "irq": irq_mutants,
        "epoch": epoch_mutants,
    }
    mutants = mutations[arguments.case](body)
    for label, changed in mutants:
        compile_and_run(arguments.source, arguments.compiler,
                        arguments.output / label, arguments.case, changed, True)
        print(f"PASS compiler-success causal assertion mutant {label}", flush=True)


if __name__ == "__main__":
    main()
