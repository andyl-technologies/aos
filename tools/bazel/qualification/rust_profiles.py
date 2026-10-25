"""Qualifies ordinary Rust-family target and execution compiler profiles.

First-party compilations are paired by source and libtest role using retained,
digest-bound compiler inputs. Procedural macros additionally retain package
versions, crate names and explicit cfg values, so two versions of one macro
cannot collapse into a single comparison. This checks selected scalar profile
settings; it does not establish complete compiler or linker equivalence.
"""

import argparse
import hashlib
import json
from pathlib import Path

from reconstruct_compiler_inputs import reconstruct
from verify_cache import execution_events
from verify_compiler_options import audit, cargo_compilation_source, compiler_options


def option_values(arguments, name):
    """Reads paired or equals-form values without collapsing repeated options."""
    values = []
    for index, argument in enumerate(arguments):
        if argument == name:
            if index + 1 == len(arguments) or arguments[index + 1].startswith("-"):
                raise ValueError("missing compiler option value: " + name)
            values.append(arguments[index + 1])
        elif argument.startswith(name + "="):
            values.append(argument[len(name) + 1:])
    if any(not value for value in values):
        raise ValueError("empty compiler option: " + name)
    return values


def option(arguments, name):
    """Requires a unique nonempty compiler option value."""
    values = option_values(arguments, name)
    if len(values) != 1:
        raise ValueError("missing or ambiguous compiler option: " + name)
    return values[0]


def enabled(value, default):
    """Interprets a Rust boolean while preserving absent values in evidence."""
    if value is None:
        return default
    if value is True or value in {"yes", "on", "true"}:
        return True
    if value in {"no", "off", "false"}:
        return False
    raise ValueError("unsupported Rust boolean: " + str(value))


def profile(arguments, optimization, explicit):
    """Checks optimization, debug information, assertions and overflow checks."""
    scalar = compiler_options(arguments)["effective_scalar_codegen"]
    required = {"opt-level", "debuginfo", "debug-assertions", "overflow-checks"}
    if explicit and not required <= scalar.keys():
        raise ValueError("Bazel compiler profile omitted explicit settings")
    if scalar.get("opt-level", "0") != optimization or scalar.get("debuginfo", "0") != "0":
        raise ValueError("compiler optimization or debug information differs: " + str(scalar))
    assertions = enabled(scalar.get("debug-assertions"), optimization == "0")
    overflow = enabled(scalar.get("overflow-checks"), assertions)
    if not assertions or not overflow:
        raise ValueError("ordinary test profile disabled assertions or overflow checks")
    return scalar


def macro_key(package, version, arguments):
    """Identifies a macro without losing versions or configured feature units."""
    if not package or not version or option(arguments, "--crate-type") != "proc-macro":
        raise ValueError("procedural macro omitted its exact package identity or role")
    options = compiler_options(arguments)
    return package, version, option(arguments, "--crate-name"), tuple(options["cfg"])


def native_macros(invocations):
    """Indexes actual native macro requests, excluding compiler capability queries."""
    result = {}
    for invocation in invocations:
        if invocation.get("schema_version") != 1:
            raise ValueError("unsupported Cargo compiler trace schema")
        arguments = invocation["arguments"]
        if any(argument == "--print" or argument.startswith("--print=") for argument in arguments):
            continue
        types = [
            kind
            for value in option_values(arguments, "--crate-type")
            for kind in value.split(",")
        ]
        if "proc-macro" not in types:
            continue
        environment = invocation["environment"]
        key = macro_key(
            environment.get("CARGO_PKG_NAME"),
            environment.get("CARGO_PKG_VERSION"),
            arguments,
        )
        if key in result:
            raise ValueError("duplicate native procedural macro unit: " + str(key))
        result[key] = {"arguments": arguments, "scalar": profile(arguments, "0", False)}
    if not result:
        raise ValueError("native procedural macro inventory is empty")
    return result


def generator_sources(messages):
    """Selects first-party generators from Cargo artifacts, including custom paths."""
    sources = set()
    for message in messages:
        if message.get("reason") != "compiler-artifact":
            continue
        if "custom-build" not in message["target"]["kind"]:
            continue
        source = cargo_compilation_source({
            "directory": str(Path(message["manifest_path"]).parent),
            "arguments": [message["target"]["src_path"]],
        })
        if source is None:
            continue
        if source in sources:
            raise ValueError("ambiguous native first-party generator source: " + source)
        sources.add(source)
    return sources


def match_macros(actions, reports, native):
    """Requires every configured macro action to match an exact native unit."""
    declarations = {}
    for report in reports:
        if report["kind"] != "rust_proc_macro":
            continue
        if report["label"] in declarations:
            raise ValueError("ambiguous configured procedural macro label")
        names = [
            tag.removeprefix("crate-name=")
            for tag in report["tags"]
            if tag.startswith("crate-name=")
        ]
        if len(names) != 1 or not report["version"]:
            raise ValueError("configured macro omitted its exact package identity")
        declarations[report["label"]] = names[0], report["version"]

    selected = {}
    labels = set()
    for action in actions:
        label = action["target_label"]
        if label not in declarations:
            continue
        key = macro_key(*declarations[label], action["arguments"])
        if key in selected or label in labels:
            raise ValueError("duplicate executed procedural macro unit: " + str(key))
        if key not in native:
            raise ValueError("Bazel procedural macro has no matching native unit: " + str(key))
        actual_options = compiler_options(action["arguments"])
        native_options = compiler_options(native[key]["arguments"])
        if actual_options["edition"] != native_options["edition"]:
            raise ValueError("procedural macro editions differ: " + str(key))
        selected[key] = {
            "label": label,
            "edition": actual_options["edition"],
            "bazel_scalar": profile(action["arguments"], "0", True),
            "native_scalar": native[key]["scalar"],
            "remaining_option_differences": {
                field: {"bazel": actual_options[field], "cargo": native_options[field]}
                for field in actual_options
                if actual_options[field] != native_options[field]
            },
        }
        labels.add(label)
    if not selected or labels != declarations.keys() or selected.keys() != native.keys():
        raise ValueError("configured, executed and native procedural macro inventories differ")
    return [
        {
            "package": key[0], "version": key[1], "crate_name": key[2],
            "cfg": list(key[3]), **value,
        }
        for key, value in sorted(selected.items())
    ]


def verify(build, cargo):
    """Audits every first-party compiler unit and configured procedural macro."""
    evidence = build / "evidence"
    events = execution_events(build)
    rust_events = [event for event in events if event["mnemonic"] == "Rustc"]
    if not rust_events or any(
        event["runner"] != "linux-sandbox" or event["cacheHit"] or event["exitCode"] != 0
        for event in rust_events
    ):
        raise ValueError("profile qualification requires actual uncached Linux sandbox compilation")
    actions = reconstruct(
        json.loads((evidence / "actions.json").read_text()), events,
        json.loads((evidence / "compiler-inputs.json").read_text()),
    )["actions"]
    paired = audit(build, cargo)
    messages = [
        json.loads(line)
        for line in (cargo / "cargo-messages.jsonl").read_text().splitlines()
    ]
    generators = generator_sources(messages)
    first_party = []
    for pair in paired["pairs"]:
        generator = pair["source"] in generators
        optimization = "0" if generator else "s"
        first_party.append({
            "source": pair["source"], "test": pair["test"], "label": pair["bazel"]["label"],
            "role": "generator" if generator else "target",
            "bazel_scalar": profile(pair["bazel"]["arguments"], optimization, True),
            "native_scalar": profile(pair["cargo"]["arguments"], optimization, False),
            "remaining_option_differences": pair["differences"],
        })
    if not any(unit["test"] for unit in first_party) or not any(unit["role"] == "generator" for unit in first_party):
        raise ValueError("family qualification omitted test or generator compiler units")
    if {unit["source"] for unit in first_party if unit["role"] == "generator"} != generators:
        raise ValueError("native generator artifacts and paired compiler units differ")

    trace = cargo / "compiler-arguments.jsonl"
    invocations = [json.loads(line) for line in trace.read_text().splitlines()]
    reports = json.loads((build / "inventory.json").read_text())["configured_targets"]
    macros = match_macros(actions, reports, native_macros(invocations))
    return {
        "schema_version": 1, "status": "PASS", "build": str(build), "cargo": str(cargo),
        "first_party_units": first_party, "procedural_macros": macros,
        "evidence_sha256": {name: hashlib.sha256((evidence / name).read_bytes()).hexdigest()
                            for name in ["actions.json", "execution.json", "compiler-inputs.json"]},
        "native_trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
        "limits": [
            "Pairs every first-party source/libtest unit and exact macro package/version/cfg unit in this native test family.",
            "Checks selected scalar optimization, debug information, assertion and overflow settings against actual native compiler requests. Other explicit option differences remain visible.",
            "The required independent Cargo/test parity gate proves successful native compilation and execution; a captured compiler request alone does not prove success.",
            "Complete compiler defaults, native C/C++ flags, linker/ABI equivalence, runtime closure, editor/release/foreign profiles, cache behavior and performance acceptance remain separate.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options.build, options.cargo), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
