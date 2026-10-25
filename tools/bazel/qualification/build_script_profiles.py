"""Checks executed build-script metadata against target and execution compilers.

The fixture forwards its observed environment into generated rustc environment
files. Reconstruction authenticates those files against executed input digests.
The real pinned libm dependency independently turns OPT_LEVEL into a compiler cfg.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from reconstruct_compiler_inputs import reconstruct
from verify_cache import execution_events
from verify_compiler_options import compiler_options


PREFIX = "//tools/bazel/qualification/build-script-profile:"
LIBM = "@@+aos_tools_repository+aos_aos_cli_tests_crates__libm-0.2.16//:"
PROFILE_KEYS = ("OPT_LEVEL", "DEBUG", "PROFILE", "HOST", "TARGET")


def expected_profile(name, role, native):
    """Defines the independent profile contract for each fixture configuration."""
    execution = role == "execution"
    return {
        "OPT_LEVEL": "0" if execution or name == "editor" else "s",
        "DEBUG": "true" if name == "editor" and not execution else "false",
        "PROFILE": "release" if name == "release" else "debug",
        "HOST": native,
        "TARGET": "wasm32-unknown-unknown" if name == "wasm" and not execution else native,
    }


def compiler_role(arguments, configurations):
    """Identifies the actual compiler configuration through its output directory."""
    directories = []
    for index, argument in enumerate(arguments):
        if argument == "--out-dir" and index + 1 < len(arguments):
            directories.append(arguments[index + 1])
        elif argument.startswith("--out-dir="):
            directories.append(argument[len("--out-dir="):])
    if len(directories) != 1:
        raise ValueError("compiler omitted a unique output directory")
    roles = {
        "execution" if configuration.get("isTool", False) else "target"
        for configuration in configurations
        if directories[0].startswith("bazel-out/" + configuration["mnemonic"] + "/")
    }
    if len(roles) != 1:
        raise ValueError("compiler output does not identify one configured role")
    return roles.pop()


def verify(name, build):
    """Requires exact build-script and compiler units with uncached execution."""
    evidence = build / "evidence"
    graph = json.loads((evidence / "actions.json").read_text())
    retained = json.loads((evidence / "compiler-inputs.json").read_text())
    events = execution_events(build)
    if not events or any(event["exitCode"] != 0 or event["cacheHit"]
                         or event["runner"] != "linux-sandbox" for event in events):
        raise ValueError("profile qualification requires successful uncached Linux actions")
    compiled = reconstruct(graph, events, retained)["actions"]
    targets = {str(row["id"]): row["label"] for row in graph["targets"]}
    configurations = {str(row["id"]): row for row in graph["configuration"]}
    fixture_script = PREFIX + "build_script"
    libm_script = LIBM + "_bs"
    expected_units = {(fixture_script, "target"), (fixture_script, "execution"), (libm_script, "execution")}
    if name != "wasm":
        expected_units.add((libm_script, "target"))

    macro_compilers = [row for row in compiled if row["target_label"] == PREFIX + "profile_macro"]
    if len(macro_compilers) != 1:
        raise ValueError("profile qualification requires one native procedural macro")
    native = compiler_options(macro_compilers[0]["arguments"])["target"]
    if not native or native == "wasm32-unknown-unknown":
        raise ValueError("procedural macro must use an explicit native compiler target")
    scripts = {}
    for action in graph["actions"]:
        label = targets[str(action["targetId"])]
        if action["mnemonic"] != "CargoBuildScriptRun" or label not in {fixture_script, libm_script}:
            continue
        role = "execution" if configurations[str(action["configurationId"])].get("isTool", False) else "target"
        environment = {row["key"]: row.get("value", "") for row in action["environmentVariables"]}
        profile = {key: environment[key] for key in PROFILE_KEYS}
        unit = label, role
        if unit in scripts or profile != expected_profile(name, role, native):
            raise ValueError("build-script profile differs or is duplicated: " + repr(unit))
        scripts[unit] = profile
    if scripts.keys() != expected_units:
        raise ValueError("incomplete configured build-script inventory")

    # Authenticate the analyzed environment against the actual executed actions.
    executed = []
    for event in events:
        if event["mnemonic"] == "CargoBuildScriptRun" and event["targetLabel"] in {fixture_script, libm_script}:
            environment = {row["name"]: row.get("value", "") for row in event["environmentVariables"]}
            executed.append((event["targetLabel"], tuple(environment[key] for key in PROFILE_KEYS)))
    analyzed = [(label, tuple(profile[key] for key in PROFILE_KEYS)) for (label, _), profile in scripts.items()]
    if Counter(executed) != Counter(analyzed):
        raise ValueError("executed build scripts differ from their analyzed profiles")

    compilers = {}
    for invocation in compiled:
        label = invocation["target_label"]
        if label not in {PREFIX + "library", PREFIX + "profile_macro", LIBM + "libm"}:
            continue
        role = compiler_role(invocation["arguments"], configurations.values())
        unit = label, role
        expected = expected_profile(name, role, native)
        options = compiler_options(invocation["arguments"])
        scalar = options["effective_scalar_codegen"]
        debug = "2" if expected["DEBUG"] == "true" else "0"
        if unit in compilers or scalar.get("opt-level") != expected["OPT_LEVEL"] or scalar.get("debuginfo") != debug:
            raise ValueError("actual compiler profile differs: " + repr(unit))
        if label.startswith(PREFIX):
            generated = {key: invocation["environment"].get("AOS_PROFILE_" + key) for key in PROFILE_KEYS}
            if generated != expected:
                raise ValueError("compiler did not consume its generated build-script environment")
        elif ("optimizations_enabled" in options["cfg"]) != (expected["OPT_LEVEL"] not in {"0", "1"}):
            raise ValueError("libm's generated optimization cfg differs from its compiler")
        compilers[unit] = {"scalar_codegen": scalar, "cfg": options["cfg"]}
    expected_compilers = {(PREFIX + "library", "target"), (PREFIX + "profile_macro", "execution"), (LIBM + "libm", "execution")}
    if name != "wasm":
        expected_compilers.add((LIBM + "libm", "target"))
    if compilers.keys() != expected_compilers:
        raise ValueError("incomplete executed compiler inventory")

    return {
        "build": str(build),
        "executed_actions": len(events),
        "build_scripts": [{"label": label, "role": role, **profile} for (label, role), profile in sorted(scripts.items())],
        "compilers": [{"label": label, "role": role, **profile} for (label, role), profile in sorted(compilers.items())],
        "inputs_sha256": {filename: hashlib.sha256((evidence / filename).read_bytes()).hexdigest()
                          for filename in ["actions.json", "execution.json", "compiler-inputs.json"]},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--builds", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    builds = json.loads(options.builds.read_text())
    if builds.keys() != {"default", "release", "editor", "wasm"} or len(set(builds.values())) != 4:
        raise ValueError("qualification requires four distinct profile builds")
    results = {name: verify(name, Path(build)) for name, build in sorted(builds.items())}
    options.output.write_text(json.dumps({
        "schema_version": 1, "status": "PASS", "configurations": results,
        "scope": "Declared global target/execution profiles, generated fixture environment, and libm optimization cfgs.",
        "limits": ["This does not qualify complete native/C/linker profiles or other build families."],
    }, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
