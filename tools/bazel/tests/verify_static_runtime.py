"""Qualifies declared static runtime inputs and execution/target separation."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from verify_cache import execution_events


def expanded_command(graph, event):
    """Matches expanded arguments to the executed action's parameter digest."""
    targets = {target["id"]: target["label"] for target in graph["targets"]}
    actions = [action for action in graph["actions"]
               if targets[action["targetId"]] == event["targetLabel"]
               and action["mnemonic"] == event["mnemonic"]]
    if len(actions) != 1:
        raise ValueError("executed action does not match retained action graph")
    expanded = actions[0]["arguments"]
    executed = event["commandArgs"]
    parameters = [index for index, argument in enumerate(executed) if argument.startswith("@")]
    if not parameters:
        if expanded != executed:
            raise ValueError("executed command differs from retained action graph")
        return expanded

    # These Rust actions use Bazel's multiline trailing response file. Reject
    # other layouts rather than guessing quoting or parameter-file boundaries.
    if parameters != [len(executed) - 1] or expanded[:parameters[0]] != executed[:-1]:
        raise ValueError("unsupported executed parameter-file layout")
    path = executed[-1][1:]
    inputs = {entry["path"]: entry for entry in event["inputs"]}
    if path not in inputs:
        raise ValueError("executed parameter file omitted from retained evidence")
    contents = "\n".join(expanded[parameters[0]:]) + "\n"
    digest = hashlib.sha256(contents.encode()).hexdigest()
    if digest != inputs[path].get("digest", {}).get("hash"):
        raise ValueError("retained parameter contents differ from executed action input")
    return expanded


def inspect_elf(binary, readelf):
    """Requires a classic static executable without an interpreter or imports."""
    header = subprocess.check_output([str(readelf), "-h", str(binary)], text=True)
    program = subprocess.check_output([str(readelf), "-l", str(binary)], text=True)
    dynamic = subprocess.check_output([str(readelf), "-d", str(binary)], text=True)
    if not re.search(r"Type:\s+EXEC\b", header) or "INTERP" in program or "(NEEDED)" in dynamic:
        raise ValueError(f"artifact is not a classic static executable: {binary}")
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30, check=True)
    if result.stdout != "native-libraries=42\n" or result.stderr:
        raise ValueError(f"static native ABI probe differs: {result}")
    return {"sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "header": header, "program_headers": program, "dynamic": dynamic,
            "stdout": result.stdout}


def verify(build, package, libraries, readelf):
    """Checks actual link inputs, native ABI behavior, and target-only flags."""
    events = execution_events(build)
    graph = json.loads((build / "evidence/actions.json").read_text())
    prefix = "//tools/bazel/tests/static-runtime:"
    identities = {name: json.loads((libraries / name / "closure.json").read_text())
                  for name in ["sqlite", "zstd", "static"]}
    required = {f"{name}/lib/{Path(identity['libraryFile']).name}":
                Path(identity["package"]) / identity["libraryFile"]
                for name, identity in identities.items() if name != "static"}
    required.update({f"static/lib/{name}": libraries / "static/lib" / name
                     for name in ["libc.a", "libm.a", "libgcc_eh.a"]})
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in required.items()}
    actions = {}
    for name, mnemonic in [("rust_app", "Rustc"), ("c_app", "CppLink")]:
        selected = [event for event in events
                    if event["targetLabel"] == prefix + name and event["mnemonic"] == mnemonic]
        if len(selected) != 1 or "sandbox" not in selected[0]["runner"]:
            raise ValueError(f"missing actual sandboxed static link: {name}")
        event = selected[0]
        inputs = event["inputs"]
        for path, digest in hashes.items():
            if not any(entry["path"].endswith("/" + path) and
                       entry.get("digest", {}).get("hash") == digest for entry in inputs):
                raise ValueError(f"static link omitted exact archive/script bytes: {name}: {path}")
        for library in identities:
            if not any(entry["path"].endswith(f"/{library}/closure.json") for entry in inputs):
                raise ValueError(f"static link omitted realized library closure: {name}: {library}")
        actions[name] = {"mnemonic": mnemonic, "input_count": len(inputs), "selected_inputs": hashes,
                         "command": expanded_command(graph, event)}

    macros = [event for event in events if event["targetLabel"] == prefix + "execution_macro"
              and event["mnemonic"] == "Rustc"]
    if len(macros) != 1 or "sandbox" not in macros[0]["runner"]:
        raise ValueError("missing sandboxed execution-platform procedural macro")
    macro_command = expanded_command(graph, macros[0])
    if not any("proc-macro" in argument for argument in macro_command):
        raise ValueError("execution macro did not compile as a procedural macro")
    if any("crt-static" in argument or "relocation-model=static" in argument for argument in macro_command):
        raise ValueError("guest flags reached execution-platform procedural macro")
    for flag in ["target-feature=+crt-static", "relocation-model=static"]:
        if not any(flag in argument for argument in actions["rust_app"]["command"]):
            raise ValueError(f"static target did not receive {flag}")
    artifacts = {name: inspect_elf(package / "bin" / name, readelf) for name in ["static-c", "static-rust"]}
    return {"schema_version": 1, "libraries": identities, "actions": actions,
            "execution_macro_command": macro_command, "artifacts": artifacts}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["build", "package", "libraries", "readelf", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    report = verify(options.build, options.package, options.libraries, options.readelf)
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
