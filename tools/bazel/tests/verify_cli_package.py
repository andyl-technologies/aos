"""Compares installed CLI outputs, entry points, and native loader contracts."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

from installed_package import compare_installed, inventory, runtime_closures


def validate_openssl_flags(text):
    """Rejects archive linking even when the OpenSSL feature set is correct."""
    flags = shlex.split(text)
    for library in ("ssl", "crypto"):
        declarations = [flag for flag in flags if re.fullmatch(r"-l(?:[^=]+=)?" + library, flag)]
        if len(declarations) != 1 or declarations[0] not in ("-l" + library, "-ldylib=" + library):
            raise ValueError("OpenSSL must link the AOS shared library: " + library)
    return flags


def shared_openssl_linkage(build):
    """Inspects the retained, digest-bound linker inputs of the actual build."""
    retained = json.loads((build / "evidence/compiler-inputs.json").read_text())
    selected = {}
    for name, record in retained["files"].items():
        if "__openssl-sys-" not in name or not name.endswith("/_bs.linkflags"):
            continue
        if hashlib.sha256(record["text"].encode()).hexdigest() != record["sha256"]:
            raise ValueError("retained OpenSSL linker input has an invalid digest")
        selected[name] = {"sha256": record["sha256"], "flags": validate_openssl_flags(record["text"])}
    if not selected:
        raise ValueError("CLI compilation omitted retained OpenSSL linker evidence")
    return selected


def dynamic_symbols(path, readelf, *, undefined):
    """Reads versioned dynamic symbols without depending on column widths."""
    output = subprocess.check_output([str(readelf), "--dyn-syms", "--wide", str(path)], text=True)
    symbols = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].rstrip(":").isdigit() and (fields[6] == "UND") == undefined:
            symbols.add(fields[7].split("@")[0])
    return symbols


def openssl_imports(packages, records, readelf):
    """Compares imports against exports from the libraries the AOS loader selected."""
    result = {}
    exports = {}
    for name, ordinary in records["ordinary"].items():
        if ordinary["kind"] != "elf":
            continue
        libraries = [path for path in ordinary["contract"]["resolved_libraries"]
                     if re.fullmatch(r"lib(?:ssl|crypto)\.so(?:\..+)?", Path(path).name)]
        library_symbols = set()
        for library in libraries:
            if library not in exports:
                exports[library] = dynamic_symbols(library, readelf, undefined=False)
            library_symbols.update(exports[library])

        output, relative = name.split("/", 1)
        imports = {driver: sorted(dynamic_symbols(Path(paths[output]) / relative, readelf, undefined=True)
                                  & library_symbols)
                   for driver, paths in packages.items()}
        if imports["ordinary"] != imports["bazel"]:
            raise ValueError("installed OpenSSL imports differ: " + name)
        result[name] = imports["bazel"]
    return result


def verify(options):
    linkage = shared_openssl_linkage(options.bazel_build)
    packages = json.loads(options.packages.read_text())
    if set(packages) != {"ordinary", "bazel"}:
        raise ValueError("package comparison needs both production drivers")
    expected = {"out", "apm", "apr", "packageRuntime", "testSupport"}
    if any(set(outputs) != expected for outputs in packages.values()):
        raise ValueError("CLI output inventory differs")
    closures = runtime_closures(packages, json.loads(options.closure_attributes.read_text()))
    records = {name: inventory(outputs, options.readelf, options.loader) for name, outputs in packages.items()}
    search_changes = compare_installed(records["ordinary"], records["bazel"])
    imports = openssl_imports(packages, records, options.readelf)

    commands = {"aos": "out", "apm": "apm", "apr": "apr", "aos-package-runtime": "packageRuntime"}
    help_digests = {}
    for command, output in commands.items():
        results = {}
        for driver, outputs in packages.items():
            executable = Path(outputs[output]) / "bin" / command
            result = subprocess.run([str(executable), "--help"], capture_output=True, check=True, timeout=30)
            results[driver] = (result.stdout, result.stderr)
        if results["ordinary"] != results["bazel"]:
            raise ValueError("installed CLI help differs: " + command)
        help_digests[command] = {stream: hashlib.sha256(value).hexdigest()
                                 for stream, value in zip(("stdout", "stderr"), results["bazel"])}
    return {
        "schema_version": 1,
        "packages": packages,
        "installed": records["bazel"],
        "ordinary_installed": records["ordinary"],
        "library_search_changes": search_changes,
        "openssl_build_script_linkage": linkage,
        "openssl_imports": imports,
        "runtime_closures": closures,
        "help": help_digests,
        "normalization": "Only each package's own five output paths are replaced in non-ELF text and symlink targets.",
        "excluded_driver_diagnostics": ["out/nix-support/cargo-build-messages.jsonl"],
        "scope": (
            "Installed structure, permissions, text, CLI help, and ELF loading; full CLI integration, "
            "ABI, platform, and performance qualification remain separate gates."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("packages", "readelf", "loader", "closure-attributes", "bazel-build", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
