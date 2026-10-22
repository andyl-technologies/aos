"""Requires Bazel to reject conflicting package metadata during analysis."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


CASES = {
    "invalid-version": ('version = "1.2"', "", "Rust package version must be SemVer"),
    "numeric-prerelease": ('version = "1.2.3-01"', "", "Rust package version must be SemVer"),
    "empty-build": ('version = "1.2.3+"', "", "Rust package version must be SemVer"),
    "invalid-name": ('name = "bad/name"', "", "invalid Rust package name"),
    "invalid-edition": ('edition = "2027"', "", "unsupported Rust edition"),
    "compile-version": ("", 'version = "9.0.0",', "conflicts with package version"),
    "compile-edition": ("", 'edition = "2021",', "conflicts with package edition"),
    "compile-environment": ("", 'rustc_env = {"CARGO_PKG_NAME": "wrong"},', "overrides package metadata CARGO_PKG_NAME"),
    "compile-license": ("", 'license_domain = "gpl-qemu",', "conflicts with package license domain"),
    "test-name": ("", 'package_name = "wrong",', "Rust test conflicts with package name"),
    "install-version": ("", 'version = "9.0.0",', "installed package conflicts with Rust package version"),
}


def verify(arguments):
    build = arguments.workspace / "tools/bazel/tests/fixture/BUILD.bazel"
    results = {}
    arguments.output.mkdir(parents=True, exist_ok=True)
    for name, (declaration, override, expected) in CASES.items():
        fields = {
            "name": 'name = "fixture"', "version": 'version = "1.2.3"',
            "license_expression": 'license_expression = "Apache-2.0"',
            "edition": 'edition = "2024"',
        }
        if declaration:
            fields[declaration.split(" =", 1)[0]] = declaration
        if name.startswith("test-"):
            rule = 'aos_rust_test(name = "probe", package = META, srcs = ["lib.rs"], ' + override + ')'
        elif name.startswith("install-"):
            rule = 'aos_package(name = "probe", package = META, artifacts = {}, ' + override + ')'
        else:
            rule = 'rust_library(name = "probe", package = META, srcs = ["lib.rs"], ' + override + ')'
        build.write_text(
            'load("//tools/bazel/rules:rust_package.bzl", "aos_rust_package")\n'
            'load("//tools/bazel/rules:compile.bzl", "rust_library")\n'
            'load("//tools/bazel/rules:test.bzl", "aos_rust_test")\n'
            'load("//tools/bazel/rules:package.bzl", "aos_package")\n'
            + "META = aos_rust_package(" + ", ".join(fields.values()) + ")\n" + rule + "\n"
        )
        result = subprocess.run([
            sys.executable, str(arguments.launcher), "--config", str(arguments.config),
            "--workspace", str(arguments.workspace), "--output-base", str(arguments.output_base),
            "--nix-sandbox", "--batch", "--", "build", "//tools/bazel/tests/fixture:probe",
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        (arguments.output / (name + ".log")).write_text(result.stdout)
        if result.returncode == 0 or expected not in result.stdout:
            raise ValueError(f"package metadata rejection {name} did not fail as expected: {result.stdout}")
        results[name] = {"exit_code": result.returncode, "diagnostic": expected}
    (arguments.output / "results.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ["workspace", "launcher", "config", "output-base", "output"]:
        parser.add_argument("--" + option, type=Path, required=True)
    verify(parser.parse_args())
