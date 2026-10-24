##! Qualifies the static guest without changing the production package builder.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/guest-inventory.json,
}: let
  label = "//crates/crucible/crucible-guest";
  inputPaths = [
    "MODULE.bazel"
    "tests/build/_bazel-guest.nix"
    "tests/crucible/phase1-production-fingerprint-sample.nix"
    "tests/crucible/phase7-production-rust-plugin-flight.nix"
    "docs/rfcs/0010-crucible/24-determinism-harness-testing.md"
  ];
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {
    inherit (pkgs) lib;
    extraPaths = inputPaths;
  };
  triple = pkgs.stdenv.hostPlatform.config;
  cargoSetup = ''
    export CARGO_BUILD_TARGET=${pkgs.lib.escapeShellArg triple}
    export CARGO_TARGET_${pkgs.lib.toUpper (builtins.replaceStrings ["-"] ["_"] triple)}_RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static -L ${pkgs.aosBazelGuestLibraries}/static/lib"
    export SQLITE3_LIB_DIR=${pkgs.sqliteStatic}/lib SQLITE3_INCLUDE_DIR=${pkgs.sqliteStatic}/include SQLITE3_STATIC=1
    export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1 PKG_CONFIG_ALL_STATIC=1
  '';
  family = import ./_bazel-rust-family.nix {
    inherit pkgs sourceInventory cargoSource cargoSetup;
    pname = "aos-bazel-guest";
    packages.crucible-guest = "crates/crucible/crucible-guest";
    dependencyPackages = {
      crucible-qemu-protocol = "crates/crucible/crucible-qemu-protocol";
      crucible-campaign = "crates/crucible/crucible-campaign";
      crucible-store = "crates/crucible/crucible-store";
    };
    editorComparisonScope = "selected-packages";
    dependencyProfile = "guest";
    rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Ctarget-feature=+crt-static" "-Crelocation-model=static"];
    cargoFlags = ["--release"];
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.guest // {aos_native = pkgs.aosBazelGuestLibraries;};
    nativeLibraries = [pkgs.sqliteStatic pkgs.zstdStaticMultithread];
    nativeTools = [pkgs.pkg-config];
    extraSourceDirectories =
      inputPaths
      ++ [
        "BUILD.bazel"
        "tests/build/BUILD.bazel"
        "tests/crucible/BUILD.bazel"
        "docs/rfcs/0010-crucible/BUILD.bazel"
        "docs/rfcs/0020-crucible-campaigns"
        "crates/crucible/crucible-qemu-protocol"
        "crates/crucible/crucible-store"
        "crates/crucible/crucible-campaign"
      ];
    extraTests = ["${label}:bin_crucible-guest"];
    extraEditorTargets = ["${label}:crucible-guest" "${label}:bin_crucible-guest_binary"];
  };
in
  family
  // rec {
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-guest-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets = map (name: "${label}:${name}") [
        "lib"
        "crucible-guest"
        "unit"
        "unit_binary"
        "bin_crucible-guest"
        "bin_crucible-guest_binary"
        "gate_abi_conformance"
        "gate_abi_conformance_binary"
        "gate_single_vm_fingerprint"
        "gate_single_vm_fingerprint_binary"
        "doc"
        "clippy"
        "documentation"
        "format"
        "license_closure"
        "package"
      ];
    };
    build = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-guest-package";
      workspace = family.workspace;
      targets = ["${label}:package"];
      sharedBuildCache = false;
      retainActionGraph = true;
    };
    package = pkgs.mkAosBazelPackage {
      pname = "crucible-guest";
      version = "0.1.0";
      inherit build;
      packageLabel = "${label}:package";
    };
    runtime =
      pkgs.runCommand "aos-bazel-guest-runtime" {
        buildDeps = [pkgs.python3];
        outputChecks.out = {};
        exportReferencesGraph.package = [package];
      } ''
        mkdir -p "$out"
        cp ${../../tools/bazel/tests/verify_cache.py} verify_cache.py
        cp ${../../tools/bazel/tests/verify_static_runtime.py} verify_static_runtime.py
        cp ${../../tools/bazel/metadata/guest_build_info.py} guest_build_info.py
        cp ${../../tools/bazel/tests/verify_guest.py} verify_guest.py
        ${pkgs.python3}/bin/python3 verify_guest.py \
          --build ${build} --package ${package} --libraries ${pkgs.aosBazelGuestLibraries} \
          --cargo ${family.cargo} --system ${pkgs.lib.escapeShellArg pkgs.stdenv.hostPlatform.system} \
          --source ${../../crates/crucible/crucible-qemu-protocol/src/doorbell_abi.rs} \
          --readelf ${pkgs.binutils}/bin/readelf --output "$out/runtime.json"
        ${pkgs.python3}/bin/python3 - "$out/closure.json" <<'PYTHON'
        import json
        import os
        from pathlib import Path
        import sys

        graph = json.loads(Path(os.environ["NIX_ATTRS_JSON_FILE"]).read_text())["package"]
        references = {entry["path"]: entry["references"] for entry in graph}
        root = "${package}"
        runtime = json.loads(Path("${pkgs.aosBazelGuestLibraries}/static/closure.json").read_text())
        # Static libc retains its optional locale and timezone data reference.
        if set(references[root]) - {root, runtime["glibc"]}:
            raise ValueError(f"guest retained an unexpected runtime reference: {references[root]}")
        Path(sys.argv[1]).write_text(json.dumps({"root": root, "references": references[root],
            "glibc_data_reference": runtime["glibc"], "closure": graph}, indent=2) + "\n")
        PYTHON
      '';
    all =
      pkgs.runCommand "aos-bazel-guest-qualified-checks" {
        buildDeps = [family.all family.editor-parity runtime];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp -r ${runtime} "$out/runtime"
      '';
  }
