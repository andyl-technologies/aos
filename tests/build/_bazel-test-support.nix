##! Compares executable harness fixtures with an independent native rustc build.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/test-support-inventory.json,
}: let
  packagePath = "crates/crucible/crucible-test-support";
  label = "//${packagePath}";
  source = ../../crates/crucible/crucible-test-support;
  integrations = [
    "gate_abi_conformance"
    "gate_adversarial_determinism"
    "gate_divergence_bisect"
    "gate_e2e_determinism"
    "gate_layer0_determinism"
    "reproduction_artifact"
  ];
  targets = map (name: "${label}:${name}") (["unit" "doc"] ++ integrations);
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  parityTools = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-test-support-parity-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_pilot.py" "verify_protocol.py"];
  };
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) [
      "tools/bazel/toolchains"
      "tools/bazel/rules"
      "tools/bazel/metadata"
      "tools/bazel/testing"
      packagePath
      "crates/crucible/crucible-qemu-protocol"
      "crates/crucible/crucible-qemu-shmem"
      "third_party/rust"
    ];
    inherit rustcFlags;
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = targets;
  };
in rec {
  inherit workspace;
  tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-crucible-test-support-fixtures";
    inherit workspace targets;
    retainActionGraph = true;
    sharedBuildCache = false;
  };
  parity =
    pkgs.runCommand "aos-bazel-crucible-test-support-fixture-parity" {
      buildDeps = [pkgs.rust pkgs.python3];
    } ''
      mkdir -p "$out/native"
      mkdir -p crates/crucible/crucible-qemu-shmem/src crates/crucible/crucible-qemu-protocol/src
      cp -R ${source} ${packagePath}
      cp ${../../crates/crucible/crucible-qemu-shmem/src/abi_version.in} crates/crucible/crucible-qemu-shmem/src/abi_version.in
      cp ${../../crates/crucible/crucible-qemu-protocol/src/control_protocol_version.in} crates/crucible/crucible-qemu-protocol/src/control_protocol_version.in
      export CARGO_PKG_VERSION=0.1.0
      rustc --edition=2024 --crate-name crucible_test_support --crate-type rlib \
        ${pkgs.lib.escapeShellArgs rustcFlags} ${packagePath}/src/lib.rs -o libcrucible_test_support.rlib
      rustc --edition=2024 --crate-name crucible_test_support --test \
        ${pkgs.lib.escapeShellArgs rustcFlags} ${packagePath}/src/lib.rs -o unit
      for name in ${pkgs.lib.escapeShellArgs integrations}; do
        rustc --edition=2024 --crate-name "$name" --test \
          ${pkgs.lib.escapeShellArgs rustcFlags} "${packagePath}/tests/$name.rs" \
          --extern crucible_test_support=libcrucible_test_support.rlib -o "$name"
      done
      for name in unit ${pkgs.lib.escapeShellArgs integrations}; do
        env -u LD_LIBRARY_PATH "./$name" --test-threads=1 > "$out/native/$name.log"
      done
      rustdoc --edition=2024 --test ${packagePath}/src/lib.rs \
        --extern crucible_test_support=libcrucible_test_support.rlib > "$out/native/doc.log"
      PYTHONPATH=${parityTools} ${pkgs.python3}/bin/python3 - "$out" <<'PY'
      import json
      from pathlib import Path
      import sys

      from verify_pilot import verify
      from verify_protocol import doctest_cases

      output = Path(sys.argv[1])
      tests = Path("${tests}/evidence/tests")
      if ${
        if sourceInventory != null
        then "True"
        else "False"
      }:
          manifests = [path for path in Path("${workspace.source}").rglob("Cargo.*")
                       if path.name in {"Cargo.toml", "Cargo.lock"}]
          if manifests:
              raise ValueError("selected test-support workspace contains Cargo build metadata")

      targets = ${builtins.toJSON (["unit"] ++ integrations)}
      oracles = {"${label}:" + name: Path(name).resolve() for name in targets}
      parity = verify(tests, oracles)
      (output / "test-parity.json").write_text(json.dumps(parity, indent=2, sort_keys=True) + "\n")

      results = json.loads((tests / "index.json").read_text())["results"]
      selected = [result for result in results if result["identity"]["label"] == "${label}:doc"]
      if len(selected) != 1 or selected[0]["status"] != "PASSED":
          raise ValueError("test-support doctests did not pass exactly once")
      expected = doctest_cases((output / "native/doc.log").read_text(), "${packagePath}")
      actual = doctest_cases((tests / selected[0]["outputs"]["test.log"]).read_text(), "${packagePath}")
      if actual != expected:
          raise ValueError("test-support doctest names, locations, or statuses changed")
      (output / "doctest-parity.json").write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
      PY
      printf 'PASS\n' > "$out/result"
    '';
  all = pkgs.runCommand "aos-bazel-crucible-test-support-fixture-checks" {buildDeps = [parity];} ''
    mkdir -p "$out"
    cp ${parity}/test-parity.json "$out/"
    cp ${parity}/doctest-parity.json "$out/"
    cp -R ${parity}/native "$out/"
    printf 'PASS\n' > "$out/result"
  '';
}
