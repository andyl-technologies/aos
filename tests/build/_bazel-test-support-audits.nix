##! Runs source ownership audits against Bazel's declared package catalog.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/test-support-audit-inventory.json,
}: let
  audits = ["crate_unsafe_fence" "concurrency_abi_oracle_standards" "harness_lint_annotations" "determinism_core_coverage"];
  parityTools = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-source-audit-parity-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_pilot.py" "verify_source_audits.py"];
  };
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) [
      "BUILD.bazel"
      "crates"
      "tools/bazel/rules"
      "tools/bazel/metadata"
      "tools/bazel/testing"
      "tools/bazel/toolchains"
      "pkgs/tools/crucible/_packages.nix"
    ];
    dependencyProfile = "engine";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.engine;
    analysisTargets = map (name: "//crates/crucible/crucible-test-support:${name}") audits ++ ["//crates:source_catalog_package" "//crates/crucible/crucible-test-support:source_audit_binaries"];
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  };
in rec {
  inherit workspace;
  tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-test-support-source-audits";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
    sharedBuildCache = false;
  };
  catalog = pkgs.mkAosBazelPackage {
    pname = "aos-workspace-source-catalog";
    version = "1";
    build = tests;
    packageLabel = "//crates:source_catalog_package";
  };
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-test-support-source-audit-cargo-oracle";
    packages = ["crucible-test-support"];
    cargoFlags = pkgs.lib.concatMap (name: ["--test" name]) audits;
    captureCompilerArguments = true;
  };
  parity = pkgs.runCommand "aos-bazel-test-support-source-audit-parity" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
      ${parityTools}/verify_source_audits.py \
      --build ${tests} --oracle ${cargo} --workspace ${workspace.source} \
      --catalog ${catalog}/share/aos/source-catalog.json \
      ${pkgs.lib.optionalString (sourceInventory != null) "--precise"} \
      --output "$out/report.json"
  '';
  all = pkgs.runCommand "aos-bazel-test-support-source-audit-checks" {buildDeps = [parity];} ''
    mkdir -p "$out"
    cp ${parity}/report.json "$out/report.json"
    printf 'PASS\n' > "$out/result"
  '';
}
