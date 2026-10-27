##! Compiles both complete BPF provider packages and their static release tests.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelStaticLibraries,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelBpfTools,
  aosBazelBpfLibraries,
  sourceInventory ? ../../tools/bazel/metadata/bpf-provider-inventory.json,
}: let
  prefixes = ["//crates/activation/aos-activation-bpf-lsm:" "//crates/activation/aos-activation-bpf-network:"];
  labelsFor = names: builtins.concatMap (prefix: map (name: prefix + name) names) prefixes;
  libraries = mkAosBazelStaticLibraries {libraries = {};};
  targetFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no" "-Ctarget-feature=+crt-static" "-Crelocation-model=static"];
  executionFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
  workspaceFor = profile: targets:
    mkAosBazelWorkspace {
      root = ../..;
      inherit sourceInventory;
      sourceDirectories =
        if sourceInventory == null
        then [
          "tools/bazel"
          "third_party/rust"
          "pkgs/security"
          "crates/activation/aos-activation-bpf-lsm"
          "crates/activation/aos-activation-bpf-network"
          "crates/activation/aos-activation"
          "crates/core/aos-core"
          "crates/modules/aos-module-format"
          "crates/artifacts/aos-artifact-evidence"
        ]
        else [];
      dependencyProfile = profile;
      cargoProfile = "release";
      repositories =
        aosBazelRepositories
        // aosBazelRustRepositories.${profile}
        // {
          aos_native = libraries;
          aos_bpf_tools = aosBazelBpfTools;
          aos_bpf_native = aosBazelBpfLibraries;
        };
      rustcFlags = targetFlags;
      execRustcFlags = executionFlags;
      analysisTargets = targets;
    };
  workspace = workspaceFor "preparation-provider" (
    labelsFor ["static_package" "static_production_license_closure"]
    ++ ["//pkgs/security:bpf_native_license_closure"]
  );
  testWorkspace = workspaceFor "preparation-provider-tests" (labelsFor ["static_unit" "static_bin" "doc_static" "static_license_closure"]);
in {
  inherit workspace testWorkspace libraries;
  build = mkAosBazelBuild {
    pname = "aos-bazel-bpf-provider-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-bpf-provider-release-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-bpf-provider-production-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-bpf-provider-release-tests-inventory";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    inventoryOnly = true;
  };
}
