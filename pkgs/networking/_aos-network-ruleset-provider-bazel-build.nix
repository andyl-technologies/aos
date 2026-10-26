##! Compiles the static nftables handler and its required release tests.
{
  callPackage,
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelStaticLibraries,
  aosBazelRepositories,
  aosBazelRustRepositories,
  sourceInventory ? ../../tools/bazel/metadata/network-ruleset-provider-inventory.json,
}: let
  prefix = "//crates/activation/aos-activation-nftables:";
  runtime = callPackage ../build-support/_bazel/nft-runtime.nix {};
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
          "crates/activation/aos-activation-nftables"
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
          aos_nft_runtime = runtime;
        };
      rustcFlags = targetFlags;
      execRustcFlags = executionFlags;
      analysisTargets = map (name: prefix + name) targets;
    };
  workspace = workspaceFor "preparation-provider" ["static_package" "static_production_license_closure"];
  testWorkspace = workspaceFor "preparation-provider-tests" ["static_unit" "static_bin" "doc_static" "static_license_closure"];
in {
  inherit workspace testWorkspace libraries runtime;
  build = mkAosBazelBuild {
    pname = "aos-bazel-network-ruleset-provider-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-network-ruleset-provider-release-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-network-ruleset-provider-production-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-network-ruleset-provider-release-tests-inventory";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    inventoryOnly = true;
  };
}
