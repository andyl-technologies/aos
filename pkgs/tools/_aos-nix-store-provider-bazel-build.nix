##! Compiles the static Nix store handler and its required source-built Nix test.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelStaticLibraries,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelNixTestTools,
  sourceInventory ? ../../tools/bazel/metadata/nix-store-provider-inventory.json,
}: let
  prefix = "//crates/activation/aos-activation-nix-store:";
  libraries = mkAosBazelStaticLibraries {libraries = {};};
  targetFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no" "-Ctarget-feature=+crt-static" "-Crelocation-model=static"];
  executionFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
  workspaceFor = targets:
    mkAosBazelWorkspace {
      root = ../..;
      inherit sourceInventory;
      sourceDirectories =
        if sourceInventory == null
        then [
          "tools/bazel"
          "third_party/rust"
          "crates/activation/aos-activation-nix-store"
          "crates/activation/aos-activation"
          "crates/core/aos-core"
          "crates/modules/aos-module-format"
          "crates/artifacts/aos-artifact-evidence"
        ]
        else [];
      dependencyProfile = "nix-store-provider";
      cargoProfile = "release";
      repositories =
        aosBazelRepositories
        // aosBazelRustRepositories.nix-store-provider
        // {
          aos_native = libraries;
          aos_nix_test_tools = aosBazelNixTestTools;
        };
      rustcFlags = targetFlags;
      execRustcFlags = executionFlags;
      analysisTargets = map (name: prefix + name) targets;
    };
  workspace = workspaceFor ["static_package" "static_production_license_closure"];
  testWorkspace = workspaceFor ["static_unit" "static_bin" "static_real_nix" "doc_static" "static_license_closure"];
in {
  inherit workspace testWorkspace libraries;
  build = mkAosBazelBuild {
    pname = "aos-bazel-nix-store-provider-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-nix-store-provider-release-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-nix-store-provider-production-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-nix-store-provider-release-tests-inventory";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    inventoryOnly = true;
  };
}
