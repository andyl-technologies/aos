##! Compiles the configuration handler and its required release tests.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelToolchains,
  gccUnwrapped,
  aosBazelRepositories,
  aosBazelRustRepositories,
  sourceInventory ? ../../tools/bazel/metadata/configuration-provider-inventory.json,
}: let
  prefix = "//crates/activation/aos-activation-config-files:";
  toolchains = mkAosBazelToolchains {gccRuntime = gccUnwrapped;};
  targetFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
  executionFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
  workspaceFor = profile: targets:
    mkAosBazelWorkspace {
      root = ../..;
      inherit sourceInventory toolchains;
      cargoProfile = "release";
      sourceDirectories =
        if sourceInventory == null
        then [
          "tools/bazel"
          "third_party/rust"
          "crates/activation/aos-activation-config-files"
          "pkgs/system/_aos-configuration-provider"
        ]
        else [];
      dependencyProfile = profile;
      repositories = aosBazelRepositories // aosBazelRustRepositories.${profile};
      rustcFlags = targetFlags;
      execRustcFlags = executionFlags;
      analysisTargets = map (name: prefix + name) targets;
    };
  workspace = workspaceFor "configuration-files" ["package" "production_license_closure"];
  testWorkspace = workspaceFor "configuration-files-tests" ["unit" "bin_aos-configuration-provider" "doc" "license_closure"];
in {
  inherit workspace testWorkspace;
  build = mkAosBazelBuild {
    pname = "aos-bazel-configuration-provider-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-configuration-provider-release-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-configuration-provider-production-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-configuration-provider-release-tests-inventory";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    inventoryOnly = true;
  };
}
