##! Compiles the metadata handlers and their required release tests.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelToolchains,
  gccUnwrapped,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelNativeFoundationLibraries,
  sourceInventory ? ../../tools/bazel/metadata/metadata-provider-inventory.json,
}: let
  prefix = "//crates/boot/aos-platform-metadata:";
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
        then ["tools/bazel" "third_party/rust" "crates"]
        else [];
      dependencyProfile = profile;
      repositories =
        aosBazelRepositories
        // aosBazelRustRepositories.${profile}
        // {
          aos_native = aosBazelNativeFoundationLibraries;
        };
      rustcFlags = targetFlags;
      execRustcFlags = executionFlags;
      analysisTargets = map (name: prefix + name) targets;
    };
  workspace = workspaceFor "boot-preparation-minimal" ["package" "production_license_closure"];
  testWorkspace = workspaceFor "boot-preparation-minimal" ["unit" "bin_aos-metadata-acquisition-provider" "bin_aos-metadata-policy-provider" "doc" "license_closure"];
in {
  inherit workspace testWorkspace;
  build = mkAosBazelBuild {
    pname = "aos-bazel-metadata-provider-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-metadata-provider-release-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-metadata-provider-production-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-metadata-provider-release-tests-inventory";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    inventoryOnly = true;
  };
}
