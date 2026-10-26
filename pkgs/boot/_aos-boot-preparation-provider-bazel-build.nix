##! Compiles the static preparation handler without its optional boot tooling.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelStaticLibraries,
  aosBazelRepositories,
  aosBazelRustRepositories,
  sourceInventory ? ../../tools/bazel/metadata/boot-preparation-provider-inventory.json,
}: let
  prefix = "//crates/boot/aos-boot-runtime:";
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
          "crates/boot/aos-boot-runtime"
          "crates/activation/aos-activation"
          "crates/core/aos-core"
          "crates/modules/aos-module-format"
          "crates/artifacts/aos-artifact-evidence"
        ]
        else [];
      dependencyProfile = profile;
      cargoProfile = "release";
      repositories = aosBazelRepositories // aosBazelRustRepositories.${profile} // {aos_native = libraries;};
      rustcFlags = targetFlags;
      execRustcFlags = executionFlags;
      analysisTargets = map (name: prefix + name) targets;
    };
  workspace = workspaceFor "preparation-provider" ["preparation_package" "preparation_production_license_closure"];
  testWorkspace = workspaceFor "preparation-provider-tests" ["preparation_unit" "preparation_bin" "doc_preparation" "preparation_license_closure"];
in {
  inherit workspace testWorkspace libraries;
  build = mkAosBazelBuild {
    pname = "aos-bazel-preparation-provider-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-preparation-provider-release-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-preparation-provider-production-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-preparation-provider-release-tests-inventory";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    inventoryOnly = true;
  };
}
