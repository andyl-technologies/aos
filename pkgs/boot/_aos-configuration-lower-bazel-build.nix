##! Compiles configuration commands and release tests with declared static inputs.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelStaticLibraries,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelConfigurationTools,
  sourceInventory ? ../../tools/bazel/metadata/configuration-image-inventory.json,
}: let
  prefix = "//crates/boot/aos-configuration-image:";
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
          "crates/boot/aos-configuration-image"
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
          aos_boot_tools = aosBazelConfigurationTools;
        };
      rustcFlags = targetFlags;
      execRustcFlags = executionFlags;
      analysisTargets = map (name: prefix + name) targets;
    };
  productionTargets = ["static_package" "static_production_license_closure"];
  testTargets = ["static_unit" "static_bin_aos-certificate-bundle" "static_bin_aos-configuration-boot" "static_bin_aos-configuration-lower" "static_bin_aos-configuration-mount" "doc_static" "static_license_closure"];
  workspace = workspaceFor "configuration-image" productionTargets;
  testWorkspace = workspaceFor "configuration-image-tests" testTargets;
in {
  inherit workspace testWorkspace libraries;
  tools = aosBazelConfigurationTools;
  build = mkAosBazelBuild {
    pname = "aos-bazel-configuration-image-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-configuration-image-release-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-configuration-image-production-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-configuration-image-release-tests-inventory";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    inventoryOnly = true;
  };
}
