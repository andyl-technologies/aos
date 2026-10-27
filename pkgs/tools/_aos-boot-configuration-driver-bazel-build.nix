##! Builds the installed boot-configuration libtest with its release profile.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelToolchains,
  gccUnwrapped,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelNativeFoundationLibraries,
  aosBazelCodegenTools,
  aosBazelCrucibleCliRuntime,
  aosBazelRegistryTestTools,
  sourceInventory ? ../../tools/bazel/metadata/boot-configuration-driver-inventory.json,
}: let
  prefix = "//crates/packages/aos-package-manager:";
  targets = map (name: prefix + name) ["boot_configuration_driver_package" "boot_configuration_driver_license_closure"];
  testTargets = ["${prefix}unit"];
  workspace = mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories =
      if sourceInventory == null
      then ["crates" "api/proto" "tools/bazel" "third_party/rust"]
      else [];
    dependencyProfile = "package-evaluation-driver";
    cargoProfile = "release";
    toolchains = mkAosBazelToolchains {gccRuntime = gccUnwrapped;};
    rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.package-evaluation-driver
      // {
        aos_native = aosBazelNativeFoundationLibraries;
        aos_codegen = aosBazelCodegenTools;
        aos_cli_runtime = aosBazelCrucibleCliRuntime;
        aos_registry_runtime = aosBazelRegistryTestTools;
      };
    analysisTargets = targets ++ testTargets;
  };
in {
  inherit workspace;
  build = mkAosBazelBuild {
    pname = "aos-bazel-boot-configuration-driver-production";
    inherit workspace targets;
    retainActionGraph = true;
  };
  tests = mkAosBazelBuild {
    pname = "aos-bazel-boot-configuration-driver-release-tests";
    inherit workspace;
    targets = testTargets;
    command = "test";
    retainActionGraph = true;
  };
  inventory = mkAosBazelBuild {
    pname = "aos-bazel-boot-configuration-driver-inventory";
    inherit workspace;
    targets = targets ++ testTargets;
    inventoryOnly = true;
  };
}
