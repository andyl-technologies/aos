##! Compiles the production evaluation example with its Cargo-compatible inputs.
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
  sourceInventory ? ../../tools/bazel/metadata/package-evaluation-driver-inventory.json,
}: let
  prefix = "//crates/packages/aos-package-manager:";
  targets = map (name: prefix + name) ["package_evaluation_driver_package" "package_evaluation_driver_license_closure"];
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
    analysisTargets = targets;
  };
in {
  inherit workspace;
  build = mkAosBazelBuild {
    pname = "aos-bazel-package-evaluation-driver-production";
    inherit workspace targets;
    retainActionGraph = true;
  };
  inventory = mkAosBazelBuild {
    pname = "aos-bazel-package-evaluation-driver-inventory";
    inherit workspace targets;
    inventoryOnly = true;
  };
}
