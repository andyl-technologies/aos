##! Compiles the production deployment validator with its Cargo-compatible inputs.
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
  sourceInventory ? ../../tools/bazel/metadata/deployment-check-inventory.json,
}: let
  prefix = "//crates/packages/aos-package-manager:";
  targets = map (name: prefix + name) ["deployment_check_package" "deployment_check_license_closure"];
  testTargets = ["${prefix}bin_aos-deployment-check"];
  workspaceFor = profile: selected:
    mkAosBazelWorkspace {
      root = ../..;
      inherit sourceInventory;
      sourceDirectories =
        if sourceInventory == null
        then ["crates" "api/proto" "tools/bazel" "third_party/rust"]
        else [];
      dependencyProfile = profile;
      cargoProfile = "release";
      toolchains = mkAosBazelToolchains {gccRuntime = gccUnwrapped;};
      rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
      execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
      repositories =
        aosBazelRepositories
        // aosBazelRustRepositories.${profile}
        // {
          aos_native = aosBazelNativeFoundationLibraries;
          aos_codegen = aosBazelCodegenTools;
          aos_cli_runtime = aosBazelCrucibleCliRuntime;
          aos_registry_runtime = aosBazelRegistryTestTools;
        };
      analysisTargets = selected;
    };
  workspace = workspaceFor "deployment-check" targets;
  testWorkspace = workspaceFor "package-evaluation-driver" testTargets;
in {
  inherit workspace testWorkspace;
  build = mkAosBazelBuild {
    pname = "aos-bazel-deployment-check-production";
    inherit workspace targets;
    retainActionGraph = true;
  };
  tests = mkAosBazelBuild {
    pname = "aos-bazel-deployment-check-release-tests";
    workspace = testWorkspace;
    targets = testTargets;
    command = "test";
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-deployment-check-production-inventory";
    inherit workspace targets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-deployment-check-tests-inventory";
    workspace = testWorkspace;
    targets = testTargets;
    inventoryOnly = true;
  };
}
