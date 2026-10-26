##! Compiles installed native Hub programs with production PostgreSQL and browser assets.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelToolchains,
  gccUnwrapped,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelHubServiceLibraries,
  aosBazelCodegenTools,
  aosBazelConsoleAssets,
  aosBazelRegistryTestTools,
  aosBazelCrucibleCliRuntime,
  sourceInventory ? ../../tools/bazel/metadata/hub-installed-inventory.json,
}: let
  targets = [
    "//crates/hub/aos-hub-native:native_package"
    "//crates/hub/aos-hub-native:production_license_closure"
    "//crates/hub/aos-hub-service:generated_assets_evidence"
  ];
  workspace = mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories =
      if sourceInventory == null
      then ["crates" "api/proto" "tests/vm" "tools/bazel" "third_party/rust"]
      else [];
    extraFiles = ["crates/hub/aos-hub-model/tests/fixtures"];
    dependencyProfile = "hub-native-postgres";
    cargoProfile = "release";
    toolchains = mkAosBazelToolchains {gccRuntime = gccUnwrapped;};
    rustcFlags = [
      "-Copt-level=3"
      "-Cdebuginfo=0"
      "-Cdebug-assertions=no"
      "-Coverflow-checks=no"
      # Preserve the installed Cargo egress executable's declared imports too.
      "-Clink-arg=-Xlinker"
      "-Clink-arg=--push-state"
      "-Clink-arg=-Xlinker"
      "-Clink-arg=--no-as-needed"
      "-Clink-arg=-lssl"
      "-Clink-arg=-lcrypto"
      "-Clink-arg=-lssh2"
      "-Clink-arg=-lz"
      "-Clink-arg=-Xlinker"
      "-Clink-arg=--pop-state"
    ];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.hub-native-postgres
      // {
        aos_native = aosBazelHubServiceLibraries;
        aos_codegen = aosBazelCodegenTools;
        aos_console_assets = aosBazelConsoleAssets;
        aos_registry_runtime = aosBazelRegistryTestTools;
        aos_cli_runtime = aosBazelCrucibleCliRuntime;
      };
    analysisTargets = targets;
  };
in {
  inherit workspace;
  inventory = mkAosBazelBuild {
    pname = "aos-bazel-hub-installed-production-inventory";
    inherit workspace targets;
    inventoryOnly = true;
  };
  build = mkAosBazelBuild {
    pname = "aos-bazel-hub-installed-production";
    inherit workspace targets;
    retainActionGraph = true;
  };
}
