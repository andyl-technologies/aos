##! Compiles the native file signer with independent execution and target tools.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelToolchains,
  gccUnwrapped,
  aosBazelRepositories,
  aosBazelRustRepositories,
  sourceInventory ? ../../tools/bazel/metadata/release-signer-inventory.json,
}: let
  prefix = "//crates/release/aos-release-signer:";
  targets = map (name: prefix + name) ["package" "production_license_closure"];
  testTargets = ["${prefix}bin_aos-release-signer"];
  workspaceFor = selected:
    mkAosBazelWorkspace {
      root = ../..;
      inherit sourceInventory;
      sourceDirectories =
        if sourceInventory == null
        then ["crates" "tools/bazel" "third_party/rust"]
        else [];
      dependencyProfile = "release-signer";
      cargoProfile = "release";
      toolchains = mkAosBazelToolchains {gccRuntime = gccUnwrapped;};
      rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
      execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
      repositories = aosBazelRepositories // aosBazelRustRepositories.release-signer;
      analysisTargets = selected;
    };
  workspace = workspaceFor targets;
  testWorkspace = workspaceFor testTargets;
in {
  inherit workspace testWorkspace;
  build = mkAosBazelBuild {
    pname = "aos-bazel-release-signer-production";
    inherit workspace targets;
    retainActionGraph = true;
  };
  tests = mkAosBazelBuild {
    pname = "aos-bazel-release-signer-release-tests";
    workspace = testWorkspace;
    targets = testTargets;
    command = "test";
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-release-signer-production-inventory";
    inherit workspace targets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-release-signer-tests-inventory";
    workspace = testWorkspace;
    targets = testTargets;
    inventoryOnly = true;
  };
}
