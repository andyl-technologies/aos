##! Builds the static ability adapter and its release tests without Cargo.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelStaticLibraries,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelGuestLibraries,
  sourceInventory ? ../../tools/bazel/metadata/activation-crucible-inventory.json,
}: let
  prefix = "//crates/activation/aos-activation-crucible:";
  libraries = mkAosBazelStaticLibraries {libraries = {};};
  targetFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no" "-Ctarget-feature=+crt-static" "-Crelocation-model=static"];
  executionFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
  workspaceFor = profile: nativeLibraries: targets:
    mkAosBazelWorkspace {
      root = ../..;
      inherit sourceInventory;
      dependencyProfile = profile;
      cargoProfile = "release";
      repositories = aosBazelRepositories // aosBazelRustRepositories.${profile} // {aos_native = nativeLibraries;};
      rustcFlags = targetFlags;
      execRustcFlags = executionFlags;
      analysisTargets = map (name: prefix + name) targets;
    };
  productionTargets = ["package" "production_license_closure"];
  testTargets = ["unit" "bin_aos-ability-crucible" "doc" "license_closure"];
  workspace = workspaceFor "activation-crucible" libraries productionTargets;
  testWorkspace = workspaceFor "activation-crucible-tests" aosBazelGuestLibraries testTargets;
in {
  inherit workspace testWorkspace libraries;
  build = mkAosBazelBuild {
    pname = "aos-bazel-ability-crucible-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-ability-crucible-release-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
}
