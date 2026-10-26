##! Compiles the Kubernetes handler with its production and debug test profiles.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelToolchains,
  gccUnwrapped,
  aosBazelRepositories,
  aosBazelRustRepositories,
  sourceInventory ? ../../tools/bazel/metadata/kubernetes-provider-inventory.json,
}: let
  prefix = "//crates/activation/aos-activation-kubernetes:";
  toolchains = mkAosBazelToolchains {gccRuntime = gccUnwrapped;};
  workspaceFor = test: targets: let
    profile =
      if test
      then "preparation-provider-tests"
      else "preparation-provider";
  in
    mkAosBazelWorkspace {
      root = ../..;
      inherit sourceInventory toolchains;
      sourceDirectories =
        if sourceInventory == null
        then [
          "tools/bazel"
          "third_party/rust"
          "crates/activation/aos-activation-kubernetes"
          "crates/activation/aos-activation"
          "crates/core/aos-core"
          "crates/modules/aos-module-format"
          "crates/artifacts/aos-artifact-evidence"
        ]
        else [];
      dependencyProfile = profile;
      cargoProfile =
        if test
        then "debug"
        else "release";
      repositories = aosBazelRepositories // aosBazelRustRepositories.${profile};
      rustcFlags =
        if test
        then ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"]
        else ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
      execRustcFlags =
        if test
        then ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"]
        else ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
      analysisTargets = map (name: prefix + name) targets;
    };
  workspace = workspaceFor false ["package" "production_license_closure"];
  testWorkspace = workspaceFor true ["unit" "bin_aos-kubernetes-provider" "doc" "license_closure"];
in {
  inherit workspace testWorkspace;
  build = mkAosBazelBuild {
    pname = "aos-bazel-kubernetes-provider-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-kubernetes-provider-debug-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-kubernetes-provider-production-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-kubernetes-provider-debug-tests-inventory";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    inventoryOnly = true;
  };
}
