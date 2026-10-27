##! Compiles the static OpenZFS commands with their pinned runtime version.
{
  callPackage,
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelStaticLibraries,
  aosBazelRepositories,
  aosBazelRustRepositories,
  sourceInventory ? ../../tools/bazel/metadata/zfs-provider-inventory.json,
}: let
  prefix = "//crates/activation/aos-activation-storage:";
  libraries = mkAosBazelStaticLibraries {libraries = {};};
  runtime = callPackage ../build-support/_bazel/zfs-runtime.nix {};
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
          "crates/activation/aos-activation-storage"
          "crates/boot/aos-storage-layout"
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
          aos_zfs_runtime = runtime;
        };
      rustcFlags = targetFlags;
      execRustcFlags = executionFlags;
      analysisTargets = map (name: prefix + name) targets;
    };
  # Reuse the minimal event/fs/net SDK. Installed parity independently checks
  # this package's actual production and test compiler feature selections.
  workspace = workspaceFor "preparation-provider" ["static_zfs_package" "static_zfs_production_license_closure"];
  testWorkspace = workspaceFor "preparation-provider-tests" ["boot_transaction_unit" "static_zfs_pool_bin" "static_zfs_dataset_bin" "static_zfs_memory_policy_bin" "static_zfs_maintenance_bin" "doc_boot_transaction" "static_zfs_license_closure"];
in {
  inherit workspace testWorkspace libraries runtime;
  build = mkAosBazelBuild {
    pname = "aos-bazel-zfs-provider-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-zfs-provider-release-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-zfs-provider-production-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-zfs-provider-release-tests-inventory";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    inventoryOnly = true;
  };
}
