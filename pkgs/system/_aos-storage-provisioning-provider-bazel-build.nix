##! Compiles static provisioning commands and both required library test suites.
{
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelStaticLibraries,
  aosBazelRepositories,
  aosBazelRustRepositories,
  sourceInventory ? ../../tools/bazel/metadata/storage-provisioning-provider-inventory.json,
}: let
  prefix = "//crates/activation/aos-activation-storage:";
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
      repositories = aosBazelRepositories // aosBazelRustRepositories.${profile} // {aos_native = libraries;};
      rustcFlags = targetFlags;
      execRustcFlags = executionFlags;
      analysisTargets = targets;
    };
  # Reuse the minimal event/fs/net SDK. Installed parity independently checks
  # this package's actual production and test compiler feature selections.
  workspace = workspaceFor "preparation-provider" (map (name: prefix + name) ["static_provisioning_package" "static_provisioning_production_license_closure"]);
  testWorkspace = workspaceFor "preparation-provider-tests" (
    (map (name: prefix + name) ["boot_transaction_unit" "static_provisioning_bin" "static_provisioning_marker_bin" "doc_boot_transaction" "static_provisioning_license_closure"])
    ++ ["//crates/boot/aos-storage-layout:static_provisioning_unit" "//crates/boot/aos-storage-layout:doc"]
  );
in {
  inherit workspace testWorkspace libraries;
  build = mkAosBazelBuild {
    pname = "aos-bazel-storage-provisioning-provider-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-storage-provisioning-provider-release-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-storage-provisioning-provider-production-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-storage-provisioning-provider-release-tests-inventory";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    inventoryOnly = true;
  };
}
