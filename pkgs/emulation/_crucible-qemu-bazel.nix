##! Builds the GPL plugin and gateway from the declared offline Bazel graph.
{
  lib,
  stdenv,
  gccUnwrapped,
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelQemuPluginAbi,
  callPackage,
  sourceInventory ? ../../tools/bazel/metadata/qemu-gpl-production-inventory.json,
}: let
  plugin = "//crates/crucible/crucible-qemu-plugin:";
  gateway = "//crates/crucible/crucible-qemu-debug-gateway:";
  productionTargets = [
    "${plugin}plugin"
    "${plugin}production_license_closure"
    "${plugin}compiler_artifact"
    "${gateway}lib"
    "${gateway}crucible-debug-gateway"
    "${gateway}production_license_closure"
    "${gateway}compiler_artifact"
  ];
  workspace = mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    dependencyProfile = "qemu-gpl-production";
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.qemu-gpl-production
      // {aos_qemu_plugin_abi = aosBazelQemuPluginAbi;};
    rustcFlags = [
      "-Copt-level=3"
      "-Cdebuginfo=0"
      "-Cdebug-assertions=no"
      "-Coverflow-checks=no"
      "-Cstrip=debuginfo"
      # Match the ordinary AOS driver's libgcc linker script before the
      # shared C++ runtime search path supplied by the Bazel C toolchain.
      "-Lnative=${gccUnwrapped}/lib/gcc/${stdenv.hostPlatform.config}/${gccUnwrapped.version}"
    ];
    sourceDirectories = lib.optionals (sourceInventory == null) [
      "tools/bazel"
      "third_party/rust"
      "crates/crucible/crucible-qemu-plugin"
      "crates/crucible/crucible-qemu-debug-gateway"
      "crates/crucible/crucible-qemu-protocol"
      "crates/crucible/crucible-qemu-shmem"
    ];
    analysisTargets = productionTargets;
  };
in rec {
  inherit workspace productionTargets;
  build = mkAosBazelBuild {
    pname = "aos-bazel-qemu-gpl-production";
    inherit workspace;
    targets = productionTargets;
    retainActionGraph = true;
  };
  installed = callPackage ./_crucible-qemu-bazel-installed.nix {inherit build;};
}
