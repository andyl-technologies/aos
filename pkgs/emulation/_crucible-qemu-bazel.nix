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
  components ? ["plugin" "gateway"],
  sourceInventory ? ../../tools/bazel/metadata/qemu-gpl-production-inventory.json,
}: let
  plugin = "//crates/crucible/crucible-qemu-plugin:";
  gateway = "//crates/crucible/crucible-qemu-debug-gateway:";
  validComponents =
    components
    != []
    && builtins.all (component: builtins.elem component ["plugin" "gateway"]) components
    && builtins.length components == builtins.length (lib.unique components);
  productionTargets =
    lib.optionals (builtins.elem "plugin" components) [
      "${plugin}plugin"
      "${plugin}production_license_closure"
      "${plugin}compiler_artifact"
    ]
    ++ lib.optionals (builtins.elem "gateway" components) [
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
  build = mkAosBazelBuild {
    pname = "aos-bazel-qemu-gpl-production";
    inherit workspace;
    targets = productionTargets;
    retainActionGraph = true;
  };
in
  assert validComponents; {
    inherit workspace productionTargets build;
    installed =
      lib.filterAttrs (name: _: builtins.elem name components)
      (callPackage ./_crucible-qemu-bazel-installed.nix {inherit build;});
  }
