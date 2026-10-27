##! Runs GPL plugin assertions against a separately linked Apache executable.
{
  lib,
  callPackage,
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelQemuPluginAbi,
  hostSourceInventory ? ../../tools/bazel/metadata/qemu-test-oracle-host-inventory.json,
  testSourceInventory ? ../../tools/bazel/metadata/qemu-plugin-process-test-inventory.json,
  release ? false,
}: let
  root = ../..;
  plugin = "//crates/crucible/crucible-qemu-plugin:";
  oracle = callPackage ./_crucible-qemu-bazel-oracle.nix {
    inherit release;
    sourceInventory = hostSourceInventory;
  };
  inherit (oracle) hostBuild hostPackage hostWorkspace hostInventory testTools;
  profileOptions = lib.optionalAttrs release {
    cargoProfile = "release";
    rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
  };
  testTargets = [
    "${plugin}unit"
    "${plugin}gate_abi_conformance"
    "${plugin}gate_patch_microtests"
    "${plugin}gate_qemu_inert"
    "${plugin}test_license_closure"
    "${plugin}production_license_closure"
  ];
  workspace = mkAosBazelWorkspace ({
      inherit root;
      sourceInventory = testSourceInventory;
      extraFiles = lib.optionals (testSourceInventory == null) ["BUILD.bazel" "default.nix"];
      sourceDirectories = lib.optionals (testSourceInventory == null) [
        "tools/bazel"
        "third_party/rust"
        "crates"
        "docs/rfcs/0010-crucible"
        "tests/crucible"
        "pkgs/emulation"
      ];
      dependencyProfile = "qemu-gpl-plugin-tests";
      analysisTargets = testTargets;
      repositories =
        aosBazelRepositories
        // aosBazelRustRepositories.qemu-gpl-plugin-tests
        // {
          aos_qemu_plugin_abi = aosBazelQemuPluginAbi;
          aos_qemu_test_tools = testTools;
        };
    }
    // profileOptions);
in {
  inherit workspace hostBuild hostPackage hostWorkspace hostInventory testTools;
  tests = mkAosBazelCheck {
    pname = "aos-bazel-qemu-plugin-process-tests";
    inherit workspace;
    targets = testTargets;
    retainActionGraph = true;
  };
  development = mkAosBazelBuild {
    pname = "aos-bazel-qemu-plugin-test-development";
    inherit workspace;
    targets = ["${plugin}test_clippy"];
  };
  format = mkAosBazelCheck {
    pname = "aos-bazel-qemu-plugin-test-format";
    inherit workspace;
    targets = ["${plugin}test_format"];
  };
  inventory = mkAosBazelBuild {
    pname = "aos-bazel-qemu-plugin-process-test-inventory";
    inherit workspace;
    inventoryOnly = true;
    targets = testTargets ++ ["${plugin}test_clippy" "${plugin}test_format"];
  };
}
