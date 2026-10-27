##! Runs GPL gateway assertions against a separately linked Apache executable.
{
  lib,
  callPackage,
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  aosBazelRepositories,
  aosBazelRustRepositories,
  hostSourceInventory ? ../../tools/bazel/metadata/qemu-test-oracle-host-inventory.json,
  testSourceInventory ? ../../tools/bazel/metadata/qemu-gateway-process-test-inventory.json,
  release ? false,
}: let
  root = ../..;
  gateway = "//crates/crucible/crucible-qemu-debug-gateway:";
  protocol = "//crates/crucible/crucible-qemu-protocol:";
  sourceDirectories = ["tools/bazel" "third_party/rust" "crates"];
  oracle = callPackage ./_crucible-qemu-bazel-oracle.nix {
    inherit release;
    sourceInventory = hostSourceInventory;
  };
  inherit (oracle) hostBuild hostPackage hostWorkspace testTools hostDevelopment hostFormat hostInventory;
  profileOptions = lib.optionalAttrs release {
    cargoProfile = "release";
    rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
  };
  testTargets = [
    "${gateway}unit"
    "${gateway}bin_crucible-debug-gateway"
    "${gateway}process_lifecycle"
    "${gateway}test_license_closure"
    "${gateway}production_license_closure"
  ];
  testWorkspace = mkAosBazelWorkspace ({
      inherit root;
      sourceInventory = testSourceInventory;
      sourceDirectories = lib.optionals (testSourceInventory == null) sourceDirectories;
      dependencyProfile = "qemu-gpl-tests";
      analysisTargets = testTargets;
      repositories =
        aosBazelRepositories
        // aosBazelRustRepositories.qemu-gpl-tests
        // {aos_qemu_test_tools = testTools;};
    }
    // profileOptions);
in {
  inherit hostBuild hostPackage hostWorkspace testWorkspace testTools hostDevelopment hostFormat hostInventory;
  tests = mkAosBazelCheck {
    pname = "aos-bazel-qemu-gateway-process-tests";
    workspace = testWorkspace;
    targets = testTargets;
    retainActionGraph = true;
  };
  codecTests = mkAosBazelCheck {
    pname = "aos-bazel-qemu-test-oracle-codec-tests";
    workspace = testWorkspace;
    targets = ["${protocol}test_oracle_unit"];
  };
  testDevelopment = mkAosBazelBuild {
    pname = "aos-bazel-qemu-gateway-test-development";
    workspace = testWorkspace;
    targets = ["${gateway}test_clippy"];
  };
  testFormat = mkAosBazelCheck {
    pname = "aos-bazel-qemu-gateway-test-format";
    workspace = testWorkspace;
    targets = ["${gateway}test_format"];
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-qemu-gateway-process-test-inventory";
    workspace = testWorkspace;
    inventoryOnly = true;
    targets = testTargets ++ ["${gateway}test_clippy" "${gateway}test_format" "${protocol}test_oracle_unit"];
  };
}
