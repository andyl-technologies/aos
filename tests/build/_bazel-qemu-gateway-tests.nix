##! Qualifies GPL lifecycle tests using an independently linked Apache oracle.
{
  pkgs,
  hostSourceInventory ? ../../tools/bazel/metadata/qemu-test-oracle-host-inventory.json,
  testSourceInventory ? ../../tools/bazel/metadata/qemu-gateway-process-test-inventory.json,
}: let
  root = ../..;
  oracle = pkgs.callPackage ../../pkgs/emulation/_crucible-qemu-bazel-oracle.nix {
    sourceInventory = hostSourceInventory;
  };
  inherit (oracle) hostBuild hostPackage hostWorkspace testTools hostDevelopment hostFormat hostInventory;
  sourceDirectories = ["tools/bazel" "third_party/rust" "crates"];
  gateway = "//crates/crucible/crucible-qemu-debug-gateway:";
  protocol = "//crates/crucible/crucible-qemu-protocol:";
  hostPackages = {
    crucible-control-server = "crates/crucible/crucible-control-server";
    crucible-control-client = "crates/crucible/crucible-control-client";
    crucible-control-api = "crates/crucible/crucible-control-api";
    crucible-session = "crates/crucible/crucible-session";
    crucible-engine = "crates/crucible/crucible-engine";
    crucible-determinism = "crates/crucible/crucible-determinism";
    crucible-device = "crates/crucible/crucible-device";
    crucible-campaign = "crates/crucible/crucible-campaign";
    crucible-store = "crates/crucible/crucible-store";
    crucible-qemu-protocol = "crates/crucible/crucible-qemu-protocol";
    crucible-qemu-shmem = "crates/crucible/crucible-qemu-shmem";
  };
  hostPackageOptions =
    pkgs.lib.concatMap
    (name: ["--package-path" "${name}=${hostPackages.${name}}"])
    (builtins.attrNames hostPackages);
  parityTools = builtins.path {
    path = root + "/tools/bazel/tests";
    name = "aos-qemu-process-parity-tools";
    filter = path: type: type == "directory" || pkgs.lib.hasSuffix ".py" path;
  };
  testTargets = [
    "${gateway}unit"
    "${gateway}bin_crucible-debug-gateway"
    "${gateway}process_lifecycle"
    "${gateway}test_license_closure"
    "${gateway}production_license_closure"
  ];
  testWorkspace = pkgs.mkAosBazelWorkspace {
    inherit root;
    sourceInventory = testSourceInventory;
    sourceDirectories = pkgs.lib.optionals (testSourceInventory == null) sourceDirectories;
    dependencyProfile = "qemu-gpl-tests";
    analysisTargets = testTargets;
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.qemu-gpl-tests
      // {aos_qemu_test_tools = testTools;};
  };
in rec {
  inherit hostBuild hostPackage hostWorkspace testWorkspace testTools hostPackageOptions hostDevelopment hostFormat hostInventory;
  cargo = import ./_bazel-qemu-process-cargo.nix {inherit pkgs;};
  tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-qemu-gateway-process-tests";
    workspace = testWorkspace;
    targets = testTargets;
    retainActionGraph = true;
  };
  codecTests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-qemu-test-oracle-codec-tests";
    workspace = testWorkspace;
    targets = ["${protocol}test_oracle_unit"];
  };
  testDevelopment = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-qemu-gateway-test-development";
    workspace = testWorkspace;
    targets = ["${gateway}test_clippy"];
  };
  testFormat = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-qemu-gateway-test-format";
    workspace = testWorkspace;
    targets = ["${gateway}test_format"];
  };
  testInventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-qemu-gateway-process-test-inventory";
    workspace = testWorkspace;
    inventoryOnly = true;
    targets = testTargets ++ ["${gateway}test_clippy" "${gateway}test_format" "${protocol}test_oracle_unit"];
  };
  parity = pkgs.runCommand "aos-bazel-qemu-gateway-process-parity" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    export PYTHONDONTWRITEBYTECODE=1
    ${pkgs.python3}/bin/python3 ${parityTools}/verify_protocol.py \
      --features-only --inventory ${hostInventory}/inventory.json \
      --messages ${cargo}/host/cargo-messages.jsonl \
      ${pkgs.lib.escapeShellArgs hostPackageOptions} --output "$out/host-features.json"
    ${pkgs.python3}/bin/python3 ${parityTools}/verify_protocol.py \
      --tests ${tests}/evidence/tests --inventory ${testInventory}/inventory.json \
      --messages ${cargo}/gpl/cargo-messages.jsonl \
      --package-path crucible-qemu-debug-gateway=crates/crucible/crucible-qemu-debug-gateway \
      --dependency-package-path crucible-qemu-protocol=crates/crucible/crucible-qemu-protocol \
      --output "$out/tests.json"
    ${pkgs.python3}/bin/python3 ${parityTools}/verify_compiler_options.py \
      --build ${hostBuild} --cargo ${cargo}/host --output "$out/host-compiler.json"
    ${pkgs.python3}/bin/python3 ${parityTools}/verify_compiler_options.py \
      --build ${tests} --cargo ${cargo}/gpl --output "$out/gpl-compiler.json"
    printf '%s\n' ${pkgs.lib.escapeShellArg (builtins.toJSON {
      schema_version = 1;
      host_build = toString hostBuild;
      host_inventory = toString hostInventory;
      test_build = toString tests;
      test_inventory = toString testInventory;
      cargo = toString cargo;
      test_tools = toString testTools;
    })} > "$out/inputs.json"
  '';
  all = pkgs.runCommand "aos-bazel-qemu-gateway-process-checks" {} ''
    mkdir -p "$out"
    ln -s ${parity} "$out/parity"
    ln -s ${codecTests} "$out/codec-tests"
    ln -s ${hostDevelopment} "$out/host-development"
    ln -s ${hostFormat} "$out/host-format"
    ln -s ${testDevelopment} "$out/test-development"
    ln -s ${testFormat} "$out/test-format"
  '';
}
