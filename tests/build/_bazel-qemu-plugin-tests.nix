##! Qualifies GPL plugin tests against a separately linked Apache engine oracle.
{
  pkgs,
  hostSourceInventory ? ../../tools/bazel/metadata/qemu-test-oracle-host-inventory.json,
  testSourceInventory ? ../../tools/bazel/metadata/qemu-plugin-process-test-inventory.json,
}: let
  root = ../..;
  plugin = "//crates/crucible/crucible-qemu-plugin:";
  gatewayChecks = import ./_bazel-qemu-gateway-tests.nix {inherit pkgs hostSourceInventory;};
  inherit (gatewayChecks) hostPackageOptions;
  execution = pkgs.callPackage ../../pkgs/emulation/_crucible-qemu-bazel-plugin-tests.nix {
    inherit hostSourceInventory testSourceInventory;
  };
  parityTools = builtins.path {
    path = root + "/tools/bazel/tests";
    name = "aos-qemu-plugin-parity-tools";
    filter = path: type: type == "directory" || pkgs.lib.hasSuffix ".py" path;
  };
in rec {
  inherit (execution) workspace hostBuild hostPackage hostWorkspace hostInventory testTools tests development format inventory;
  cargo = import ./_bazel-qemu-plugin-tests-cargo.nix {inherit pkgs;};
  parity = pkgs.runCommand "aos-bazel-qemu-plugin-process-parity" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    export PYTHONDONTWRITEBYTECODE=1
    ${pkgs.python3}/bin/python3 ${parityTools}/verify_protocol.py \
      --features-only --inventory ${hostInventory}/inventory.json \
      --messages ${cargo}/host/cargo-messages.jsonl \
      ${pkgs.lib.escapeShellArgs hostPackageOptions} --output "$out/host-features.json"
    ${pkgs.python3}/bin/python3 ${parityTools}/verify_protocol.py \
      --tests ${tests}/evidence/tests --inventory ${inventory}/inventory.json \
      --messages ${cargo}/gpl/cargo-messages.jsonl \
      --package-path crucible-qemu-plugin=crates/crucible/crucible-qemu-plugin \
      --dependency-package-path crucible-qemu-protocol=crates/crucible/crucible-qemu-protocol \
      --dependency-package-path crucible-qemu-shmem=crates/crucible/crucible-qemu-shmem \
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
      test_inventory = toString inventory;
      cargo = toString cargo;
      test_tools = toString testTools;
    })} > "$out/inputs.json"
  '';
  all = pkgs.runCommand "aos-bazel-qemu-plugin-process-checks" {} ''
    mkdir -p "$out"
    ln -s ${parity} "$out/parity"
    ln -s ${development} "$out/development"
    ln -s ${format} "$out/format"
    ln -s ${gatewayChecks.hostDevelopment} "$out/host-development"
    ln -s ${gatewayChecks.hostFormat} "$out/host-format"
  '';
}
