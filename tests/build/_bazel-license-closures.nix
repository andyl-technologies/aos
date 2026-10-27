##! Exports actual single-root Rust closures for the preserved license gate.
{pkgs}: let
  gpl = pkgs.callPackage ../../pkgs/emulation/_crucible-qemu-bazel.nix {};
  protocol = import ./_bazel-protocol.nix {inherit pkgs;};
  roots = {
    plugin = {
      workspace = gpl.workspace;
      target = "//crates/crucible/crucible-qemu-plugin:plugin";
    };
    gateway = {
      workspace = gpl.workspace;
      target = "//crates/crucible/crucible-qemu-debug-gateway:crucible-debug-gateway";
    };
    protocol = {
      workspace = protocol.workspace;
      target = "//crates/crucible/crucible-qemu-protocol:lib";
    };
    shmem = {
      workspace = protocol.workspace;
      target = "//crates/crucible/crucible-qemu-shmem:lib";
    };
  };
  inventories = builtins.mapAttrs (name: selection:
    pkgs.mkAosBazelBuild {
      pname = "aos-bazel-license-closure-${name}";
      inherit (selection) workspace;
      targets = [selection.target];
      inventoryOnly = true;
    })
  roots;
  arguments = pkgs.lib.concatStringsSep " " (pkgs.lib.mapAttrsToList (name: selection: "--inventory ${pkgs.lib.escapeShellArg selection.target} ${inventories.${name}}/inventory.json") roots);
in
  (pkgs.runCommand "aos-bazel-license-closures" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/metadata/export_license_closures.py} \
      --architecture ${pkgs.aosBazelArchitecture}/architecture.json \
      --sdk-directory ${../../third_party/rust} \
      --modules ${../../third_party/bazel/modules.json} \
      --rule-inputs ${../../third_party/bazel/rule-inputs.json} \
      ${arguments} \
      --output "$out/license-closures.json"
  '')
  // {inherit inventories;}
