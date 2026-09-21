args @ {
  pkgs,
  lib,
  ...
}: let
  authority = import ./phase6-basic-block-coverage.nix {inherit pkgs lib;};
in
  assert authority.type == "derivation";
    import ./phase9-campaign-mode-native-gate.nix (args
      // {
        inherit authority;
        gate = "gate:basic-block-coverage";
        authoritativeAttr = "checks.crucible.phase6.basicBlockCoverage";
        executionFamily = "qemu-runtime";
        name = "basic-block-coverage";
        cargoBuildCommands = [
          "test --frozen --offline --release --no-run -p crucible --test gate_basic_block_coverage"
          "test --frozen --offline --release --no-run -p crucible-qemu --lib"
          "test --frozen --offline --release --no-run -p crucible-qemu-plugin --lib"
        ];
        installedTests = [
          {
            targetName = "gate_basic_block_coverage";
            targetKind = "test";
            crateDir = "crucible";
            destination = "crucible-gate-basic-block-coverage";
          }
          {
            targetName = "crucible_qemu";
            targetKind = "lib";
            crateDir = "crucible-qemu";
            destination = "crucible-qemu-lib";
          }
          {
            targetName = "crucible_qemu_plugin";
            targetKind = "lib";
            crateDir = "crucible-qemu-plugin";
            destination = "crucible-qemu-plugin-lib";
          }
        ];
        runtimeCommands = [
          {
            executable = "crucible-gate-basic-block-coverage";
            arguments = [];
            evidence = "crucible_coverage_contracts";
            expectedCount = 3;
          }
          {
            executable = "crucible-qemu-lib";
            arguments = ["mapped_quantum::coverage_tests"];
            evidence = "qemu_coverage_contracts";
            expectedCount = 2;
          }
          {
            executable = "crucible-qemu-plugin-lib";
            arguments = ["coverage"];
            evidence = "plugin_coverage_contracts";
            expectedCount = 20;
          }
        ];
      })
