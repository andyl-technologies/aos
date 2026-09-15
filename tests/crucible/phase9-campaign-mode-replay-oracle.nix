args @ {
  pkgs,
  lib,
  ...
}: let
  authority = import ./phase6-fork-replay-oracle.nix {inherit pkgs lib;};
in
  assert authority.type == "derivation";
    import ./phase9-campaign-mode-native-gate.nix (args
      // {
        gate = "gate:replay-oracle";
        authoritativeAttr = "checks.crucible.phase6.gates.replayOracle";
        inherit authority;
        executionFamily = "qemu-runtime";
        name = "fork-replay-oracle";
        cargoBuildCommands = [
          "test --frozen --offline --release --no-run -p crucible --test gate_fork_replay_oracle"
        ];
        installedTests = [
          {
            targetName = "gate_fork_replay_oracle";
            targetKind = "test";
            crateDir = "crucible";
            destination = "crucible-gate-fork-replay-oracle";
          }
        ];
        runtimeCommands = [
          {
            executable = "crucible-gate-fork-replay-oracle";
            arguments = [];
            evidence = "fork_replay_oracle";
            expectedCount = 3;
          }
        ];
      })
