{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.ioSubnodeSuite",
  taskIds ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
  taskList = builtins.concatStringsSep "," taskIds;
in
  mkCrucibleTestGate {
    pname = "crucible-phase3-io-subnode-suite";

    buildDeps = [
      pkgs.coreutils
      pkgs.sed
    ];

    phases = [
      {
        name = "run-io-subnode-suite";
        script = ''
          set -eu
          crucible-cargo test \
            -p crucible-device \
            -- --test-threads=1
          crucible-cargo test \
            -p crucible-engine \
            --lib \
            device \
            -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          set -eu
          mkdir -p "$out"
          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          tasks=${taskList}
          component=crucible-device
          io_subnode_trait=true
          block_overlay=true
          block_completion_model=true
          block_snapshot_restore=true
          ninep_server=true
          ninep_session_lifecycle=true
          ninep_wire_abi=true
          network_link_subnode=true
          RESULT
        '';
      }
    ];
  }
