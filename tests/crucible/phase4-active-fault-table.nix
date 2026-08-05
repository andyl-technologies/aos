{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.activeFaultTable",
  taskIds ? ["T-FAULT-13"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  canonical = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  tableTest = builtins.readFile ../../crates/crucible/tests/active_fault_table.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-13 completion note";
        needle = "Completed by `checks.crucible.phase4.activeFaultTable`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "materialized active fault table";
        needle = "pub active_fault_table: ActiveFaultTable";
      }
      {
        label = "directed active network edge key";
        needle = "pub struct ActiveNetworkEdgeKey";
      }
      {
        label = "table recompute helper";
        needle = "pub fn recompute_active_fault_table";
      }
      {
        label = "schedule replay recomputes table";
        needle = "self.recompute_active_fault_table()";
      }
    ]
    ++ failuresFor "crates/crucible/src/model/canonical.rs" canonical [
      {
        label = "active fault table hash entry";
        needle = "write_active_fault_table(hasher, &state.active_fault_table)";
      }
      {
        label = "network table deterministic writer";
        needle = "fn write_combined_network_faults";
      }
      {
        label = "directed network table hash writer";
        needle = "write_active_network_edge_direction";
      }
      {
        label = "device table deterministic writer";
        needle = "fn write_combined_block_faults";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "scheduler captures active trigger faults";
        needle = "state.active_fault_tags = self.trigger_actions.active_faults.clone()";
      }
      {
        label = "scheduler materializes active table";
        needle = "state.recompute_active_fault_table()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/active_fault_table.rs" tableTest [
      {
        label = "schedule replay recompute test";
        needle = "schedule_replay_recomputes_active_fault_table";
      }
      {
        label = "declarative trigger capture test";
        needle = "declarative_trigger_capture_materializes_combined_active_fault_table";
      }
      {
        label = "legacy membership table test";
        needle = "legacy_declarative_faults_enter_combined_table_and_directed_edges";
      }
      {
        label = "reversed legacy partition table test";
        needle = "legacy_partition_projection_preserves_reversed_endpoint_direction";
      }
      {
        label = "non-projectable legacy retention test";
        needle = "non_projectable_legacy_faults_remain_in_legacy_membership_table";
      }
      {
        label = "block and 9p table test";
        needle = "block_and_9p_faults_enter_materialized_active_table";
      }
      {
        label = "direct checkpoint table materialization test";
        needle = "direct_fat_checkpoint_materializes_active_fault_table_from_schedule";
      }
      {
        label = "materialized hash test";
        needle = "active_fault_table_contributes_to_materialized_state_identity";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 active fault table import";
        needle = "activeFaultTable = import ./phase4-active-fault-table.nix";
      }
      {
        label = "phase4 active fault table attr path";
        needle = "attrPath = \"checks.crucible.phase4.activeFaultTable\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/active_fault_table.rs" tableTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 active-fault-table check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-active-fault-table";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-active-fault-table";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-active-fault-table-target" \
              -p crucible \
              --test active_fault_table \
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
            table=active-faults
            materialized=combined-faults
            RESULT
          '';
        }
      ];
    }
