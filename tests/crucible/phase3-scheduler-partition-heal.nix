{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerPartitionHeal",
  taskIds ? ["T-SCHED-23"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  partitionHealTest = builtins.readFile ../../crates/crucible/tests/scheduler_partition_heal.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-23 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerPartitionHeal`";
      }
      {
        label = "partition removal note";
        needle = "Partition changes remove directed";
      }
      {
        label = "heal restoration note";
        needle = "heal changes restore";
      }
      {
        label = "last inbound infinite note";
        needle = "last inbound edge is removed";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "topology effect enum";
        needle = "pub enum SchedulerTopologyChangeEffect";
      }
      {
        label = "edge endpoint type";
        needle = "pub struct SchedulerLookaheadEdgeEndpoint";
      }
      {
        label = "edge endpoint constructor";
        needle = "pub fn new(from: SchedulerNodeId, to: SchedulerNodeId) -> Self";
      }
      {
        label = "partition constructor";
        needle = "pub fn partition";
      }
      {
        label = "heal constructor";
        needle = "pub fn heal";
      }
      {
        label = "remove effect";
        needle = "RemoveEffectiveEdges";
      }
      {
        label = "restore effect";
        needle = "RestoreEffectiveEdges";
      }
      {
        label = "graph remove helper";
        needle = "pub fn remove_effective_edges";
      }
      {
        label = "graph restore helper";
        needle = "pub fn restore_effective_edges";
      }
      {
        label = "boundary current-graph removal";
        needle = "self.effective_topology.remove_effective_edges(endpoints)";
      }
      {
        label = "boundary current-graph restoration";
        needle = "restore_effective_edges(restored_edges)";
      }
      {
        label = "minimum inbound recompute";
        needle = ".filter(|edge| &edge.to == node && &edge.from != node)";
      }
      {
        label = "infinite no-inbound recompute";
        needle = "None => NetworkLookahead::Infinite";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "topology effect export";
        needle = "SchedulerTopologyChangeEffect";
      }
      {
        label = "edge endpoint export";
        needle = "SchedulerLookaheadEdgeEndpoint";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_partition_heal.rs" partitionHealTest [
      {
        label = "next minimum test";
        needle = "partition_removes_one_inbound_edge_and_recomputes_next_minimum";
      }
      {
        label = "last inbound infinite test";
        needle = "partition_last_inbound_edge_recomputes_infinite_lookahead";
      }
      {
        label = "heal current graph test";
        needle = "heal_restores_edge_over_current_partitioned_graph";
      }
      {
        label = "send block until heal test";
        needle = "partition_removed_edge_blocks_send_until_heal_restores_it";
      }
      {
        label = "partition constructor exercised";
        needle = "SchedulerTopologyChange::partition";
      }
      {
        label = "heal constructor exercised";
        needle = "SchedulerTopologyChange::heal";
      }
      {
        label = "infinite assertion";
        needle = "NetworkLookahead::Infinite";
      }
      {
        label = "next minimum assertion";
        needle = "finite_lookahead(17)";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_partition_heal.rs" partitionHealTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler partition-heal check";
        needle = "schedulerPartitionHeal = import ./phase3-scheduler-partition-heal.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler partition-heal check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-partition-heal";
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
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-scheduler-partition-heal";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-partition-heal-target" \
              -p crucible \
              --test scheduler_partition_heal \
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
            component=crucible-scheduler
            partition=edge-removal-current-effective-graph
            heal=edge-restoration-current-effective-graph
            lookahead=min-inbound-or-infinite
            RESULT
          '';
        }
      ];
    }
