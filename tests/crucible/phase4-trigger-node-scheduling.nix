{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerNodeScheduling",
  taskIds ? ["T-TRIG-13"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  nodeSchedulingTest = builtins.readFile ../../crates/crucible/tests/trigger_node_scheduling.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  nodeSchedulingSources = builtins.concatStringsSep "\n" [
    scheduler
    trigger
    nodeSchedulingTest
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-13 completion note";
        needle = "Completed by `checks.crucible.phase4.triggerNodeScheduling`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "scenario carries trigger static topology";
        needle = "pub trigger_static_topology: Option<WorldStaticTopology>";
      }
      {
        label = "scenario accepts world for trigger validation";
        needle = "pub fn with_trigger_world";
      }
      {
        label = "scheduler retains trigger static topology";
        needle = "trigger_static_topology: Option<WorldStaticTopology>";
      }
      {
        label = "scheduler exposes trigger static topology";
        needle = "pub fn trigger_static_topology";
      }
      {
        label = "world topology material included in scenario identity";
        needle = "world_static_topology_material";
      }
      {
        label = "node schedule target validator";
        needle = "fn validate_trigger_node_schedule_target";
      }
      {
        label = "participant validation";
        needle = "static_topology.participants.contains(node)";
      }
      {
        label = "bake-set validation";
        needle = "static_topology.bake_nodes.contains(node)";
      }
      {
        label = "trigger action apply uses world topology";
        needle = "self.trigger_static_topology.as_ref()";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "graph validation can inspect world static topology";
        needle = "WorldStaticTopology";
      }
      {
        label = "world-aware graph constructor";
        needle = "pub fn new_for_world";
      }
      {
        label = "action reference validator";
        needle = "fn validate_action_references";
      }
      {
        label = "start stop action validation";
        needle = "Action::StartNode { node } | Action::StopNode { node }";
      }
      {
        label = "graph participant validation";
        needle = "static_topology.participants.contains(node)";
      }
      {
        label = "graph bake-set validation";
        needle = "static_topology.bake_nodes.contains(node)";
      }
      {
        label = "missing world graph error";
        needle = "NodeScheduleTargetRequiresWorld";
      }
      {
        label = "nested group validation";
        needle = "Action::Group(actions) =>";
      }
      {
        label = "undeclared graph error";
        needle = "UndeclaredNodeScheduleTarget";
      }
      {
        label = "unbaked graph error";
        needle = "UnbakedNodeScheduleTarget";
      }
    ]
    ++ failuresFor "crates/crucible/tests/trigger_node_scheduling.rs" nodeSchedulingTest [
      {
        label = "valid node scheduling topology test";
        needle = "start_stop_schedule_declared_baked_nodes_without_topology_mutation";
      }
      {
        label = "no world rejection test";
        needle = "start_stop_without_world_static_topology_is_rejected_atomically";
      }
      {
        label = "undeclared runtime rejection test";
        needle = "scheduler_rejects_undeclared_node_schedule_target_atomically";
      }
      {
        label = "world required graph validation test";
        needle = "event_graph_requires_world_for_start_stop_targets";
      }
      {
        label = "world-aware graph validation test";
        needle = "event_graph_for_world_rejects_undeclared_start_stop_targets";
      }
      {
        label = "missing world graph error assertion";
        needle = "EventGraphError::NodeScheduleTargetRequiresWorld";
      }
      {
        label = "world-aware graph construction exercised";
        needle = "EventGraph::new_for_world";
      }
      {
        label = "participants unchanged assertion";
        needle = "assert_eq!(after_topology.participants, world_topology.participants);";
      }
      {
        label = "rng streams unchanged assertion";
        needle = "assert_eq!(after_topology.rng_streams, world_topology.rng_streams);";
      }
      {
        label = "lookahead graph unchanged assertion";
        needle = "after_topology.lookahead_graph";
      }
      {
        label = "world lookahead graph comparison";
        needle = "world_topology.lookahead_graph";
      }
      {
        label = "bake nodes unchanged assertion";
        needle = "assert_eq!(after_topology.bake_nodes, world_topology.bake_nodes);";
      }
      {
        label = "atomic error state assertion";
        needle = "assert_eq!(scheduler.trigger_actions(), &before_actions);";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes trigger node scheduling check";
        needle = "triggerNodeScheduling = import ./phase4-trigger-node-scheduling.nix";
      }
    ]
    ++ forbiddenFor "trigger node scheduling sources" nodeSchedulingSources [
      {
        label = "topology participant mutation";
        needle = ".participants.push(";
      }
      {
        label = "topology rng stream mutation";
        needle = ".rng_streams.push(";
      }
      {
        label = "topology lookahead mutation";
        needle = ".lookahead_graph.push(";
      }
      {
        label = "topology bake-set mutation";
        needle = ".bake_nodes.push(";
      }
      {
        label = "trigger action decision variant";
        needle = "Decision::Trigger";
      }
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 trigger-node-scheduling check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-trigger-node-scheduling";
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
          name = "run-trigger-node-scheduling";
          script = ''
            cargo test \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test trigger_node_scheduling \
              -- --test-threads=1
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/nix-support"
            {
              echo "attr=${attrPath}"
              echo "tasks=${taskList}"
              echo "gate=phase4-trigger-node-scheduling"
              echo "node_scheduling_uses_world_static_topology=true"
              echo "node_scheduling_does_not_mutate_topology=true"
            } > "$out/nix-support/metadata"
          '';
        }
      ];
    }
