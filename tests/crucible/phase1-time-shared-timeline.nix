{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.timeSharedTimeline",
  taskIds ? ["T-TIME-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  publicTest = builtins.readFile ../../crates/crucible/tests/time_shared_timeline.rs;
  timeSpec = builtins.readFile ../../docs/rfcs/0010-crucible/09-virtual-time-icount.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "uniform node counter type";
        needle = "pub struct NodeCounter";
      }
      {
        label = "VM icount to node counter conversion";
        needle = "pub fn from_icount(icount: Icount) -> Self";
      }
      {
        label = "node counter projection";
        needle = "pub fn to_virtual(self, shift: Shift) -> Result<VirtualInstant, TimeConversionError>";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "shared timeline context";
        needle = "pub struct SharedTimeline";
      }
      {
        label = "single shared shift constructor";
        needle = "pub fn new(shift: Shift) -> Result<Self, TimeConversionError>";
      }
      {
        label = "shared shift accessor";
        needle = "pub fn shift(&self) -> Shift";
      }
      {
        label = "counter projection API";
        needle = "pub fn project_counter(";
      }
      {
        label = "projection result type";
        needle = "pub struct NodeTimelineProjection";
      }
      {
        label = "projection records source counter";
        needle = "pub counter: NodeCounter";
      }
      {
        label = "projection records shared virtual time";
        needle = "pub virtual_time: SimInstant";
      }
      {
        label = "projection to timeline key";
        needle = "pub fn timeline_key(&self, sequence: u64) -> SharedTimelineKey";
      }
      {
        label = "shared timeline key type";
        needle = "pub struct SharedTimelineKey";
      }
      {
        label = "timeline key node field";
        needle = "pub node: SchedulerNodeId";
      }
      {
        label = "timeline key sequence field";
        needle = "pub sequence: u64";
      }
      {
        label = "timeline key canonical ordering helper";
        needle = "pub fn ordered_timeline_keys";
      }
      {
        label = "timeline key helper sorts by derived Ord";
        needle = "ordered.sort();";
      }
      {
        label = "scheduled event key consumes shared timeline";
        needle = "pub timeline: SharedTimelineKey";
      }
      {
        label = "scheduled event key constructor from shared timeline";
        needle = "pub fn new(timeline: SharedTimelineKey, producer: SchedulerNodeId) -> Self";
      }
      {
        label = "scheduled event key refines shared time";
        needle = "self.timeline\n            .virtual_time";
      }
      {
        label = "scheduled event key refines consumer node";
        needle = "self.timeline.node";
      }
      {
        label = "scheduled event key preserves producer tie-break";
        needle = "self.producer.cmp(&other.producer)";
      }
      {
        label = "scheduled event key finally uses sequence";
        needle = "self.timeline.sequence";
      }
      {
        label = "scheduler covers VM nodes";
        needle = "SchedulingNodeKind::Vm";
      }
      {
        label = "scheduler covers I/O disk sub-nodes";
        needle = "SchedulingNodeKind::Disk";
      }
      {
        label = "scheduler covers I/O network sub-nodes";
        needle = "SchedulingNodeKind::Network";
      }
      {
        label = "module test covers VM and I/O projection";
        needle = "shared_timeline_projects_vm_and_io_counters_uniformly";
      }
      {
        label = "module test covers canonical key order";
        needle = "shared_timeline_keys_order_by_time_node_and_sequence";
      }
      {
        label = "module test covers scheduled event consumption";
        needle = "scheduled_event_keys_consume_shared_timeline_and_refine_by_producer";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "node counter export";
        needle = "NodeCounter";
      }
      {
        label = "shared timeline exports";
        needle = "SharedTimeline,";
      }
      {
        label = "shared timeline key export";
        needle = "SharedTimelineKey";
      }
      {
        label = "ordered timeline helper export";
        needle = "ordered_timeline_keys";
      }
    ]
    ++ failuresFor "crates/crucible/tests/time_shared_timeline.rs" publicTest [
      {
        label = "public VM/I/O projection test";
        needle = "vm_and_io_counters_project_to_one_shared_timeline";
      }
      {
        label = "VM icount projection assertion";
        needle = "NodeCounter::from_icount(Icount { retired: 6 })";
      }
      {
        label = "I/O counter projection assertion";
        needle = "NodeCounter { ticks: 6 }";
      }
      {
        label = "arrival order independent key test";
        needle = "shared_timeline_keys_are_arrival_order_independent";
      }
      {
        label = "public scheduled event consumption test";
        needle = "scheduled_event_keys_consume_shared_timeline_keys";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/09-virtual-time-icount.md" timeSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes shared-timeline check";
        needle = "timeSharedTimeline = import ./phase1-time-shared-timeline.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 time shared-timeline check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-time-shared-timeline";
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
          name = "run-time-shared-timeline";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-shared-timeline-target" \
              -p crucible \
              --lib shared_timeline \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-shared-timeline-target" \
              -p crucible \
              --test time_shared_timeline \
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
            tasks=${builtins.concatStringsSep "," taskIds}
            node_counter=vm_icount,io_subnode_counter
            shared_axis=virtual_time
            timeline_order=virtual_time,node_id,sequence
            scheduler_consumes_shared_timeline_key=true
            RESULT
          '';
        }
      ];
    }
