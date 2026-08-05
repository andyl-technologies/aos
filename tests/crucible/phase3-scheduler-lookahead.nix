{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerLookahead",
  taskIds ? ["T-SCHED-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  schedulerLookaheadTest = builtins.readFile ../../crates/crucible/tests/scheduler_lookahead.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-2 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerLookahead`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "network lookahead value";
        needle = "pub enum NetworkLookahead";
      }
      {
        label = "infinite lookahead";
        needle = "Infinite";
      }
      {
        label = "scheduler lookahead edge";
        needle = "pub struct SchedulerLookaheadEdge";
      }
      {
        label = "scheduler lookahead graph";
        needle = "pub struct SchedulerLookaheadGraph";
      }
      {
        label = "effective edge constructor";
        needle = "pub fn from_edges";
      }
      {
        label = "world topology adapter";
        needle = "pub fn from_world_edges";
      }
      {
        label = "minimum inbound implementation";
        needle = ".filter(|edge| &edge.to == node && &edge.from != node)";
      }
      {
        label = "minimum latency selector";
        needle = ".map(|edge| edge.minimum_latency)";
      }
      {
        label = "inbound min reduction";
        needle = ".min()";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "network lookahead export";
        needle = "NetworkLookahead";
      }
      {
        label = "lookahead edge export";
        needle = "SchedulerLookaheadEdge";
      }
      {
        label = "lookahead graph export";
        needle = "SchedulerLookaheadGraph";
      }
      {
        label = "lookahead helper export";
        needle = "lookahead_for_node";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_lookahead.rs" schedulerLookaheadTest [
      {
        label = "minimum inbound latency test";
        needle = "scheduler_lookahead_uses_minimum_inbound_latency";
      }
      {
        label = "infinite no-inbound test";
        needle = "scheduler_lookahead_is_infinite_without_inbound_edges";
      }
      {
        label = "directionality test";
        needle = "scheduler_lookahead_is_directional";
      }
      {
        label = "canonical edge test";
        needle = "scheduler_lookahead_edges_are_canonical_and_duplicate_stable";
      }
      {
        label = "world topology test";
        needle = "scheduler_lookahead_consumes_world_static_topology_edges";
      }
      {
        label = "jitter-reduced latency assertion";
        needle = "graph.edges().contains(&edge(\"a\", \"b\", 8))";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler lookahead check";
        needle = "schedulerLookahead = import ./phase3-scheduler-lookahead.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler lookahead check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-lookahead";
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
          name = "run-scheduler-lookahead";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-lookahead-target" \
              -p crucible \
              --test scheduler_lookahead \
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
            lookahead=min-inbound-link-latency
            no_inbound=positive-infinity
            RESULT
          '';
        }
      ];
    }
