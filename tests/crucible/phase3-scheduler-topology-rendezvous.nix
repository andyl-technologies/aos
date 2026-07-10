{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerTopologyRendezvous",
  taskIds ? ["T-SCHED-24"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  topologyRendezvousTest = builtins.readFile ../../crates/crucible/tests/scheduler_topology_rendezvous.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-24 checked off";
        needle = "- [x] **T-SCHED-24**";
      }
      {
        label = "T-SCHED-24 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerTopologyRendezvous`";
      }
      {
        label = "activation rendezvous note";
        needle = "exact activation virtual time";
      }
      {
        label = "no shifted fixed tick note";
        needle = "not shifted to the next fixed rendezvous tick";
      }
      {
        label = "no mid-run note";
        needle = "never applies the topology mutation mid-RUN";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "change activation time";
        needle = "pub activation_time: Option<SimInstant>";
      }
      {
        label = "activation setter";
        needle = "pub fn with_activation_time";
      }
      {
        label = "application activation evidence";
        needle = "activation_time: Option<SimInstant>";
      }
      {
        label = "activation readiness helper";
        needle = "fn topology_activation_ready";
      }
      {
        label = "activation cap helper";
        needle = "fn pending_topology_activation_cap";
      }
      {
        label = "activation cap participates in shared rendezvous";
        needle = "let topology_cap = self.pending_topology_activation_cap()?;";
      }
      {
        label = "fixed and activation caps use minimum";
        needle = "min_instant(fixed_cap, topology_cap)";
      }
      {
        label = "not ready changes are deferred";
        needle = "if !self.topology_activation_ready(activation_time)?";
      }
      {
        label = "missed activation guard";
        needle = "topology activation rendezvous missed exact virtual time";
      }
      {
        label = "deterministic material includes activation";
        needle = "topology_change_activation_time_ns";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_topology_rendezvous.rs" topologyRendezvousTest [
      {
        label = "exact activation cap test";
        needle = "activation_rendezvous_caps_at_fault_time_not_fixed_tick";
      }
      {
        label = "before next pick test";
        needle = "timed_topology_change_applies_after_activation_before_next_pick";
      }
      {
        label = "all nodes rendezvous test";
        needle = "timed_topology_change_waits_until_all_nodes_reach_activation";
      }
      {
        label = "old horizon continuation test";
        needle = "timed_topology_change_continues_after_old_horizon_before_activation";
      }
      {
        label = "idle no-wake activation test";
        needle = "timed_topology_change_advances_idle_no_wake_node_to_activation";
      }
      {
        label = "mixed timed immediate ordering test";
        needle = "ready_timed_change_keeps_sequence_order_with_immediate_change";
      }
      {
        label = "fixed tick sentinel";
        needle = "with_rendezvous_interval(duration(100))";
      }
      {
        label = "runtime immediate queue exercised";
        needle = "scheduler.queue_topology_change";
      }
      {
        label = "activation assertion";
        needle = "application.activation_time";
      }
      {
        label = "partition timed change";
        needle = "SchedulerTopologyChange::partition";
      }
      {
        label = "last edge partition recomputes infinity";
        needle = "NetworkLookahead::Infinite";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_topology_rendezvous.rs" topologyRendezvousTest [
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
        label = "phase3 exposes scheduler topology-rendezvous check";
        needle = "schedulerTopologyRendezvous = import ./phase3-scheduler-topology-rendezvous.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler topology-rendezvous check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-topology-rendezvous";
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
          name = "run-scheduler-topology-rendezvous";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-topology-rendezvous-target" \
              -p crucible \
              --test scheduler_topology_rendezvous \
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
            topology_rendezvous=exact-activation-time
            fixed_rendezvous_tick_shift=false
            mid_run_topology_swap=false
            RESULT
          '';
        }
      ];
    }
