{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerRendezvousPurpose",
  taskIds ? ["T-SCHED-26"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  rendezvousPurposeTest = builtins.readFile ../../crates/crucible/tests/scheduler_rendezvous_purpose.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-26 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerRendezvousPurpose`";
      }
      {
        label = "allowed assertion-drain note";
        needle = "assertion-drain";
      }
      {
        label = "allowed trigger-eval note";
        needle = "trigger-eval";
      }
      {
        label = "allowed topology-swap note";
        needle = "topology-swap";
      }
      {
        label = "allowed snapshot-control note";
        needle = "snapshot-control";
      }
      {
        label = "not delivery note";
        needle = "not an event-delivery";
      }
      {
        label = "independent resumption note";
        needle = "independent horizon-bounded advancement";
      }
      {
        label = "terminal exclusion note";
        needle = "active rendezvous set";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "rendezvous purpose enum";
        needle = "pub enum SchedulerRendezvousPurpose";
      }
      {
        label = "assertion drain purpose";
        needle = "AssertionDrain";
      }
      {
        label = "trigger evaluation purpose";
        needle = "TriggerEvaluation";
      }
      {
        label = "topology swap purpose";
        needle = "TopologySwap";
      }
      {
        label = "snapshot control purpose";
        needle = "SnapshotControl";
      }
      {
        label = "rendezvous node evidence";
        needle = "pub struct SchedulerRendezvousNode";
      }
      {
        label = "rendezvous record evidence";
        needle = "pub struct SchedulerRendezvousRecord";
      }
      {
        label = "record accessor";
        needle = "pub fn rendezvous_records";
      }
      {
        label = "record helper";
        needle = "fn record_rendezvous";
      }
      {
        label = "topology swap record";
        needle = "SchedulerRendezvousPurpose::TopologySwap";
      }
      {
        label = "zero skew guard";
        needle = "rendezvous requires zero skew";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "event delivery rendezvous purpose";
        needle = "EventDelivery";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "purpose exported";
        needle = "SchedulerRendezvousPurpose";
      }
      {
        label = "record exported";
        needle = "SchedulerRendezvousRecord";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_rendezvous_purpose.rs" rendezvousPurposeTest [
      {
        label = "fixed rendezvous is not delivery test";
        needle = "fixed_rendezvous_caps_do_not_deliver_future_event";
      }
      {
        label = "zero skew topology swap test";
        needle = "topology_swap_rendezvous_records_zero_skew_and_resumes_independently";
      }
      {
        label = "terminal membership test";
        needle = "topology_swap_rendezvous_membership_excludes_terminal_nodes";
      }
      {
        label = "no fixed rendezvous records before event";
        needle = "assert!(scheduler.rendezvous_records().is_empty())";
      }
      {
        label = "event delivered at exact event time";
        needle = "VirtualTime { ticks: 12 }";
      }
      {
        label = "topology swap purpose asserted";
        needle = "SchedulerRendezvousPurpose::TopologySwap";
      }
      {
        label = "all rendezvous node times asserted";
        needle = "node.virtual_time == activation_time";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_rendezvous_purpose.rs" rendezvousPurposeTest [
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
        label = "phase3 exposes scheduler rendezvous-purpose check";
        needle = "schedulerRendezvousPurpose = import ./phase3-scheduler-rendezvous-purpose.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler rendezvous-purpose check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-rendezvous-purpose";
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
          name = "run-scheduler-rendezvous-purpose";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-rendezvous-purpose-target" \
              -p crucible \
              --test scheduler_rendezvous_purpose \
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
            rendezvous_purposes=assertion-drain,trigger-eval,topology-swap,snapshot-control
            event_delivery_rendezvous=false
            topology_swap_zero_skew=true
            independent_resumption=true
            RESULT
          '';
        }
      ];
    }
