{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerActionApplication",
  taskIds ? ["T-TRIG-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  actionTest = builtins.readFile ../../crates/crucible/tests/trigger_action_application.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  actionSources = builtins.concatStringsSep "\n" [
    scheduler
    libSource
    actionTest
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-12 completion note";
        needle = "Completed by `checks.crucible.phase4.triggerActionApplication`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "trigger action state";
        needle = "pub struct TriggerActionState";
      }
      {
        label = "trigger action applications";
        needle = "pub struct TriggerActionApplication";
      }
      {
        label = "trigger action payload";
        needle = "TriggerActionApplied(TriggerActionApplication)";
      }
      {
        label = "trigger action apply API";
        needle = "pub fn apply_trigger_firings";
      }
      {
        label = "firing prefix validation reused";
        needle = "self.validate_trigger_firings(firings)?";
      }
      {
        label = "atomic cloned trigger action state";
        needle = "let mut trigger_actions = self.trigger_actions.clone();";
      }
      {
        label = "state committed after event log append";
        needle = "self.trigger_actions = trigger_actions;";
      }
      {
        label = "group action recursion";
        needle = "Action::Group(actions) =>";
      }
      {
        label = "arm timer effect";
        needle = ".armed_timers\n                .insert(name.clone(), VirtualTime { ticks })";
      }
      {
        label = "cancel timer effect";
        needle = "state.armed_timers.remove(name)";
      }
      {
        label = "start node effect";
        needle = "NodeLifecycle::Started";
      }
      {
        label = "stop node effect";
        needle = "NodeLifecycle::Exited";
      }
      {
        label = "savepoint effect";
        needle = "state.savepoints.push";
      }
      {
        label = "fork effect";
        needle = "state.forks.push";
      }
      {
        label = "verdict effect";
        needle = "state.verdict = Some";
      }
      {
        label = "diagnostic effect";
        needle = "state.diagnostics.push";
      }
      {
        label = "log action observational class";
        needle = "if let Action::Log { level, message } = &application.action {";
      }
      {
        label = "log action carried as observational diagnostic payload";
        needle = "return EventPayload::diagnostic(\"trigger.log\", details);";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "trigger action application export";
        needle = "TriggerActionApplication";
      }
      {
        label = "trigger action state export";
        needle = "TriggerActionState";
      }
    ]
    ++ failuresFor "crates/crucible/tests/trigger_action_application.rs" actionTest [
      {
        label = "full action set test";
        needle = "trigger_actions_apply_full_set_in_group_order_without_schedule_decisions";
      }
      {
        label = "forked deterministic state test";
        needle = "forked_same_prefix_rederives_identical_action_state_and_bytes";
      }
      {
        label = "stale action batch rejection test";
        needle = "stale_firing_batch_cannot_apply_actions_twice";
      }
      {
        label = "nested group exercised";
        needle = "Action::Group(vec![";
      }
      {
        label = "schedule decisions forbidden";
        needle = "SchedulerEventLogPayload::Decision(_)";
      }
      {
        label = "observational log assertion";
        needle = "SchedulerEventLogClass::Observational";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes trigger action application check";
        needle = "triggerActionApplication = import ./phase4-trigger-action-application.nix";
      }
    ]
    ++ forbiddenFor "trigger action application sources" actionSources [
      {
        label = "trigger action decision variant";
        needle = "Decision::Trigger";
      }
      {
        label = "trigger action stored inside a Decision";
        needle = "Decision(TriggerAction";
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
  then throw "crucible phase4 trigger-action-application check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-trigger-action-application";
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
          name = "run-trigger-action-application";
          script = ''
            cargo test \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test trigger_action_application \
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
              echo "gate=phase4-trigger-action-application"
              echo "trigger_actions_applied_at_firing_time=true"
              echo "trigger_group_order_atomic=true"
            } > "$out/nix-support/metadata"
          '';
        }
      ];
    }
