{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerFiringCausalLog",
  taskIds ? ["T-TRIG-11"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  eventCatalog = builtins.readFile ../../crates/crucible/src/event_catalog.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  causalLogTest = builtins.readFile ../../crates/crucible/tests/trigger_firing_causal_log.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
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
  causalSources = builtins.concatStringsSep "\n" [
    trigger
    scheduler
    libSource
    causalLogTest
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-11 checked off";
        needle = "- [x] **T-TRIG-11**";
      }
      {
        label = "T-TRIG-11 completion note";
        needle = "Completed by `checks.crucible.phase4.triggerFiringCausalLog`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "opaque ordered firing batch";
        needle = "pub struct EventFirings";
      }
      {
        label = "firing batch captures evaluation point";
        needle = "point: EventEvaluationPoint";
      }
      {
        label = "firing batch captures event-log offset";
        needle = "event_log_offset: EventLogOffset";
      }
      {
        label = "firing batch owns ordered firings";
        needle = "firings: Vec<EventFiring>";
      }
      {
        label = "event graph returns firing batch";
        needle = ") -> EventFirings";
      }
      {
        label = "batch exposes read-only slice";
        needle = "pub fn as_slice(&self) -> &[EventFiring]";
      }
      {
        label = "batch exposes event-log offset";
        needle = "pub fn event_log_offset(&self) -> EventLogOffset";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "trigger fired scheduler payload";
        needle = "TriggerFired(EventFiring)";
      }
      {
        label = "trigger firing append API";
        needle = "pub fn append_trigger_firings";
      }
      {
        label = "trigger firing point validation";
        needle = "firings.point() != current_point";
      }
      {
        label = "trigger firing offset validation";
        needle = "firings.event_log_offset() != current_offset";
      }
      {
        label = "trigger firing payload append";
        needle = "SchedulerEventLogPayload::TriggerFired(firing.clone())";
      }
      {
        label = "trigger fired canonical payload name";
        needle = "payload=trigger_fired";
      }
    ]
    ++ failuresFor "crates/crucible/src/event_catalog.rs" eventCatalog [
      {
        label = "trigger fired payload is causal";
        needle = "kind: \"trigger_fired\",\n        class: SchedulerEventLogClass::Causal,";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "event firings batch export";
        needle = "EventFirings";
      }
    ]
    ++ failuresFor "crates/crucible/tests/trigger_firing_causal_log.rs" causalLogTest [
      {
        label = "causal not decision test";
        needle = "trigger_firing_is_causal_event_log_entry_not_schedule_decision";
      }
      {
        label = "forked prefix rederive test";
        needle = "forked_same_prefix_rederives_identical_trigger_firing_entries";
      }
      {
        label = "event-boundary stale batch regression";
        needle = "stale_event_boundary_firing_batch_cannot_be_reappended";
      }
      {
        label = "probabilistic action boundary test";
        needle = "trigger_firing_for_probabilistic_fault_action_is_not_a_fault_outcome_decision";
      }
      {
        label = "explicit trigger fired payload assertion";
        needle = "SchedulerEventLogPayload::TriggerFired(firing)";
      }
      {
        label = "explicit no Decision assertion";
        needle = "SchedulerEventLogPayload::Decision(_)";
      }
      {
        label = "schedule unchanged assertion";
        needle = "scheduler.configuration().schedule, before_schedule";
      }
      {
        label = "event-boundary stale batch offset assertion";
        needle = "event_boundary_firings.event_log_offset()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes trigger firing causal log check";
        needle = "triggerFiringCausalLog = import ./phase4-trigger-firing-causal-log.nix";
      }
    ]
    ++ forbiddenFor "trigger firing causal sources" causalSources [
      {
        label = "public event firings raw constructor";
        needle = "pub fn new(point: EventEvaluationPoint, firings: Vec<EventFiring>)";
      }
      {
        label = "public event firings fields";
        needle = "pub struct EventFirings {\n    pub";
      }
      {
        label = "trigger firing decision variant";
        needle = "Decision::Trigger";
      }
      {
        label = "trigger fired stored inside a Decision";
        needle = "Decision(TriggerFired";
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
  then throw "crucible phase4 trigger-firing-causal-log check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-trigger-firing-causal-log";
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
          name = "run-trigger-firing-causal-log";
          script = ''
            cargo test \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test trigger_firing_causal_log \
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
              echo "gate=phase4-trigger-firing-causal-log"
              echo "trigger_firings_causal_event_log=true"
              echo "trigger_firings_not_decisions=true"
            } > "$out/nix-support/metadata"
          '';
        }
      ];
    }
