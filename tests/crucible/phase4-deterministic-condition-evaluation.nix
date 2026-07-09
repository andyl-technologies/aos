{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.deterministicConditionEvaluation",
  taskIds ? ["T-TRIG-10"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  trigger = builtins.readFile ../../crates/crucible/src/trigger.rs;
  scheduler = builtins.readFile ../../crates/crucible/src/scheduler.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  deterministicTest = builtins.readFile ../../crates/crucible/tests/deterministic_condition_evaluation.rs;
  schedulerEmitTest = builtins.readFile ../../crates/crucible/tests/scheduler_emit_step.rs;
  observableTest = builtins.readFile ../../crates/crucible/tests/observable_condition_leaves.rs;
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
  evaluationSources = builtins.concatStringsSep "\n" [
    trigger
    scheduler
    deterministicTest
    schedulerEmitTest
    observableTest
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-10 checked off";
        needle = "- [x] **T-TRIG-10**";
      }
      {
        label = "T-TRIG-10 completion note";
        needle = "Completed by `checks.crucible.phase4.deterministicConditionEvaluation`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "checked event-log prefix type";
        needle = "pub struct ConditionEventLogPrefix";
      }
      {
        label = "empty scheduler prefix error";
        needle = "EmptyEventLogPrefix";
      }
      {
        label = "dense scheduler prefix sequence error";
        needle = "NonPrefixEventLogSequence";
      }
      {
        label = "invalid scheduler entry hash error";
        needle = "InvalidEventLogEntryHash";
      }
      {
        label = "future event-log entry error";
        needle = "FutureEventLogEntry";
      }
      {
        label = "crate-local prefix constructor validates scheduler event-log entries";
        needle = "pub(crate) fn from_scheduler_event_log_entries";
      }
      # Invariant pins for the public prefix constructors. `from_scheduler_event_log_entries`
      # and `from_evaluation_boundary` were originally pub(crate) but were widened to `pub`
      # (06f17151d "Implement session breakpoints") for legitimate crucible-session/-cli
      # callers. Enforcement was downgraded from crate-boundary to invariant-pinning on
      # 2026-07-09: rather than forbid the public surface, require that every prefix
      # constructor routes through the checked base helper that raises these validation
      # errors, so a future refactor cannot remove the dense-prefix/hash/ordering/future
      # checks while staying green (a public caller still cannot mint an unchecked prefix).
      {
        label = "public prefix constructors delegate to the checked base helper";
        needle = "Self::from_scheduler_event_log_entries_with_base";
      }
      {
        label = "checked base helper rejects empty prefixes";
        needle = "ConditionEvaluationError::EmptyEventLogPrefix";
      }
      {
        label = "checked base helper rejects non-dense sequences";
        needle = "ConditionEvaluationError::NonPrefixEventLogSequence";
      }
      {
        label = "checked base helper rejects invalid entry hashes";
        needle = "ConditionEvaluationError::InvalidEventLogEntryHash";
      }
      {
        label = "checked base helper rejects out-of-order observations";
        needle = "ConditionEvaluationError::OutOfOrderEventLogEntry";
      }
      {
        label = "checked base helper rejects future entries past the evaluation point";
        needle = "ConditionEvaluationError::FutureEventLogEntry";
      }
      {
        label = "condition evaluator built from prefix";
        needle = "pub fn from_log_prefix(prefix: ConditionEventLogPrefix, oracle: O) -> Self";
      }
      {
        label = "shared evaluation pass";
        needle = "pub struct ConditionEvaluationPass";
      }
      {
        label = "assertion condition pass method";
        needle = "pub fn evaluate_assertion_condition";
      }
      {
        label = "event graph pass method";
        needle = "pub fn evaluate_event_graph";
      }
      {
        label = "event boundary kind";
        needle = "EventBoundary";
      }
      {
        label = "quantum boundary kind";
        needle = "QuantumBoundary";
      }
      {
        label = "rendezvous boundary kind";
        needle = "RendezvousBoundary";
      }
      {
        label = "scheduler event-log entry point derivation";
        needle = "pub fn event_log_entry(entry: &SchedulerEventLogEntry) -> Self";
      }
      {
        label = "observable entries are derived from scheduler payloads";
        needle = "SchedulerEventLogPayload::Observable(payload)";
      }
      {
        label = "prefix validates scheduler entry content hashes";
        needle = "entry.has_valid_content_hash()";
      }
      {
        label = "event graph state evaluate is crate-local";
        needle = "pub(crate) fn evaluate<E>";
      }
      {
        label = "shared evaluator function is crate-local";
        needle = "pub(crate) fn evaluate_condition";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "crate-local scheduler observable event-log entry constructor";
        needle = "pub(crate) fn observable(";
      }
      {
        label = "crate-local scheduler evaluation-boundary entry constructor";
        needle = "pub(crate) fn evaluation_boundary(";
      }
      {
        label = "scheduler entry hash verifier";
        needle = "pub fn has_valid_content_hash";
      }
      {
        label = "scheduler event-log sequence accessor";
        needle = "pub fn sequence(&self) -> u64";
      }
      {
        label = "scheduler event-log time accessor";
        needle = "pub fn at(&self) -> VirtualTime";
      }
      {
        label = "scheduler event-log class accessor";
        needle = "pub fn class(&self) -> SchedulerEventLogClass";
      }
      {
        label = "scheduler event-log payload accessor";
        needle = "pub fn payload(&self) -> &SchedulerEventLogPayload";
      }
      {
        label = "scheduler event-log content-hash accessor";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "scheduler-owned condition prefix projection";
        needle = "self.event_log.condition_prefix()";
      }
      {
        label = "scheduler-owned condition event-log prefix accessor";
        needle = "pub fn condition_event_log_prefix(&self) -> &ConditionEventLogPrefix";
      }
      {
        label = "scheduler evaluation boundary kind";
        needle = "pub enum SchedulerEvaluationBoundaryKind";
      }
      {
        label = "observable scheduler payload";
        needle = "Observable(ObservableEventPayload)";
      }
      {
        label = "evaluation-boundary scheduler payload";
        needle = "EvaluationBoundary(SchedulerEvaluationBoundaryKind)";
      }
      {
        label = "scheduler EMIT appends quantum evaluation boundary";
        needle = "SchedulerEvaluationBoundaryKind::Quantum,";
      }
      {
        label = "scheduler event log segment includes boundary entry";
        needle = "Vec::with_capacity(payloads.len() + 1)";
      }
      {
        label = "scheduler boundary emission is explicit";
        needle = "emit_boundary: bool";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "condition evaluation error export";
        needle = "ConditionEvaluationError";
      }
      {
        label = "condition evaluation pass export";
        needle = "ConditionEvaluationPass";
      }
      {
        label = "condition event-log prefix export";
        needle = "ConditionEventLogPrefix";
      }
      {
        label = "scheduler evaluation boundary kind export";
        needle = "SchedulerEvaluationBoundaryKind";
      }
    ]
    ++ failuresFor "crates/crucible/tests/deterministic_condition_evaluation.rs" deterministicTest [
      {
        label = "deterministic boundary source test";
        needle = "evaluation_points_name_deterministic_boundary_sources";
      }
      {
        label = "invalid scheduler prefix rejection test";
        needle = "log_prefix_rejects_invalid_scheduler_prefixes";
      }
      {
        label = "shared pass test";
        needle = "shared_pass_evaluates_assertions_and_triggers_over_one_prefix";
      }
      {
        label = "prefix current-point test";
        needle = "condition_evaluation_uses_checked_prefix_events_only";
      }
    ]
    ++ failuresFor "crates/crucible/tests/observable_condition_leaves.rs" observableTest [
      {
        label = "future scheduler event-log entry negative path";
        needle = "ConditionEvaluationError::FutureEventLogEntry";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_emit_step.rs" schedulerEmitTest [
      {
        label = "no-progress polling boundary regression";
        needle = "no_progress_quantum_does_not_append_polling_boundary_entries";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes deterministic condition evaluation check";
        needle = "deterministicConditionEvaluation = import ./phase4-deterministic-condition-evaluation.nix";
      }
    ]
    ++ forbiddenFor "condition evaluation sources" evaluationSources [
      {
        label = "raw condition evaluator constructor";
        needle = "ConditionEvaluation::new";
      }
      {
        label = "raw observable event injection";
        needle = "with_observable_events";
      }
      {
        label = "raw observable event prefix constructor";
        needle = "from_observable_events";
      }
      {
        label = "raw empty event-log prefix constructor";
        needle = "ConditionEventLogPrefix::empty";
      }
      {
        label = "public raw event-boundary constructor";
        needle = "pub const fn event_boundary(at: VirtualTime)";
      }
      {
        label = "public raw quantum-boundary constructor";
        needle = "pub const fn quantum_boundary(at: VirtualTime)";
      }
      {
        label = "public raw rendezvous-boundary constructor";
        needle = "pub const fn rendezvous_boundary(at: VirtualTime)";
      }
      {
        label = "public raw graph evaluator";
        needle = "pub fn evaluate<E>";
      }
      {
        label = "public free condition evaluator";
        needle = "pub fn evaluate_condition<E>";
      }
      # `pub fn from_scheduler_event_log_entries` and `from_evaluation`(_boundary) are
      # intentionally NOT forbidden here. Both were widened from pub(crate) to `pub`
      # (06f17151d) for legitimate crucible-session/-cli callers; the safety they provide
      # lives in the full validation the base helper performs, which is pinned by the
      # required needles above (dense-prefix/hash/ordering/future error variants), not by
      # keeping the constructors crate-private. Enforcement downgraded from crate-boundary
      # to invariant-pinning on 2026-07-09. The remaining forbidden constructors below have
      # no such validation contract, so their public raw surface stays banned.
      {
        label = "public scheduler observable constructor";
        needle = "pub fn observable(";
      }
      {
        label = "public scheduler evaluation-boundary constructor";
        needle = "pub fn evaluation_boundary(";
      }
      {
        label = "public scheduler event-log sequence field";
        needle = "/// Dense per-run sequence number assigned by the scheduler append path.\n    pub sequence: u64,";
      }
      {
        label = "public scheduler event-log time field";
        needle = "/// Virtual-time coordinate at which the entry occurred.\n    pub at: VirtualTime,";
      }
      {
        label = "public scheduler event-log class field";
        needle = "/// Causal-vs-observational class recorded by the typed append path.\n    pub class: SchedulerEventLogClass,";
      }
      {
        label = "public scheduler event-log payload field";
        needle = "/// Typed payload carried by the event-log entry.\n    pub payload: SchedulerEventLogPayload,";
      }
      {
        label = "public scheduler event-log content-hash field";
        needle = "/// Content address of this entry's canonical material.\n    pub content_hash: ContentHash,";
      }
      {
        # Scoped to the raw bypass form `from_evaluation(`. The bare substring
        # `from_evaluation` also matched the legitimate checked constructor
        # `from_evaluation_boundary` (widened to `pub` in 06f17151d for crucible-session);
        # the open-paren anchor still bans a configured-evaluator bypass while allowing the
        # boundary constructor, whose validation is pinned above. Rescoped 2026-07-09.
        label = "pass from configured evaluator bypass";
        needle = "from_evaluation(";
      }
      {
        label = "mutable underlying evaluator escape hatch";
        needle = "evaluator_mut";
      }
      {
        label = "host instant clock";
        needle = "Instant::now";
      }
      {
        label = "host system clock";
        needle = "SystemTime::now";
      }
      {
        label = "host instant type";
        needle = "std::time::Instant";
      }
      {
        label = "host system-time type";
        needle = "std::time::SystemTime";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/deterministic_condition_evaluation.rs" deterministicTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 deterministic-condition-evaluation check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-deterministic-condition-evaluation";
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
          name = "run-deterministic-condition-evaluation";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-deterministic-condition-evaluation-target" \
              -p crucible \
              --test deterministic_condition_evaluation \
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
            component=crucible-trigger
            evaluation_points=event-boundary,quantum-boundary,rendezvous-boundary
            source=checked-event-log-prefix
            shared_pass=assertions-and-triggers
            host_clock_polling=forbidden
            RESULT
          '';
        }
      ];
    }
