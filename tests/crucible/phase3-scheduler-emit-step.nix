{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerEmitStep",
  taskIds ? ["T-SCHED-19"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  sessionSource = import ./_crucible-session-source.nix {inherit lib;};
  emitStepTest = builtins.readFile ../../crates/crucible/tests/scheduler_emit_step.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  indexOf = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
    matches = builtins.filter (index:
      builtins.substring index needleLen haystack == needle)
    indexes;
  in
    if matches == []
    then -1
    else builtins.head matches;

  orderedNeedlesFor = fileLabel: content: requirements: let
    positions = builtins.map (requirement:
      requirement // {position = indexOf requirement.needle content;})
    requirements;
    missing =
      lib.concatMap (
        requirement:
          lib.optionals (requirement.position < 0) [
            "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
          ]
      )
      positions;
    pairs = lib.zipLists positions (builtins.tail positions);
    outOfOrder =
      lib.concatMap (
        pair:
          lib.optionals (pair.fst.position >= 0 && pair.snd.position >= 0 && pair.fst.position >= pair.snd.position) [
            "${fileLabel}: phase order regression: `${pair.fst.label}` must precede `${pair.snd.label}`"
          ]
      )
      pairs;
  in
    missing ++ outOfOrder;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-19 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerEmitStep`";
      }
      {
        label = "EMIT requirement";
        needle = "append ordered, content-addressed event-log";
      }
      {
        label = "STEP requirement";
        needle = "advance the frontier, then **yield**";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "event-log entry type";
        needle = "pub struct SchedulerEventLogEntry";
      }
      {
        label = "event-log payload type";
        needle = "pub enum SchedulerEventLogPayload";
      }
      {
        label = "event-log append type";
        needle = "pub struct SchedulerEventLogAppend";
      }
      {
        label = "quantum outcome entries";
        needle = "event_log_entries: Vec<SchedulerEventLogEntry>";
      }
      {
        label = "quantum outcome offset";
        needle = "event_log_offset: EventLogOffset";
      }
      {
        label = "quantum outcome segment bytes";
        needle = "event_log_segment_bytes: Vec<u8>";
      }
      {
        label = "quantum outcome segment hash";
        needle = "event_log_segment_hash: Option<ContentHash>";
      }
      {
        label = "EMIT helper";
        needle = "fn emit_quantum_event_log";
      }
      {
        label = "resolved happening payload";
        needle = "SchedulerEventLogPayload::ResolvedHappening";
      }
      {
        label = "decision payload";
        needle = "SchedulerEventLogPayload::Decision";
      }
      {
        label = "content-addressed entry";
        needle = "ContentHash::from_canonical_material";
      }
      {
        label = "content-addressed segment bytes";
        needle = "self.segment_store.put_segment(&segment_bytes)";
      }
      {
        label = "event-log segment offset";
        needle = "EventLogOffset::with_appended_segment";
      }
      {
        label = "event-log sequence owner";
        needle = "self.event_log.next_sequence";
      }
      {
        label = "STEP helper";
        needle = "self.step_quantum(&decisions)";
      }
    ]
    ++ orderedNeedlesFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "post-STEP yield";
        needle = "STEP yield phase";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionSource [
      {
        label = "session consumes emitted event-log offset";
        needle = "outcome.event_log_offset.events";
      }
      {
        label = "session validates event-log mismatch";
        needle = "EventLogOffsetMismatch";
      }
      {
        label = "session validates event-log regression";
        needle = "EventLogOffsetRegression";
      }
      {
        label = "session mismatch regression test";
        needle = "engine_rejects_event_log_offset_mismatch";
      }
      {
        label = "session offset regression test";
        needle = "engine_rejects_event_log_offset_regression";
      }
    ]
    ++ orderedNeedlesFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "boundary admission";
        needle = "self.admit_control_at_boundary(request.control)";
      }
      {
        label = "PICK";
        needle = "// PICK phase";
      }
      {
        label = "RUN";
        needle = "// RUN phase";
      }
      {
        label = "RESOLVE";
        needle = "// RESOLVE phase";
      }
      {
        label = "EMIT";
        needle = "// EMIT phase";
      }
      {
        label = "STEP";
        needle = "// STEP phase";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "event-log entry export";
        needle = "SchedulerEventLogEntry";
      }
      {
        label = "event-log payload export";
        needle = "SchedulerEventLogPayload";
      }
      {
        label = "event-log append export";
        needle = "SchedulerEventLogAppend";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_emit_step.rs" emitStepTest [
      {
        label = "entry order test";
        needle = "emit_appends_resolved_happenings_before_decisions_with_dense_content_hashes";
      }
      {
        label = "prefix advance test";
        needle = "step_advances_schedule_and_event_log_prefix_across_quanta";
      }
      {
        label = "liveness report test";
        needle = "liveness_report_includes_deterministic_event_log_hashes";
      }
      {
        label = "resolved happening assertion";
        needle = "SchedulerEventLogPayload::ResolvedHappening";
      }
      {
        label = "decision assertion";
        needle = "SchedulerEventLogPayload::Decision";
      }
      {
        label = "dense sequence assertion";
        needle = "vec![0, 1, 2, 3, 4, 5]";
      }
      {
        label = "segment assertion";
        needle = "event_log_offset.appended_segment.is_some()";
      }
      {
        label = "segment hash assertion";
        needle = "ContentHash::from_bytes(&outcome.event_log_segment_bytes)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler EMIT/STEP check";
        needle = "schedulerEmitStep = import ./phase3-scheduler-emit-step.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_emit_step.rs" emitStepTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
      {
        label = "wall-clock dependency";
        needle = "std::time";
      }
      {
        label = "sleep dependency";
        needle = "sleep(";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler EMIT/STEP check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-emit-step";
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
          name = "run-scheduler-emit-step";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-emit-step-target" \
              -p crucible \
              --test scheduler_emit_step \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-emit-step-target" \
              -p crucible \
              --test scheduler_quantum_loop \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-emit-step-target" \
              -p crucible \
              --test scheduler_resolve_rng \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-emit-step-target" \
              -p crucible-session \
              --test gate_control_responsive \
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
            emit_event_log_entries=true
            event_log_entries_content_addressed=true
            step_consumes_decisions=true
            RESULT
          '';
        }
      ];
    }
