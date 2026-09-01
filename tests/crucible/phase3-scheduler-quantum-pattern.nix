{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerQuantumPattern",
  taskIds ? ["T-PAT-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  authoritativeScheduler =
    builtins.readFile ../../crates/crucible/src/scheduler/single_scheduler_drive.rs;
  patternDoc = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;
  quantumTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/scheduler_quantum_loop.rs;
  };
  effectiveHorizonTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/scheduler_effective_horizon.rs;
  };
  runCeilingTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/scheduler_run_ceiling.rs;
  };
  resolveTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/scheduler_resolve.rs;
  };
  eventOrderTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/scheduler_event_order.rs;
  };
  emitStepTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/scheduler_emit_step.rs;
  };

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
            "${fileLabel}: pattern order regression: `${pair.fst.label}` must precede `${pair.snd.label}`"
          ]
      )
      pairs;
  in
    missing ++ outOfOrder;

  sliceBetween = startNeedle: endNeedle: haystack: let
    start = indexOf startNeedle haystack;
    end = indexOf endNeedle haystack;
  in
    if start < 0 || end <= start
    then ""
    else builtins.substring start (end - start) haystack;

  authoritativeQuantum =
    sliceBetween
    "fn drive_authoritative_quantum"
    "\n    pub(super) fn emit_quantum_event_log"
    authoritativeScheduler;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternDoc [
      {
        label = "T-PAT-2 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerQuantumPattern`";
      }
      {
        label = "PAT-3 requirement";
        needle = "- **[PAT-3]** The scheduler SHOULD follow the PICK / RUN / RESOLVE / EMIT / STEP";
      }
      {
        label = "single ceiling pattern";
        needle = "publish a single ceiling per RUN";
      }
      {
        label = "total-order RESOLVE pattern";
        needle = "`(virtual_time, consumer, producer, sequence)` total order";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "authoritative quantum section";
        needle = "## 8.9 The quantum: PICK / RUN / RESOLVE / EMIT / STEP";
      }
      {
        label = "single ceiling rule";
        needle = "published once per RUN";
      }
      {
        label = "RESOLVE ordering rule";
        needle = "(virtual_time, consumer node_id, producer node_id, sequence)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler quantum pattern check";
        needle = "schedulerQuantumPattern = import ./phase3-scheduler-quantum-pattern.nix";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "authoritative quantum implementation";
        needle = "fn drive_authoritative_quantum";
      }
      {
        label = "single ceiling publish helper";
        needle = "fn publish_run_ceiling";
      }
      {
        label = "RUN publishes from plan";
        needle = "self.scheduler.publish_run_ceiling(";
      }
      {
        label = "event resolver total-order sort";
        needle = "ordered_scheduled_events(&resolved)";
      }
      {
        label = "EMIT event-log helper";
        needle = "fn emit_quantum_event_log";
      }
      {
        label = "STEP helper";
        needle = "fn step_quantum";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler/single_scheduler_drive.rs::drive_authoritative_quantum" authoritativeQuantum [
      {
        label = "control boundary before pick";
        needle = "self.admit_control_at_boundary(request.control)";
      }
      {
        label = "global minimum pick";
        needle = "self.pick_global_minimum_horizon_node()?";
      }
      {
        label = "single RUN advance plan";
        needle = "critical_section.advance_plan(candidate)?";
      }
      {
        label = "RESOLVE due helper";
        needle = "resolve_due_scheduled_events(";
      }
      {
        label = "merged delivery ordering";
        needle = "merge_node_deliveries(frame_deliveries, device_events)";
      }
      {
        label = "EMIT event-log call";
        needle = "self.emit_quantum_event_log(";
      }
      {
        label = "STEP helper call";
        needle = "self.step_quantum(&decisions)";
      }
      {
        label = "post-STEP control yield";
        needle = "self.yield_to_control_inbox()";
      }
    ]
    ++ orderedNeedlesFor "crates/crucible/src/scheduler/single_scheduler_drive.rs::drive_authoritative_quantum" authoritativeQuantum [
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
    ++ failuresFor "crates/crucible/tests/scheduler_quantum_loop.rs" quantumTest [
      {
        label = "atomic quantum test";
        needle = "quantum_loop_pick_run_resolve_and_step_are_one_atomic_boundary";
      }
      {
        label = "pure quantum sequence test";
        needle = "quantum_loop_sequence_is_pure_for_identical_scenario_inputs";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_effective_horizon.rs" effectiveHorizonTest [
      {
        label = "PICK unified projection test";
        needle = "effective_horizon_pick_uses_running_idle_halted_done_projection";
      }
      {
        label = "RUN horizon test";
        needle = "run_reaches_horizon_and_never_advances_past_it";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_run_ceiling.rs" runCeilingTest [
      {
        label = "single ceiling per RUN test";
        needle = "run_publishes_one_max_advance_ceiling_for_selected_node";
      }
      {
        label = "no intermediate ceiling test";
        needle = "each_run_gets_one_ceiling_and_no_intermediate_publication";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_resolve.rs" resolveTest [
      {
        label = "mixed due set total-order test";
        needle = "resolve_quantum_processes_frame_io_and_fault_at_exact_delivery_icount_in_total_order";
      }
      {
        label = "transport-order independence test";
        needle = "resolve_due_events_are_independent_of_pending_transport_order";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_event_order.rs" eventOrderTest [
      {
        label = "four-field event key ordering test";
        needle = "scheduled_event_keys_order_by_virtual_consumer_producer_sequence";
      }
      {
        label = "runtime saved sequence-state test";
        needle = "single_scheduler_allocates_control_event_keys_from_saved_sequence_state";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_emit_step.rs" emitStepTest [
      {
        label = "ordered EMIT test";
        needle = "emit_appends_resolved_happenings_before_decisions_with_dense_content_hashes";
      }
      {
        label = "STEP/event-log prefix test";
        needle = "step_advances_schedule_and_event_log_prefix_across_quanta";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_quantum_loop.rs" quantumTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_effective_horizon.rs" effectiveHorizonTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_run_ceiling.rs" runCeilingTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_resolve.rs" resolveTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_event_order.rs" eventOrderTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
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
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler quantum-pattern check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-quantum-pattern";
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
          name = "run-scheduler-quantum-pattern";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-quantum-pattern-target" \
              -p crucible \
              --test scheduler_quantum_loop \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-quantum-pattern-target" \
              -p crucible \
              --test scheduler_effective_horizon \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-quantum-pattern-target" \
              -p crucible \
              --test scheduler_run_ceiling \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-quantum-pattern-target" \
              -p crucible \
              --test scheduler_resolve \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-quantum-pattern-target" \
              -p crucible \
              --test scheduler_event_order \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-quantum-pattern-target" \
              -p crucible \
              --test scheduler_emit_step \
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
            pattern=PICK-RUN-RESOLVE-EMIT-STEP
            single_ceiling_per_run=true
            resolve_order=virtual-consumer-producer-sequence
            boundary_yield=true
            RESULT
          '';
        }
      ];
    }
