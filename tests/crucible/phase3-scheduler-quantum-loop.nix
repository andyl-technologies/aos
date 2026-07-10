{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerQuantumLoop",
  taskIds ? ["T-SCHED-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  quantumTest = builtins.readFile ../../crates/crucible/tests/scheduler_quantum_loop.rs;
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
    matches =
      builtins.filter (index:
        builtins.substring index needleLen haystack == needle)
      indexes;
  in
    if matches == []
    then -1
    else builtins.head matches;

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

  orderedNeedlesFor = fileLabel: content: requirements: let
    positions =
      builtins.map (requirement:
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
        label = "T-SCHED-12 checked off";
        needle = "- [x] **T-SCHED-12**";
      }
      {
        label = "T-SCHED-12 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerQuantumLoop`";
      }
      {
        label = "quantum phase requirement";
        needle = "PICK, RUN, RESOLVE, EMIT, STEP";
      }
      {
        label = "pure sequence requirement";
        needle = "pure function of `(ScenarioDef, Seed, Schedule)`";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "quantum loop trait";
        needle = "pub trait QuantumLoop";
      }
      {
        label = "single scheduler quantum implementation";
        needle = "fn drive_authoritative_quantum";
      }
      {
        label = "scheduler state enters scenario identity";
        needle = "fn scheduler_liveness_scenario_material";
      }
      {
        label = "authored material carried by scenario";
        needle = "authored_material";
      }
      {
        label = "frontier configuration guard";
        needle = "request.configuration != self.configuration";
      }
      {
        label = "control boundary before pick";
        needle = "self.admit_control_at_boundary(request.control)";
      }
      {
        label = "PICK candidate selection";
        needle = "self.pick_global_minimum_horizon_node()?";
      }
      {
        label = "RUN advance plan";
        needle = "SchedulerCriticalSection::enter(self)";
      }
      {
        label = "RUN after yield";
        needle = "self.advance_node_after_yield(&plan)?";
      }
      {
        label = "RESOLVE due events";
        needle = "resolve_due_scheduled_events(\n            &mut self.pending_events";
      }
      {
        label = "EMIT helper";
        needle = "fn emit_quantum_decisions";
      }
      {
        label = "control-only EMIT path";
        needle = "self.emit_quantum_decisions(\n                    &resolved_events,";
      }
      {
        label = "STEP appends decisions";
        needle = "fn step_quantum";
      }
      {
        label = "STEP updates scheduler frontier";
        needle = "self.frontier = frontier_for(&self.nodes, self.timeline.shift())?";
      }
      {
        label = "STEP counts one quantum";
        needle = "self.quanta = self.quanta.saturating_add(1)";
      }
    ]
    ++ orderedNeedlesFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "control boundary";
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
        label = "quantum loop export";
        needle = "QuantumLoop";
      }
      {
        label = "quantum request export";
        needle = "QuantumRequest";
      }
      {
        label = "quantum outcome export";
        needle = "QuantumOutcome";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_quantum_loop.rs" quantumTest [
      {
        label = "atomic quantum boundary test";
        needle = "quantum_loop_pick_run_resolve_and_step_are_one_atomic_boundary";
      }
      {
        label = "pure identical scenario test";
        needle = "quantum_loop_sequence_is_pure_for_identical_scenario_inputs";
      }
      {
        label = "scheduler state identity test";
        needle = "quantum_loop_scheduler_state_contributes_to_effective_scenario_def";
      }
      {
        label = "control-only STEP test";
        needle = "quantum_loop_steps_boundary_control_when_no_node_advances";
      }
      {
        label = "frontier request rejection test";
        needle = "quantum_loop_rejects_non_frontier_configuration_request";
      }
      {
        label = "step equivalence assertion";
        needle = "apply_decisions(&input, &outcome.decisions)";
      }
      {
        label = "delivery order decision assertion";
        needle = "Decision::DeliveryOrder";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler quantum-loop check";
        needle = "schedulerQuantumLoop = import ./phase3-scheduler-quantum-loop.nix";
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
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler quantum-loop check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-quantum-loop";
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
          name = "run-scheduler-quantum-loop";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-quantum-loop-target" \
              -p crucible \
              --test scheduler_quantum_loop \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-quantum-loop-target" \
              -p crucible \
              --features test-double \
              --test gate_scheduler_liveness \
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
            quantum=PICK-RUN-RESOLVE-decision-EMIT-STEP-boundary
            pure_sequence=true
            step_equivalence=true
            full_event_log_emit=deferred-to-T-SCHED-19
            frontier_guard=true
            RESULT
          '';
        }
      ];
    }
