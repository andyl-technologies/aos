{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.stateSpaceSearch",
  taskIds ? ["T-ADV-7"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  modelCanonical = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  stateSpaceGateTest = builtins.readFile ../../crates/crucible/tests/gate_state_space_search.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

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
      builtins.filter (
        index: builtins.substring index needleLen haystack == needle
      )
      indexes;
  in
    if matches == []
    then null
    else builtins.head matches;

  sliceFromUntil = content: startNeedle: endNeedle: let
    start = indexOf startNeedle content;
    tailStart = start + builtins.stringLength startNeedle;
    tail = builtins.substring tailStart (builtins.stringLength content - tailStart) content;
    end = indexOf endNeedle tail;
  in
    if start == null
    then ""
    else if end == null
    then startNeedle + tail
    else startNeedle + builtins.substring 0 end tail;

  defaultStateSpaceSearchBlock =
    sliceFromUntil
    defaultChecks
    "    stateSpaceSearch = greenBeforeAdvance {"
    "    gates = {";

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/22-advanced-features.md" advancedDoc [
      {
        label = "T-ADV-7 completion note";
        needle = "Completed by `checks.crucible.phase6.stateSpaceSearch`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "search API";
        needle = "pub fn search(";
      }
      {
        label = "frontier realized before expansion";
        needle = "let frontier_runtime = self.resume(frontier)?;";
      }
      {
        label = "runtime-derived search decisions";
        needle = "let choices = search_frontier_choices(&frontier_runtime.runtime);";
      }
      {
        label = "search frontier choices state";
        needle = "pub struct SearchFrontierChoices";
      }
      {
        label = "closed taxonomy filter";
        needle = "fn is_genuine_search_frontier_decision(decision: &Decision) -> bool";
      }
      {
        label = "delivery order excluded from search";
        needle = "Decision::DeliveryOrder(_) => false";
      }
      {
        label = "non-search decisions excluded";
        needle = "Decision::Preemption(_) | Decision::AppRandom(_) | Decision::ControlFault(_) => false";
      }
      {
        label = "search result reports realized frontier";
        needle = "pub frontier_runtime: TemporalGraphRuntime";
      }
      {
        label = "reduced frontier API";
        needle = "pub fn enumerate_frontier_reduced<I>";
      }
      {
        label = "content-address frontier dedup map";
        needle = "let mut children = BTreeMap::new();";
      }
      {
        label = "step each child decision";
        needle = "let configuration = try_step(frontier, decision.clone())?;";
      }
      {
        label = "dedup by configuration id";
        needle = "children.entry(configuration.id()).or_insert(FrontierChild";
      }
      {
        label = "already recorded marker";
        needle = "child.already_recorded = !self.record_checkpoint_closure(&child.configuration)?;";
      }
      {
        label = "materialization policy applied to children";
        needle = "self.materialize_hot_checkpoint(";
      }
      {
        label = "materialization budget API";
        needle = "pub const fn with_budget";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "materialized scheduler pending frames";
        needle = "state.pending_frames = pending_frames_from_scheduled_events(&self.pending_events);";
      }
      {
        label = "materialized scheduler active faults";
        needle = "state.recompute_active_fault_table();";
      }
      {
        label = "materialized scheduler search frontier";
        needle = "state.search_frontier = search_frontier_choices_from_scheduled_events(";
      }
      {
        label = "probabilistic search frontier capture";
        needle = "ScheduledEventPayload::ProbabilisticFault(choice)";
      }
      {
        label = "probabilistic false branch";
        needle = "u64::from(choice.rate.basis_points()),\n                false,";
      }
      {
        label = "probabilistic true branch";
        needle = "probabilistic_fault_search_choice(event, choice, 0, true)";
      }
      {
        label = "probabilistic frontier capture test";
        needle = "search_frontier_choices_from_scheduled_events_captures_probabilistic_fault_branches";
      }
    ]
    ++ failuresFor "crates/crucible/src/model/canonical.rs" modelCanonical [
      {
        label = "canonical scheduler search frontier count";
        needle = "hasher.write_u64(state.search_frontier.choices().len() as u64);";
      }
      {
        label = "canonical scheduler search frontier choice sequences";
        needle = "for choice in state.search_frontier.choices()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_state_space_search.rs" stateSpaceGateTest [
      {
        label = "frontier dedup gate";
        needle = "gate_state_space_search_expands_genuine_decisions_and_dedups_by_content_address";
      }
      {
        label = "frontier realization gate";
        needle = "gate_state_space_search_realizes_frontier_from_cached_ancestor_without_stale_choices";
      }
      {
        label = "materialization budget gate";
        needle = "gate_state_space_search_materializes_captured_frontier_under_budget";
      }
      {
        label = "scheduler-derived choices gate";
        needle = "gate_state_space_search_derives_choices_from_materialized_scheduler_state";
      }
      {
        label = "closed decision taxonomy helper";
        needle = "fn genuine_frontier_decisions";
      }
      {
        label = "scheduler-captured choices";
        needle = "SearchFrontierChoices::from_decisions";
      }
      {
        label = "invalid control fault candidate";
        needle = "fn control_fault_decision";
      }
      {
        label = "non-genuine delivery candidate";
        needle = "fn non_genuine_delivery_decision";
      }
      {
        label = "delivery-order candidate rejected";
        needle = "Decision::DeliveryOrder";
      }
      {
        label = "fault-fires frontier decision";
        needle = "Decision::FaultFires";
      }
      {
        label = "decision-rng frontier decision";
        needle = "Decision::RngDraw";
      }
      {
        label = "override frontier decision";
        needle = "Decision::Override";
      }
      {
        label = "duplicate child input";
        needle = "decisions.push(decisions[2].clone())";
      }
      {
        label = "dedup expected set";
        needle = "collect::<Result<BTreeSet<_>, EngineError>>()";
      }
      {
        label = "content-address ordering assertion";
        needle = "assert_eq!(explored_ids, sorted_ids)";
      }
      {
        label = "thin ordinary search checkpoints";
        needle = "CheckpointKind::Thin";
      }
      {
        label = "cached ancestor materialized";
        needle = "graph.materialize_checkpoint(&base)?";
      }
      {
        label = "frontier realized through instantiate path";
        needle = "instantiate(&graph, &frontier)?";
      }
      {
        label = "hot-node materialization budget";
        needle = "MaterializationPolicy::with_budget(2)";
      }
      {
        label = "shared replay path trigger";
        needle = "MaterializationTrigger::SharedReplayPath";
      }
      {
        label = "fat child materialization";
        needle = "CheckpointKind::Fat";
      }
      {
        label = "ancestor cache assertion";
        needle = "graph.cached_snapshot(&base).is_some()";
      }
      {
        label = "frontier remains thin assertion";
        needle = "graph.cached_snapshot(&frontier).is_none()";
      }
      {
        label = "stale choices cleared assertion";
        needle = "search.frontier_report.explored.is_empty()";
      }
      {
        label = "rerun marks reused children";
        needle = "child.already_recorded";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "pending frames as search branches";
        needle = "fn delivery_tie_decisions_from_pending_frames";
      }
      {
        label = "active faults as search branches";
        needle = "for (fault, state) in &runtime.scheduler.active_faults";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_state_space_search.rs" stateSpaceGateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix stateSpaceSearch block" defaultStateSpaceSearchBlock [
      {
        label = "phase6 state-space search green wrapper";
        needle = "stateSpaceSearch = greenBeforeAdvance";
      }
      {
        label = "phase6 state-space search import";
        needle = "gate = import ./phase6-state-space-search.nix";
      }
      {
        label = "phase6 state-space search attr path";
        needle = "checks.crucible.phase6.stateSpaceSearch";
      }
      {
        label = "phase6 state-space search task id";
        needle = ''taskIds = ["T-ADV-7"]'';
      }
      {
        label = "phase4 replay oracle raw dependency";
        needle = "\n          phase4.gates.replayOracle.rawGate\n";
      }
      {
        label = "phase4 e2e determinism raw dependency";
        needle = "\n          phase4.gates.e2eDeterminism.rawGate\n";
      }
      {
        label = "phase6 restore strategies raw dependency";
        needle = "\n          phase6.restoreStrategies.rawGate\n";
      }
      {
        label = "phase6 checkpoint materialization raw dependency";
        needle = "\n          phase6.checkpointMaterialization.rawGate\n";
      }
      {
        label = "phase6 replay oracle raw dependency";
        needle = "\n          phase6.gates.replayOracle.rawGate\n";
      }
      {
        label = "phase4 replay oracle green dependency";
        needle = "\n        phase4.gates.replayOracle\n";
      }
      {
        label = "phase4 e2e determinism green dependency";
        needle = "\n        phase4.gates.e2eDeterminism\n";
      }
      {
        label = "phase6 restore strategies green dependency";
        needle = "\n        phase6.restoreStrategies\n";
      }
      {
        label = "phase6 checkpoint materialization green dependency";
        needle = "\n        phase6.checkpointMaterialization\n";
      }
      {
        label = "phase6 replay oracle green dependency";
        needle = "\n        phase6.gates.replayOracle\n";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 state-space search check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-state-space-search";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;

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
            set -eu
            : "$DEPENDENCIES"
            export CARGO_HOME="$TMPDIR/cargo-home"
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
          name = "run-state-space-search";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-state-space-search-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_state_space_search \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-state-space-search-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib search_frontier_choices_from_scheduled_events_captures_probabilistic_fault_branches \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            gate=gate:state-space-search
            search=frontier-realized,content-address-dedup,budget-materialized
            rust_test=crucible::gate_state_space_search
            RESULT
          '';
        }
      ];
    }
