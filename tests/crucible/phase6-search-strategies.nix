{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.searchStrategies",
  taskIds ? ["T-ADV-8"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  strategyGateTest = builtins.readFile ../../crates/crucible/tests/gate_search_strategies.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

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

  defaultSearchStrategiesBlock =
    sliceFromUntil
    defaultChecks
    "    searchStrategies = greenBeforeAdvance {"
    "    gates = {";

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

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
        label = "T-ADV-8 checked off";
        needle = "- [x] **T-ADV-8**";
      }
      {
        label = "T-ADV-8 completion note";
        needle = "Completed by `checks.crucible.phase6.searchStrategies`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "search strategy enum";
        needle = "pub enum SearchStrategy";
      }
      {
        label = "breadth-first strategy";
        needle = "BreadthFirst";
      }
      {
        label = "depth-first strategy";
        needle = "DepthFirst";
      }
      {
        label = "seeded priority strategy";
        needle = "Priority {\n        /// Strategy-local seed used only to order the frontier.\n        seed: Seed,";
      }
      {
        label = "coverage-guided strategy";
        needle = "CoverageGuided";
      }
      {
        label = "search budget";
        needle = "pub struct SearchBudget";
      }
      {
        label = "strategy run report";
        needle = "pub struct TemporalGraphSearchRun";
      }
      {
        label = "search with strategy API";
        needle = "pub fn search_with_strategy(";
      }
      {
        label = "single-frontier search reused";
        needle = "let search = self.search(";
      }
      {
        label = "multi-frontier reductions deferred";
        needle = "FrontierReductionPolicy::none(),";
      }
      {
        label = "deterministic candidate selector";
        needle = "fn select_search_frontier_candidate(";
      }
      {
        label = "breadth-first depth key";
        needle = "SearchStrategy::BreadthFirst => left\n            .depth\n            .cmp(&right.depth)";
      }
      {
        label = "depth-first depth key";
        needle = "SearchStrategy::DepthFirst => right\n            .depth\n            .cmp(&left.depth)";
      }
      {
        label = "priority score domain";
        needle = "SEARCH_PRIORITY_SCORE_DOMAIN";
      }
      {
        label = "coverage-guided coverage key";
        needle = "fn search_coverage_guided_key(";
      }
      {
        label = "coverage feedback reader";
        needle = "fn search_candidate_coverage_fingerprint";
      }
      {
        label = "content-address tie breaker";
        needle = ".then_with(|| left.id().cmp(&right.id()))";
      }
      {
        label = "deduplicated graph report";
        needle = "pub explored_graph: BTreeSet<ContentHash>";
      }
      {
        label = "failure report contract";
        needle = "pub discovered_failures: Vec<SearchDiscoveredFailure>";
      }
      {
        label = "failure oracle contract";
        needle = "pub struct SearchFailureOracle";
      }
      {
        label = "exhausted work-list report";
        needle = "pub exhausted: bool";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_search_strategies.rs" strategyGateTest [
      {
        label = "reproducibility gate";
        needle = "gate_search_strategies_are_reproducible_for_identical_inputs";
      }
      {
        label = "same graph gate";
        needle = "gate_search_strategies_reach_same_graph_under_complete_budget";
      }
      {
        label = "content tie gate";
        needle = "gate_breadth_first_breaks_equal_depth_ties_by_content_address";
      }
      {
        label = "coverage feedback gate";
        needle = "gate_coverage_guided_prefers_recorded_coverage_feedback";
      }
      {
        label = "priority and coverage tie gate";
        needle = "gate_priority_and_coverage_guided_break_equal_score_ties_by_content_address";
      }
      {
        label = "discovered failures gate";
        needle = "gate_search_strategies_report_discovered_failures_deterministically";
      }
      {
        label = "strategy API call";
        needle = "graph.search_with_strategy_and_failure_oracle(";
      }
      {
        label = "breadth-first exercised";
        needle = "SearchStrategy::BreadthFirst";
      }
      {
        label = "depth-first exercised";
        needle = "SearchStrategy::DepthFirst";
      }
      {
        label = "priority exercised";
        needle = "SearchStrategy::Priority";
      }
      {
        label = "coverage-guided exercised";
        needle = "SearchStrategy::CoverageGuided";
      }
      {
        label = "same expansion order assertion";
        needle = "assert_eq!(expansion_order(&first), expansion_order(&second));";
      }
      {
        label = "same discovered failures assertion";
        needle = "assert_eq!(first.discovered_failures, second.discovered_failures);";
      }
      {
        label = "content-address sort assertion";
        needle = "sorted_children.sort();";
      }
      {
        label = "coverage feedback fixture";
        needle = "checkpoint.with_coverage_fingerprint(coverage)";
      }
      {
        label = "exhausted assertion";
        needle = "assert!(fixture.run.exhausted);";
      }
      {
        label = "failure oracle fixture";
        needle = "SearchFailureOracle::none().with_failure";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_search_strategies.rs" strategyGateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix searchStrategies block" defaultSearchStrategiesBlock [
      {
        label = "phase6 search strategies green wrapper";
        needle = "searchStrategies = greenBeforeAdvance";
      }
      {
        label = "phase6 search strategies import";
        needle = "gate = import ./phase6-search-strategies.nix";
      }
      {
        label = "phase6 search strategies attr path";
        needle = "checks.crucible.phase6.searchStrategies";
      }
      {
        label = "phase6 search strategies task id";
        needle = ''taskIds = ["T-ADV-8"]'';
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
        label = "phase6 state-space search raw dependency";
        needle = "\n          phase6.stateSpaceSearch.rawGate\n";
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
        label = "phase6 state-space search green dependency";
        needle = "\n        phase6.stateSpaceSearch\n";
      }
      {
        label = "phase6 replay oracle green dependency";
        needle = "\n        phase6.gates.replayOracle\n";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 search strategies check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-search-strategies";
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
          name = "run-search-strategies";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-search-strategies-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_search_strategies \
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
            gate=gate:search-strategies
            strategy=bfs,dfs,priority,coverage-guided
            rust_test=crucible::gate_search_strategies
            RESULT
          '';
        }
      ];
    }
