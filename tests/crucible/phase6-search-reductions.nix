{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.searchReductions",
  taskIds ? ["T-ADV-9"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalDoc = builtins.readFile ../../docs/rfcs/0010-crucible/07-temporal-graph.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  reductionGateTest = builtins.readFile ../../crates/crucible/tests/gate_search_reductions.rs;
  contentAddressGateTest = builtins.readFile ../../crates/crucible/tests/gate_content_address.rs;
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

  defaultSearchReductionsBlock =
    sliceFromUntil
    defaultChecks
    "    searchReductions = greenBeforeAdvance {"
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
        label = "T-ADV-9 completion note";
        needle = "Completed by `checks.crucible.phase6.searchReductions`";
      }
      {
        label = "explicit graph-level node dedup";
        needle = "sound graph-level node-deduplication over the content-addressed DAG";
      }
      {
        label = "explicit non-model-checker scope";
        needle = "explicitly not a model checker / spec-language evaluator";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/07-temporal-graph.md" temporalDoc [
      {
        label = "T-TEMP-10 completion records canonical representative on demand";
        needle = "after recording that\n    canonical representative on demand";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "reduced strategy API";
        needle = "pub fn search_with_strategy_reduced(";
      }
      {
        label = "reduced strategy carries reduction policy";
        needle = "reduction_policy: FrontierReductionPolicy,";
      }
      {
        label = "strategy schedules covered representatives";
        needle = "recorded_configurations\n                    .get(&covered.representative)";
      }
      {
        label = "POR canonical representative helper";
        needle = "fn partial_order_canonical_representative(";
      }
      {
        label = "POR records representative on demand";
        needle = "graph.record_checkpoint_closure(&representative)?;";
      }
      {
        label = "graph-level symmetry representative helper";
        needle = "fn symmetry_representative_for_key_excluding(";
      }
      {
        label = "symmetry excludes current candidates";
        needle = "excluded.contains(&checkpoint.configuration)";
      }
      {
        label = "partial-order covered reason";
        needle = "FrontierReductionReason::PartialOrder";
      }
      {
        label = "symmetry covered reason";
        needle = "FrontierReductionReason::Symmetry";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_search_reductions.rs" reductionGateTest [
      {
        label = "POR on-demand representative gate";
        needle = "gate_search_reductions_partial_order_records_canonical_representative_on_demand";
      }
      {
        label = "graph-level symmetry gate";
        needle = "gate_search_reductions_symmetry_uses_graph_level_representative";
      }
      {
        label = "reduced strategy schedules representative gate";
        needle = "gate_search_reductions_reduced_strategy_schedules_covered_representative";
      }
      {
        label = "reduced strategy API exercised";
        needle = "graph.search_with_strategy_reduced(";
      }
      {
        label = "representative becomes recorded";
        needle = "assert!(graph.contains_configuration(&representative));";
      }
      {
        label = "covered noncanonical child remains absent";
        needle = "assert!(!graph.contains_configuration(&covered));";
      }
      {
        label = "symmetry representative assertion";
        needle = "assert_eq!(report.covered[0].representative, representative.id());";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_content_address.rs" contentAddressGateTest [
      {
        label = "content-address POR records missing representative";
        needle = "gate_content_address_temporal_graph_partial_order_reduction_records_missing_representative";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_search_reductions.rs" reductionGateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix searchReductions block" defaultSearchReductionsBlock [
      {
        label = "phase6 search reductions green wrapper";
        needle = "searchReductions = greenBeforeAdvance";
      }
      {
        label = "phase6 search reductions import";
        needle = "gate = import ./phase6-search-reductions.nix";
      }
      {
        label = "phase6 search reductions attr path";
        needle = "checks.crucible.phase6.searchReductions";
      }
      {
        label = "phase6 search reductions task id";
        needle = ''taskIds = ["T-ADV-9"]'';
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
        label = "phase6 search strategies raw dependency";
        needle = "\n          phase6.searchStrategies.rawGate\n";
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
        label = "phase6 search strategies green dependency";
        needle = "\n        phase6.searchStrategies\n";
      }
      {
        label = "phase6 replay oracle green dependency";
        needle = "\n        phase6.gates.replayOracle\n";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 search reductions check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-search-reductions";
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
          name = "run-search-reductions";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-search-reductions-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_search_reductions \
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
            gate=gate:search-reductions
            reductions=symmetry,partial-order
            scope=content-addressed-dag-node-dedup
            rust_test=crucible::gate_search_reductions
            RESULT
          '';
        }
      ];
    }
