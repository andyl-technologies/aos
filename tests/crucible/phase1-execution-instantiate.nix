{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionInstantiate",
  taskIds ? ["T-EXEC-6" "T-PAT-9"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  rfc = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;
  patternsAndSketches = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "instantiate implementation";
        needle = "pub fn instantiate(";
      }
      {
        label = "exact snapshot branch";
        needle = "graph.cached_snapshot(config)";
      }
      {
        label = "nearest cached ancestor branch";
        needle = "graph.nearest_cached_ancestor(config)?";
      }
      {
        label = "recursive ancestor materialization";
        needle = "instantiate(graph, &ancestor)?";
      }
      {
        label = "ancestor suffix replay";
        needle = "replay_suffix(ancestor_runtime, &ancestor, &suffix, config)";
      }
      {
        label = "ancestor suffix replay boundary";
        needle = "suffix_from(ancestor.schedule.len())";
      }
      {
        label = "genesis recursion";
        needle = "Configuration::genesis(config.def.clone())";
      }
      {
        label = "baked genesis lookup";
        needle = "genesis_snapshot(&config.def)";
      }
      {
        label = "genesis suffix replay";
        needle = "replay_suffix(genesis_runtime, &genesis, &suffix, config)";
      }
      {
        label = "missing baked genesis error";
        needle = "EngineError::MissingBakedGenesis";
      }
      {
        label = "nearest cached ancestor helper";
        needle = "pub fn nearest_cached_ancestor";
      }
      {
        label = "snapshot cache registration";
        needle = "pub fn with_cached_snapshot";
      }
      {
        label = "baked genesis registration";
        needle = "pub fn with_baked_genesis";
      }
      {
        label = "schedule suffix helper";
        needle = "pub fn suffix_from(&self, len: usize) -> Result<Self, ScheduleError>";
      }
      {
        label = "loadable checkpoint validation";
        needle = "fn validate_loadable_checkpoint";
      }
      {
        label = "suffix replay helper";
        needle = "fn replay_suffix";
      }
      {
        label = "plain cached genesis rejected";
        needle = "EngineError::GenesisSnapshotMustBeBaked";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/src/model.rs" model [
      {
        label = "instantiate placeholder";
        needle = "operation: \"instantiate\"";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "exact snapshot test";
        needle = "instantiate_loads_exact_snapshot_without_genesis";
      }
      {
        label = "nearest ancestor replay test";
        needle = "instantiate_replays_from_nearest_cached_ancestor";
      }
      {
        label = "baked genesis test";
        needle = "instantiate_loads_baked_genesis_for_genesis";
      }
      {
        label = "baked genesis descendant replay test";
        needle = "instantiate_replays_from_baked_genesis_for_uncached_descendant";
      }
      {
        label = "missing genesis error test";
        needle = "instantiate_requires_baked_genesis_when_no_cached_path";
      }
      {
        label = "invalid checkpoint test";
        needle = "temporal_graph_rejects_mismatched_or_thin_cached_snapshots";
      }
      {
        label = "plain cached genesis rejection test";
        needle = "temporal_graph_rejects_plain_cached_genesis_snapshot";
      }
      {
        label = "invalid baked genesis test";
        needle = "temporal_graph_rejects_mismatched_or_thin_baked_genesis";
      }
      {
        label = "reduced state oracle assertion";
        needle = "assert_eq!(runtime.id, reduced_state_id(&config));";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes recursive instantiate check";
        needle = "executionInstantiate = import ./phase1-execution-instantiate.nix";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" rfc [
      {
        label = "T-EXEC-6 completion note";
        needle = "Completed by `crates/crucible/src/model.rs`: `instantiate` now resolves exact";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsAndSketches [
      {
        label = "T-PAT-9 completion names exact resume lifecycle";
        needle = "atomic exact-resume lifecycle";
      }
      {
        label = "T-PAT-9 completion names baked genesis replay catalog";
        needle = "baked-genesis replay catalog";
      }
      {
        label = "T-PAT-9 completion names execution instantiate gate";
        needle = "`checks.crucible.phase1.executionInstantiate`";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution instantiate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase1-execution-instantiate";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-execution-instantiate";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible \
              --lib \
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
            tasks=${builtins.concatStringsSep "," taskIds}
            instantiate_branches=exact-snapshot,ancestor-replay,baked-genesis
            pattern_PAT_11=recursive-instantiate
            hot_loop_cold_boot=false
            RESULT
          '';
        }
      ];
    }
