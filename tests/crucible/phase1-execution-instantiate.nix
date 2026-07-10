{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionInstantiate",
  taskIds ? ["T-EXEC-6" "T-PAT-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  defaultChecks = builtins.readFile ./default.nix;
  rfc = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;
  patternsAndSketches = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;

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
        label = "T-EXEC-6 checked off";
        needle = "- [x] **T-EXEC-6**";
      }
      {
        label = "T-EXEC-6 completion note";
        needle = "Completed by `crates/crucible/src/model.rs`: `instantiate` now resolves exact";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsAndSketches [
      {
        label = "T-PAT-9 checklist complete";
        needle = "- [x] **T-PAT-9**";
      }
      {
        label = "T-PAT-9 completion names instantiate";
        needle = "`crucible::instantiate`";
      }
      {
        label = "T-PAT-9 completion names baked genesis";
        needle = "`TemporalGraph::with_baked_genesis`";
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
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-instantiate";
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
          name = "run-execution-instantiate";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-instantiate-target" \
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
