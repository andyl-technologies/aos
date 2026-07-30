{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionGraphOperations",
  taskIds ? ["T-EXEC-13"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  rfc = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "save checkpoint operation";
        needle = "pub fn save_checkpoint(";
      }
      {
        label = "save materializes fat checkpoint";
        needle = "materialized_checkpoint_for_runtime(configuration, runtime)";
      }
      {
        label = "save caches by configuration id";
        needle = "self.cache_snapshot(configuration, checkpoint.clone())?;";
      }
      {
        label = "replay checkpoint operation";
        needle = "pub fn replay_checkpoint(";
      }
      {
        label = "replay uses thin replay path";
        needle = "let thin_runtime = instantiate_thin_replay(self, configuration)?;";
      }
      {
        label = "thin replay helper";
        needle = "fn instantiate_thin_replay";
      }
      {
        label = "replay oracle mismatch error";
        needle = "EngineError::ReplayOracleMismatch";
      }
      {
        label = "frontier enumeration operation";
        needle = "pub fn enumerate_frontier";
      }
      {
        label = "recorded configuration dedup index";
        needle = "recorded_configurations";
      }
      {
        label = "configuration containment API";
        needle = "pub fn contains_configuration";
      }
      {
        label = "recorded configuration count API";
        needle = "pub fn recorded_configuration_count";
      }
      {
        label = "frontier child result type";
        needle = "pub struct FrontierChild";
      }
      {
        label = "replay oracle result type";
        needle = "pub struct ReplayOracleCheck";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "save checkpoint model-operation test";
        needle = "temporal_graph_save_materializes_fat_checkpoint_keyed_by_configuration";
      }
      {
        label = "on-demand replay oracle test";
        needle = "temporal_graph_replay_checkpoint_is_on_demand_replay_oracle";
      }
      {
        label = "exact target snapshot avoidance test";
        needle = "temporal_graph_replay_checkpoint_ignores_exact_target_snapshot";
      }
      {
        label = "frontier dedup test";
        needle = "temporal_graph_frontier_enumeration_deduplicates_by_configuration_id";
      }
      {
        label = "snapshot cache count assertion";
        needle = "cached_snapshot_count()";
      }
      {
        label = "frontier already-recorded marker";
        needle = "already_recorded";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes execution graph operation check";
        needle = "executionGraphOperations = import ./phase1-execution-graph-operations.nix";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" rfc [
      {
        label = "T-EXEC-13 completion note";
        needle = "Completed by `crates/crucible/src/model.rs`: `TemporalGraph::save_checkpoint`";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution graph operations check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-graph-operations";
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
          name = "run-execution-graph-operations";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-graph-operations-target" \
              -p crucible \
              --lib \
              temporal_graph_ \
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
            save=fat-checkpoint-keyed-by-configuration-id
            replay=on-demand-thin-replay-oracle
            search=frontier-step-enumeration
            dedup=content-addressed-configuration-node
            RESULT
          '';
        }
      ];
    }
