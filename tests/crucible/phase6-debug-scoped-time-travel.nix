{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.debugScopedTimeTravel",
  taskIds ? ["T-DBG-5"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  debugDoc = builtins.readFile ../../docs/rfcs/0010-crucible/36-time-travel-debugging.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/lib.rs;
  };
  timeTravelTest = builtins.readFile ../../crates/crucible/tests/gate_debug_time_travel.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

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
    failuresFor "docs/rfcs/0010-crucible/36-time-travel-debugging.md" debugDoc [
      {
        label = "T-DBG-5 completion note";
        needle = "Completed by `checks.crucible.phase6.debugScopedTimeTravel`";
      }
      {
        label = "checkpoint stride wording";
        needle = "--checkpoint-stride";
      }
      {
        label = "thin replay default wording";
        needle = "thin/replay";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-DBG-5 plan summary";
        needle = "`T-DBG-5` is green through `checks.crucible.phase6.debugScopedTimeTravel`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "per-node API";
        needle = "pub fn debug_per_node_time_travel";
      }
      {
        label = "per-node request";
        needle = "pub struct DebugPerNodeTimeTravelRequest";
      }
      {
        label = "per-node report";
        needle = "pub struct DebugPerNodeTimeTravelReport";
      }
      {
        label = "per-node goto report";
        needle = "pub struct DebugPerNodeGotoReport";
      }
      {
        label = "scoped node candidates";
        needle = "debug_scoped_node_coordinate_candidates";
      }
      {
        label = "uninstantiated node proof";
        needle = "leaves_other_nodes_unreinstantiated";
      }
      {
        label = "single-node materialization proof";
        needle = "materialized_nodes";
      }
      {
        label = "coherent node proof";
        needle = "lands_node_coherently";
      }
      {
        label = "whole-world API";
        needle = "pub fn debug_whole_world_time_travel";
      }
      {
        label = "whole-world target";
        needle = "pub enum DebugWholeWorldTarget";
      }
      {
        label = "whole-world coherence proof";
        needle = "lands_all_nodes_coherently";
      }
      {
        label = "fork-without-divergence proof";
        needle = "is_fork_without_divergence";
      }
      {
        label = "checkpoint stride type";
        needle = "pub struct DebugCheckpointStride";
      }
      {
        label = "checkpoint cadence API";
        needle = "pub fn debug_apply_checkpoint_cadence";
      }
      {
        label = "explicit thin-only cache policy";
        needle = "pub fn thin_only() -> Self";
      }
      {
        label = "ordinary materialization integration";
        needle = "materialize_hot_checkpoint";
      }
      {
        label = "performance-only proof";
        needle = "is_performance_only_cache_decision";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "per-node request export";
        needle = "DebugPerNodeTimeTravelRequest";
      }
      {
        label = "per-node report export";
        needle = "DebugPerNodeTimeTravelReport";
      }
      {
        label = "per-node goto report export";
        needle = "DebugPerNodeGotoReport";
      }
      {
        label = "whole-world request export";
        needle = "DebugWholeWorldTimeTravelRequest";
      }
      {
        label = "whole-world target export";
        needle = "DebugWholeWorldTarget";
      }
      {
        label = "checkpoint stride export";
        needle = "DebugCheckpointStride";
      }
      {
        label = "checkpoint cadence report export";
        needle = "DebugCheckpointCadenceReport";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_debug_time_travel.rs" timeTravelTest [
      {
        label = "scoped time-travel test";
        needle = "debug_per_node_and_whole_world_time_travel_land_coherently";
      }
      {
        label = "checkpoint stride test";
        needle = "debug_checkpoint_stride_is_performance_only_under_explicit_cache_policy";
      }
      {
        label = "per-node request use";
        needle = "DebugPerNodeTimeTravelRequest::new";
      }
      {
        label = "forward per-node travel assertion";
        needle = "forward_per_node.target_configuration";
      }
      {
        label = "unknown per-node target assertion";
        needle = "DebugTimeTravelUnknownNode";
      }
      {
        label = "whole-world prefix use";
        needle = "DebugWholeWorldTarget::prefix_len";
      }
      {
        label = "whole-world event use";
        needle = "DebugWholeWorldTarget::event_sequence";
      }
      {
        label = "explicit thin policy assertion";
        needle = "kept_all_thin";
      }
      {
        label = "eviction-safe assertion";
        needle = "assert_eq!(exact_runtime.id, replay_runtime.id)";
      }
      {
        label = "thin default evicts fat assertion";
        needle = "cached_snapshots_after, 0";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green scoped debug time-travel gate";
        needle = "debugScopedTimeTravel = greenBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-DBG-5\"]";
      }
      {
        label = "debug time-travel raw dependency";
        needle = "phase6.debugTimeTravel.rawGate";
      }
      {
        label = "debug time-travel green dependency";
        needle = "phase6.debugTimeTravel";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_debug_time_travel.rs" timeTravelTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 debug-scoped-time-travel check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-debug-scoped-time-travel";
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
          name = "run-debug-scoped-time-travel";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-scoped-time-travel-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_debug_time_travel \
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
            gate=gate:debug-scoped-time-travel
            per_node=icount-scoped-other-nodes-untouched
            whole_world=prefix-fork-minus-divergence
            checkpoint_stride=performance-only-explicit-cache-policy
            RESULT
          '';
        }
      ];
    }
