{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.debugCliSurface",
  taskIds ? ["T-DBG-8" "T-CLI-18"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  debugDoc = builtins.readFile ../../docs/rfcs/0010-crucible/36-time-travel-debugging.md;
  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/lib.rs;
  };
  cliManifest = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
  cliMain = import ./_cli-source.nix {inherit lib;};
  surfaceTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/gate_debug_cli_surface.rs;
  };
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

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
        label = "T-DBG-8 partial-evidence note";
        needle = "Completed under `checks.crucible.phase6.debugCliSurface`";
      }
      {
        label = "no symbol server wording";
        needle = "no symbol server";
      }
      {
        label = "raw gdb step fallback";
        needle = "gdb single-step disabled until green";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-18 partial-evidence note";
        needle = "Completed under `checks.crucible.phase6.debugCliSurface`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-DBG-8 plan summary";
        needle = "`T-DBG-8`/`T-CLI-18` are completed through `checks.crucible.phase6.debugCliSurface`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "debug cli contract";
        needle = "pub struct DebugCliSurfaceContract";
      }
      {
        label = "symbol policy";
        needle = "pub struct DebugSymbolResolutionPolicy";
      }
      {
        label = "multi vcpu policy";
        needle = "pub struct DebugMultiVcpuPolicy";
      }
      {
        label = "gdbstub step policy";
        needle = "pub struct DebugGdbstubStepPolicy";
      }
      {
        label = "read mutate policy";
        needle = "pub struct DebugReadMutationBoundaryPolicy";
      }
      {
        label = "reverse latency policy";
        needle = "pub struct DebugReverseLatencyPolicy";
      }
      {
        label = "T-DBG-8 proof";
        needle = "proves_t_dbg_8";
      }
      {
        label = "no symbol server constructor";
        needle = "no_symbol_server";
      }
      {
        label = "coherent multi-vcpu constructor";
        needle = "coherent_round_robin_threads";
      }
      {
        label = "raw gdb single-step fallback";
        needle = "disabled_raw_single_step_until_green";
      }
      {
        label = "read mutate constructor";
        needle = "read_only_default_with_explicit_branching";
      }
      {
        label = "reverse latency constructor";
        needle = "performance_only_checkpoint_cadence";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "debug cli contract export";
        needle = "DebugCliSurfaceContract";
      }
      {
        label = "symbol policy export";
        needle = "DebugSymbolResolutionPolicy";
      }
      {
        label = "multi vcpu policy export";
        needle = "DebugMultiVcpuPolicy";
      }
      {
        label = "gdbstub policy export";
        needle = "DebugGdbstubStepPolicy";
      }
      {
        label = "read mutate policy export";
        needle = "DebugReadMutationBoundaryPolicy";
      }
      {
        label = "reverse latency policy export";
        needle = "DebugReverseLatencyPolicy";
      }
    ]
    ++ failuresFor "crates/crucible-cli/Cargo.toml" cliManifest [
      {
        label = "session client dependency";
        needle = "crucible-session";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "debug executes live QEMU admission";
        needle = "run_local_qemu_debug_workflow(&backend, &plan)";
      }
      {
        label = "coordinate flag group";
        needle = "ArgGroup::new(\"debug_coordinate\")";
      }
      {
        label = "session flag";
        needle = "session: Option<String>";
      }
      {
        label = "at flag";
        needle = "at: Option<String>";
      }
      {
        label = "at-event flag";
        needle = "at_event: Option<u64>";
      }
      {
        label = "at-checkpoint flag";
        needle = "at_checkpoint: Option<String>";
      }
      {
        label = "node flag";
        needle = "node: Option<String>";
      }
      {
        label = "read-only flag";
        needle = "read_only: bool";
      }
      {
        label = "allow-mutate flag";
        needle = "allow_mutate: bool";
      }
      {
        label = "checkpoint stride flag";
        needle = "checkpoint_stride: Option<u64>";
      }
      {
        label = "checkpoint stride validation";
        needle = "validate_debug_checkpoint_stride";
      }
      {
        label = "interactive verbs";
        needle = "enum DebugVerbArgs";
      }
      {
        label = "attach gdb verb";
        needle = "AttachGdb";
      }
      {
        label = "reverse step verb";
        needle = "ReverseStep";
      }
      {
        label = "reverse continue verb";
        needle = "ReverseContinue";
      }
      {
        label = "debug planner";
        needle = "fn plan_debug_invocation";
      }
      {
        label = "debug reverse-step delegation";
        needle = "DebugEngineOperation::ReverseStep";
      }
      {
        label = "session fork delegation";
        needle = "SessionCommand::Fork";
      }
      {
        label = "open gdbstub operation";
        needle = "DebugEngineOperation::OpenGdbstub";
      }
      {
        label = "restore replay operation";
        needle = "DebugEngineOperation::RestoreNearestCheckpointReplay";
      }
      {
        label = "raw gdb single-step disabled";
        needle = "DebugEngineOperation::DisableRawGdbSingleStep";
      }
      {
        label = "backend error";
        needle = "CliError::Backend";
      }
      {
        label = "usage error";
        needle = "CliError::Usage";
      }
      {
        label = "full cli surface test";
        needle = "cli_debug_surface_parses_full_t_dbg_8_flags_and_verbs";
      }
      {
        label = "allow mutate test";
        needle = "cli_debug_surface_requires_explicit_fork_for_allow_mutate";
      }
      {
        label = "conflict test";
        needle = "cli_debug_surface_rejects_conflicts_and_backend_without_gdbstub";
      }
      {
        label = "zero stride regression";
        needle = "zero checkpoint stride must be rejected";
      }
      {
        label = "target-aware default test";
        needle = "cli_debug_surface_defaults_coordinate_by_target_kind";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_debug_cli_surface.rs" surfaceTest [
      {
        label = "contract positive test";
        needle = "debug_cli_surface_contract_covers_t_dbg_8_policy";
      }
      {
        label = "contract negative test";
        needle = "debug_cli_surface_contract_rejects_symbol_server_or_raw_gdb_step";
      }
      {
        label = "no symbol server assertion";
        needle = "proves_no_crucible_symbol_server";
      }
      {
        label = "multi vcpu assertion";
        needle = "proves_multi_vcpu_coherence";
      }
      {
        label = "gdbstub fallback assertion";
        needle = "proves_s14_fallback";
      }
      {
        label = "read mutate assertion";
        needle = "proves_read_mutate_boundary";
      }
      {
        label = "reverse latency assertion";
        needle = "proves_reverse_latency_policy";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green debug cli gate";
        needle = "debugCliSurface = greenBeforeAdvance";
      }
      {
        label = "explicit task ids";
        needle = "taskIds = [\"T-DBG-8\" \"T-CLI-18\"]";
      }
      {
        label = "layer0 raw dependency";
        needle = "phase1.gates.layer0Determinism.rawGate";
      }
      {
        label = "replay oracle raw dependency";
        needle = "phase4.gates.replayOracle.rawGate";
      }
      {
        label = "e2e raw dependency";
        needle = "phase4.gates.e2eDeterminism.rawGate";
      }
      {
        label = "control raw dependency";
        needle = "phase5.gates.controlResponsive.rawGate";
      }
      {
        label = "target resolver raw dependency";
        needle = "phase6.debugTargetResolver.rawGate";
      }
      {
        label = "non-canonical raw dependency";
        needle = "phase6.debugNonCanonicalBranch.rawGate";
      }
      {
        label = "scoped time-travel raw dependency";
        needle = "phase6.debugScopedTimeTravel.rawGate";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "unsupported session step delegation";
        needle = "SessionCommand::Step {";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_debug_cli_surface.rs" surfaceTest [
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
  then throw "crucible phase6 debug-cli-surface check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-debug-cli-surface";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-debug-cli-surface";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-cli-surface-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_debug_cli_surface \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-cli-surface-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-cli \
              cli_debug_surface \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-cli-surface-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-cli \
              cli_failure_artifact_writer_emits_replay_and_debug_commands \
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
            open_tasks=${openTaskList}
            status=complete
            evidence_scope=debug-cli-model-and-proxy
            gate=gate:debug-cli-surface
            surface=thin-session-wrapper,gdbstub-proxy,read-only-default,allow-mutate-non-canonical
            RESULT
          '';
        }
      ];
    }
