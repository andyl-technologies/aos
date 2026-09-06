{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.debugTargetResolver",
  taskIds ? ["T-DBG-7"],
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
  cliMain = import ./_cli-source.nix {inherit lib;};
  resolverTest = builtins.readFile ../../crates/crucible/tests/gate_debug_target_resolver.rs;
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
        label = "T-DBG-7 completion note";
        needle = "Completed by `checks.crucible.phase6.debugTargetResolver`";
      }
      {
        label = "at-failure wording";
        needle = "--at-failure";
      }
      {
        label = "divergence coordinate wording";
        needle = "divergence-bisection";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-DBG-7 plan summary";
        needle = "`T-DBG-7` is green through `checks.crucible.phase6.debugTargetResolver`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "target resolver API";
        needle = "pub fn debug_resolve_target";
      }
      {
        label = "target resolver request";
        needle = "pub struct DebugTargetResolverRequest";
      }
      {
        label = "target resolver report";
        needle = "pub struct DebugTargetResolverReport";
      }
      {
        label = "target selector";
        needle = "pub enum DebugTargetSelector";
      }
      {
        label = "divergence coordinate";
        needle = "pub struct DebugDivergenceCoordinate";
      }
      {
        label = "failure footer command";
        needle = "pub struct DebugFailureFooterCommand";
      }
      {
        label = "first assertion violation scan";
        needle = "debug_first_assertion_violation_sequence";
      }
      {
        label = "event sequence presence check";
        needle = "debug_event_log_contains_sequence";
      }
      {
        label = "exact divergence resolver";
        needle = "debug_resolve_exact_divergence_coordinate";
      }
      {
        label = "quoted failure footer argument";
        needle = "shell_quote_command_argument";
      }
      {
        label = "missing failure error";
        needle = "DebugTargetResolverFailureNotFound";
      }
      {
        label = "goto delegation proof";
        needle = "proves_debug_target_resolution";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "target resolver request export";
        needle = "DebugTargetResolverRequest";
      }
      {
        label = "target resolver report export";
        needle = "DebugTargetResolverReport";
      }
      {
        label = "target selector export";
        needle = "DebugTargetSelector";
      }
      {
        label = "divergence coordinate export";
        needle = "DebugDivergenceCoordinate";
      }
      {
        label = "failure footer export";
        needle = "DebugFailureFooterCommand";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "shared debug footer command";
        needle = "DebugFailureFooterCommand::new";
      }
      {
        label = "cli footer test";
        needle = "cli_failure_artifact_writer_emits_replay_and_debug_commands";
      }
      {
        label = "cli quoted path regression";
        needle = "artifact dir with spaces";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_debug_target_resolver.rs" resolverTest [
      {
        label = "all selectors test";
        needle = "debug_target_resolver_accepts_all_t_dbg_7_selectors";
      }
      {
        label = "at failure missing test";
        needle = "at_failure_requires_assertion_violation_event";
      }
      {
        label = "at event selector";
        needle = "DebugTargetSelector::at_event";
      }
      {
        label = "at failure selector";
        needle = "DebugTargetSelector::at_failure";
      }
      {
        label = "at checkpoint selector";
        needle = "DebugTargetSelector::at_checkpoint";
      }
      {
        label = "divergence selector";
        needle = "DebugTargetSelector::divergence";
      }
      {
        label = "open payload assertion failure";
        needle = "open_assertion_violation_entry";
      }
      {
        label = "divergence no rounding regression";
        needle = "Icount { retired: 150 }";
      }
      {
        label = "goto delegation execution";
        needle = "debug_goto(&attach, &by_divergence.goto_request)";
      }
      {
        label = "footer assertion";
        needle = "has_copy_pasteable_at_failure_footer";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green target resolver gate";
        needle = "debugTargetResolver = greenBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-DBG-7\"]";
      }
      {
        label = "non-canonical branch raw dependency";
        needle = "phase6.debugNonCanonicalBranch.rawGate";
      }
      {
        label = "control responsive raw dependency";
        needle = "phase5.gates.controlResponsive.rawGate";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_debug_target_resolver.rs" resolverTest [
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
  then throw "crucible phase6 debug-target-resolver check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-debug-target-resolver";
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
          name = "run-debug-target-resolver";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-target-resolver-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_debug_target_resolver \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-target-resolver-target" \
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
            gate=gate:debug-target-resolver
            selectors=at,at-event,at-failure,at-checkpoint,divergence
            footer=crucible-debug-at-failure
            RESULT
          '';
        }
      ];
    }
