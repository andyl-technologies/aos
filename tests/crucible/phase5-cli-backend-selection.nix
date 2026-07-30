{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliBackendSelection",
  taskIds ? ["T-CLI-3" "T-CLI-19" "T-CLI-20"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliManifest = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
  cliHelpTests = builtins.readFile ../../crates/crucible-cli/tests/help_surface.rs;
  machineReadableTests = builtins.readFile ../../crates/crucible-cli/tests/machine_readable.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-3 completion note";
        needle = "Completed by `checks.crucible.phase5.cliBackendSelection`";
      }
      {
        label = "T-CLI-20 completion note";
        needle = "Completed by `checks.crucible.phase5.cliBackendSelection`: backend command";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI backend-selection status note";
        needle = "`T-CLI-3` is green through `checks.crucible.phase5.cliBackendSelection`";
      }
    ]
    ++ failuresFor "crates/crucible-cli/Cargo.toml" cliManifest [
      {
        label = "production-default feature set";
        needle = "default = []";
      }
      {
        label = "explicit test-double feature";
        needle = ''test-double = ["crucible-session/test-double"]'';
      }
      {
        label = "process double tests require feature";
        needle = ''required-features = ["test-double"]'';
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "double backend compile-time gate";
        needle = ''#[cfg(any(test, feature = "test-double"))]'';
      }
      {
        label = "production auto backend fails closed";
        needle = "no hermetic QEMU backend was discovered; this production build does not";
      }
      {
        label = "backend-selection plan type";
        needle = "struct BackendSelectionPlan";
      }
      {
        label = "backend-selection proof predicate";
        needle = "fn proves_t_cli_3";
      }
      {
        label = "observed backend execution evidence";
        needle = "enum BackendExecutionEvidence";
      }
      {
        label = "post-execution identity validation";
        needle = "execution.evidence.proves_t_cli_3(backend_plan)";
      }
      {
        label = "injected live-QEMU probe runner";
        needle = "trait LiveQemuProbeRunner";
      }
      {
        label = "live-QEMU probe consistency comparison";
        needle = "live QEMU selftest probes diverged across identical executions";
      }
      {
        label = "executed build-identity negative control";
        needle = "cli_backend_selection_rejects_execution_identity_divergence";
      }
      {
        label = "live-probe divergence negative control";
        needle = "divergent live-QEMU probes must fail closed";
      }
      {
        label = "live-probe identity negative control";
        needle = "a live-QEMU build identity mismatch must fail closed";
      }
      {
        label = "backend-selection planner";
        needle = "fn plan_backend_selection";
      }
      {
        label = "backend-selection executor";
        needle = "fn execute_backend_selection_plan";
      }
      {
        label = "backend route recorder";
        needle = "trait BackendRouteRecorder";
      }
      {
        label = "backend command runner";
        needle = "trait BackendCommandRunner";
      }
      {
        label = "backend command executor";
        needle = "fn execute_backend_routed_command";
      }
      {
        label = "dispatch executes backend plan";
        needle = "execute_backend_selection_plan(&backend_plan, cli.quiet, &mut NullBackendRouteRecorder)?";
      }
      {
        label = "dispatch executes backend command route";
        needle = "execute_backend_routed_command(";
      }
      {
        label = "remote daemon target";
        needle = "BackendExecutionTarget::RemoteDaemon";
      }
      {
        label = "local target";
        needle = "BackendExecutionTarget::Local";
      }
      {
        label = "qemu resolved backend";
        needle = "ResolvedLocalBackend::Qemu";
      }
      {
        label = "live QEMU backend execution";
        needle = "fn run_live_qemu_backend_probe";
      }
      {
        label = "API-owned live plugin gate";
        needle = "production_api::run_production_plugin_install_gate";
      }
      {
        label = "double resolved backend";
        needle = "ResolvedLocalBackend::Double";
      }
      {
        label = "auto qemu reason";
        needle = "AutoQemuArtifactsSupplied";
      }
      {
        label = "auto double fallback reason";
        needle = "AutoFallbackDouble";
      }
      {
        label = "explicit qemu reason";
        needle = "ExplicitQemu";
      }
      {
        label = "explicit double reason";
        needle = "ExplicitDouble";
      }
      {
        label = "daemon API route";
        needle = "remote_uses_control_api: true";
      }
      {
        label = "local simulation backend route";
        needle = "local_uses_simulation_backend: true";
      }
      {
        label = "auto announcement method";
        needle = "fn should_announce";
      }
      {
        label = "backend announcement message";
        needle = "crucible: backend = double (--backend auto; patched QEMU/plugin not discoverable)";
      }
      {
        label = "explicit qemu config error";
        needle = "fn qemu_backend_config_error";
      }
      {
        label = "explicit qemu artifact readability check";
        needle = "fn validate_qemu_artifacts";
      }
      {
        label = "qemu artifact open check";
        needle = "fs::File::open(path)";
      }
      {
        label = "directory artifact rejected";
        needle = "not a regular file";
      }
      {
        label = "serve daemon rejection";
        needle = "serve hosts the daemon and cannot itself use --daemon";
      }
      {
        label = "backend command outcome";
        needle = "struct BackendCommandOutcome";
      }
      {
        label = "backend outcome captures stdout";
        needle = "stdout: Vec<String>";
      }
      {
        label = "backend outcome captures stderr";
        needle = "stderr: Vec<String>";
      }
      {
        label = "backend outcome captures canonical log digest";
        needle = "canonical_log_digest";
      }
      {
        label = "backend outcome captures artifact digest";
        needle = "artifact_digest";
      }
      {
        label = "fake backend runner test harness";
        needle = "struct RecordingBackendCommandRunner";
      }
      {
        label = "backend auto test";
        needle = "cli_backend_selection_auto_announces_qemu_or_double_resolution";
      }
      {
        label = "explicit backend test";
        needle = "cli_backend_selection_honors_explicit_backend_and_qemu_failure_exit";
      }
      {
        label = "daemon route test";
        needle = "cli_backend_selection_routes_daemon_over_api_without_local_backend";
      }
      {
        label = "all backend-routed subcommands test";
        needle = "cli_backend_selection_covers_every_backend_routed_subcommand";
      }
      {
        label = "local remote equivalence test";
        needle = "cli_backend_selection_local_and_remote_have_equivalent_canonical_outcome";
      }
      {
        label = "serve daemon rejection test";
        needle = "cli_backend_selection_rejects_daemon_on_serve";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/help_surface.rs" cliHelpTests [
      {
        label = "production double rejection regression";
        needle = "cli_production_build_rejects_the_test_double_backend";
      }
      {
        label = "production backend help surface";
        needle = ''const BACKEND_HELP: &str = "--backend <auto|qemu>"'';
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI backend-selection check";
        needle = "cliBackendSelection = import ./phase5-cli-backend-selection.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "host PATH QEMU discovery";
        needle = "std::env::var(\"PATH\")";
      }
      {
        label = "host PATH QEMU discovery";
        needle = "Command::new(\"which\")";
      }
      {
        label = "host PATH QEMU launch";
        needle = "Command::new(\"qemu";
      }
      {
        label = "live-QEMU probe environment bypass";
        needle = "CRUCIBLE_TEST_SKIP_LIVE_QEMU_PROBE";
      }
    ]
    ++ forbiddenFor "crates/crucible-cli/tests/machine_readable.rs" machineReadableTests [
      {
        label = "live-QEMU probe environment bypass";
        needle = "CRUCIBLE_TEST_SKIP_LIVE_QEMU_PROBE";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "ELF dynamic-symbol parser";
        needle = "fn defined_global_dynamic_symbols(";
      }
      {
        label = "dynamic-symbol section selection";
        needle = "ELF_SECTION_DYNAMIC_SYMBOLS";
      }
      {
        label = "undefined dynamic-symbol rejection";
        needle = "section_index == ELF_SYMBOL_UNDEFINED_SECTION";
      }
      {
        label = "global dynamic-symbol binding validation";
        needle = "ELF_SYMBOL_BINDING_GLOBAL | ELF_SYMBOL_BINDING_WEAK";
      }
      {
        label = "ELF symbol-table adversarial controls";
        needle = "names outside .dynsym must not impersonate exported symbols";
      }
      {
        label = "undefined-symbol adversarial control";
        needle = "undefined dynamic symbols must not satisfy plugin discovery";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-cli-backend-selection";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_CLI_3_FAILURES = failureText;
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;
    OPEN_TASK_IDS = openTaskList;
    DEPENDENCY_COUNT = toString (builtins.length dependencies);
    DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          set -eu
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
        name = "run-cli-backend-selection";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_CLI_3_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_CLI_3_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-cli-backend-selection-target" \
            -p crucible-cli \
            cli_backend_selection \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-cli-backend-selection-target" \
            -p crucible-cli \
            cli_hermetic_qemu_discovery_rejects_text_artifact_impersonation \
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
          check=$ATTR_PATH
          tasks=$TASK_IDS
          open_tasks=$OPEN_TASK_IDS
          status=complete
          evidence_scope=backend-routing-live-qemu-and-production-api
          plugin_validation=elf64-dynsym-defined-global
          plugin_negative_controls=names-only,undefined,non-elf
          RESULT
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 CLI backend-selection gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds openTaskIds dependencies;
        failureText = failureText;
      };
    };
  }
