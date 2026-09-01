{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliDeterminismErgonomics",
  taskIds ? ["T-CLI-4"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-4 completion note";
        needle = "Completed by `checks.crucible.phase5.cliDeterminismErgonomics`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI determinism-ergonomics status note";
        needle = "`T-CLI-4` is green through `checks.crucible.phase5.cliDeterminismErgonomics`";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "explicit seed environment constant";
        needle = "const CRUCIBLE_SEED_ENV: &str = \"CRUCIBLE_SEED\";";
      }
      {
        label = "determinism ergonomics plan";
        needle = "struct DeterminismErgonomicsPlan";
      }
      {
        label = "determinism ergonomics proof predicate";
        needle = "fn proves_t_cli_4";
      }
      {
        label = "seed source enum";
        needle = "enum SeedSource";
      }
      {
        label = "flag seed source";
        needle = "SeedSource::Flag";
      }
      {
        label = "environment seed source";
        needle = "SeedSource::Environment";
      }
      {
        label = "generated seed source";
        needle = "SeedSource::Generated";
      }
      {
        label = "seed environment seam";
        needle = "trait SeedEnvironment";
      }
      {
        label = "process seed environment";
        needle = "std::env::var(name).ok()";
      }
      {
        label = "seed entropy seam";
        needle = "trait SeedEntropySource";
      }
      {
        label = "OS entropy source";
        needle = "struct OsSeedEntropySource";
      }
      {
        label = "entropy drawn before run";
        needle = "generated_seed_drawn_before_run";
      }
      {
        label = "generated seed identity-only proof";
        needle = "generated_seed_is_identity_only";
      }
      {
        label = "seed resolver";
        needle = "fn resolve_seed";
      }
      {
        label = "seed resolution mode";
        needle = "enum SeedResolutionMode";
      }
      {
        label = "fresh run identity seed mode";
        needle = "SeedResolutionMode::FreshRunIdentity";
      }
      {
        label = "artifact or savepoint seed mode";
        needle = "SeedResolutionMode::ArtifactOrSavepointOwned";
      }
      {
        label = "seed parser";
        needle = "fn parse_seed_value";
      }
      {
        label = "seed hex formatter";
        needle = "fn format_seed";
      }
      {
        label = "seed printed at run start";
        needle = "seed_printed_at_run_start: true";
      }
      {
        label = "dispatch prints resolved seed";
        needle = "println!(\"{}\", plan.seed_announcement())";
      }
      {
        label = "determinism ergonomics planner";
        needle = "fn plan_determinism_ergonomics";
      }
      {
        label = "determinism ergonomics executor";
        needle = "fn execute_determinism_ergonomics_plan";
      }
      {
        label = "failure artifact rule";
        needle = "struct FailureArtifactRule";
      }
      {
        label = "failure footer";
        needle = "struct FailureReproductionFooter";
      }
      {
        label = "failure footer builder";
        needle = "fn failure_reproduction_footer";
      }
      {
        label = "replay command footer";
        needle = "crucible replay";
      }
      {
        label = "debug at failure footer";
        needle = "--at-failure";
      }
      {
        label = "self-contained artifact proof";
        needle = "self_contained_artifact: true";
      }
      {
        label = "actual failed-run artifact builder";
        needle = "fn run_failure_reproduction_artifact_bytes";
      }
      {
        label = "backend outcome status";
        needle = "enum BackendCommandStatus";
      }
      {
        label = "non-passing status coverage";
        needle = "fn non_passing_variants";
      }
      {
        label = "non-passing outcome exits through CliError";
        needle = "Outcome(BackendCommandStatus)";
      }
      {
        label = "dispatch propagates outcome exit";
        needle = "return Err(CliError::Outcome(outcome.status));";
      }
      {
        label = "seed-aware backend command route";
        needle = "ergonomics_plan: Option<&DeterminismErgonomicsPlan>";
      }
      {
        label = "backend canonical entries";
        needle = "fn backend_canonical_log_entries";
      }
      {
        label = "seed feeds run identity entry";
        needle = "kind: String::from(\"run_identity\")";
      }
      {
        label = "seed feeds canonical summary";
        needle = "seed={} source={:?}";
      }
      {
        label = "generic non-passing outcome artifact path";
        needle = "run_failure_reproduction_artifact_bytes(";
      }
      {
        label = "actual failed-run artifact adversarial test";
        needle = "cli_non_passing_run_artifact_captures_actual_run_evidence";
      }
      {
        label = "generic backend output emission";
        needle = "fn emit_backend_command_output";
      }
      {
        label = "trace emitter";
        needle = "fn emit_canonical_trace";
      }
      {
        label = "trace render report";
        needle = "struct TraceRenderReport";
      }
      {
        label = "trace streaming entry count";
        needle = "streamed_entries";
      }
      {
        label = "canonical log entry model";
        needle = "struct CanonicalLogEntry";
      }
      {
        label = "rendered canonical log model";
        needle = "struct RenderedCanonicalLog";
      }
      {
        label = "canonical log renderer";
        needle = "fn render_canonical_event_log";
      }
      {
        label = "jsonl entry-by-entry renderer";
        needle = "fn jsonl_for_canonical_log_entries";
      }
      {
        label = "canonical log render proof";
        needle = "fn render_canonical_trace_format_proof";
      }
      {
        label = "jsonl trace format";
        needle = "OutputFormat::Jsonl";
      }
      {
        label = "json trace format";
        needle = "OutputFormat::Json";
      }
      {
        label = "table trace format";
        needle = "OutputFormat::Table";
      }
      {
        label = "markdown trace rejected";
        needle = "--format markdown is reserved for triage reports, not canonical event-log traces";
      }
      {
        label = "jsonl streaming proof";
        needle = "jsonl_streams_entries";
      }
      {
        label = "format-only rendering proof";
        needle = "format_changes_only_rendering";
      }
      {
        label = "no wall-clock proof flag";
        needle = "no_wall_clock_feeds_canonical_state: true";
      }
      {
        label = "canonical state wall-clock guard";
        needle = "fn canonical_state_wall_clock_guard";
      }
      {
        label = "canonical model scanned for wall-clock";
        needle = "include_str!(\"../../../../crucible/src/model.rs\")";
      }
      {
        label = "canonical session scanned for wall-clock";
        needle = "include_str!(\"../../../../crucible-session/src/lib.rs\")";
      }
      {
        label = "determinism ergonomics recorder";
        needle = "trait DeterminismErgonomicsRecorder";
      }
      {
        label = "shell-quoted replay footer";
        needle = "fn shell_quote_command_argument";
      }
      {
        label = "fake seed environment test seam";
        needle = "struct FakeSeedEnvironment";
      }
      {
        label = "fake seed entropy test seam";
        needle = "struct FakeSeedEntropySource";
      }
      {
        label = "seed precedence test";
        needle = "cli_determinism_ergonomics_resolves_seed_by_flag_env_or_generated";
      }
      {
        label = "invalid seed and markdown test";
        needle = "cli_determinism_ergonomics_rejects_invalid_seed_and_markdown_trace_format";
      }
      {
        label = "trace format equivalence test";
        needle = "cli_determinism_ergonomics_renders_three_formats_over_same_canonical_log";
      }
      {
        label = "seed feeds backend outcome test";
        needle = "cli_determinism_ergonomics_threads_seed_into_backend_outcome";
      }
      {
        label = "failure artifact seed/footer test";
        needle = "cli_determinism_ergonomics_failure_artifact_carries_resolved_seed_and_footer";
      }
      {
        label = "generic outcome trace/artifact test";
        needle = "cli_determinism_ergonomics_emits_trace_and_failure_artifact_from_outcome";
      }
      {
        label = "wall-clock source scan test";
        needle = "cli_determinism_ergonomics_keeps_wall_clock_out_of_canonical_paths";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI determinism-ergonomics check";
        needle = "cliDeterminismErgonomics = import ./phase5-cli-determinism-ergonomics.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "Clap env hides seed source precedence";
        needle = "env = \"CRUCIBLE_SEED\"";
      }
      {
        label = "wall-clock time source";
        needle = "SystemTime";
      }
      {
        label = "wall-clock time source";
        needle = "UNIX_EPOCH";
      }
      {
        label = "wall-clock time source";
        needle = "Instant::now";
      }
      {
        label = "wall-clock time source";
        needle = "std::time::Instant";
      }
      {
        label = "wall-clock shell fallback";
        needle = "Command::new(\"date\")";
      }
      {
        label = "buffered jsonl newline collect";
        needle = ".collect::<Vec<_>>().join(\"\\n\")";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-cli-determinism-ergonomics";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_CLI_4_FAILURES = failureText;
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;
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
        name = "run-cli-determinism-ergonomics";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_CLI_4_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_CLI_4_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-cli-determinism-ergonomics-target" \
            -p crucible-cli \
            cli_determinism_ergonomics \
            -- --test-threads=1
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 CLI determinism-ergonomics gate for ${taskList}";
      passthru = {
        inherit attrPath taskIds dependencies;
        failureText = failureText;
      };
    };
  }
