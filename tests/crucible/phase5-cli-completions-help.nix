{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliCompletionsHelp",
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  cliPage = builtins.readFile ../../docs/engineering/crucible/cli.md;
  cliImplementation = import ./_cli-source.nix {inherit lib;};
  cliProcessTest = builtins.readFile ../../crates/crucible/crucible-cli/tests/help_surface.rs;
  cliManifest = builtins.readFile ../../crates/crucible/crucible-cli/Cargo.toml;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/engineering/crucible/cli.md" cliPage [
      {
        label = "completions top-level subcommand";
        needle = "`crucible completions <SHELL>`";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-cli/Cargo.toml" cliManifest [
      {
        label = "clap dependency";
        needle = "clap = { workspace = true }";
      }
      {
        label = "clap_complete dependency";
        needle = "clap_complete = { workspace = true }";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-cli/src Rust source tree" cliImplementation [
      {
        label = "completion shell argument";
        needle = "shell: Shell";
      }
      {
        label = "completion generator";
        needle = "clap_complete::generate";
      }
      {
        label = "completion dispatch";
        needle = "write_completions(args.shell";
      }
      {
        label = "documented backend value surface";
        needle = "const BACKEND_VALUE_NAME: &str = \"auto|qemu|double\"";
      }
      {
        label = "replay help surface";
        needle = "struct ReplayArgs";
      }
      {
        label = "serve help surface";
        needle = "struct ServeArgs";
      }
      {
        label = "completion generation test";
        needle = "cli_completions_generates_every_supported_shell_script";
      }
      {
        label = "completion daemon metadata test";
        needle = "cli_completions_ignores_global_daemon_for_thin_wrapper_metadata";
      }
      {
        label = "help/version surface test";
        needle = "cli_resume_help_and_version_surface_matches_expected_copy";
      }
      {
        label = "normalized exact help snapshots";
        needle = "cli_help_surface_matches_normalized_exact_snapshots";
      }
      {
        label = "normative required-input parser test";
        needle = "cli_parser_enforces_every_normatively_required_input";
      }
      {
        label = "normative alternative/conflict parser test";
        needle = "cli_parser_enforces_normative_alternative_and_conflicting_inputs";
      }
      {
        label = "required serve listener";
        needle = "#[arg(long, value_name = \"addr\", required = true)]";
      }
      {
        label = "future flag rejection test";
        needle = "cli_help_surface_rejects_unimplemented_future_flags";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-cli/tests/help_surface.rs" cliProcessTest [
      {
        label = "process help regression";
        needle = "cli_help_process_outputs_top_level_surface";
      }
      {
        label = "process version regression";
        needle = "cli_help_process_version_exits_zero";
      }
      {
        label = "process completions regression";
        needle = "cli_completions_process_emits_every_supported_shell_script";
      }
      {
        label = "process completions usage regression";
        needle = "cli_completions_process_rejects_missing_shell";
      }
      {
        label = "process hidden gate flag regression";
        needle = "cli_help_process_hides_gate_only_flags";
      }
      {
        label = "process normative required-input regression";
        needle = "cli_process_rejects_every_missing_normative_input";
      }
      {
        label = "process normative alternative/conflict regression";
        needle = "cli_process_rejects_normative_conflicts_and_incomplete_alternatives";
      }
      {
        label = "exact process version regression";
        needle = "format!(\"crucible {}\\n\", env!(\"CARGO_PKG_VERSION\"))";
      }
      {
        label = "real crucible binary execution";
        needle = "CARGO_BIN_EXE_crucible";
      }
      {
        label = "hidden gate flag excluded from process help";
        needle = "--emit-mock-failure-artifact";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI completions/help check";
        needle = "cliCompletionsHelp = import ./phase5-cli-completions-help.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI completions/help check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-completions-help";
      version = "0";
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      runtimeDeps = [pkgs.sqlite];
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed

        pkgs.pkg-config
        pkgs.sqlite
      ];

      ATTR_PATH = attrPath;
      DEPENDENCY_COUNT = toString (builtins.length dependencies);
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

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
          name = "run-cli-completions-help";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-completions-help-target" \
              -p crucible-cli \
              cli_completions \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-completions-help-target" \
              -p crucible-cli \
              cli_help \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-completions-help-target" \
              -p crucible-cli \
              cli_parser_enforces_every_normatively_required_input \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-completions-help-target" \
              -p crucible-cli \
              cli_parser_enforces_normative_alternative_and_conflicting_inputs \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-completions-help-target" \
              -p crucible-cli \
              cli_process_rejects_every_missing_normative_input \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-completions-help-target" \
              -p crucible-cli \
              cli_process_rejects_normative_conflicts_and_incomplete_alternatives \
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
            status=complete
            evidence_scope=exact-help-version-all-completions-required-alternatives-and-conflicts
            component=crucible-cli
            completions=clap_complete
            help_surface=normalized-exact-copy
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
