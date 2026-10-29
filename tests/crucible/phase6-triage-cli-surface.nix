{
  attrPath ? "checks.crucible.phase6.triageCliSurface",
  dependencies ? [],
  lib,
  pkgs,
}: let
  inherit (import ./_lib.nix {inherit lib;}) failuresFor;

  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  failureTriagePage = builtins.readFile ../../docs/engineering/crucible/failure-triage.md;
  cliSource = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  failures =
    failuresFor "docs/engineering/crucible/failure-triage.md" failureTriagePage [
      {
        label = "policy help copy";
        needle = "[--policy coarse|default|fine|exact]";
      }
      {
        label = "minimize help copy";
        needle = "[--minimize none|representative|all]";
      }
      {
        label = "report help copy";
        needle = "[--report <dir>]";
      }
      {
        label = "markdown format help copy";
        needle = "[--format jsonl|json|table|markdown]";
      }
      {
        label = "recompute help copy";
        needle = "[--recompute-signatures]";
      }
      {
        label = "uniform triage exit code one";
        needle = "minimization signature preservation";
      }
      {
        label = "malformed ledger exit";
        needle = "Malformed or unresolvable ledger, artifact, store, or I/O failure";
      }
      {
        label = "jsonl default copy";
        needle = "`table` on a terminal, else `jsonl`";
      }
      {
        label = "usage parse exit note";
        needle = "Usage error, including parse-time errors";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-cli/src/main.rs" cliSource [
      {
        label = "command factory help rendering";
        needle = "use clap::CommandFactory;";
      }
      {
        label = "triage help regression";
        needle = "cli_triage_help_surface_lists_required_flags_and_exit_code_contract";
      }
      {
        label = "top-level help rendering";
        needle = "render_long_help";
      }
      {
        label = "try_parse main";
        needle = "Cli::try_parse()";
      }
      {
        label = "parse error exit helper";
        needle = "fn cli_parse_error_exit_code";
      }
      {
        label = "triage subcommand help lookup";
        needle = "find_subcommand_mut(\"triage\")";
      }
      {
        label = "format value set";
        needle = "value_name = \"jsonl|json|table|markdown\"";
      }
      {
        label = "policy value set";
        needle = "value_name = \"coarse|default|fine|exact\"";
      }
      {
        label = "minimize value set";
        needle = "value_name = \"none|representative|all\"";
      }
      {
        label = "triage exit code";
        needle = "Self::Triage(_) => 1";
      }
      {
        label = "backend exit code";
        needle = "Self::Backend(_) => 4";
      }
      {
        label = "artifact exit code";
        needle = "Self::Artifact(_) => 5";
      }
      {
        label = "usage exit code";
        needle = "Self::Usage(_) => 64";
      }
      {
        label = "missing findings parse regression";
        needle = "missing triage findings must be a parse error";
      }
      {
        label = "invalid policy parse regression";
        needle = "invalid triage policy must be a parse error";
      }
      {
        label = "focused cargo test in source gate";
        needle = "cli_triage_help_surface_lists_required_flags_and_exit_code_contract";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "triage CLI surface wiring";
        needle = "triageCliSurface = greenBeforeAdvance";
      }
      {
        label = "triage CLI surface attr path";
        needle = "checks.crucible.phase6.triageCliSurface";
      }
      {
        label = "triage CLI surface gate import";
        needle = "phase6-triage-cli-surface.nix";
      }
      {
        label = "triage thin-driver raw dependency";
        needle = "phase6.triageThinDriver.rawGate";
      }
      {
        label = "CLI skeleton dependency";
        needle = "phase5.cliSkeleton";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 triage CLI surface check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-triage-cli-surface";
      version = "0";
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      runtimeDeps = [pkgs.sqlite];
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.rust
          pkgs.sed

          pkgs.pkg-config
          pkgs.sqlite
        ]
        ++ dependencies;

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
          name = "run-triage-cli-surface-test";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-triage-cli-surface-target" \
              -p crucible-cli \
              --bin crucible \
              cli_triage_help_surface_lists_required_flags_and_exit_code_contract \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out/nix-support"
            {
              echo "crucible_gate=phase6-triage-cli-surface"
              echo "attr_path=${attrPath}"
              echo "cargo_deps=${cargoDeps}"
              echo "rust_test=crucible-cli::cli_triage_help_surface_lists_required_flags_and_exit_code_contract"
            } > "$out/nix-support/hydra-build-products"
          '';
        }
      ];
    }
