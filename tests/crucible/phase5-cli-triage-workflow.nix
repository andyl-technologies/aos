{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliTriageWorkflow",
  taskIds ? ["T-CLI-17"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-17 completion note";
        needle = "Completed under `checks.crucible.phase5.cliTriageWorkflow`";
      }
      {
        label = "T-CLI-17 signed findings";
        needle = "property findings ledgers";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI triage completion note";
        needle = "`T-CLI-17` is complete under `checks.crucible.phase5.cliTriageWorkflow`";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "triage arguments";
        needle = "struct TriageArgs";
      }
      {
        label = "triage invocation plan";
        needle = "struct TriageInvocationPlan";
      }
      {
        label = "triage planner";
        needle = "fn plan_triage_invocation";
      }
      {
        label = "triage runner";
        needle = "fn run_triage_invocation";
      }
      {
        label = "findings ledger loader";
        needle = "fn load_triage_findings_ledger";
      }
      {
        label = "signed findings schema";
        needle = "crucible.failure-triage.findings-ledger.v2";
      }
      {
        label = "signed findings parser";
        needle = "fn parse_failure_findings_ledger_v2_bytes";
      }
      {
        label = "triage minimization";
        needle = "fn build_triage_minimization";
      }
      {
        label = "triage report set";
        needle = "fn build_triage_report_set";
      }
      {
        label = "triage signature self-check";
        needle = "fn build_triage_signature_self_check";
      }
      {
        label = "triage compare support";
        needle = "fn compare_triage_result";
      }
      {
        label = "thin-driver contract guard";
        needle = "fn proves_t_tri_7";
      }
      {
        label = "CLI sidecar signature blocker";
        needle = "engine-owned discovery artifacts";
      }
      {
        label = "artifact-only ledger blocker";
        needle = "discovery-time signature evidence is not available in this ledger format";
      }
      {
        label = "triage help test";
        needle = "cli_triage_help_surface_lists_required_flags_and_exit_code_contract";
      }
      {
        label = "triage pipeline test";
        needle = "cli_triage_surface_parses_full_t_tri_7_flags_and_pipeline";
      }
      {
        label = "triage sidecar blocker test";
        needle = "cli_triage_rejects_cli_sidecar_signature_evidence";
      }
      {
        label = "triage artifact-only blocker test";
        needle = "cli_triage_rejects_artifact_only_findings_without_engine_evidence";
      }
      {
        label = "triage signature mismatch test";
        needle = "cli_triage_rejects_mismatched_engine_owned_signature_evidence";
      }
      {
        label = "triage exit-code test";
        needle = "cli_triage_is_offline_and_uses_uniform_failure_exit_code";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI triage workflow check";
        needle = "cliTriageWorkflow = import ./phase5-cli-triage-workflow.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI triage workflow check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-triage-workflow";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
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
          name = "run-cli-triage-workflow";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-triage-workflow-target" \
              -p crucible-cli \
              cli_triage \
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
            component=crucible-cli
            contract=triage-workflow-complete
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
