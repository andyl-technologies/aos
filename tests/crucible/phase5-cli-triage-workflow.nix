{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliTriageWorkflow",
  taskIds ? ["T-CLI-17"],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  portableArtifacts = builtins.readFile ../../crates/crucible/crucible-cli/src/portable_artifact_constants.rs;
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
    ++ failuresFor "crates/crucible/crucible-cli/src/main.rs" cliMain [
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
        label = "signed findings parser";
        needle = "fn parse_reproduction_findings_ledger_bytes";
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
        label = "triage help test";
        needle = "cli_triage_help_surface_lists_required_flags_and_exit_code_contract";
      }
      {
        label = "triage pipeline test";
        needle = "cli_triage_surface_parses_full_t_tri_7_flags_and_pipeline";
      }
      {
        label = "triage directory blocker test";
        needle = "cli_triage_rejects_directory_inputs";
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
    ++ failuresFor "crates/crucible/crucible-cli/src/portable_artifact_constants.rs" portableArtifacts [
      {
        label = "signed findings schema";
        needle = "crucible.failure-triage.findings-ledger.v5";
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
    mkCrucibleTestGate {
      pname = "crucible-phase5-cli-triage-workflow";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      DEPENDENCY_COUNT = toString (builtins.length dependencies);
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

      phases = [
        {
          name = "run-cli-triage-workflow";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
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
