{
  attrPath ? "checks.crucible.phase6.triageThinDriver",
  dependencies ? [],
  lib,
  pkgs,
  taskIds ? ["T-TRI-7"],
}: let
  # Substring scan by index. The regex form (builtins.match ".*needle.*")
  # overflows the Nix regex engine's stack on large haystacks such as the CLI
  # main.rs, so use a linear index walk instead.
  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  triageDoc = builtins.readFile ../../docs/rfcs/0010-crucible/34-failure-triage.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  modelSource = import ./_crucible-model-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  cliSource = import ./_cli-source.nix {inherit lib;};
  signatureTest = builtins.readFile ../../crates/crucible/tests/gate_failure_signature.rs;
  defaultChecks = builtins.readFile ./default.nix;
  taskList = builtins.concatStringsSep "," taskIds;

  failures =
    failuresFor "docs/rfcs/0010-crucible/34-failure-triage.md" triageDoc [
      {
        label = "T-TRI-7 completion note";
        needle = "Completed by `checks.crucible.phase6.triageThinDriver`";
      }
      {
        label = "content-addressed triage result";
        needle = "content-addressed triage result in the DagStore";
      }
      {
        label = "self-check wording";
        needle = "recomputed signatures equal discovery-time signatures byte-for-byte";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-TRI-7 plan summary";
        needle = "checks.crucible.phase6.triageThinDriver";
      }
      {
        label = "downstream triage CLI surface gate";
        needle = "checks.crucible.phase6.triageCliSurface";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" modelSource [
      {
        label = "findings ledger domain";
        needle = "FAILURE_FINDINGS_LEDGER_DOMAIN";
      }
      {
        label = "triage result domain";
        needle = "FAILURE_TRIAGE_RESULT_DOMAIN";
      }
      {
        label = "triage result diff domain";
        needle = "FAILURE_TRIAGE_RESULT_DIFF_DOMAIN";
      }
      {
        label = "findings ledger type";
        needle = "pub struct FailureFindingsLedger";
      }
      {
        label = "ledger dedup constructor";
        needle = "pub fn from_artifacts";
      }
      {
        label = "stored artifact report";
        needle = "pub struct FailureTriageStoredArtifact";
      }
      {
        label = "signature self-check input";
        needle = "pub struct FailureTriageSignatureSelfCheckInput";
      }
      {
        label = "signature self-check";
        needle = "pub struct FailureTriageSignatureSelfCheck";
      }
      {
        label = "signature self-check record";
        needle = "pub struct FailureTriageSignatureCheckRecord";
      }
      {
        label = "self-check pair comparison";
        needle = "from_signature_pairs";
      }
      {
        label = "self-check byte material";
        needle = "discovery_signature.report_material()";
      }
      {
        label = "clean self-check evidence material";
        needle = "check_record_count";
      }
      {
        label = "self-check fail path";
        needle = "recomputed signature does not match discovery-time signature";
      }
      {
        label = "self-check coverage validation";
        needle = "signature self-check did not cover every finding";
      }
      {
        label = "self-check cluster binding validation";
        needle = "signature self-check discovery hash does not match cluster member";
      }
      {
        label = "self-check matched flag validation";
        needle = "signature self-check matched flag contradicts signature bytes";
      }
      {
        label = "triage result type";
        needle = "pub struct FailureTriageResult";
      }
      {
        label = "triage result constructor";
        needle = "pub fn from_parts";
      }
      {
        label = "policy validation";
        needle = "report-set policy does not match clustering policy";
      }
      {
        label = "cluster id validation";
        needle = "cluster, minimization, and report ids do not match";
      }
      {
        label = "minimal representative validation";
        needle = "report minimal representative does not match minimization";
      }
      {
        label = "run representative validation";
        needle = "minimization run does not use cluster representative";
      }
      {
        label = "duplicate minimization validation";
        needle = "duplicate minimization run for cluster";
      }
      {
        label = "report membership validation";
        needle = "report membership does not match cluster";
      }
      {
        label = "result store API";
        needle = "pub fn store<S>(&self, store: &S)";
      }
      {
        label = "dedup cache-hit helper";
        needle = "store_failure_triage_artifact";
      }
      {
        label = "store key validation";
        needle = "stored_key != key";
      }
      {
        label = "triage result diff";
        needle = "pub struct FailureTriageResultDiff";
      }
      {
        label = "content diff renderer";
        needle = "pub fn content_diff(&self) -> String";
      }
      {
        label = "diff changed cluster";
        needle = "pub struct FailureTriageChangedCluster";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "ledger export";
        needle = "FailureFindingsLedger";
      }
      {
        label = "triage result export";
        needle = "FailureTriageResult";
      }
      {
        label = "triage diff export";
        needle = "FailureTriageResultDiff";
      }
      {
        label = "self-check export";
        needle = "FailureTriageSignatureSelfCheck";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliSource [
      {
        label = "triage findings argument";
        needle = "struct TriageArgs";
      }
      {
        label = "policy flag enum";
        needle = "enum TriagePolicyArg";
      }
      {
        label = "minimize flag enum";
        needle = "enum TriageMinimizeArg";
      }
      {
        label = "markdown format support";
        needle = "Markdown => crucible::FailureClusterReportFormat::Markdown";
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
        label = "offline daemon rejection";
        needle = "triage is an offline DagStore operation and must not use --daemon";
      }
      {
        label = "local DagStore open";
        needle = "crucible::LocalDagStore::new";
      }
      {
        label = "ledger loader";
        needle = "fn load_triage_findings_ledger";
      }
      {
        label = "real clustering call";
        needle = "crucible::FailureClusteringResult::from_findings";
      }
      {
        label = "real result assembly";
        needle = "crucible::FailureTriageResult::from_parts";
      }
      {
        label = "result store call";
        needle = "result.store(&store)";
      }
      {
        label = "report writer";
        needle = "fn write_triage_report";
      }
      {
        label = "compare implementation";
        needle = "fn compare_triage_result";
      }
      {
        label = "stored result summary parser";
        needle = "TriageResultSummary::from_artifact_bytes";
      }
      {
        label = "findings source parser";
        needle = "parse_triage_findings_source";
      }
      {
        label = "compare target parser";
        needle = "parse_triage_compare_target";
      }
      {
        label = "load ledger pipeline";
        needle = "TriagePipelineStep::LoadFindingsLedger";
      }
      {
        label = "self-check pipeline";
        needle = "TriagePipelineStep::RecomputeSignatureSelfCheck";
      }
      {
        label = "cluster pipeline";
        needle = "TriagePipelineStep::Cluster";
      }
      {
        label = "representative minimization pipeline";
        needle = "TriagePipelineStep::MinimizeRepresentative";
      }
      {
        label = "report pipeline";
        needle = "TriagePipelineStep::EmitReports";
      }
      {
        label = "store result pipeline";
        needle = "TriagePipelineStep::StoreTriageResult";
      }
      {
        label = "compare content diff pipeline";
        needle = "TriagePipelineStep::CompareContentDiff";
      }
      {
        label = "thin-driver proof";
        needle = "fn proves_t_tri_7";
      }
      {
        label = "uniform triage failure exit";
        needle = "Self::Triage(_) => 1";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_failure_signature.rs" signatureTest [
      {
        label = "triage result regression";
        needle = "triage_result_artifact_dedups_diffs_and_self_checks_offline";
      }
      {
        label = "ledger dedup regression";
        needle = "FailureFindingsLedger::from_artifacts";
      }
      {
        label = "memory store dedup regression";
        needle = "MemoryDagStore::new";
      }
      {
        label = "self-check mismatch regression";
        needle = "mismatch_check.assert_clean";
      }
      {
        label = "partial self-check regression";
        needle = "non-skipped self-checks must cover every clustered finding";
      }
      {
        label = "forged self-check regression";
        needle = "self-check discovery hashes must bind to clustered finding signatures";
      }
      {
        label = "forged minimization regression";
        needle = "triage result must re-bind minimization runs to cluster representatives";
      }
      {
        label = "duplicate minimization regression";
        needle = "triage result must reject duplicate minimization runs for a cluster";
      }
      {
        label = "forged report regression";
        needle = "triage result must re-bind report membership to clusters";
      }
      {
        label = "content diff regression";
        needle = "changed_diff.content_diff()";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliSource [
      {
        label = "triage CLI surface regression";
        needle = "cli_triage_surface_parses_full_t_tri_7_flags_and_pipeline";
      }
      {
        label = "triage runner regression";
        needle = "run_triage_invocation(&cli, args)";
      }
      {
        label = "triage CLI offline regression";
        needle = "cli_triage_is_offline_and_uses_uniform_failure_exit_code";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "triage thin-driver wiring";
        needle = "triageThinDriver = greenBeforeAdvance";
      }
      {
        label = "triage thin-driver attr path";
        needle = "checks.crucible.phase6.triageThinDriver";
      }
      {
        label = "triage thin-driver gate import";
        needle = "phase6-triage-thin-driver.nix";
      }
      {
        label = "per-cluster report dependency";
        needle = "phase6.perClusterReports.rawGate";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-cli/src/main.rs" cliSource [
      {
        label = "ignored triage test";
        needle = "#[ignore]";
      }
      {
        label = "todo marker";
        needle = "todo!";
      }
      {
        label = "unimplemented marker";
        needle = "unimplemented!";
      }
    ];

  failureText = lib.concatStringsSep "\n" failures;
in
  pkgs.runCommand "crucible-phase6-triage-thin-driver-0" {
    nativeBuildInputs = dependencies;
    CRUCIBLE_TASK_IDS = taskList;
    CRUCIBLE_ATTR_PATH = attrPath;
    CRUCIBLE_CARGO_DEPS = cargoDeps;
    inherit failureText;
    passAsFile = ["failureText"];
  } ''
    if [ -s "$failureTextPath" ]; then
      cat "$failureTextPath" >&2
      exit 1
    fi
    mkdir -p "$out/nix-support"
    {
      echo "crucible_gate=phase6-triage-thin-driver"
      echo "attr_path=$CRUCIBLE_ATTR_PATH"
      echo "task_ids=$CRUCIBLE_TASK_IDS"
      echo "cargo_deps=$CRUCIBLE_CARGO_DEPS"
    } > "$out/nix-support/hydra-build-products"
  ''
