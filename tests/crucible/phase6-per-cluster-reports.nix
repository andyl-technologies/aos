{
  attrPath ? "checks.crucible.phase6.perClusterReports",
  dependencies ? [],
  lib,
  pkgs,
  taskIds ? ["T-TRI-6"],
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
  signatureTest = builtins.readFile ../../crates/crucible/tests/gate_failure_signature.rs;
  defaultChecks = builtins.readFile ./default.nix;
  taskList = builtins.concatStringsSep "," taskIds;

  failures =
    failuresFor "docs/rfcs/0010-crucible/34-failure-triage.md" triageDoc [
      {
        label = "T-TRI-6 completion note";
        needle = "Completed by `checks.crucible.phase6.perClusterReports`";
      }
      {
        label = "rendering note";
        needle = "deterministic `json`, `jsonl`, `table`, and `markdown` renderings";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "T-TRI-6 plan summary";
        needle = "checks.crucible.phase6.perClusterReports";
      }
      {
        label = "downstream triage thin-driver gate";
        needle = "checks.crucible.phase6.triageThinDriver";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" modelSource [
      {
        label = "cluster report domain";
        needle = "FAILURE_CLUSTER_REPORT_DOMAIN";
      }
      {
        label = "cluster report set domain";
        needle = "FAILURE_CLUSTER_REPORT_SET_DOMAIN";
      }
      {
        label = "report format enum";
        needle = "pub enum FailureClusterReportFormat";
      }
      {
        label = "report divergence detail";
        needle = "pub struct FailureClusterReportDivergence";
      }
      {
        label = "divergence icount-node retention";
        needle = "pub icount_node: Option<NodeId>";
      }
      {
        label = "property/divergence report detail enum";
        needle = "pub enum FailureClusterReportFailure";
      }
      {
        label = "causal step model";
        needle = "pub struct FailureClusterReportCausalStep";
      }
      {
        label = "minimal reproduction ref";
        needle = "pub struct FailureClusterReportReproduction";
      }
      {
        label = "per cluster report";
        needle = "pub struct FailureClusterReport";
      }
      {
        label = "report set";
        needle = "pub struct FailureClusterReportSet";
      }
      {
        label = "cluster-bound constructor";
        needle = "pub fn from_cluster";
      }
      {
        label = "event log artifact validation";
        needle = "event_log.artifact() != minimal_representative";
      }
      {
        label = "representative member binding";
        needle = "minimization run does not use cluster representative";
      }
      {
        label = "minimization original binding";
        needle = "minimization original does not match cluster representative";
      }
      {
        label = "target signature key binding";
        needle = "minimization target signature key does not match cluster";
      }
      {
        label = "full minimized signature recomputation";
        needle = "failure_signature_for_report_failure";
      }
      {
        label = "property anchor validation";
        needle = "validate_violation_point(event_log, record)";
      }
      {
        label = "divergence anchor validation";
        needle = "validate_divergence_point(event_log, &divergence.to_divergence_point())";
      }
      {
        label = "last-N causal excerpt";
        needle = "failure_report_excerpt";
      }
      {
        label = "causal cone narrative";
        needle = "failure_causal_cone_entries(event_log, causal_index, &canonicalizer)";
      }
      {
        label = "exact replay command";
        needle = "crucible replay";
      }
      {
        label = "json rendering";
        needle = "FailureClusterReportFormat::Json";
      }
      {
        label = "jsonl rendering";
        needle = "FailureClusterReportFormat::JsonLines";
      }
      {
        label = "table rendering";
        needle = "FailureClusterReportFormat::Table";
      }
      {
        label = "markdown rendering";
        needle = "FailureClusterReportFormat::Markdown";
      }
      {
        label = "canonical report material";
        needle = "failure_cluster_report_material";
      }
      {
        label = "canonical report-set material";
        needle = "failure_cluster_report_set_material";
      }
      {
        label = "content hash includes report material";
        needle = "FAILURE_CLUSTER_REPORT_DOMAIN";
      }
      {
        label = "member hash material";
        needle = "member.{index}.reproduction_artifact";
      }
      {
        label = "causal excerpt material";
        needle = "event_log_excerpt_count";
      }
      {
        label = "causal chain material";
        needle = "causal_chain_count";
      }
      {
        label = "JSON escaping helper";
        needle = "fn json_string";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "report export";
        needle = "FailureClusterReport";
      }
      {
        label = "report format export";
        needle = "FailureClusterReportFormat";
      }
      {
        label = "report set export";
        needle = "FailureClusterReportSet";
      }
      {
        label = "divergence detail export";
        needle = "FailureClusterReportDivergence";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_failure_signature.rs" signatureTest [
      {
        label = "per-cluster report regression";
        needle = "per_cluster_reports_render_same_content_deterministically";
      }
      {
        label = "property report constructor";
        needle = "FailureClusterReportFailure::property";
      }
      {
        label = "stale full-signature detail regression";
        needle = "stale-report-detail";
      }
      {
        label = "full signature recompute assertion";
        needle = "report construction must recompute the full minimized signature from checked evidence";
      }
      {
        label = "wrong representative regression";
        needle = "wrong-cluster-representative";
      }
      {
        label = "wrong original regression";
        needle = "wrong-report-original";
      }
      {
        label = "divergence report constructor";
        needle = "FailureClusterReportFailure::divergence";
      }
      {
        label = "bisected first diff helper";
        needle = "from_bisected_first_diff";
      }
      {
        label = "node-sourced divergence regression";
        needle = "recorded_node_divergence_event_log";
      }
      {
        label = "icount-node report regression";
        needle = "failure.icount_node";
      }
      {
        label = "JSON render regression";
        needle = "FailureClusterReportFormat::Json";
      }
      {
        label = "JSONL render regression";
        needle = "FailureClusterReportFormat::JsonLines";
      }
      {
        label = "table render regression";
        needle = "FailureClusterReportFormat::Table";
      }
      {
        label = "markdown render regression";
        needle = "FailureClusterReportFormat::Markdown";
      }
      {
        label = "causal projection regression";
        needle = "report excerpts must use the causal projection";
      }
      {
        label = "report set ordering regression";
        needle = "sorted_report_ids";
      }
      {
        label = "report hash evidence regression";
        needle = "report identity must include causal excerpt evidence";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green per-cluster report gate";
        needle = "perClusterReports = greenBeforeAdvance";
      }
      {
        label = "phase6 report import";
        needle = "gate = import ./phase6-per-cluster-reports.nix";
      }
      {
        label = "phase6 report attr path";
        needle = "checks.crucible.phase6.perClusterReports";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-TRI-6\"]";
      }
      {
        label = "signature minimization raw dependency";
        needle = "phase6.signaturePreservingMinimization.rawGate";
      }
      {
        label = "signature minimization green dependency";
        needle = "phase6.signaturePreservingMinimization";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_failure_signature.rs" signatureTest [
      {
        label = "ignored test";
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
    ]
    ++ forbiddenFailuresFor "crates/crucible/src/model.rs" modelSource [
      {
        label = "serde_json dependency in report renderer";
        needle = "serde_json";
      }
    ];

  failureText = lib.concatStringsSep "\n" failures;
in
  pkgs.runCommand "crucible-phase6-per-cluster-reports-0" {
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
      echo "crucible_gate=phase6-per-cluster-reports"
      echo "attr_path=$CRUCIBLE_ATTR_PATH"
      echo "task_ids=$CRUCIBLE_TASK_IDS"
      echo "cargo_deps=$CRUCIBLE_CARGO_DEPS"
    } > "$out/nix-support/hydra-build-products"
  ''
