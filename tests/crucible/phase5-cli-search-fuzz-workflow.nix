{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliSearchFuzzWorkflow",
  taskIds ? [],
  openTaskIds ? ["T-CLI-13"],
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
  cliMachineReadable = builtins.readFile ../../crates/crucible-cli/tests/machine_readable.rs;
  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  engineModel = import ./_crucible-model-source.nix {inherit lib;};
  engineTrigger = import ./_crucible-trigger-source.nix {inherit lib;};
  searchStrategiesTest = builtins.readFile ../../crates/crucible/tests/gate_search_strategies.rs;
  defaultChecks = builtins.readFile ./default.nix;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-13 remains open";
        needle = "- [ ] **T-CLI-13** Implement `search`/`fuzz`";
      }
      {
        label = "T-CLI-13 partial-evidence note";
        needle = "Partial evidence under `checks.crucible.phase5.cliSearchFuzzWorkflow`";
      }
      {
        label = "T-CLI-13 local-double search progress";
        needle = "accepts explicit `--on-violation`";
      }
      {
        label = "T-CLI-13 schedule-named truth CLI progress";
        needle = "now accepts `--schedule-named-truths <path>`";
      }
      {
        label = "T-CLI-13 retained evidence CLI progress";
        needle = "hidden retained-evidence fixture input";
      }
      {
        label = "T-CLI-13 terminal retained evidence CLI progress";
        needle = "`terminal-quiescence` evidence on the root or an explicit configuration hash";
      }
      {
        label = "T-CLI-13 terminal retained sometimes CLI progress";
        needle = "terminal `sometimes` failures through local-double\n  `search`";
      }
      {
        label = "T-CLI-13 local-double sampled API progress";
        needle = "search_with_strategy_and_failure_oracle_bounded_depth_sampled";
      }
      {
        label = "T-CLI-13 local-double depth progress";
        needle = "honors `--max-depth` as a bounded\n  decision-depth search run";
      }
      {
        label = "T-CLI-13 local-double budget status progress";
        needle = "RFC §13 status mapping for discovered failures, stop-mode\n  budget exhaustion";
      }
      {
        label = "T-CLI-13 local-double replay oracle sampling progress";
        needle = "1/1 replay-oracle sampling counts over fat search materializations";
      }
      {
        label = "T-CLI-13 local-double search counterexample artifact progress";
        needle = "Engine\n  failures discovered by the local-double search path now attach replayable CLI\n  reproduction artifacts";
      }
      {
        label = "T-CLI-13 local-double fuzz runner progress";
        needle = "executes local `--backend double fuzz` through\n  `ScenarioFamily::fuzz_coverage_guided`";
      }
      {
        label = "T-CLI-13 local-double fuzz corpus progress";
        needle = "persists retained corpus\n  artifacts through `LocalDagStore`";
      }
      {
        label = "T-CLI-13 stored fuzz family progress";
        needle = "loads stored family hashes as strict\n  scenario-family TOML from the configured DAG store";
      }
      {
        label = "T-CLI-13 process search/fuzz progress";
        needle = "process-tests real-binary\n  local-double `search` and `fuzz` JSONL output";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI search/fuzz progress note";
        needle = "`checks.crucible.phase5.cliSearchFuzzWorkflow`";
      }
      {
        label = "phase5 CLI local-double search progress";
        needle = "`search-run` output with `failure_oracle=none`";
      }
      {
        label = "phase5 CLI schedule-named truth progress";
        needle = "`--schedule-named-truths`\n  loading of explicit data-only oracle inputs";
      }
      {
        label = "phase5 CLI retained-log provider progress";
        needle = "an engine trusted retained-log\n  provider path can now lower prefix-safe safety/unreachability failures";
      }
      {
        label = "phase5 CLI retained-log raw coverage and memory progress";
        needle = "raw guest-address\n  coverage, physical-address/register memory samples";
      }
      {
        label = "phase5 CLI retained-log resolution progress";
        needle = "resolution context for symbolic coverage and virtual/symbolic memory leaves";
      }
      {
        label = "phase5 CLI retained-log evidence-bundle progress";
        needle = "configuration-bound retained-log evidence bundles";
      }
      {
        label = "phase5 CLI retained evidence fixture progress";
        needle = "hidden local-double\n  `crucible.search-retained-evidence.v1` retained-evidence fixture loading";
      }
      {
        label = "phase5 CLI terminal retained evidence fixture progress";
        needle = "terminal quantum evaluation-boundary entries, and\n  terminal-quiescence entries";
      }
      {
        label = "phase5 CLI terminal retained sometimes fixture progress";
        needle = "local-double CLI coverage for retained\n  after-quiescence and terminal `sometimes` failures";
      }
      {
        label = "phase5 CLI retained evidence white-box validation progress";
        needle = "white-box policy";
      }
      {
        label = "phase5 CLI retained-log terminal quiescence progress";
        needle = "terminal quiescence evidence";
      }
      {
        label = "phase5 CLI local-double sampled API progress";
        needle = "search_with_strategy_and_failure_oracle_bounded_depth_sampled";
      }
      {
        label = "phase5 CLI local-double depth progress";
        needle = "bounded decision-depth execution for\n  `--max-depth`";
      }
      {
        label = "phase5 CLI local-double budget status progress";
        needle = "RFC §13 status mapping\n  for discovered failures, stop-mode budget exhaustion";
      }
      {
        label = "phase5 CLI local-double replay oracle sampling progress";
        needle = "1/1 replay-oracle\n  sampling counts over fat search materializations";
      }
      {
        label = "phase5 CLI local-double counterexample artifact progress";
        needle = "engine-discovered counterexample metadata, and replayable\n  CLI reproduction artifact emission with standard replay/debug footer commands";
      }
      {
        label = "phase5 CLI local-double fuzz runner progress";
        needle = "local-double `ScenarioFamily::fuzz_coverage_guided` and\n  `ScenarioFamily::fuzz_coverage_guided_corpus` execution";
      }
      {
        label = "phase5 CLI local-double fuzz corpus progress";
        needle = "durable\n  `LocalDagStore` corpus persistence";
      }
      {
        label = "phase5 CLI stored fuzz family progress";
        needle = "stored family-hash loading as strict\n  scenario-family TOML from the configured DAG store";
      }
      {
        label = "phase5 CLI process search/fuzz progress";
        needle = "process-level local-double `search` and `fuzz`\n  JSONL output";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "search arguments";
        needle = "struct SearchArgs";
      }
      {
        label = "fuzz arguments";
        needle = "struct FuzzArgs";
      }
      {
        label = "search driver plan";
        needle = "struct SearchDriverPlan";
      }
      {
        label = "fuzz driver plan";
        needle = "struct FuzzDriverPlan";
      }
      {
        label = "search planner";
        needle = "fn plan_search_invocation";
      }
      {
        label = "search schedule-named truths argument";
        needle = "schedule_named_truths: Option<PathBuf>";
      }
      {
        label = "search schedule-named truths loader";
        needle = "fn load_search_schedule_named_truths_file";
      }
      {
        label = "search schedule-named truths plan";
        needle = "struct SearchScheduleNamedTruthsPlan";
      }
      {
        label = "search retained evidence argument";
        needle = "retained_evidence: Option<PathBuf>";
      }
      {
        label = "search retained evidence plan";
        needle = "struct SearchRetainedEvidencePlan";
      }
      {
        label = "search retained evidence schema";
        needle = "crucible.search-retained-evidence.v1";
      }
      {
        label = "search retained evidence artifact media type";
        needle = "application/vnd.crucible.search-retained-evidence+toml";
      }
      {
        label = "search retained evidence loader";
        needle = "fn load_search_retained_evidence_file";
      }
      {
        label = "search retained evidence terminal quiescence kind";
        needle = "\"terminal-quiescence\"";
      }
      {
        label = "search retained evidence evaluation boundary kind";
        needle = "\"evaluation-boundary\"";
      }
      {
        label = "search retained evidence quiescent field";
        needle = "quiescent: Option<bool>";
      }
      {
        label = "search retained evidence virtual time field";
        needle = "virtual_time_ticks: Option<u64>";
      }
      {
        label = "search retained evidence evaluation boundary parser";
        needle = "fn parse_search_retained_evaluation_boundary_entry";
      }
      {
        label = "search retained evidence evaluation boundary binding";
        needle = "from_entries_with_quantum_evaluation_boundary";
      }
      {
        label = "search retained evidence terminal parser";
        needle = "fn parse_search_retained_terminal_quiescence_entry";
      }
      {
        label = "search retained evidence terminal binding";
        needle = "with_terminal_scheduler_quiescence";
      }
      {
        label = "search retained evidence terminal workflow regression";
        needle = "terminal quiescence search workflow must emit a search-run line";
      }
      {
        label = "search retained evidence terminal sometimes workflow regression";
        needle = "terminal sometimes search workflow must emit a search-run line";
      }
      {
        label = "search schedule-named truths schema";
        needle = "crucible.search-schedule-named-truths.v1";
      }
      {
        label = "search schedule-named truths artifact media type";
        needle = "application/vnd.crucible.search-schedule-named-truths+toml";
      }
      {
        label = "fuzz planner";
        needle = "fn plan_fuzz_invocation";
      }
      {
        label = "advanced search strategy mapping";
        needle = "crucible::SearchStrategy::CoverageGuided";
      }
      {
        label = "coverage fuzz config mapping";
        needle = "crucible::CoverageGuidedFuzzConfig::new";
      }
      {
        label = "local-double search runner";
        needle = "fn run_local_double_search_workflow";
      }
      {
        label = "local-double injectable graph runner";
        needle = "fn run_local_double_search_workflow_with_graph";
      }
      {
        label = "local-double injectable failure oracle runner";
        needle = "fn run_local_double_search_workflow_with_graph_and_failure_oracle";
      }
      {
        label = "local-double search output";
        needle = "search-run";
      }
      {
        label = "local-double search no-oracle marker";
        needle = "failure_oracle=none";
      }
      {
        label = "local-double search assertion oracle marker";
        needle = "failure_oracle=scenario-assertions";
      }
      {
        label = "local-double search named truth oracle marker";
        needle = "scenario-assertions+schedule-named-truths";
      }
      {
        label = "local-double search retained evidence oracle marker";
        needle = "scenario-assertions+retained-evidence";
      }
      {
        label = "local-double search assertion oracle derivation";
        needle = "from_search_assertion_violations";
      }
      {
        label = "local-double search named truth derivation";
        needle = "from_search_assertion_violations_with_named_predicates";
      }
      {
        label = "local-double search retained evidence derivation";
        needle = "from_search_assertion_violations_with_retained_log_evidence";
      }
      {
        label = "local-double search retained evidence merge";
        needle = "fn merge_search_failure_oracles";
      }
      {
        label = "local-double search retained evidence white-box validation";
        needle = "not white-box enabled";
      }
      {
        label = "local-double search oracle API";
        needle = "search_with_strategy_and_failure_oracle";
      }
      {
        label = "local-double bounded search budget";
        needle = "search_with_strategy_and_failure_oracle_bounded_depth";
      }
      {
        label = "local-double sampled search runner";
        needle = "search_with_strategy_and_failure_oracle_bounded_depth_sampled";
      }
      {
        label = "local-double search counterexample artifact adapter";
        needle = "fn search_failure_reproduction_artifact_bytes";
      }
      {
        label = "local-double search root failure adapter";
        needle = "root-failure";
      }
      {
        label = "local-double search fingerprint bridge";
        needle = "fn cli_digest_from_engine_hash";
      }
      {
        label = "local-double search counterexample output";
        needle = "counterexample_fingerprint={}";
      }
      {
        label = "local-double search named truth output";
        needle = "schedule_named_truths={}";
      }
      {
        label = "local-double search named truth digest output";
        needle = "schedule_named_truths_digest={}";
      }
      {
        label = "local-double search retained evidence output";
        needle = "retained_evidence={}";
      }
      {
        label = "local-double search retained evidence digest output";
        needle = "retained_evidence_digest={}";
      }
      {
        label = "local-double search named truth artifact component";
        needle = "search_schedule_named_truths";
      }
      {
        label = "local-double search retained evidence artifact component";
        needle = "search_retained_evidence";
      }
      {
        label = "local-double search counterexample artifact output";
        needle = "counterexample_artifact={}";
      }
      {
        label = "local-double search canonical log";
        needle = "search_strategy_run";
      }
      {
        label = "local-double max-depth execution";
        needle = "max_depth=1";
      }
      {
        label = "local-double search status mapper";
        needle = "fn local_double_search_status";
      }
      {
        label = "local-double search report application";
        needle = "fn apply_local_double_search_report";
      }
      {
        label = "local-double status assignment";
        needle = "outcome.status = status";
      }
      {
        label = "local-double budget exhaustion output";
        needle = "budget_exhausted={}";
      }
      {
        label = "local-double replay oracle sampling output";
        needle = "replay_oracle_sampling=1/1";
      }
      {
        label = "local-double sampled replay oracle count";
        needle = "replay_oracle_sampled={}";
      }
      {
        label = "local-double positive sampled replay oracle regression";
        needle = "replay_oracle_sampled=1";
      }
      {
        label = "local-double budget timeout test";
        needle = "local_double_search_status(false, false, SearchOnViolationArg::Stop)";
      }
      {
        label = "local-double search frontier fixture";
        needle = "write_search_frontier_scenario";
      }
      {
        label = "local-double non-exhausted workflow regression";
        needle = "run_local_double_search_workflow_with_graph(\n            &plan_cli_invocation(&frontier_cli)";
      }
      {
        label = "local-double counterexample artifact regression";
        needle = "failed search must attach a counterexample artifact";
      }
      {
        label = "local-double counterexample emission regression";
        needle = "emit_backend_command_output(&failure_cli, &failure_outcome)";
      }
      {
        label = "local-double root counterexample artifact regression";
        needle = "root search failure must attach a counterexample artifact";
      }
      {
        label = "local-double no-oracle output remains stable";
        needle = "!search_line.contains(\"counterexample=\")";
      }
      {
        label = "fuzz runner blocker";
        needle = "requires the exploration-engine driver over phase-6 fuzzing policies tracked by T-CLI-13";
      }
      {
        label = "scenario family TOML loader";
        needle = "fn load_fuzz_family_file";
      }
      {
        label = "scenario family schema";
        needle = "crucible.scenario-family.v1";
      }
      {
        label = "local-double fuzz runner";
        needle = "fn run_local_double_fuzz_workflow";
      }
      {
        label = "stored fuzz family loader";
        needle = "fn load_stored_fuzz_family";
      }
      {
        label = "stored fuzz family store get";
        needle = "store.get(&reference)";
      }
      {
        label = "fuzz dispatch route";
        needle = "enum FuzzDispatchRoute";
      }
      {
        label = "built-in fuzz proof route";
        needle = "FuzzDispatchRoute::BuiltInFaultCampaignProof";
      }
      {
        label = "local-double fuzz injectable family runner";
        needle = "fn run_local_double_fuzz_workflow_with_family";
      }
      {
        label = "local-double fuzz no-corpus API";
        needle = "fuzz_coverage_guided(plan.config, &[])";
      }
      {
        label = "local-double fuzz corpus API";
        needle = "fuzz_coverage_guided_corpus";
      }
      {
        label = "local-double fuzz output";
        needle = "fuzz-run";
      }
      {
        label = "local-double fuzz canonical log";
        needle = "coverage_guided_fuzz_run";
      }
      {
        label = "local-double fuzz corpus persistence";
        needle = "crucible::LocalDagStore::new";
      }
      {
        label = "local-double fuzz replay validation output";
        needle = "replay_oracle_validations={}";
      }
      {
        label = "local-double fuzz no-corpus output";
        needle = "corpus=none";
      }
      {
        label = "stored fuzz family positive regression";
        needle = "stored-family fuzz workflow must emit a fuzz-run line";
      }
      {
        label = "stored fuzz family missing-object error";
        needle = "could not be loaded from store";
      }
      {
        label = "stored fuzz family corrupt-object error";
        needle = "corrupt stored family TOML must fail";
      }
      {
        label = "stored fuzz family non-UTF-8 error";
        needle = "non-UTF-8 stored family bytes must fail";
      }
      {
        label = "stored fuzz family malformed TOML error";
        needle = "malformed stored family TOML must fail";
      }
      {
        label = "search fuzz help test";
        needle = "cli_search_fuzz_help_surface_lists_wip_flags";
      }
      {
        label = "search fuzz planning test";
        needle = "cli_search_fuzz_workflow_plans_drivers_and_rejects_bad_inputs";
      }
      {
        label = "search fuzz local-double execution test";
        needle = "cli_search_fuzz_workflow_executes_local_double_search";
      }
      {
        label = "search fuzz schedule-named truth regression";
        needle = "named-truth search workflow must emit a search-run line";
      }
      {
        label = "search fuzz retained evidence regression";
        needle = "retained-evidence search workflow must emit a search-run line";
      }
      {
        label = "search fuzz retained evidence preserves schedule oracle regression";
        needle = "retained evidence must not suppress schedule-only failures";
      }
      {
        label = "search fuzz duplicate schedule-named truth regression";
        needle = "duplicate schedule-named truth keys must fail";
      }
      {
        label = "search fuzz retained evidence white-box regression";
        needle = "guest-marker retained evidence must require white-box nodes";
      }
      {
        label = "search fuzz malformed retained evidence regression";
        needle = "malformed retained evidence must fail";
      }
      {
        label = "search fuzz local-double fuzz execution test";
        needle = "cli_search_fuzz_workflow_executes_local_double_fuzz";
      }
      {
        label = "local-double positive fuzz replay regression";
        needle = "replay_oracle_validations=3";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/machine_readable.rs" cliMachineReadable [
      {
        label = "process search/fuzz JSONL regression";
        needle = "cli_exit_machine_readable_search_fuzz_jsonl_reports_final_outcome";
      }
      {
        label = "process search JSONL canonical kind";
        needle = "\"search_strategy_run\"";
      }
      {
        label = "process fuzz JSONL canonical kind";
        needle = "\"coverage_guided_fuzz_run\"";
      }
      {
        label = "process search/fuzz final outcome helper";
        needle = "assert_machine_readable_jsonl(&search_stdout, &[\"search_strategy_run\"])?";
      }
      {
        label = "process fuzz final outcome helper";
        needle = "assert_machine_readable_jsonl(&fuzz_stdout, &[\"coverage_guided_fuzz_run\"])?";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "search discovered failure re-export";
        needle = "SearchDiscoveredFailure";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" engineModel [
      {
        label = "sampled strategy search wrapper";
        needle = "struct TemporalGraphSampledSearchRun";
      }
      {
        label = "sampled bounded strategy search API";
        needle = "search_with_strategy_and_failure_oracle_bounded_depth_sampled";
      }
      {
        label = "sampled strategy report aggregation";
        needle = "merge_search_replay_oracle_sampling_report";
      }
      {
        label = "sampled search-wide sequence offset";
        needle = "sampling_sequence_offset";
      }
      {
        label = "search assertion oracle helper";
        needle = "pub fn from_search_assertion_violations";
      }
      {
        label = "search assertion named truth-table helper";
        needle = "pub fn from_search_assertion_violations_with_named_predicates";
      }
      {
        label = "search assertion retained-log provider helper";
        needle = "pub fn from_search_assertion_violations_with_retained_logs";
      }
      {
        label = "search assertion retained-log resolution helper";
        needle = "pub fn from_search_assertion_violations_with_retained_logs_and_resolutions";
      }
      {
        label = "search assertion retained-log evidence helper";
        needle = "pub fn from_search_assertion_violations_with_retained_log_evidence";
      }
      {
        label = "search assertion retained-log evidence type";
        needle = "pub struct SearchRetainedLogAssertionEvidence";
      }
      {
        label = "search assertion retained-log terminal quiescence builder";
        needle = "with_terminal_scheduler_quiescence";
      }
      {
        label = "search assertion retained-log resolution type";
        needle = "pub struct SearchRetainedLogPredicateResolutions";
      }
      {
        label = "search assertion named truth-table scope";
        needle = "SearchAssertionPredicateScope::ScheduleAndNamedTruths";
      }
      {
        label = "search assertion retained-log scope";
        needle = "SearchAssertionPredicateScope::RetainedLog";
      }
      {
        label = "search assertion retained-log black-box checker";
        needle = "check_run(scenario.properties(), recorded.entries())";
      }
      {
        label = "search assertion retained-log raw coverage allowlist";
        needle = "point: CodePoint::GuestAddress { .. }";
      }
      {
        label = "search assertion retained-log raw memory allowlist";
        needle = "place: MemPlace::PhysicalAddress { .. } | MemPlace::Register { .. }";
      }
      {
        label = "search assertion retained-log symbolic coverage unsupported";
        needle = "resolves_code_point(node, point)";
      }
      {
        label = "search assertion retained-log resolved memory allowlist";
        needle = "resolves_mem_place(node, place)";
      }
      {
        label = "offline assertion checker code point resolutions";
        needle = "with_resolved_code_points";
      }
      {
        label = "offline assertion checker memory resolutions";
        needle = "with_resolved_mem_places";
      }
      {
        label = "search assertion retained-log terminal quiescence allowlist";
        needle = "allow_terminal_quiescence_predicates";
      }
      {
        label = "search assertion retained-log terminal completeness allowlist";
        needle = "terminal_complete_retained_quantifier";
      }
      {
        label = "search assertion retained-log terminal reachability failure allowlist";
        needle = "AssertionQuantifierKind::Reachable | AssertionQuantifierKind::GuestReachable";
      }
      {
        label = "search assertion retained-log guest marker allowlist";
        needle = "retained_guest_marker_failure";
      }
      {
        label = "search assertion retained-log terminal guest marker allowlist";
        needle = "terminal_retained_guest_marker_failure";
      }
      {
        label = "search assertion retained-log terminal guest marker quantifier";
        needle = "AssertionQuantifierKind::GuestSometimes";
      }
      {
        label = "search assertion retained-log terminal quiescent guard";
        needle = "SchedulerQuiescence::is_quiescent";
      }
      {
        label = "search assertion retained-log after-quiescence allowlist";
        needle = "AssertionQuantifierKind::AfterQuiescence";
      }
      {
        label = "search assertion retained-log eventually allowlist";
        needle = "AssertionQuantifierKind::Sometimes\n                | AssertionQuantifierKind::Eventually";
      }
      {
        label = "search assertion named truth-table type";
        needle = "SearchScheduleNamedPredicateTruths";
      }
      {
        label = "search assertion retained log helper";
        needle = "recorded_assertion_log_from_schedule_for_search";
      }
      {
        label = "search assertion prefix-safe filter";
        needle = "prefix_safe_search_assertion_failure";
      }
      {
        label = "search assertion schedule predicate allowlist";
        needle = "assertion_uses_only_search_schedule_predicates";
      }
      {
        label = "sampled search sequence offset bisection test";
        needle = "sampled_search_offset_localizes_bisection_sequence";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" engineTrigger [
      {
        label = "recorded assertion log terminal quantum boundary constructor";
        needle = "pub fn from_entries_with_quantum_evaluation_boundary";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_search_strategies.rs" searchStrategiesTest [
      {
        label = "sampled search strategy gate";
        needle = "gate_search_strategies_sample_replay_oracle_checks";
      }
      {
        label = "sampled search strategy config";
        needle = "SearchReplayOracleSamplingConfig::new";
      }
      {
        label = "search assertion oracle lowering gate";
        needle = "gate_search_failure_oracle_lowers_prefix_safe_assertion_violations";
      }
      {
        label = "search assertion named truth-table regression";
        needle = "from_search_assertion_violations_with_named_predicates";
      }
      {
        label = "search assertion retained-log regression";
        needle = "from_search_assertion_violations_with_retained_logs";
      }
      {
        label = "search assertion retained-log guest-marker regression";
        needle = "retained_guest_marker_oracle";
      }
      {
        label = "search assertion retained-log raw coverage regression";
        needle = "retained_raw_coverage_oracle";
      }
      {
        label = "search assertion schedule-only raw coverage regression";
        needle = "schedule_only_raw_coverage_oracle";
      }
      {
        label = "search assertion retained-log symbolic coverage regression";
        needle = "unsupported_symbol_coverage_oracle";
      }
      {
        label = "search assertion retained-log resolved symbolic coverage regression";
        needle = "resolved_symbol_coverage_oracle";
      }
      {
        label = "search assertion retained-log evidence symbolic coverage regression";
        needle = "evidence_symbol_coverage_oracle";
      }
      {
        label = "search assertion retained-log per-configuration evidence regression";
        needle = "evidence_per_configuration_oracle";
      }
      {
        label = "search assertion retained-log nonmatching symbolic coverage regression";
        needle = "nonmatching_symbol_coverage_oracle";
      }
      {
        label = "search assertion retained-log physical memory regression";
        needle = "retained_physical_memory_oracle";
      }
      {
        label = "search assertion schedule-only physical memory regression";
        needle = "schedule_only_physical_memory_oracle";
      }
      {
        label = "search assertion retained-log register memory regression";
        needle = "retained_register_memory_oracle";
      }
      {
        label = "search assertion retained-log symbolic memory regression";
        needle = "unsupported_symbol_memory_oracle";
      }
      {
        label = "search assertion retained-log resolved symbolic memory regression";
        needle = "resolved_symbol_memory_oracle";
      }
      {
        label = "search assertion retained-log nonmatching symbolic memory regression";
        needle = "nonmatching_symbol_memory_oracle";
      }
      {
        label = "search assertion retained-log evidence symbolic memory regression";
        needle = "evidence_symbol_memory_oracle";
      }
      {
        label = "search assertion retained-log nonmatching evidence symbolic memory regression";
        needle = "evidence_nonmatching_symbol_memory_oracle";
      }
      {
        label = "search assertion retained-log virtual memory regression";
        needle = "unsupported_virtual_memory_oracle";
      }
      {
        label = "search assertion retained-log resolved virtual memory regression";
        needle = "resolved_virtual_memory_oracle";
      }
      {
        label = "search assertion retained-log nonmatching virtual memory regression";
        needle = "nonmatching_virtual_memory_oracle";
      }
      {
        label = "search assertion retained-log evidence virtual memory regression";
        needle = "evidence_virtual_memory_oracle";
      }
      {
        label = "search assertion retained-log nonmatching evidence virtual memory regression";
        needle = "evidence_nonmatching_virtual_memory_oracle";
      }
      {
        label = "search assertion retained-log observable helper";
        needle = "retained_observable_log";
      }
      {
        label = "search assertion retained-log unsupported quiescence regression";
        needle = "unsupported_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal quiescence regression";
        needle = "after_quiescence_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log missing terminal quiescence regression";
        needle = "after_quiescence_without_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal quiescence always guard";
        needle = "unsupported_quiescence_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal quiescence reachability guard";
        needle = "unreachable_quiescence_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal sometimes regression";
        needle = "retained_sometimes_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log missing terminal sometimes regression";
        needle = "retained_sometimes_without_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal quiescence sometimes guard";
        needle = "sometimes_quiescence_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log blocked terminal sometimes guard";
        needle = "retained_sometimes_with_blocked_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal eventually regression";
        needle = "retained_eventually_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log missing terminal eventually regression";
        needle = "retained_eventually_without_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log blocked terminal eventually guard";
        needle = "retained_eventually_with_blocked_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal quiescence eventually guard";
        needle = "eventually_quiescence_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal eventually trigger guard";
        needle = "eventually_quiescence_trigger_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal reachable regression";
        needle = "retained_reachable_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal reachable warn guard";
        needle = "retained_reachable_warn_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log missing terminal reachable regression";
        needle = "retained_reachable_without_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log blocked terminal reachable guard";
        needle = "retained_reachable_with_blocked_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal quiescence reachable guard";
        needle = "reachable_quiescence_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log guest always marker regression";
        needle = "guest_always_false_oracle";
      }
      {
        label = "search assertion retained-log guest unreachable marker regression";
        needle = "guest_unreachable_true_oracle";
      }
      {
        label = "search assertion retained-log terminal guest sometimes regression";
        needle = "guest_sometimes_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log missing terminal guest sometimes regression";
        needle = "guest_sometimes_without_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log blocked terminal guest sometimes guard";
        needle = "guest_sometimes_with_blocked_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal guest reachable regression";
        needle = "guest_reachable_required_with_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log missing terminal guest reachable regression";
        needle = "guest_reachable_required_without_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log guest reachable kind mismatch guard";
        needle = "guest_reachable_kind_mismatch_oracle";
      }
      {
        label = "search assertion retained-log blocked terminal guest reachable guard";
        needle = "guest_reachable_required_with_blocked_terminal_quiescence_oracle";
      }
      {
        label = "search assertion retained-log terminal guest reachable warn guard";
        needle = "guest_reachable_warn_with_terminal_quiescence_oracle";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI search/fuzz workflow check";
        needle = "cliSearchFuzzWorkflow = import ./phase5-cli-search-fuzz-workflow.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI search/fuzz workflow check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-search-fuzz-workflow";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
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
          name = "run-cli-search-fuzz-workflow";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-search-fuzz-workflow-target" \
              -p crucible-cli \
              cli_search_fuzz \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-search-fuzz-workflow-target" \
              -p crucible-cli \
              cli_exit_machine_readable_search_fuzz_jsonl_reports_final_outcome \
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
            status=partial
            evidence_scope=search-fuzz-model-and-local-double
            component=crucible-cli
            contract=search-fuzz-workflow-progress
            process_search_fuzz=local-double-jsonl-final-outcome
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
