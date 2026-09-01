{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gates.replayOracle",
  taskIds ? ["T-DET-18" "T-DET-21" "T-DET-27" "T-HARN-12" "T-HARN-13" "T-EXEC-4" "T-EXEC-11" "T-PAT-4" "T-TEMP-3" "T-TEMP-4" "T-TEMP-5" "T-TEMP-7" "T-TEMP-9" "T-TEMP-11"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  guestNonModification = import ./phase1-guest-non-modification.nix {inherit pkgs lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  modelCanonical = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  libSource = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible/src/lib.rs)
    (builtins.readFile ../../crates/crucible/src/tests/model_core.rs)
  ];
  cargoManifest = builtins.readFile ../../crates/crucible/Cargo.toml;
  replayGate = builtins.readFile ../../crates/crucible/tests/gate_replay_oracle.rs;
  replayOracleHarness = builtins.readFile ../../crates/crucible-harness/src/replay_oracle.rs;
  qemuRealization = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  executionModel = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;
  patternsAndSketches = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "pure reducer implementation";
        needle = "pub fn reduce(def: &ScenarioDef, schedule: &Schedule) -> Result<State, EngineError>";
      }
      {
        label = "reduce delegates to canonical reduced-state hash";
        needle = "id: canonical::reduced_state_hash(def, schedule)";
      }
      {
        label = "configuration content hash";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "schedule content hash";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "materialized state load validator";
        needle = "fn validate_materialized_state(checkpoint: &Checkpoint) -> Result<(), EngineError>";
      }
      {
        label = "materialized state incomplete error";
        needle = "CheckpointMaterializedStateIncomplete";
      }
      {
        label = "fat checkpoint state id validation";
        needle = "materialized-state-id-mismatch";
      }
      {
        label = "extra VM snapshot rejection";
        needle = "extra-vm-snapshot";
      }
      {
        label = "thin checkpoint source API";
        needle = "pub fn record_thin_checkpoint(";
      }
      {
        label = "materialize checkpoint API";
        needle = "pub fn materialize_checkpoint(";
      }
      {
        label = "hot checkpoint policy API";
        needle = "pub fn materialize_hot_checkpoint(";
      }
      {
        label = "fat eviction API";
        needle = "pub fn evict_fat_checkpoint_to_thin(";
      }
      {
        label = "materialization policy type";
        needle = "pub struct MaterializationPolicy";
      }
      {
        label = "materialization trigger type";
        needle = "pub enum MaterializationTrigger";
      }
      {
        label = "active search replay-oracle sampling config";
        needle = "pub struct SearchReplayOracleSamplingConfig";
      }
      {
        label = "active search replay-oracle sampling report";
        needle = "pub struct SearchReplayOracleSamplingReport";
      }
      {
        label = "active search replay-oracle bisection request";
        needle = "pub struct SearchReplayOracleBisectionRequest";
      }
      {
        label = "hot-node budget rule";
        needle = "trigger.is_hot() && current_fat_checkpoints < self.max_fat_checkpoints";
      }
      {
        label = "thin replay checkpoint validation";
        needle = "validate_loadable_checkpoint(&thin_checkpoint, configuration)?;";
      }
      {
        label = "fat thin node blob comparison";
        needle = "checkpoint.node_blobs != thin_checkpoint.node_blobs";
      }
      {
        label = "fat thin materialized state comparison";
        needle = "fat_state.id != thin_state.id";
      }
      {
        label = "replay-oracle cached snapshot admission";
        needle = "pub fn replay_oracle_admit_cached_snapshot(";
      }
      {
        label = "all cached snapshots replay-oracle invariant";
        needle = "pub fn validate_cached_snapshots_with_replay_oracle(";
      }
      {
        label = "cached snapshot admission evicts rejected fat cache";
        needle = "self.evict_fat_checkpoint_to_thin(configuration)?;";
      }
      {
        label = "cached snapshot admission checks cached ancestors";
        needle = "self.replay_oracle_admit_cached_ancestors(configuration)?;";
      }
      {
        label = "materialize validates replay-oracle path before cached return";
        needle = "self.replay_oracle_admit_cached_snapshot(configuration)?;";
      }
      {
        label = "instantiate validates exact cache before load";
        needle = "graph.replay_checkpoint(config, snapshot)?;";
      }
      {
        label = "graph save operation API";
        needle = "pub fn save<S>(";
      }
      {
        label = "graph resume operation API";
        needle = "pub fn resume(&mut self, tip: &Configuration)";
      }
      {
        label = "graph fork operation API";
        needle = "pub fn fork<I>(";
      }
      {
        label = "graph replay operation API";
        needle = "pub fn replay(&self, configuration: &Configuration)";
      }
      {
        label = "graph search operation API";
        needle = "pub fn search(";
      }
      {
        label = "graph active search replay-oracle API";
        needle = "pub fn search_with_replay_oracle_sampling(";
      }
      {
        label = "graph search samples inline replay oracle";
        needle = "sample_search_replay_oracle_checkpoint(";
      }
      {
        label = "sampled search mismatch error";
        needle = "SearchReplayOracleMismatch";
      }
      {
        label = "search sampling score namespace";
        needle = "crucible.replay-oracle.search-sampling.v1";
      }
      {
        label = "graph replay uses stored fat checkpoint";
        needle = "self.cached_snapshot(configuration).cloned()";
      }
      {
        label = "graph resume records thin closure before instantiate";
        needle = "self.record_checkpoint_closure(tip)?;";
      }
    ]
    ++ failuresFor "crates/crucible/src/model/canonical.rs" modelCanonical [
      {
        label = "reduce state domain separator";
        needle = "crucible.reduce.state.v1";
      }
      {
        label = "scenario identity folded into reduce";
        needle = "write_content_hash(&mut hasher, &def.id());";
      }
      {
        label = "schedule folded into reduce";
        needle = "write_schedule(&mut hasher, schedule);";
      }
      {
        label = "explicit decision encoding";
        needle = "fn write_decision(hasher: &mut MaterialHasher, decision: &Decision)";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "reduce not-implemented placeholder";
        needle = "operation: \"reduce\"";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs and src/tests/model_core.rs" libSource [
      {
        label = "reduce purity test";
        needle = "reduce_is_pure_over_scenario_and_schedule";
      }
      {
        label = "prefix closure test";
        needle = "reduce_is_prefix_closed_by_schedule_hash";
      }
      {
        label = "materialization policy export";
        needle = "MaterializationPolicy";
      }
      {
        label = "materialization trigger export";
        needle = "MaterializationTrigger";
      }
      {
        label = "graph save result export";
        needle = "TemporalGraphSave";
      }
      {
        label = "graph resume result export";
        needle = "TemporalGraphRuntime";
      }
      {
        label = "graph fork result export";
        needle = "TemporalGraphFork";
      }
      {
        label = "graph search result export";
        needle = "TemporalGraphSearch";
      }
      {
        label = "active search replay-oracle sampling config export";
        needle = "SearchReplayOracleSamplingConfig";
      }
      {
        label = "active search replay-oracle sampling report export";
        needle = "SearchReplayOracleSamplingReport";
      }
      {
        label = "thin source-of-truth test";
        needle = "temporal_graph_materialized_cache_keeps_thin_checkpoint_source_of_truth";
      }
      {
        label = "materialized payload drift test";
        needle = "temporal_graph_replay_checkpoint_rejects_materialized_payload_drift";
      }
      {
        label = "fat eviction test";
        needle = "temporal_graph_evicts_fat_checkpoint_back_to_thin_without_state_change";
      }
      {
        label = "hot-node materialization policy test";
        needle = "temporal_graph_materialization_policy_keeps_cold_or_over_budget_nodes_thin";
      }
      {
        label = "cached snapshot replay-oracle rejection test";
        needle = "temporal_graph_replay_oracle_rejects_cached_snapshot_to_thin";
      }
      {
        label = "cached snapshot rejection leaves thin path realizable";
        needle = "thin derivation should remain realizable after rejection";
      }
      {
        label = "public exact-cache load rejects corrupt snapshot";
        needle = "public exact-cache instantiate should reject corrupt fat snapshot";
      }
      {
        label = "whole-cache replay-oracle rejection test";
        needle = "whole-cache replay-oracle validation should reject corrupt cache";
      }
      {
        label = "cached ancestor replay-oracle admission test";
        needle = "temporal_graph_replay_oracle_admits_cached_ancestors_before_target";
      }
      {
        label = "cached ancestor replay-oracle admission failure message";
        needle = "cached target should not validate against an unadmitted corrupt ancestor";
      }
      {
        label = "GC cache collection replay-oracle test";
        needle = "temporal_graph_gc_cache_collection_preserves_replay_oracle_path";
      }
      {
        label = "GC cache collection keeps thin replay valid";
        needle = "fat snapshot should still match thin derivation after GC";
      }
    ]
    ++ failuresFor "crates/crucible/Cargo.toml" cargoManifest [
      {
        label = "replay-oracle dev dependency";
        needle = "crucible-harness = { path = \"../crucible-harness\" }";
      }
      {
        label = "test-double replay oracle target";
        needle = "name = \"gate_replay_oracle\"";
      }
      {
        label = "replay oracle target requires test-double feature";
        needle = "required-features = [\"test-double\"]";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_replay_oracle.rs" replayGate [
      {
        label = "fixed checkpoint corpus";
        needle = "assert_replay_oracle_fixed_checkpoint_corpus(";
      }
      {
        label = "materialized checkpoint descriptor";
        needle = "struct MaterializedCheckpoint";
      }
      {
        label = "test-double fat checkpoint materialization";
        needle = "fn materialize_fat_checkpoint(";
      }
      {
        label = "ancestor schedule delta extraction";
        needle = "fn schedule_delta(";
      }
      {
        label = "thin ancestor replay schedule reconstruction";
        needle = "fn replay_schedule(";
      }
      {
        label = "checkpoint metadata hash";
        needle = "fn test_double_checkpoint_hash(";
      }
      {
        label = "corrupt configuration metadata negative";
        needle = "assert_replay_oracle_rejects_corrupt_configuration_metadata(";
      }
      {
        label = "corrupt schedule delta metadata negative";
        needle = "assert_replay_oracle_rejects_corrupt_schedule_delta_metadata(";
      }
      {
        label = "first mismatch reporting path";
        needle = "assert_replay_oracle_reports_first_mismatch(";
      }
      {
        label = "observational-entry exclusion";
        needle = "assert_replay_oracle_excludes_observational_entries(";
      }
      {
        label = "twice-reduce canonical digest";
        needle = "assert_twice_reduce_canonical_digest(";
      }
      {
        label = "SimDouble test-double marker";
        needle = "SimDouble";
      }
      {
        label = "materialized replay-oracle checker";
        needle = "check_materialized_replay_oracle(&corpus)";
      }
      {
        label = "temporal graph search sampling test";
        needle = "gate_replay_oracle_samples_temporal_graph_search_fat_materializations";
      }
      {
        label = "temporal graph search sampling mismatch test";
        needle = "gate_replay_oracle_search_sampling_mismatch_requests_bisection";
      }
      {
        label = "temporal graph search sampling skip test";
        needle = "gate_replay_oracle_search_sampling_rate_can_skip_materializations";
      }
      {
        label = "active search sampling rate configurable";
        needle = "SearchReplayOracleSamplingConfig::new(1, 1, \"gate-replay-oracle-graph-search\")";
      }
      {
        label = "active search fractional sampling rate";
        needle = "SearchReplayOracleSamplingConfig::new(1, u64::MAX, \"gate-replay-oracle-graph-search-skip\")";
      }
      {
        label = "active search uses sampling API";
        needle = "graph.search_with_replay_oracle_sampling(";
      }
      {
        label = "active search mismatch requests bisection";
        needle = "EngineError::SearchReplayOracleMismatch";
      }
      {
        label = "schedule-order sensitivity";
        needle = "gate_replay_oracle_is_sensitive_to_schedule_order";
      }
      {
        label = "wrong-order oracle failure";
        needle = "wrong-order thin reconstruction should fail the replay oracle";
      }
      {
        label = "reproduction artifact round-trip test";
        needle = "gate_replay_oracle_reproduction_artifact_round_trips";
      }
      {
        label = "reproduction artifact build identity drift test";
        needle = "gate_replay_oracle_reproduction_artifact_rejects_build_identity_drift";
      }
      {
        label = "reproduction artifact schedule drift test";
        needle = "gate_replay_oracle_reproduction_artifact_detects_schedule_drift";
      }
      {
        label = "reproduction artifact seed drift test";
        needle = "gate_replay_oracle_reproduction_artifact_detects_seed_drift";
      }
      {
        label = "reproduction artifact scenario drift test";
        needle = "gate_replay_oracle_reproduction_artifact_detects_scenario_drift";
      }
      {
        label = "reproduction artifact oracle equality test";
        needle = "gate_replay_oracle_reproduction_artifact_detects_oracle_case_drift";
      }
      {
        label = "representative reproduction artifact fixture";
        needle = "fn representative_replay_oracle_reproduction_artifact(";
      }
      {
        label = "replay artifact callback";
        needle = "fn replay_reproduction_artifact(";
      }
      {
        label = "artifact round-trip checker used by gate";
        needle = "check_replay_oracle_reproduction_artifact_round_trip(";
      }
      {
        label = "artifact carries deterministic seed";
        needle = "seed = 0x0010_0027";
      }
      {
        label = "materialized state loadvm sufficiency test";
        needle = "gate_replay_oracle_materialized_state_loadvm_branch_captures_resume_components";
      }
      {
        label = "incomplete materialized state rejection test";
        needle = "gate_replay_oracle_loadvm_rejects_incomplete_materialized_state";
      }
      {
        label = "saved descendant materialized state test";
        needle = "gate_replay_oracle_saved_descendant_fat_checkpoint_carries_vm_snapshot_refs";
      }
      {
        label = "temporal graph user operations instantiate test";
        needle = "gate_replay_oracle_temporal_graph_user_operations_share_instantiate_path";
      }
      {
        label = "resume operation matches instantiate";
        needle = "assert_eq!(resumed.runtime, direct);";
      }
      {
        label = "search operation result matches instantiate";
        needle = "assert_eq!(search_runtime.runtime, search_direct);";
      }
      {
        label = "replay operation rejects thin-only checkpoint";
        needle = "thin-only fork should not replay as a stored fat checkpoint";
      }
      {
        label = "baked VM snapshot icount assertion";
        needle = "assert_eq!(snapshot.icount, Icount { retired: 321 });";
      }
      {
        label = "saved descendant icount assertion";
        needle = "assert_eq!(checkpoint.node_icounts[&node], Icount { retired: 988 });";
      }
      {
        label = "saved descendant CoW assertion";
        needle = "assert!(matches!(snapshot.blob, NodeBlobRef::CowDelta { .. }));";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/gate_replay_oracle.rs" replayGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "direct byte-only corpus check";
        needle = "check_replay_oracle(&corpus)";
      }
      {
        label = "same-schedule fat/thin reducer comparison";
        needle = ".prefix(checkpoint.schedule.len())";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/replay_oracle.rs" replayOracleHarness [
      {
        label = "first mismatch reporting";
        needle = "fn mismatch(checkpoint_id: &str, fat_hash: &[u8], thin_hash: &[u8])";
      }
      {
        label = "fat checkpoint hash field";
        needle = "pub fat_hash: Vec<u8>";
      }
      {
        label = "thin reconstruction hash field";
        needle = "pub thin_hash: Vec<u8>";
      }
      {
        label = "materialized replay-oracle case type";
        needle = "pub struct ReplayOracleMaterializedCase";
      }
      {
        label = "checkpoint kind metadata";
        needle = "pub enum ReplayOracleCheckpointKind";
      }
      {
        label = "materialized checkpoint hash field";
        needle = "pub fat_checkpoint_hash: Vec<u8>";
      }
      {
        label = "materialized configuration metadata field";
        needle = "pub fat_configuration_hash: Vec<u8>";
      }
      {
        label = "materialized ancestor metadata field";
        needle = "pub fat_ancestor_hash: Vec<u8>";
      }
      {
        label = "materialized schedule-delta metadata field";
        needle = "pub fat_schedule_delta_hash: Vec<u8>";
      }
      {
        label = "metadata-validating replay-oracle checker";
        needle = "pub fn check_materialized_replay_oracle(";
      }
      {
        label = "fat checkpoint kind validation";
        needle = "case.kind != ReplayOracleCheckpointKind::Fat";
      }
      {
        label = "reproduction artifact build identity";
        needle = "pub struct ReplayOracleBuildIdentity";
      }
      {
        label = "reproduction artifact run output";
        needle = "pub struct ReplayOracleArtifactRun";
      }
      {
        label = "reproduction artifact type";
        needle = "pub struct ReplayOracleReproductionArtifact<Scenario, Schedule>";
      }
      {
        label = "round-trip report";
        needle = "pub struct ReplayOracleRoundTripReport";
      }
      {
        label = "round-trip error";
        needle = "pub enum ReplayOracleRoundTripError";
      }
      {
        label = "round-trip checker";
        needle = "pub fn check_replay_oracle_reproduction_artifact_round_trip<";
      }
      {
        label = "build identity mismatch rejection";
        needle = "ReplayOracleRoundTripError::BuildIdentityMismatch";
      }
      {
        label = "replay failure rejection";
        needle = "ReplayOracleRoundTripError::ReplayFailed";
      }
      {
        label = "expected oracle mismatch rejection";
        needle = "ReplayOracleRoundTripError::ExpectedOracleMismatch";
      }
      {
        label = "reproduced oracle mismatch rejection";
        needle = "ReplayOracleRoundTripError::ReproducedOracleMismatch";
      }
      {
        label = "fingerprint mismatch rejection";
        needle = "ReplayOracleRoundTripError::FingerprintMismatch";
      }
      {
        label = "oracle case mismatch rejection";
        needle = "ReplayOracleRoundTripError::OracleCaseMismatch";
      }
      {
        label = "search sampling config";
        needle = "pub struct ReplayOracleSamplingConfig";
      }
      {
        label = "search materialization record";
        needle = "pub struct ReplayOracleSearchMaterialization";
      }
      {
        label = "search sampling report";
        needle = "pub struct ReplayOracleSearchSamplingReport";
      }
      {
        label = "search sampling error";
        needle = "pub enum ReplayOracleSearchSamplingError";
      }
      {
        label = "search sampling checker";
        needle = "pub fn check_sampled_search_replay_oracle(";
      }
      {
        label = "search sampling bisection checker";
        needle = "pub fn check_sampled_search_replay_oracle_with_bisection";
      }
      {
        label = "search sampling score namespace";
        needle = "crucible.replay-oracle.search-sampling.v1";
      }
      {
        label = "replay failure unit test";
        needle = "reproduction_artifact_round_trip_reports_replay_failure";
      }
      {
        label = "expected oracle mismatch unit test";
        needle = "reproduction_artifact_round_trip_rejects_inconsistent_expected_oracle";
      }
      {
        label = "reproduced oracle mismatch unit test";
        needle = "reproduction_artifact_round_trip_rejects_inconsistent_reproduced_oracle";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" qemuRealization [
      {
        label = "QEMU replay-oracle checker";
        needle = "pub fn check_qemu_replay_oracle(";
      }
      {
        label = "loadvm probe executor hook";
        needle = "load_exact_snapshot_for_replay_oracle_probe";
      }
      {
        label = "QEMU loadvm materialized-state validator";
        needle = "fn validate_checkpoint_loadvm_state(";
      }
      {
        label = "QEMU materialized state id validation";
        needle = "materialized state id does not match its components";
      }
      {
        label = "QEMU rejects incomplete exact snapshot state";
        needle = "qemu_exact_snapshot_rejects_incomplete_materialized_state";
      }
      {
        label = "QEMU rejects incomplete replay-oracle probe state";
        needle = "qemu_replay_oracle_rejects_incomplete_materialized_state_probe";
      }
      {
        label = "thin replay derivation";
        needle = "fn realize_qemu_replay_oracle_thin_path(";
      }
      {
        label = "probe-only loadvm authorization";
        needle = "policy.authorize_loadvm_probe()";
      }
      {
        label = "replay-oracle match result";
        needle = "QemuReplayOracleValidation::Match";
      }
      {
        label = "replay-oracle mismatch result";
        needle = "QemuReplayOracleValidation::Mismatch";
      }
      {
        label = "QEMU replay-oracle match test";
        needle = "qemu_replay_oracle_matches_loadvm_snapshot_to_replay_from_ancestor";
      }
      {
        label = "QEMU replay-oracle mismatch test";
        needle = "qemu_replay_oracle_reports_loadvm_replay_mismatch";
      }
      {
        label = "replay-oracle probe purpose";
        needle = "QemuLoadvmCommandPurpose::ReplayOracleProbe";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "QEMU replay-oracle checker exported";
        needle = "check_qemu_replay_oracle";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "implemented replay-oracle target";
        needle = "gate: \"gate:replay-oracle\",\n        package: \"crucible\",\n        test_target: \"gate_replay_oracle\",\n        required_features: &[\"test-double\"],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "implemented replay-oracle catalog status";
        needle = "name: \"gate:replay-oracle\",\n        phase: GatePhase::Phase1,\n        owner: \"crucible\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "replay oracle implemented status assertion";
        needle = "find_gate(\"gate:replay-oracle\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "implemented replay-oracle mapping target";
        needle = "gate = \"gate:replay-oracle\";\n      package = \"crucible\";\n      testTarget = \"gate_replay_oracle\";\n      requiredFeatures = [\"test-double\"];\n      placeholder = false;";
      }
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=0";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes replay-oracle gate";
        needle = "replayOracle = import ./phase1-replay-oracle.nix";
      }
      {
        label = "phase1 replay-oracle attr path";
        needle = "attrPath = \"checks.crucible.phase1.gates.replayOracle\"";
      }
      {
        label = "phase1 replay-oracle lists T-DET-18";
        needle = "\"T-DET-18\"";
      }
      {
        label = "phase1 replay-oracle lists T-DET-21";
        needle = "\"T-DET-21\"";
      }
      {
        label = "phase1 replay-oracle lists T-DET-27";
        needle = "\"T-DET-27\"";
      }
      {
        label = "phase1 replay-oracle lists T-HARN-12";
        needle = "\"T-HARN-12\"";
      }
      {
        label = "phase1 replay-oracle lists T-HARN-13";
        needle = "\"T-HARN-13\"";
      }
      {
        label = "phase1 replay-oracle lists T-EXEC-4";
        needle = "\"T-EXEC-4\"";
      }
      {
        label = "phase1 replay-oracle lists T-EXEC-11";
        needle = "\"T-EXEC-11\"";
      }
      {
        label = "phase1 replay-oracle lists T-PAT-4";
        needle = "\"T-PAT-4\"";
      }
      {
        label = "phase1 replay-oracle lists T-TEMP-3";
        needle = "\"T-TEMP-3\"";
      }
      {
        label = "phase1 replay-oracle lists T-TEMP-4";
        needle = "\"T-TEMP-4\"";
      }
      {
        label = "phase1 replay-oracle lists T-TEMP-5";
        needle = "\"T-TEMP-5\"";
      }
      {
        label = "phase1 replay-oracle lists T-TEMP-9";
        needle = "\"T-TEMP-9\"";
      }
      {
        label = "phase1 replay-oracle lists T-TEMP-11";
        needle = "\"T-TEMP-11\"";
      }
    ]
    ++ forbiddenFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase6 still marks T-HARN-13 pending";
        needle = "taskIds = [\"T-HARN-12\" \"T-HARN-13\"];\n        reason = \"search-time replay oracle gate is intentionally pending\";";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-13 completion names sampling config";
        needle = "`ReplayOracleSamplingConfig`";
      }
      {
        label = "T-HARN-13 completion names active search config";
        needle = "`SearchReplayOracleSamplingConfig`";
      }
      {
        label = "T-HARN-13 completion names active search API";
        needle = "`TemporalGraph::search_with_replay_oracle_sampling`";
      }
      {
        label = "T-HARN-13 completion names sampled mismatch error";
        needle = "`EngineError::SearchReplayOracleMismatch`";
      }
      {
        label = "T-HARN-13 completion names sampling checker";
        needle = "`check_sampled_search_replay_oracle`";
      }
      {
        label = "T-HARN-13 completion names bisection checker";
        needle = "`check_sampled_search_replay_oracle_with_bisection`";
      }
      {
        label = "T-HARN-13 completion names replay-oracle gate";
        needle = "`checks.crucible.phase1.gates.replayOracle`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsAndSketches [
      {
        label = "T-PAT-4 completion names materialization policy";
        needle = "`crucible::MaterializationPolicy`";
      }
      {
        label = "T-PAT-4 completion names fat eviction";
        needle = "`TemporalGraph::evict_fat_checkpoint_to_thin`";
      }
      {
        label = "T-PAT-4 completion says materialization is cache policy";
        needle = "materialization a cache policy rather than identity";
      }
      {
        label = "T-PAT-4 completion names replay-oracle gate";
        needle = "`checks.crucible.phase1.gates.replayOracle`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" executionModel [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/07-temporal-graph.md" (builtins.readFile ../../docs/rfcs/0010-crucible/07-temporal-graph.md) [
      {
        label = "T-TEMP-3 completion names replay-oracle gate";
        needle = "`checks.crucible.phase1.gates.replayOracle`";
      }
      {
        label = "T-TEMP-4 completion names materialization policy";
        needle = "`crucible::MaterializationPolicy`";
      }
      {
        label = "T-TEMP-4 completion names eviction API";
        needle = "`evict_fat_checkpoint_to_thin`";
      }
      {
        label = "T-TEMP-7 names cached snapshot admission";
        needle = "`TemporalGraph::replay_oracle_admit_cached_snapshot`";
      }
      {
        label = "T-TEMP-7 names whole-cache invariant";
        needle = "`TemporalGraph::validate_cached_snapshots_with_replay_oracle`";
      }
      {
        label = "T-TEMP-9 completion names replay-oracle gate";
        needle = "`checks.crucible.phase1.gates.replayOracle`";
      }
      {
        label = "T-TEMP-11 completion names replay operation";
        needle = "`TemporalGraph::replay`";
      }
      {
        label = "T-TEMP-11 completion names search operation";
        needle = "`TemporalGraph::search`";
      }
      {
        label = "T-TEMP-11 completion names replay-oracle gate";
        needle = "`checks.crucible.phase1.gates.replayOracle`";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 replay-oracle gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-replay-oracle";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.grep
          pkgs.rust
          pkgs.sed
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
          name = "run-replay-oracle";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-replay-oracle-target" \
              -p crucible \
              --lib \
              temporal_graph_ \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-replay-oracle-target" \
              -p crucible \
              --features test-double \
              --test gate_replay_oracle \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-replay-oracle-target" \
              -p crucible-harness \
              --lib \
              replay_oracle \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-replay-oracle-target" \
              -p crucible-qemu \
              --lib \
              replay_oracle \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-replay-oracle-target" \
              -p crucible-qemu \
              --lib \
              qemu_exact_snapshot_rejects_incomplete_materialized_state \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"

            require_line() {
              result="$1/result"
              line="$2"
              grep -Fxq "$line" "$result" || {
                echo "dependency missing evidence: $line" >&2
                cat "$result" >&2
                exit 1
              }
            }

            require_leaf() {
              dependency="$1"
              shift
              require_line "$dependency" "PASS"
              for line in "$@"; do
                require_line "$dependency" "$line"
              done
            }

            require_leaf ${guestNonModification} \
              "gate=gate:replay-oracle" \
              "required_gates=gate:any-guest,gate:replay-oracle" \
              "tasks=T-DET-21" \
              "guest_writes=copy-on-write-overlay" \
              "guest_backing_state=byte-identical-genesis" \
              "guest_on_disk_mutation_policy=forbidden-by-launch-profile" \
              "guest_core_content=host-side-only"

            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            gate=gate:replay-oracle
            tasks=${builtins.concatStringsSep "," taskIds}
            rust_test=crucible::gate_replay_oracle
            harness_rust_test=crucible-harness::replay_oracle
            qemu_rust_test=crucible-qemu::realization::replay_oracle
            oracle=fat-materialized-equals-thin-from-ancestor
            qemu_oracle=loadvm-snapshot-equals-replay-from-ancestor
            qemu_oracle_probe_authorization=snapshot-completeness
            loadvm_materialized_state=vm-snapshot-icount,scheduler,decision-rng,event-log
            loadvm_incomplete_state=rejected
            loadvm_saved_descendant_state=target-cow-vm-snapshot-ref-and-icount
            thin_source_of_truth=checkpoint-node-state-none
            fat_cache_policy=hot-nodes-budgeted
            fat_eviction=ancestor-replay-preserves-state
            exact_checkpoint_policy=identity-bound-qemu-vmstate-and-host-io
            incomplete_checkpoint_policy=rejected
            replay_oracle_cached_admission=corrupt-fat-cache-evicted-to-thin
            replay_oracle_structural_invariant=all-cached-fat-snapshots
            gc_cache_collection=thin-replay-oracle-preserved
            graph_user_operations=save,resume,fork,replay,search
            graph_operation_realization=instantiate
            pattern_PAT_6_replay_oracle=fat-cache-thin-source-of-truth
            search_oracle_sampling=temporal-graph-fat-materializations
            search_oracle_sampling_rate=configurable
            search_oracle_mismatch=bisection-request
            artifact_round_trip=re-run-from-seed-scenario-schedule-build-identity
            artifact_replay_assertions=fingerprint-equality,oracle-case-equality
            artifact_replay_negative_controls=build-identity-drift,seed-drift,scenario-drift,schedule-drift,oracle-case-drift,replay-failure,expected-oracle-mismatch,reproduced-oracle-mismatch
            corpus=fixed-checkpoints
            guest_non_modification=launch-contract-gate
            required_guest_non_modification_gates=gate:any-guest,gate:replay-oracle
            guest_writes=copy-on-write-overlay
            guest_backing_state=byte-identical-genesis
            guest_on_disk_mutation_policy=forbidden-by-launch-profile
            guest_core_content=host-side-only
            RESULT
          '';
        }
      ];
    }
