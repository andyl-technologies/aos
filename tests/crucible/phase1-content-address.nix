{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gates.contentAddress",
  taskIds ? ["T-ASRT-17" "T-HARN-11" "T-PAT-4" "T-TEMP-1" "T-TEMP-2" "T-TEMP-3" "T-TEMP-6" "T-TEMP-8" "T-TEMP-9" "T-TEMP-10" "T-TEMP-11"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };
  model = import ./_crucible-model-source.nix {inherit lib;};
  modelCanonical = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  simLib = builtins.readFile ../../crates/crucible-sim/src/lib.rs;
  crucibleGate = builtins.readFile ../../crates/crucible/tests/gate_content_address.rs;
  predicateDsl = builtins.readFile ../../crates/crucible/tests/predicate_dsl.rs;
  simGate = builtins.readFile ../../crates/crucible-sim/tests/gate_content_address.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  temporalGraph = builtins.readFile ../../docs/rfcs/0010-crucible/07-temporal-graph.md;
  patternsAndSketches = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;

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

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "scenario canonical material entry point";
        needle = "pub fn from_canonical_material(domain: &str, material: &str) -> Self";
      }
      {
        label = "raw byte BLAKE3 DAG store key";
        needle = "pub fn from_bytes(bytes: &[u8]) -> Self";
      }
      {
        label = "content hash hex rendering";
        needle = "pub fn to_hex(self) -> String";
      }
      {
        label = "fault-active predicate leaf";
        needle = "FaultActive {";
      }
      {
        label = "plan-aware assertion DSL constructor";
        needle = "pub fn from_assertions_for_world_and_plan(";
      }
      {
        label = "plan-aware canonical TOML DSL constructor";
        needle = "pub fn from_canonical_toml_for_world_and_plan(";
      }
      {
        label = "predicate DSL resolver";
        needle = "fn resolve_named_predicate_dsl_for_context(";
      }
      {
        label = "TOML string predicate DSL parsing";
        needle = "PredicateToml::Dsl(name)";
      }
      {
        label = "unknown named predicates remain additive";
        needle = ".unwrap_or_else(|| predicate.clone())";
      }
      {
        label = "DAG store trait";
        needle = "pub trait DagStore: Send + Sync";
      }
      {
        label = "DAG store put";
        needle = "fn put(&self, bytes: &[u8]) -> Result<ContentHash, DagStoreError>;";
      }
      {
        label = "DAG store get";
        needle = "fn get(&self, key: &ContentHash) -> Result<Vec<u8>, DagStoreError>;";
      }
      {
        label = "DAG store exists";
        needle = "fn exists(&self, key: &ContentHash) -> Result<bool, DagStoreError>;";
      }
      {
        label = "DAG store delete";
        needle = "fn delete(&self, key: &ContentHash) -> Result<bool, DagStoreError>;";
      }
      {
        label = "memory DAG store backend";
        needle = "pub struct MemoryDagStore";
      }
      {
        label = "filesystem DAG store backend";
        needle = "pub struct LocalDagStore";
      }
      {
        label = "two-level object path API";
        needle = "pub fn object_path(&self, key: &ContentHash) -> PathBuf";
      }
      {
        label = "two-level object path implementation";
        needle = "self.root.join(&hex[0..2]).join(hex)";
      }
      {
        label = "store-key reproduction artifact";
        needle = "pub struct DagStoreReproductionArtifact";
      }
      {
        label = "store-key artifact closure";
        needle = "pub fn store_keys(&self) -> BTreeSet<ContentHash>";
      }
      {
        label = "temporal graph store key report";
        needle = "pub struct TemporalGraphStoreKeys";
      }
      {
        label = "temporal graph cached snapshot store keys";
        needle = "pub cached_snapshots: BTreeMap<ContentHash, ContentHash>";
      }
      {
        label = "temporal graph store persistence error";
        needle = "pub enum TemporalGraphStoreError";
      }
      {
        label = "temporal graph GC roots";
        needle = "pub struct TemporalGraphGcRoots";
      }
      {
        label = "temporal graph GC live tips";
        needle = "pub live_tips: BTreeMap<ContentHash, usize>";
      }
      {
        label = "temporal graph GC pinned checkpoints";
        needle = "pub pinned_checkpoints: BTreeMap<ContentHash, usize>";
      }
      {
        label = "temporal graph GC reference counts";
        needle = "pub struct TemporalGraphReferenceCounts";
      }
      {
        label = "temporal graph GC report";
        needle = "pub struct TemporalGraphGcReport";
      }
      {
        label = "temporal graph DagStore persistence API";
        needle = "pub fn persist_checkpoint_closure<S>";
      }
      {
        label = "temporal graph reference counting API";
        needle = "pub fn reference_counts(";
      }
      {
        label = "temporal graph mark-and-sweep API";
        needle = "pub fn garbage_collect(";
      }
      {
        label = "temporal graph store-backed GC API";
        needle = "pub fn garbage_collect_store<S>";
      }
      {
        label = "temporal graph cache collection API";
        needle = "pub fn collect_cached_snapshot(";
      }
      {
        label = "temporal graph store-backed cache collection API";
        needle = "pub fn collect_cached_snapshot_store<S>";
      }
      {
        label = "temporal graph GC mark helper";
        needle = "fn mark_live_checkpoints(";
      }
      {
        label = "temporal graph GC checkpoint sweep";
        needle = "self.checkpoint_nodes";
      }
      {
        label = "temporal graph GC cache sweep";
        needle = "self.cached_snapshots";
      }
      {
        label = "temporal graph GC store-key delete";
        needle = "operation: \"delete-gc-object\"";
      }
      {
        label = "temporal graph cached snapshot store operation";
        needle = "put-cached-snapshot";
      }
      {
        label = "temporal graph CoW persistence helper";
        needle = "fn persist_checkpoint_cow_deltas<S>";
      }
      {
        label = "temporal graph checkpoint node store bytes";
        needle = "fn checkpoint_store_bytes(checkpoint: &Checkpoint) -> Vec<u8>";
      }
      {
        label = "temporal graph schedule delta store bytes";
        needle = "fn schedule_delta_store_bytes(schedule: &Schedule) -> Vec<u8>";
      }
      {
        label = "temporal graph CoW delta store bytes";
        needle = "fn cow_delta_store_bytes(cow_ref: CowDeltaRef) -> Vec<u8>";
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
        label = "checkpoint type";
        needle = "pub struct Checkpoint";
      }
      {
        label = "checkpoint scenario ref";
        needle = "pub scenario_ref: ContentHash";
      }
      {
        label = "checkpoint parent";
        needle = "pub parent: Option<ContentHash>";
      }
      {
        label = "checkpoint schedule delta";
        needle = "pub schedule_delta: Schedule";
      }
      {
        label = "checkpoint virtual time";
        needle = "pub virtual_time: VirtualTime";
      }
      {
        label = "checkpoint per-node icount";
        needle = "pub node_icounts: BTreeMap<NodeId, Icount>";
      }
      {
        label = "checkpoint optional state";
        needle = "pub state: Option<MaterializedState>";
      }
      {
        label = "checkpoint coverage fingerprint";
        needle = "pub coverage_fingerprint: ContentHash";
      }
      {
        label = "checkpoint metadata";
        needle = "pub metadata: CheckpointMeta";
      }
      {
        label = "recorded configuration constructor";
        needle = "pub fn from_recorded_configuration(";
      }
      {
        label = "recorded constructor validates edge";
        needle = ") -> Result<Self, EngineError>";
      }
      {
        label = "checkpoint topology error";
        needle = "CheckpointTopologyMismatch";
      }
      {
        label = "checkpoint identity error";
        needle = "CheckpointIdentityMismatch";
      }
      {
        label = "checkpoint edge validator";
        needle = "fn checkpoint_edge(";
      }
      {
        label = "checkpoint DAG nodes";
        needle = "checkpoint_nodes: BTreeMap<ContentHash, Checkpoint>";
      }
      {
        label = "record step closure";
        needle = "pub fn record_step(";
      }
      {
        label = "parent-chain traversal";
        needle = "pub fn checkpoint_parent_chain(";
      }
      {
        label = "frontier uses checkpoint closure";
        needle = "self.record_checkpoint_closure(frontier)?;";
      }
      {
        label = "checkpoint node dedup count";
        needle = "pub fn checkpoint_node_count(&self) -> usize";
      }
      {
        label = "materialized state VM snapshots";
        needle = "pub vm_snapshots: BTreeMap<NodeId, VmSnapshotRef>";
      }
      {
        label = "materialized state device overlays";
        needle = "pub device_overlays: BTreeMap<DeviceId, DeviceOverlayDelta>";
      }
      {
        label = "materialized state scheduler";
        needle = "pub scheduler: SchedulerState";
      }
      {
        label = "materialized state decision RNG";
        needle = "pub decision_rng: DecisionRngState";
      }
      {
        label = "materialized state event log";
        needle = "pub event_log: EventLogOffset";
      }
      {
        label = "event log appended segment field";
        needle = "pub appended_segment: Option<ContentHash>";
      }
      {
        label = "event log appended segment constructor";
        needle = "pub fn with_appended_segment(";
      }
      {
        label = "materialized state component constructor";
        needle = "pub fn from_components(";
      }
      {
        label = "CoW delta kind";
        needle = "pub enum CowDeltaKind";
      }
      {
        label = "CoW delta ref";
        needle = "pub struct CowDeltaRef";
      }
      {
        label = "CoW sharing stats";
        needle = "pub struct CowSharingStats";
      }
      {
        label = "node blob CoW delta ref";
        needle = "pub fn cow_delta_ref(&self) -> Option<CowDeltaRef>";
      }
      {
        label = "device overlay CoW delta ref";
        needle = "pub fn cow_delta_ref(&self) -> CowDeltaRef";
      }
      {
        label = "checkpoint CoW delta refs";
        needle = "pub fn cow_delta_refs(&self) -> Vec<CowDeltaRef>";
      }
      {
        label = "temporal graph CoW stats";
        needle = "pub fn cow_sharing_stats(&self) -> CowSharingStats";
      }
      {
        label = "marginal fork CoW cost";
        needle = "pub fn marginal_fork_cow_delta_objects(&self, checkpoint: &Checkpoint) -> usize";
      }
      {
        label = "CoW refs are deduped by typed content hash";
        needle = "unique_refs.insert(cow_ref);";
      }
      {
        label = "frontier reduction policy";
        needle = "pub struct FrontierReductionPolicy";
      }
      {
        label = "frontier reduction report";
        needle = "pub struct FrontierReductionReport";
      }
      {
        label = "frontier covered child";
        needle = "pub struct FrontierCoveredChild";
      }
      {
        label = "symmetry reduction key";
        needle = "pub struct SymmetryReductionKey";
      }
      {
        label = "symmetry class id";
        needle = "pub struct SymmetryClassId";
      }
      {
        label = "symmetry class map";
        needle = "pub struct SymmetryReductionClasses";
      }
      {
        label = "partial-order reduction key";
        needle = "pub struct PartialOrderReductionKey";
      }
      {
        label = "partial-order independence proof";
        needle = "pub struct PartialOrderIndependenceProof";
      }
      {
        label = "partial-order proof policy";
        needle = "pub struct PartialOrderReductionPolicy";
      }
      {
        label = "decision touched-node classifier";
        needle = "pub fn touched_nodes(&self) -> Option<BTreeSet<NodeId>>";
      }
      {
        label = "proof-carrying decision independence";
        needle = "pub fn is_independent_from(&self, other: &Self, policy: &PartialOrderReductionPolicy) -> bool";
      }
      {
        label = "deterministic POR order key";
        needle = "pub fn reduction_order_key(&self) -> ContentHash";
      }
      {
        label = "reduced frontier enumeration API";
        needle = "pub fn enumerate_frontier_reduced<I>";
      }
      {
        label = "checkpoint symmetry key API";
        needle = "classes: &SymmetryReductionClasses,\n    ) -> Option<SymmetryReductionKey>";
      }
      {
        label = "graph symmetry key API";
        needle = "configuration: &Configuration,\n        classes: &SymmetryReductionClasses,";
      }
      {
        label = "POR cover helper";
        needle = "fn partial_order_cover(";
      }
      {
        label = "symmetry key helper";
        needle = "fn checkpoint_symmetry_reduction_key(\n    checkpoint: &Checkpoint,\n    classes: &SymmetryReductionClasses,";
      }
      {
        label = "symmetry refuses default coverage";
        needle = "checkpoint.coverage_fingerprint == ContentHash::default()";
      }
      {
        label = "symmetry requires explicit classes";
        needle = "classes.is_empty()";
      }
      {
        label = "symmetry requires loadable state";
        needle = "let state = checkpoint.state.as_ref()?;";
      }
      {
        label = "symmetry canonicalizes materialized state";
        needle = "fn push_symmetry_materialized_state_lines(";
      }
      {
        label = "symmetry rejects ambiguous relabeling";
        needle = "if pair[0].0 == pair[1].0";
      }
      {
        label = "POR requires explicit proof";
        needle = "policy.proves_independent(left, right)";
      }
      {
        label = "POR representative recorded on demand";
        needle = "graph.record_checkpoint_closure(&representative)?;";
      }
      {
        label = "POR proof insertion API";
        needle = "pub fn with_independent_pair(mut self, left: &Decision, right: &Decision) -> Self";
      }
      {
        label = "POR domain separator";
        needle = "crucible.model.partial-order-reduction.v1";
      }
      {
        label = "symmetry domain separator";
        needle = "crucible.model.symmetry-reduction.v1";
      }
      {
        label = "graph save operation result";
        needle = "pub struct TemporalGraphSave";
      }
      {
        label = "graph resume operation result";
        needle = "pub struct TemporalGraphRuntime";
      }
      {
        label = "graph fork operation result";
        needle = "pub struct TemporalGraphFork";
      }
      {
        label = "graph search operation result";
        needle = "pub struct TemporalGraphSearch";
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
        label = "graph save persists closure through store";
        needle = "self.persist_checkpoint_closure(store, configuration)?;";
      }
      {
        label = "graph save reports save checkpoint engine operation";
        needle = "operation: \"save-checkpoint\"";
      }
    ]
    ++ failuresFor "crates/crucible/src/model/canonical.rs" modelCanonical [
      {
        label = "content hash domain separator";
        needle = "crucible.content-hash.v1";
      }
      {
        label = "configuration hash domain separator";
        needle = "crucible.configuration.v1";
      }
      {
        label = "schedule hash domain separator";
        needle = "crucible.schedule.v1";
      }
      {
        label = "explicit schedule decision encoding";
        needle = "fn write_decision(hasher: &mut MaterialHasher, decision: &Decision)";
      }
      {
        label = "materialized state domain separator";
        needle = "crucible.materialized-state.v1";
      }
      {
        label = "materialized state VM snapshot hashing";
        needle = "fn write_vm_snapshots(";
      }
      {
        label = "materialized state device overlay hashing";
        needle = "fn write_device_overlays(";
      }
      {
        label = "materialized state scheduler hashing";
        needle = "fn write_scheduler_state(";
      }
      {
        label = "materialized state event-log hashing";
        needle = "fn write_event_log_offset(";
      }
      {
        label = "event-log appended segment hashing";
        needle = "offset.appended_segment";
      }
    ]
    ++ failuresFor "crates/crucible-sim/src/lib.rs" simLib [
      {
        label = "stable hashing primitive";
        needle = "pub struct StableHasher";
      }
      {
        label = "canonical stable digest bytes";
        needle = "pub bytes: [u8; 32]";
      }
      {
        label = "content-addressing seam";
        needle = "FUTURE_RATCHET_INTEGRATION_SEAM";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "fault-active condition evaluation";
        needle = "Condition::FaultActive { tag } => fault_tag_is_active(evaluator.fault_facts(), tag)";
      }
      {
        label = "fault facts observation";
        needle = "fn fault_tag_is_active(facts: &[ObservedFaultFact], expected_tag: &FaultTag) -> bool";
      }
      {
        label = "fault-active graph validation";
        needle = "UnknownFaultTagReference";
      }
    ]
    ++ failuresFor "crates/crucible/tests/predicate_dsl.rs" predicateDsl [
      {
        label = "T-ASRT-17 regression module";
        needle = "Checks T-ASRT-17 predicate DSL desugaring.";
      }
      {
        label = "properties desugar to concrete identity";
        needle = "predicate_dsl_desugars_to_concrete_conditions_for_properties";
      }
      {
        label = "DSL hashes as expanded condition tree";
        needle = "DSL properties must hash as the concrete expanded condition tree";
      }
      {
        label = "string-authored properties TOML";
        needle = "predicate = \"no_active_faults\"";
      }
      {
        label = "string-authored trigger TOML";
        needle = "trigger = \"quiescent\"";
      }
      {
        label = "fault-active leaf coverage";
        needle = "Predicate::fault_active(tag(\"split\"))";
      }
      {
        label = "recorded fault facts coverage";
        needle = "fault_active_condition_uses_recorded_fault_facts";
      }
      {
        label = "host predicate additivity";
        needle = "uncovered predicates remain host-extensible";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_content_address.rs" crucibleGate [
      {
        label = "fixed vector coverage";
        needle = "gate_content_address_keeps_fixed_vectors_stable";
      }
      {
        label = "equal content coverage";
        needle = "gate_content_address_hashes_equal_content_to_equal_ids";
      }
      {
        label = "single-byte mutation coverage";
        needle = "gate_content_address_changes_on_single_byte_mutations";
      }
      {
        label = "schedule order sensitivity";
        needle = "gate_content_address_is_sensitive_to_schedule_order";
      }
      {
        label = "materialization cache exclusion";
        needle = "gate_content_address_excludes_materialization_cache_from_identity";
      }
      {
        label = "checkpoint identity corpus";
        needle = "gate_content_address_checkpoint_identity_matches_configuration_id";
      }
      {
        label = "checkpoint id equals configuration id";
        needle = "assert_eq!(checkpoint.id, configuration.id());";
      }
      {
        label = "materialized state does not affect checkpoint id";
        needle = "assert_eq!(materialized.id, checkpoint.id);";
      }
      {
        label = "coverage fingerprint does not affect checkpoint id";
        needle = "assert_eq!(covered.id, checkpoint.id);";
      }
      {
        label = "metadata does not affect checkpoint id";
        needle = "assert_eq!(annotated.id, checkpoint.id);";
      }
      {
        label = "malformed parent edge rejection";
        needle = "gate_content_address_checkpoint_rejects_malformed_parent_edges";
      }
      {
        label = "corrupt checkpoint cache topology rejection";
        needle = "gate_content_address_rejects_corrupt_checkpoint_cache_topology";
      }
      {
        label = "temporal graph closure test";
        needle = "gate_content_address_temporal_graph_records_step_closure_and_parent_chain";
      }
      {
        label = "temporal graph frontier checkpoint DAG test";
        needle = "gate_content_address_temporal_graph_frontier_records_checkpoint_dag_children";
      }
      {
        label = "parent chain exact baked root assertion";
        needle = "assert_eq!(chain[0], root_checkpoint);";
      }
      {
        label = "duplicate step dedup assertion";
        needle = "assert_eq!(duplicate_first.id, first_checkpoint.id);";
      }
      {
        label = "parent-chain schedule reconstruction";
        needle = "assert_eq!(reconstructed, second_config.schedule);";
      }
      {
        label = "materialized state component hash test";
        needle = "gate_content_address_materialized_state_hashes_loadvm_components";
      }
      {
        label = "materialized state icount sensitivity";
        needle = "assert_ne!(state.id, changed.id);";
      }
      {
        label = "CoW sharing sibling fork test";
        needle = "gate_content_address_cow_sharing_dedups_identical_fork_deltas";
      }
      {
        label = "CoW marginal fork assertion";
        needle = "graph.marginal_fork_cow_delta_objects(&second_checkpoint)";
      }
      {
        label = "CoW test separates log prefix from segment";
        needle = "shared_log_prefix";
      }
      {
        label = "CoW test uses explicit appended segment";
        needle = "EventLogOffset::with_appended_segment(log_prefix, 96, 3, log_segment)";
      }
      {
        label = "CoW unique object accounting";
        needle = "assert_eq!(stats.unique_objects, 5);";
      }
      {
        label = "DAG store put get exists test";
        needle = "gate_content_address_dag_store_put_get_exists_dedups_equal_bytes";
      }
      {
        label = "DAG store fixed BLAKE3 vector";
        needle = "ccd5518b5e42662190b09ab692a0d86827cea51e1c2e782cabe9474e575a0ee3";
      }
      {
        label = "DAG store delete assertion";
        needle = "stored object delete should succeed";
      }
      {
        label = "local DAG store two-level layout test";
        needle = "gate_content_address_local_dag_store_uses_two_level_layout";
      }
      {
        label = "local DAG store fanout assertion";
        needle = "root.join(&hex[0..2]).join(&hex)";
      }
      {
        label = "local DAG store corruption repair test";
        needle = "gate_content_address_local_dag_store_repairs_corrupt_object_path";
      }
      {
        label = "local DAG store corruption mismatch assertion";
        needle = "Err(DagStoreError::ContentMismatch { expected, .. }) if expected == key";
      }
      {
        label = "DAG store reproduction artifact test";
        needle = "gate_content_address_reproduction_artifact_is_store_key_closure";
      }
      {
        label = "DAG store artifact dedup assertion";
        needle = "BTreeSet::from([scenario_key, genesis_key, first_delta])";
      }
      {
        label = "temporal graph DagStore persistence test";
        needle = "gate_content_address_temporal_graph_persists_checkpoint_closure_in_dag_store";
      }
      {
        label = "temporal graph persistence API exercised";
        needle = "persist_checkpoint_closure(&store, &first)";
      }
      {
        label = "temporal graph persisted checkpoint nodes";
        needle = "first_keys.checkpoint_nodes.len(), 2";
      }
      {
        label = "temporal graph persisted cached snapshots";
        needle = "first_keys.cached_snapshots.len(), 1";
      }
      {
        label = "temporal graph persisted schedule delta CoW ref";
        needle = "first_keys.cow_deltas[&schedule_ref]";
      }
      {
        label = "temporal graph persisted VM CoW ref";
        needle = "first_keys.cow_deltas.contains_key(&vm_ref)";
      }
      {
        label = "temporal graph persisted device CoW ref";
        needle = "first_keys.cow_deltas.contains_key(&overlay_ref)";
      }
      {
        label = "temporal graph persisted log CoW ref";
        needle = "first_keys.cow_deltas.contains_key(&log_ref)";
      }
      {
        label = "GC refcount abandoned branch test";
        needle = "gate_content_address_gc_refcounts_abandoned_branch_unique_objects";
      }
      {
        label = "GC shared CoW refcount assertion";
        needle = "assert_eq!(counts.cow_deltas[&shared_vm_ref], 2);";
      }
      {
        label = "GC shared CoW retained after sibling abandon";
        needle = "assert!(!report.collectible_cow_deltas.contains(&shared_vm_ref));";
      }
      {
        label = "GC store-backed API exercised";
        needle = "garbage_collect_store(&store";
      }
      {
        label = "GC deleted store keys assertion";
        needle = "report.deleted_store_keys.contains(&left_overlay_store_key)";
      }
      {
        label = "GC missing store keys assertion";
        needle = "assert!(report.missing_store_keys.is_empty());";
      }
      {
        label = "GC mark sweep roots and pins test";
        needle = "gate_content_address_gc_mark_sweep_roots_live_tips_pins_and_genesis";
      }
      {
        label = "GC pinned root API exercised";
        needle = "with_pinned_checkpoint(second.id())";
      }
      {
        label = "GC pinned checkpoint remains realizable";
        needle = "pinned checkpoint should remain realizable";
      }
      {
        label = "GC counted root refs assertion";
        needle = "report.live_reference_counts.checkpoint_nodes[&second.id()]";
      }
      {
        label = "GC counted root refs expected value";
        needle = "        2\n    );";
      }
      {
        label = "GC zero-count roots are ignored";
        needle = "roots.live_tips.insert(abandoned.id(), 0);";
      }
      {
        label = "GC missing root negative test";
        needle = "gate_content_address_gc_missing_root_errors_without_deleting_store_objects";
      }
      {
        label = "GC missing root leaves store untouched";
        needle = "store count should be readable after failed GC";
      }
      {
        label = "GC cache not identity test";
        needle = "gate_content_address_gc_collects_cache_not_identity";
      }
      {
        label = "GC cache collection API exercised";
        needle = "collect_cached_snapshot_store(&store, &first)";
      }
      {
        label = "GC cache collection deletes cached snapshot store key";
        needle = "report.deleted_store_keys.contains(&cache_store_key)";
      }
      {
        label = "GC cache collection retains thin checkpoint store key";
        needle = "thin checkpoint key should remain";
      }
      {
        label = "GC collected cache becomes thin";
        needle = "assert_eq!(thin.kind, CheckpointKind::Thin);";
      }
      {
        label = "symmetry reduction covers relabelled frontier";
        needle = "gate_content_address_temporal_graph_symmetry_reduction_covers_relabelled_frontier";
      }
      {
        label = "symmetry reduction explores without proof";
        needle = "gate_content_address_temporal_graph_symmetry_reduction_explores_without_proof";
      }
      {
        label = "symmetry reduction explores when state differs";
        needle = "gate_content_address_temporal_graph_symmetry_reduction_explores_when_state_differs";
      }
      {
        label = "POR skips noncanonical interleaving";
        needle = "gate_content_address_temporal_graph_partial_order_reduction_skips_noncanonical_interleaving";
      }
      {
        label = "POR records missing representative";
        needle = "gate_content_address_temporal_graph_partial_order_reduction_records_missing_representative";
      }
      {
        label = "POR explores dependent decisions";
        needle = "gate_content_address_temporal_graph_partial_order_reduction_explores_when_dependent";
      }
      {
        label = "symmetry covered by representative";
        needle = "FrontierReductionReason::Symmetry";
      }
      {
        label = "POR covered by representative";
        needle = "FrontierReductionReason::PartialOrder";
      }
      {
        label = "POR does not record skipped child";
        needle = "assert!(!graph.contains_configuration(&covered));";
      }
      {
        label = "dependent app-random same stream";
        needle = "assert!(!same_stream_a.is_independent_from(&same_stream_b, &same_stream_proof));";
      }
      {
        label = "POR proof policy used by tests";
        needle = "PartialOrderReductionPolicy::new().with_independent_pair";
      }
      {
        label = "temporal graph user operation test";
        needle = "gate_content_address_temporal_graph_user_operations_share_single_dag";
      }
      {
        label = "save operation persists store keys";
        needle = ".save(&store, &saved)";
      }
      {
        label = "search operation materializes explored identities";
        needle = "assert_eq!(materialized_ids, explored_ids);";
      }
      {
        label = "symmetry class map used by tests";
        needle = "SymmetryReductionClasses::new()";
      }
      {
        label = "missing parent reason";
        needle = "descendant-missing-parent";
      }
      {
        label = "wrong parent reason";
        needle = "parent-mismatch";
      }
      {
        label = "wrong delta reason";
        needle = "schedule-delta-mismatch";
      }
      {
        label = "collision corpus";
        needle = "gate_content_address_collision_corpus_has_unique_ids";
      }
      {
        label = "twice-reduce canonical digest";
        needle = "assert_twice_reduce_canonical_digest(";
      }
    ]
    ++ failuresFor "crates/crucible-sim/tests/gate_content_address.rs" simGate [
      {
        label = "fixed vector coverage";
        needle = "gate_content_address_keeps_fixed_vectors_stable";
      }
      {
        label = "equal content coverage";
        needle = "gate_content_address_hashes_equal_content_to_equal_ids";
      }
      {
        label = "single-byte mutation coverage";
        needle = "gate_content_address_changes_on_single_byte_mutations";
      }
      {
        label = "domain and ordering coverage";
        needle = "gate_content_address_separates_domains_and_ordering";
      }
      {
        label = "collision corpus";
        needle = "gate_content_address_collision_corpus_has_unique_ids";
      }
      {
        label = "twice-reduce canonical digest";
        needle = "assert_twice_reduce_canonical_digest(";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/gate_content_address.rs" crucibleGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "red placeholder panic";
        needle = "implementation is pending T-HARN-11";
      }
    ]
    ++ forbiddenFor "crates/crucible-sim/tests/gate_content_address.rs" simGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "red placeholder panic";
        needle = "implementation is pending T-HARN-11";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "implemented crucible content-address target";
        needle = "gate: \"gate:content-address\",\n        package: \"crucible\",\n        test_target: \"gate_content_address\",\n        required_features: &[\"test-double\"],\n        placeholder: false,";
      }
      {
        label = "implemented crucible-sim content-address target";
        needle = "gate: \"gate:content-address\",\n        package: \"crucible-sim\",\n        test_target: \"gate_content_address\",\n        required_features: &[],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "implemented content-address catalog status";
        needle = "name: \"gate:content-address\",\n        phase: GatePhase::Phase1,\n        owner: \"crucible\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "content-address implemented status assertion";
        needle = "find_gate(\"gate:content-address\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "implemented crucible mapping target";
        needle = "gate = \"gate:content-address\";\n      package = \"crucible\";\n      testTarget = \"gate_content_address\";\n      requiredFeatures = [\"test-double\"];\n      placeholder = false;";
      }
      {
        label = "implemented crucible-sim mapping target";
        needle = "gate = \"gate:content-address\";\n      package = \"crucible-sim\";\n      testTarget = \"gate_content_address\";\n      requiredFeatures = [];\n      placeholder = false;";
      }
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=2";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes content-address gate";
        needle = "contentAddress = import ./phase1-content-address.nix";
      }
      {
        label = "phase1 content-address attr path";
        needle = "attrPath = \"checks.crucible.phase1.gates.contentAddress\"";
      }
      {
        label = "phase1 content-address lists T-HARN-11";
        needle = "\"T-HARN-11\"";
      }
      {
        label = "phase1 content-address lists T-ASRT-17";
        needle = "\"T-ASRT-17\"";
      }
      {
        label = "phase1 content-address lists T-PAT-4";
        needle = "\"T-PAT-4\"";
      }
      {
        label = "phase1 content-address lists T-TEMP-1";
        needle = "\"T-TEMP-1\"";
      }
      {
        label = "phase1 content-address lists T-TEMP-2";
        needle = "\"T-TEMP-2\"";
      }
      {
        label = "phase1 content-address lists T-TEMP-3";
        needle = "\"T-TEMP-3\"";
      }
      {
        label = "phase1 content-address lists T-TEMP-6";
        needle = "\"T-TEMP-6\"";
      }
      {
        label = "phase1 content-address lists T-TEMP-8";
        needle = "\"T-TEMP-8\"";
      }
      {
        label = "phase1 content-address lists T-TEMP-9";
        needle = "\"T-TEMP-9\"";
      }
      {
        label = "phase1 content-address lists T-TEMP-10";
        needle = "\"T-TEMP-10\"";
      }
      {
        label = "phase1 content-address lists T-TEMP-11";
        needle = "\"T-TEMP-11\"";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-11 checklist complete";
        needle = "- [x] **T-HARN-11**";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/07-temporal-graph.md" temporalGraph [
      {
        label = "T-TEMP-1 checklist complete";
        needle = "- [x] **T-TEMP-1**";
      }
      {
        label = "T-TEMP-1 completion names content-address gate";
        needle = "`checks.crucible.phase1.gates.contentAddress`";
      }
      {
        label = "T-TEMP-2 checklist complete";
        needle = "- [x] **T-TEMP-2**";
      }
      {
        label = "T-TEMP-2 completion names content-address gate";
        needle = "`checks.crucible.phase1.gates.contentAddress`";
      }
      {
        label = "T-TEMP-3 checklist complete";
        needle = "- [x] **T-TEMP-3**";
      }
      {
        label = "T-TEMP-3 completion names content-address gate";
        needle = "`checks.crucible.phase1.gates.contentAddress`";
      }
      {
        label = "T-TEMP-6 checklist complete";
        needle = "- [x] **T-TEMP-6**";
      }
      {
        label = "T-TEMP-6 completion names CoW refs";
        needle = "`crucible::CowDeltaRef`";
      }
      {
        label = "T-TEMP-6 completion names marginal fork API";
        needle = "`marginal_fork_cow_delta_objects`";
      }
      {
        label = "T-TEMP-6 completion says log prefix is shared";
        needle = "inherited log prefix as a shared reference";
      }
      {
        label = "T-TEMP-6 completion names content-address gate";
        needle = "`checks.crucible.phase1.gates.contentAddress`";
      }
      {
        label = "T-TEMP-8 checklist complete";
        needle = "- [x] **T-TEMP-8**";
      }
      {
        label = "T-TEMP-8 completion names DAG store trait";
        needle = "`crucible::DagStore`";
      }
      {
        label = "T-TEMP-8 completion names local backend";
        needle = "`crucible::LocalDagStore`";
      }
      {
        label = "T-TEMP-8 completion names store-key artifact";
        needle = "`crucible::DagStoreReproductionArtifact`";
      }
      {
        label = "T-TEMP-9 checklist complete";
        needle = "- [x] **T-TEMP-9**";
      }
      {
        label = "T-TEMP-9 completion names GC roots";
        needle = "`crucible::TemporalGraphGcRoots`";
      }
      {
        label = "T-TEMP-9 completion names GC report";
        needle = "`crucible::TemporalGraphGcReport`";
      }
      {
        label = "T-TEMP-9 completion names content-address gate";
        needle = "`checks.crucible.phase1.gates.contentAddress`";
      }
      {
        label = "T-TEMP-10 checklist complete";
        needle = "- [x] **T-TEMP-10**";
      }
      {
        label = "T-TEMP-10 completion names frontier policy";
        needle = "`crucible::FrontierReductionPolicy`";
      }
      {
        label = "T-TEMP-10 completion names reduced enumeration";
        needle = "`TemporalGraph::enumerate_frontier_reduced`";
      }
      {
        label = "T-TEMP-10 completion names content-address gate";
        needle = "`checks.crucible.phase1.gates.contentAddress`";
      }
      {
        label = "T-TEMP-11 checklist complete";
        needle = "- [x] **T-TEMP-11**";
      }
      {
        label = "T-TEMP-11 completion names save operation";
        needle = "`TemporalGraph::save`";
      }
      {
        label = "T-TEMP-11 completion names fork operation";
        needle = "`TemporalGraph::fork`";
      }
      {
        label = "T-TEMP-11 completion names content-address gate";
        needle = "`checks.crucible.phase1.gates.contentAddress`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsAndSketches [
      {
        label = "T-PAT-4 checklist complete";
        needle = "- [x] **T-PAT-4**";
      }
      {
        label = "T-PAT-4 completion names checkpoint";
        needle = "`crucible::Checkpoint`";
      }
      {
        label = "T-PAT-4 completion names node blob refs";
        needle = "`crucible::NodeBlobRef`";
      }
      {
        label = "T-PAT-4 completion names CoW refs";
        needle = "`crucible::CowDeltaRef`";
      }
      {
        label = "T-PAT-4 completion names DagStore";
        needle = "`crucible::DagStore`";
      }
      {
        label = "T-PAT-4 completion names local DagStore backend";
        needle = "`crucible::LocalDagStore`";
      }
      {
        label = "T-PAT-4 completion names checkpoint closure persistence";
        needle = "`TemporalGraph::persist_checkpoint_closure`";
      }
      {
        label = "T-PAT-4 completion names cached snapshot store collection";
        needle = "`TemporalGraph::collect_cached_snapshot_store`";
      }
      {
        label = "T-PAT-4 completion names content-address gate";
        needle = "`checks.crucible.phase1.gates.contentAddress`";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 content-address gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-content-address";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
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
          name = "run-content-address";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-content-address-target" \
              -p crucible \
              --features test-double \
              --test predicate_dsl \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-content-address-target" \
              -p crucible \
              --features test-double \
              --test gate_content_address \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-content-address-target" \
              -p crucible-sim \
              --test gate_content_address \
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
            check=${attrPath}
            gate=gate:content-address
            tasks=${builtins.concatStringsSep "," taskIds}
            rust_tests=crucible::predicate_dsl,crucible::gate_content_address,crucible-sim::gate_content_address
            corpus=fixed-vectors-and-collision-sampling
            predicate_dsl=world-plan-resolved-content-addressed-conditions
            predicate_dsl_host_closures=additive-unknown-named-predicates
            checkpoint=Checkpoint
            checkpoint_identity=Configuration::id
            checkpoint_delta=schedule_delta
            checkpoint_state_identity=false
            checkpoint_coverage_identity=false
            checkpoint_metadata_identity=false
            checkpoint_malformed_edges=rejected
            temporal_graph=content-addressed-step-closure
            temporal_graph_root=baked-genesis
            temporal_graph_dedup=configuration-id
            temporal_graph_parent_chain=schedule-prefix
            temporal_graph_frontier=checkpoint-dag
            materialized_state_components=vm-snapshots,device-overlays,scheduler,decision-rng,event-log
            materialized_state_identity=component-content-addressed
            cow_sharing=typed-content-addressed-delta-refs
            cow_marginal_fork_cost=delta-objects-not-full-state
            cow_dedup=identical-deltas-stored-once
            dag_store=put-get-exists
            dag_store_keys=blake3-content-hash
            dag_store_dedup=idempotent-equal-bytes
            dag_store_backend=local-two-level-layout
            dag_store_integrity=corrupt-path-repair
            temporal_graph_store=checkpoint-closure
            temporal_graph_store_objects=checkpoint-nodes,cached-snapshots,cow-deltas
            reproduction_artifact=store-key-closure
            dag_gc=reference-counts,mark-and-sweep
            dag_gc_roots=live-tips,pinned-checkpoints,genesis
            dag_gc_cache_rule=collect-cache-not-identity
            dag_gc_store=delete-unreachable-store-keys
            dag_gc_pins=pinned-stays-realizable
            search_reduction=symmetry,partial-order
            search_reduction_scope=graph-level-content-addressed-dag
            pattern_PAT_6=content-addressed-store-thin-fat-cow-delta
            symmetry_reduction=explicit-classes-coverage-full-state-canonical-relabeling
            partial_order_reduction=explicit-proof-disjoint-node-recorded-representative
            graph_user_operations=save,resume,fork,replay,search
            graph_operation_state=single-temporal-dag
            RESULT
          '';
        }
      ];
    }
