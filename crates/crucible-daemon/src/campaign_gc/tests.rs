//! Canonical identity and bound tests for campaign GC plan headers.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::sync::{
    Arc, Mutex, MutexGuard,
    mpsc::{self, Sender, TryRecvError},
};
use std::thread;
use std::time::Duration;

use crucible::ContentHash;
use crucible_campaign::{
    AssignmentId, AttemptId, AttemptResourceLimits, BudgetGrant, CampaignCommandId,
    CampaignControlAction, CampaignLineage, CampaignLineageId, CampaignMode, CampaignName,
    CampaignPolicy, CampaignRepository, CampaignSeed, CancelAttemptExecutionDisposition,
    CancelAttemptExecutionRequest, CheckpointAttemptExecutionDisposition,
    CheckpointAttemptExecutionRequest, ConfigurationId, ControlRequest, CoverageProjection,
    DaemonEpoch, ExecutionId, ExecutionRetentionIntent, ExecutorCompatibilityProfile,
    ExecutorControlService, ExecutorStatusService, ExplorerPolicy, FairnessPolicy,
    FindingCandidateBundle, FindingCandidateBundleId, FindingExactPins, FindingKind,
    FindingMinimizationAttempt, FindingMinimizationEvidence, FindingSignature,
    FindingSignatureMinimizationEvidence, FindingTarget, GetAttemptExecutionDisposition,
    GetAttemptExecutionRequest, MeasurementSet, Observation, ObservationId, PropertyVerdictSet,
    RetentionPolicy, ScenarioDefId, StopOutcome, SubmitAttemptRequest,
};
use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{
    BlobHandle, BlobInventoryFence, BlobInventoryRecord, BlobInventorySummary, BlobStoreAdmin,
    ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MemoryBlobBackend,
    MemoryRefBackend, MutableRefBackend, ObjectKind, PackedBlobBackend, PlannedDeleteDisposition,
    RefBackendCapabilities, RefCasOutcome, RefName, RefPublicationGuard, RefScanPage,
    StoreEncryptionKey, StoreEncryptionKeyId, StoreError, StoreGraph, StoreGraphConfig,
    StoreGraphKeyring, StoreNodeId, StoreNodeSpec,
};
use crucible_cas::content_store::{RefInventoryFence, RefStoreAdmin};

use super::apply::CampaignGcApplySources;
use super::*;
use super::{
    apply_single_host_campaign_gc_with_physical as apply_single_host_campaign_gc,
    plan_single_host_campaign_gc_with_physical as plan_single_host_campaign_gc,
};
use crate::{
    AssignmentLedger, AssignmentRetentionAdmin, AssignmentRetentionFence,
    AssignmentRetentionGeneration, AssignmentRetentionInventoryError, AssignmentRetentionRoot,
    AssignmentRetentionSummary, AssignmentRetentionVisitorError, AttemptExecutionKey,
    AttemptExecutionOrigin, AttemptRuntimeState, AttemptStateCas, CompletedFindingCandidate,
    DirectoryAssignmentLedger, FindingCandidateRetentionOutcome, HotCheckpointFallback,
    HotCheckpointFallbackRecord, HotCheckpointFallbackRetentionCas,
    HotCheckpointFallbackRetentionStore, HotCheckpointFallbackSlot, MemoryAssignmentLedger,
    MemoryHotCheckpointFallbackRetentionStore, QemuHotForkTemplateKey, RepositoryAttemptAdmission,
    acknowledge_incorporated_finding_candidate, incorporate_and_acknowledge_finding_candidate,
};
use crate::{
    CampaignTransferJournalError, CampaignTransferRetentionAdmin, CampaignTransferRetentionFence,
    CampaignTransferRetentionGeneration, CampaignTransferRetentionRoot,
    CampaignTransferRetentionSummary, CompletionValidationFailure, ExecutorCapacity,
    LocalExecutorError, LocalExecutorSupervisor,
};

mod s3;

#[derive(Default)]
struct TestCampaignTransferRoots {
    roots: Mutex<Vec<CampaignTransferRetentionRoot>>,
}

impl TestCampaignTransferRoots {
    fn replace(&self, roots: Vec<CampaignTransferRetentionRoot>) {
        *self.roots.lock().expect("transfer roots") = roots;
    }
}

impl CampaignTransferRetentionAdmin for TestCampaignTransferRoots {
    fn acquire_campaign_transfer_retention_fence(
        &self,
    ) -> Result<Box<dyn CampaignTransferRetentionFence + '_>, CampaignTransferJournalError> {
        Ok(Box::new(TestCampaignTransferFence {
            roots: self.roots.lock().expect("transfer roots"),
        }))
    }
}

struct TestCampaignTransferFence<'a> {
    roots: MutexGuard<'a, Vec<CampaignTransferRetentionRoot>>,
}

impl CampaignTransferRetentionFence for TestCampaignTransferFence<'_> {
    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(CampaignTransferRetentionRoot) -> Result<(), StoreError>,
    ) -> Result<CampaignTransferRetentionSummary, CampaignTransferJournalError> {
        for root in self.roots.iter().copied() {
            visitor(root).map_err(CampaignTransferJournalError::Visitor)?;
        }
        Ok(CampaignTransferRetentionSummary::new(
            CampaignTransferRetentionGeneration::from_bytes([0x73; 32]),
            u64::from(!self.roots.is_empty()),
            self.roots.len() as u64,
        ))
    }
}

fn hash(domain: &str, byte: u8) -> CampaignHash {
    CampaignHash::derive(domain, &[byte])
}

fn pending_finding_request(lineage: CampaignLineageId, attempt: AttemptId) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x54; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x55; 16]).expect("daemon epoch"),
        lineage,
        attempt,
        AttemptResourceLimits::new(1, 4096, 8192, 64).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("pending finding request")
}

struct LockOrderDirectoryRefs {
    inner: DirectoryRefBackend,
    publication_requested: Mutex<Option<Sender<()>>>,
    inventory_acquired: Mutex<Option<Sender<()>>>,
}

impl LockOrderDirectoryRefs {
    fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            inner: DirectoryRefBackend::new(root),
            publication_requested: Mutex::new(None),
            inventory_acquired: Mutex::new(None),
        }
    }

    fn arm(&self, publication_requested: Sender<()>, inventory_acquired: Sender<()>) {
        *self
            .publication_requested
            .lock()
            .expect("publication signal mutex") = Some(publication_requested);
        *self
            .inventory_acquired
            .lock()
            .expect("inventory signal mutex") = Some(inventory_acquired);
    }
}

impl MutableRefBackend for LockOrderDirectoryRefs {
    fn capabilities(&self) -> RefBackendCapabilities {
        self.inner.capabilities()
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        if let Some(signal) = self
            .publication_requested
            .lock()
            .expect("publication signal mutex")
            .as_ref()
        {
            signal.send(()).expect("signal publication request");
        }
        self.inner.acquire_publication_guard()
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        self.inner.read_ref(name)
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        self.inner.scan_refs(namespace, after, limit)
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        self.inner.compare_exchange(name, expected, next)
    }
}

impl RefStoreAdmin for LockOrderDirectoryRefs {
    fn acquire_ref_inventory_fence(&self) -> Result<Box<dyn RefInventoryFence + '_>, StoreError> {
        let fence = self.inner.acquire_ref_inventory_fence()?;
        if let Some(signal) = self
            .inventory_acquired
            .lock()
            .expect("inventory signal mutex")
            .as_ref()
        {
            signal.send(()).expect("signal inventory acquisition");
        }
        Ok(fence)
    }
}

#[derive(Clone)]
struct LockOrderDirectoryLedger {
    inner: Arc<Mutex<DirectoryAssignmentLedger>>,
    gate: Arc<Mutex<()>>,
    acquisition_requested: Sender<()>,
}

struct LockOrderDirectoryFence<'a> {
    inner: Arc<Mutex<DirectoryAssignmentLedger>>,
    _gate: MutexGuard<'a, ()>,
}

impl AssignmentRetentionAdmin for LockOrderDirectoryLedger {
    type Error = crate::AssignmentLedgerError;

    fn acquire_retention_fence(
        &mut self,
    ) -> Result<Box<dyn AssignmentRetentionFence<BackendError = Self::Error> + '_>, Self::Error>
    {
        self.acquisition_requested
            .send(())
            .expect("signal ledger acquisition request");
        let gate = self.gate.lock().expect("lock-order ledger gate");
        Ok(Box::new(LockOrderDirectoryFence {
            inner: self.inner.clone(),
            _gate: gate,
        }))
    }
}

impl AssignmentRetentionFence for LockOrderDirectoryFence<'_> {
    type BackendError = crate::AssignmentLedgerError;

    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(
            AssignmentRetentionRoot,
        ) -> Result<(), AssignmentRetentionVisitorError>,
    ) -> Result<AssignmentRetentionSummary, AssignmentRetentionInventoryError<Self::BackendError>>
    {
        let mut ledger = self.inner.lock().expect("lock directory ledger");
        let mut fence = ledger
            .acquire_retention_fence()
            .map_err(AssignmentRetentionInventoryError::Backend)?;
        fence.visit_roots(visitor)
    }

    fn load_attempt(
        &mut self,
        key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::BackendError> {
        self.inner
            .lock()
            .expect("lock directory ledger")
            .load_attempt(key)
    }

    fn compare_exchange_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::BackendError> {
        self.inner
            .lock()
            .expect("lock directory ledger")
            .compare_exchange_attempt(key, expected, next)
    }
}

fn publish_pending_finding_fixture(
    repository: &CampaignRepository,
) -> (
    CampaignLineageId,
    AttemptId,
    ObservationId,
    FindingCandidateBundleId,
) {
    const CAMPAIGN: &str = "pending-finding-gc-fixture";

    let scenario = ScenarioDefId::from_hash(hash("crucible.test.pending-finding.scenario", 0x11));
    let genesis =
        ConfigurationId::from_hash(hash("crucible.test.pending-finding.configuration", 0x12));
    let scenario_artifact = repository
        .publish_scenario_artifact(scenario, 1, b"pending finding scenario".to_vec())
        .expect("publish pending finding scenario");
    let genesis_artifact = repository
        .publish_configuration_artifact(
            scenario,
            scenario_artifact,
            genesis,
            1,
            b"pending finding genesis".to_vec(),
        )
        .expect("publish pending finding genesis");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_artifact,
        genesis,
        genesis_artifact,
        "crucible-pending-finding-test",
        "qemu-pending-finding-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("pending finding lineage");
    let policy = CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([0x13; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 1,
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("pending finding fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("pending finding policy");
    let created = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create pending finding campaign");
    let resumed = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(hash(
                    "crucible.test.pending-finding.command",
                    0x14,
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume pending finding campaign");
    let funded = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(hash(
                    "crucible.test.pending-finding.command",
                    0x15,
                )),
                expected_snapshot: resumed.new_snapshot,
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("pending finding attempt budget"),
                ),
            },
        )
        .expect("fund pending finding campaign");
    assert_eq!(
        repository
            .head(CAMPAIGN)
            .expect("pending finding funded head")
            .snapshot_id(),
        funded.new_snapshot
    );

    let attempt = repository
        .admit_initial_discovery_if_ready(CAMPAIGN)
        .expect("admit pending finding discovery")
        .expect("pending finding discovery attempt");
    let attempt_record = repository
        .load_attempt(attempt)
        .expect("load pending finding attempt");
    let child =
        ConfigurationId::from_hash(hash("crucible.test.pending-finding.configuration", 0x16));
    let child_artifact = repository
        .publish_configuration_artifact(
            scenario,
            scenario_artifact,
            child,
            1,
            b"pending finding child".to_vec(),
        )
        .expect("publish pending finding child");
    let measurements = repository
        .publish_measurement_set(&MeasurementSet::new(BTreeMap::new()).expect("measurements"))
        .expect("publish pending finding measurements");
    let properties = repository
        .publish_property_verdict_set(
            &PropertyVerdictSet::new(BTreeMap::new()).expect("properties"),
        )
        .expect("publish pending finding properties");
    let coverage = repository
        .publish_coverage_projection(
            &CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage"),
        )
        .expect("publish pending finding coverage");
    let observation_record = Observation::new(
        attempt,
        child,
        child_artifact,
        attempt_record.path(),
        StopOutcome::TerminalSuccess,
        measurements,
        properties,
        coverage,
        BTreeSet::new(),
    )
    .expect("pending finding observation");
    let observed = repository
        .publish_observation(
            CAMPAIGN,
            repository
                .head(CAMPAIGN)
                .expect("pending finding admission head")
                .snapshot_id(),
            &observation_record,
        )
        .expect("publish pending finding observation");

    let fingerprint = hash("crucible.test.pending-finding.fingerprint", 0x17);
    let original = repository
        .publish_reproduction_artifact(
            scenario,
            scenario_artifact,
            child,
            child_artifact,
            fingerprint,
            1,
            b"pending finding original reproduction".to_vec(),
        )
        .expect("publish pending finding reproduction");
    let replayed_state = hash("crucible.test.pending-finding.replayed-state", 0x18);
    let minimization = FindingMinimizationEvidence::new(
        original,
        1,
        b"pending finding deterministic minimizer".to_vec(),
        vec![FindingMinimizationAttempt::new(
            0,
            hash("crucible.test.pending-finding.candidate-artifact", 0x19),
            hash("crucible.test.pending-finding.candidate-schedule", 0x1a),
            replayed_state,
            Some(fingerprint),
            true,
        )],
        replayed_state,
    )
    .expect("pending finding minimization evidence");
    let minimized = repository
        .publish_minimized_reproduction_artifact(
            scenario,
            scenario_artifact,
            child,
            child_artifact,
            fingerprint,
            1,
            b"pending finding minimized reproduction".to_vec(),
            minimization.clone(),
        )
        .expect("publish pending finding minimized reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        String::from("qemu.pending-finding-divergence"),
        Some(FindingTarget::Configuration(child_artifact)),
        BTreeSet::new(),
    )
    .expect("pending finding signature");
    let replay_pass = vec![Some(signature.clone()), Some(signature.clone())];
    let signature_minimization = FindingSignatureMinimizationEvidence::new(
        &signature,
        &minimization,
        replay_pass.clone(),
        replay_pass,
    )
    .expect("pending finding signature minimization");
    let bundle = FindingCandidateBundle::new(
        observed.observation,
        signature,
        original,
        minimized,
        signature_minimization,
        FindingExactPins::default(),
    )
    .expect("pending finding candidate bundle");
    let candidate = repository
        .publish_finding_candidate_bundle(&bundle)
        .expect("publish pending finding candidate bundle");

    (
        lineage.id().expect("pending finding lineage identity"),
        attempt,
        observed.observation,
        candidate,
    )
}

fn basis(
    backend: &str,
    generation: u8,
    objects: u64,
    logical_bytes: u64,
) -> CampaignGcBlobInventoryBasis {
    CampaignGcBlobInventoryBasis::new(
        backend,
        InventoryGeneration::from_bytes([generation; 32]),
        objects,
        logical_bytes,
    )
    .expect("valid physical basis")
}

fn plan_with(
    ref_generation: u8,
    ledger_generation: u8,
    physical: Vec<CampaignGcBlobInventoryBasis>,
) -> CampaignGcPlan {
    CampaignGcPlan::new(
        hash("crucible.test.gc.store-graph.v1", 1),
        CampaignGcRootSetId::from_hash(hash("crucible.test.gc.root-set.v1", 2)),
        RefInventorySummary::from_parts(
            RefInventoryGeneration::from_bytes([ref_generation; 32]),
            3,
        ),
        AssignmentRetentionSummary::new(
            AssignmentRetentionGeneration::from_bytes([ledger_generation; 32]),
            4,
            2,
            1,
            0,
        ),
        CampaignGcCandidateSetSummary::new(
            CampaignGcCandidateSetId::from_hash(hash("crucible.test.gc.candidates.v1", 3)),
            3,
            30,
        ),
        physical,
    )
    .expect("valid GC plan")
}

#[test]
fn plan_header_round_trips_and_has_one_frozen_identity() {
    let plan = plan_with(
        0x21,
        0x31,
        vec![basis("cache", 0x41, 10, 100), basis("durable", 0x42, 5, 50)],
    );
    let bytes = plan.canonical_bytes().expect("canonical plan");
    let decoded = CampaignGcPlan::from_canonical_bytes(&bytes).expect("decode canonical plan");

    assert_eq!(decoded, plan);
    assert_eq!(decoded.id(), plan.id());
    assert_eq!(plan.candidates().candidates(), 3);
    assert_eq!(plan.physical().len(), 2);
    assert_eq!(
        plan.id().expect("plan identity").to_hex(),
        "35f3e4ba9ccd69cf3ec05b8406f8b9473827118aaee9541f87834e6570a97da5"
    );
}

#[test]
fn every_administrative_generation_changes_plan_identity() {
    let original = plan_with(0x21, 0x31, vec![basis("durable", 0x41, 10, 100)]);
    let changed_ref = plan_with(0x22, 0x31, vec![basis("durable", 0x41, 10, 100)]);
    let changed_ledger = plan_with(0x21, 0x32, vec![basis("durable", 0x41, 10, 100)]);
    let changed_blob = plan_with(0x21, 0x31, vec![basis("durable", 0x42, 10, 100)]);

    let original = original.id().expect("original plan identity");
    assert_ne!(changed_ref.id().expect("changed ref identity"), original);
    assert_ne!(
        changed_ledger.id().expect("changed ledger identity"),
        original
    );
    assert_ne!(changed_blob.id().expect("changed blob identity"), original);
}

#[test]
fn plan_rejects_unordered_excessive_and_inconsistent_summaries() {
    let common = || {
        (
            hash("crucible.test.gc.store-graph.v1", 1),
            CampaignGcRootSetId::from_hash(hash("crucible.test.gc.root-set.v1", 2)),
            RefInventorySummary::from_parts(RefInventoryGeneration::from_bytes([0x21; 32]), 3),
            CampaignGcCandidateSetSummary::new(
                CampaignGcCandidateSetId::from_hash(hash("crucible.test.gc.candidates.v1", 3)),
                3,
                30,
            ),
        )
    };
    let (graph, roots, refs, candidates) = common();
    assert_eq!(
        CampaignGcPlan::new(
            graph,
            roots,
            refs,
            AssignmentRetentionSummary::new(
                AssignmentRetentionGeneration::from_bytes([0x31; 32]),
                4,
                2,
                1,
                0,
            ),
            candidates,
            vec![basis("z", 1, 10, 100), basis("a", 2, 10, 100)],
        ),
        Err(CampaignGcPlanError::InvalidPhysicalInventoryCount)
    );

    let excessive = (0..=MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES)
        .map(|index| basis(&format!("node{index:03}"), 1, 1, 1))
        .collect();
    let (graph, roots, refs, candidates) = common();
    assert_eq!(
        CampaignGcPlan::new(
            graph,
            roots,
            refs,
            AssignmentRetentionSummary::new(
                AssignmentRetentionGeneration::from_bytes([0x31; 32]),
                4,
                2,
                1,
                0,
            ),
            candidates,
            excessive,
        ),
        Err(CampaignGcPlanError::InvalidPhysicalInventoryCount)
    );

    let (graph, roots, refs, candidates) = common();
    assert_eq!(
        CampaignGcPlan::new(
            graph,
            roots,
            refs,
            AssignmentRetentionSummary::new(
                AssignmentRetentionGeneration::from_bytes([0x31; 32]),
                2,
                2,
                1,
                0,
            ),
            candidates,
            vec![basis("durable", 1, 10, 100)],
        ),
        Err(CampaignGcPlanError::InvalidLedgerSummary)
    );

    let (graph, roots, refs, _) = common();
    assert_eq!(
        CampaignGcPlan::new(
            graph,
            roots,
            refs,
            AssignmentRetentionSummary::new(
                AssignmentRetentionGeneration::from_bytes([0x31; 32]),
                4,
                2,
                1,
                0,
            ),
            CampaignGcCandidateSetSummary::new(
                CampaignGcCandidateSetId::from_hash(hash("crucible.test.gc.candidates.v1", 3,)),
                11,
                30,
            ),
            vec![basis("durable", 1, 10, 100)],
        ),
        Err(CampaignGcPlanError::InvalidCandidateSummary)
    );
}

#[test]
fn decoder_rejects_truncation_trailing_bytes_and_wrong_schema() {
    let plan = plan_with(0x21, 0x31, vec![basis("durable", 0x41, 10, 100)]);
    let bytes = plan.canonical_bytes().expect("canonical plan");
    assert_eq!(
        CampaignGcPlan::from_canonical_bytes(&bytes[..bytes.len() - 1]),
        Err(CampaignGcPlanError::InvalidLength)
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        CampaignGcPlan::from_canonical_bytes(&trailing),
        Err(CampaignGcPlanError::InvalidLength)
    );

    let mut wrong_schema = bytes;
    wrong_schema[0] ^= 1;
    assert_eq!(
        CampaignGcPlan::from_canonical_bytes(&wrong_schema),
        Err(CampaignGcPlanError::UnsupportedSchema)
    );
}

#[test]
fn root_and_candidate_manifests_round_trip_with_stable_identity() {
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, b"first");
    let second = ContentId::for_bytes(ObjectKind::Finding, 2, b"second");
    let roots = CampaignGcRootManifest::new([second, first, first]).expect("root manifest");
    let root_id = roots.id();
    let mut root_bytes = Vec::new();
    roots
        .write_canonical(&mut root_bytes)
        .expect("encode roots");
    let decoded_roots = CampaignGcRootManifest::from_canonical_reader(&mut Cursor::new(root_bytes))
        .expect("decode roots");
    assert_eq!(decoded_roots, roots);
    assert_eq!(decoded_roots.id(), root_id);
    let mut expected_roots = vec![first, second];
    expected_roots.sort_unstable_by(content_id_manifest_order);
    assert_eq!(decoded_roots.iter().collect::<Vec<_>>(), expected_roots);

    let candidates = CampaignGcCandidateManifest::new(vec![
        CampaignGcCandidate::new("z-tier", second, 20).expect("candidate"),
        CampaignGcCandidate::new("a-tier", first, 10).expect("candidate"),
    ])
    .expect("candidate manifest");
    let summary = candidates.summary();
    let mut candidate_bytes = Vec::new();
    candidates
        .write_canonical(&mut candidate_bytes)
        .expect("encode candidates");
    let decoded_candidates =
        CampaignGcCandidateManifest::from_canonical_reader(&mut Cursor::new(candidate_bytes))
            .expect("decode candidates");
    assert_eq!(decoded_candidates, candidates);
    assert_eq!(decoded_candidates.summary(), summary);
    assert_eq!(summary.candidates(), 2);
    assert_eq!(summary.logical_bytes(), 30);
    assert_eq!(
        decoded_candidates.iter().next().expect("first").backend(),
        "a-tier"
    );
}

#[test]
fn manifests_reject_duplicates_trailing_bytes_and_noncanonical_order() {
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, b"first");
    assert!(matches!(
        CampaignGcCandidateManifest::new(vec![
            CampaignGcCandidate::new("tier", first, 1).expect("candidate"),
            CampaignGcCandidate::new("tier", first, 2).expect("candidate"),
        ]),
        Err(CampaignGcManifestError::DuplicateCandidate)
    ));

    let roots = CampaignGcRootManifest::new([first]).expect("root manifest");
    let mut bytes = Vec::new();
    roots.write_canonical(&mut bytes).expect("encode roots");
    bytes.push(0);
    assert!(matches!(
        CampaignGcRootManifest::from_canonical_reader(&mut Cursor::new(bytes)),
        Err(CampaignGcManifestError::Noncanonical)
    ));

    let second = ContentId::for_bytes(ObjectKind::Trace, 1, b"second");
    let mut descending = [second, first];
    descending.sort_unstable_by(|left, right| content_id_manifest_order(right, left));
    let mut unordered = Vec::new();
    unordered.extend_from_slice(b"crucible.campaign.gc-root-manifest.v1\0");
    unordered.extend_from_slice(&2_u64.to_be_bytes());
    for id in descending {
        let encoded = id.encode();
        unordered.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
        unordered.extend_from_slice(encoded.as_bytes());
    }
    assert!(matches!(
        CampaignGcRootManifest::from_canonical_reader(&mut Cursor::new(unordered)),
        Err(CampaignGcManifestError::Noncanonical)
    ));
}

#[test]
fn planner_authenticates_roots_and_selects_only_unreachable_placements() {
    let blobs = Arc::new(MemoryBlobBackend::new("gc-primary", 8 * 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());

    let live = ContentEnvelope::new(
        "crucible.test.gc-live",
        1,
        BTreeSet::new(),
        b"live".to_vec(),
    )
    .expect("live envelope");
    let live_bytes = live.canonical_bytes();
    let live_id = live.content_id(ObjectKind::Trace);
    blobs
        .put_if_absent(live_id, &BlobHandle::from_bytes(live_bytes))
        .expect("store live object");
    assert_eq!(
        refs.compare_exchange(
            &RefName::new("retained/gc-live").expect("ref name"),
            None,
            live_id,
        )
        .expect("publish ref"),
        RefCasOutcome::Advanced { next: live_id }
    );

    let orphan_bytes = b"unreachable".to_vec();
    let orphan_id = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    blobs
        .put_if_absent(orphan_id, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store orphan");

    let mut ledger = MemoryAssignmentLedger::default();
    let physical =
        CampaignGcPhysicalStore::new("gc-primary", blobs.as_ref()).expect("physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        hash("crucible.test.gc.store-graph.v1", 9),
        &[physical],
    )
    .expect("plan GC");

    assert_eq!(prepared.roots().iter().collect::<Vec<_>>(), vec![live_id]);
    assert_eq!(prepared.reachable_objects(), 1);
    assert_eq!(prepared.candidates().len(), 1);
    let candidate = prepared
        .candidates()
        .iter()
        .next()
        .expect("orphan candidate");
    assert_eq!(candidate.backend(), "gc-primary");
    assert_eq!(candidate.id(), orphan_id);
    assert_eq!(prepared.plan().root_set(), prepared.roots().id());
    assert_eq!(
        prepared.plan().candidates(),
        prepared.candidates().summary()
    );
}

#[test]
fn pending_finding_candidate_closure_survives_gc_and_ledger_restart() {
    let blobs = Arc::new(MemoryBlobBackend::new(
        "pending-finding-gc",
        8 * 1024 * 1024,
    ));
    let fixture_repository =
        CampaignRepository::new(blobs.clone(), Arc::new(MemoryRefBackend::new()));
    let (lineage, attempt, observation, candidate) =
        publish_pending_finding_fixture(&fixture_repository);

    // The executor ledger is the only root owner in this flight. Campaign
    // construction records not referenced by the handoff remain collectible.
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let expected_closure = repository
        .authenticated_closure_ids([candidate.content_id(), observation.content_id()])
        .expect("authenticate pending finding closure");

    let orphan_bytes = b"unreachable pending-finding neighbor".to_vec();
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store orphan");

    let ledger_root = tempfile::tempdir().expect("assignment ledger directory");
    let request = pending_finding_request(lineage, attempt);
    let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
    let completed = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution: ExecutionId::from_bytes([0x64; 16]).expect("execution"),
        observation,
        finding_candidate: CompletedFindingCandidate::Pending(candidate),
    };
    {
        let mut ledger =
            DirectoryAssignmentLedger::open(ledger_root.path()).expect("open assignment ledger");
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, None, Some(completed))
                .expect("retain pending finding"),
            AttemptStateCas::Advanced
        );
    }

    let mut ledger =
        DirectoryAssignmentLedger::open(ledger_root.path()).expect("reopen assignment ledger");
    assert_eq!(
        ledger.load_attempt(key).expect("reload pending finding"),
        Some(completed)
    );
    let graph = hash("crucible.test.pending-finding-gc-graph.v1", 0x75);
    let physical =
        CampaignGcPhysicalStore::new("pending-finding-gc", blobs.as_ref()).expect("physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("plan pending finding GC");
    let retained = prepared.roots().iter().collect::<BTreeSet<_>>();
    assert_eq!(
        retained,
        BTreeSet::from([observation.content_id(), candidate.content_id()])
    );
    assert_eq!(
        prepared.reachable_objects(),
        u64::try_from(expected_closure.len()).expect("pending finding closure count")
    );
    assert!(
        prepared
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == orphan)
    );

    let journal_root = tempfile::tempdir().expect("GC journal directory");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(journal_root.path().join("journal"), &prepared)
            .expect("create pending finding GC journal");
    let report = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None),
        graph,
        &[physical],
    )
    .expect("apply pending finding GC");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(!blobs.contains(orphan).expect("orphan deleted"));
    for object in &expected_closure {
        assert!(
            blobs
                .contains(*object)
                .expect("pending finding object retained")
        );
    }

    drop(ledger);
    let mut restarted_ledger = DirectoryAssignmentLedger::open(ledger_root.path())
        .expect("restart assignment ledger after GC");
    let restarted_repository = CampaignRepository::new(blobs.clone(), refs.clone());
    restarted_repository
        .load_finding_candidate_bundle(candidate)
        .expect("load retained finding candidate after restart");
    let restarted = plan_single_host_campaign_gc(
        &restarted_repository,
        refs.as_ref(),
        &mut restarted_ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("plan after pending finding restart");
    assert_eq!(
        restarted.reachable_objects(),
        u64::try_from(expected_closure.len()).expect("restarted pending finding closure count")
    );
    assert!(restarted.candidates().is_empty());
}

#[test]
fn incorporated_finding_releases_exact_candidate_root_across_restart() {
    const CAMPAIGN: &str = "pending-finding-gc-fixture";

    let storage = tempfile::tempdir().expect("durable handoff storage");
    let blob_root = storage.path().join("blobs");
    let ref_root = storage.path().join("refs");
    let ledger_root = storage.path().join("ledger");
    let campaign = CampaignName::new(CAMPAIGN).expect("campaign name");
    let (key, execution, observation, candidate, expected_snapshot, completed, publication) = {
        let blobs = Arc::new(DirectoryBlobBackend::new(
            "incorporated-finding-gc",
            &blob_root,
        ));
        let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
        let repository = CampaignRepository::new(blobs, refs);
        let (lineage, attempt, observation, candidate) =
            publish_pending_finding_fixture(&repository);
        let expected_snapshot = repository
            .head(CAMPAIGN)
            .expect("observation-owning head")
            .snapshot_id();
        let request = pending_finding_request(lineage, attempt);
        let key = AttemptExecutionKey::new(lineage, attempt);
        let execution = ExecutionId::from_bytes([0x65; 16]).expect("execution");
        let completed = AttemptRuntimeState::Completed {
            execution_basis: request.execution_basis_digest(),
            origin: AttemptExecutionOrigin::Initial,
            daemon_epoch: request.daemon_epoch(),
            execution,
            observation,
            finding_candidate: CompletedFindingCandidate::Pending(candidate),
        };
        let mut ledger =
            DirectoryAssignmentLedger::open(&ledger_root).expect("open assignment ledger");
        assert_eq!(
            ledger
                .compare_exchange_attempt(key, None, Some(completed))
                .expect("retain pending candidate"),
            AttemptStateCas::Advanced
        );

        let publication = repository
            .incorporate_finding_candidate_bundle(CAMPAIGN, expected_snapshot, candidate)
            .expect("incorporate candidate before simulated crash");

        (
            key,
            execution,
            observation,
            candidate,
            expected_snapshot,
            completed,
            publication,
        )
    };

    let blobs = Arc::new(DirectoryBlobBackend::new(
        "incorporated-finding-gc",
        &blob_root,
    ));
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let mut restarted =
        DirectoryAssignmentLedger::open(&ledger_root).expect("restart before acknowledgement");
    assert_eq!(
        restarted
            .load_attempt(key)
            .expect("candidate remains after crash"),
        Some(completed)
    );
    let released = acknowledge_incorporated_finding_candidate(
        &repository,
        &mut restarted,
        &campaign,
        key,
        execution,
        observation,
        publication.finding,
        candidate,
    )
    .expect("reauthenticate and release after restart");
    let FindingCandidateRetentionOutcome::Released(acknowledgement) = released else {
        panic!("expected exact candidate release");
    };
    assert_eq!(acknowledgement.bundle(), candidate);
    assert_eq!(acknowledgement.finding(), publication.finding);
    assert_eq!(acknowledgement.snapshot(), publication.new_snapshot);
    assert!(matches!(
        restarted
            .load_attempt(key)
            .expect("load released completion"),
        Some(AttemptRuntimeState::Completed {
            finding_candidate: CompletedFindingCandidate::Acknowledged(retained_candidate),
            ..
        }) if retained_candidate == candidate
    ));
    let wrong_candidate_content =
        ContentId::for_bytes(ObjectKind::Finding, 1, b"wrong acknowledged candidate");
    let wrong_candidate = FindingCandidateBundleId::parse(&format!(
        "crucible.campaign.finding-candidate-bundle@{wrong_candidate_content}"
    ))
    .expect("wrong candidate identity");
    assert_eq!(
        acknowledge_incorporated_finding_candidate(
            &repository,
            &mut restarted,
            &campaign,
            key,
            execution,
            observation,
            publication.finding,
            wrong_candidate,
        )
        .expect("wrong candidate is a stable non-current result"),
        FindingCandidateRetentionOutcome::NotCurrent
    );

    drop(restarted);
    drop(repository);
    drop(refs);
    drop(blobs);

    let blobs = Arc::new(DirectoryBlobBackend::new(
        "incorporated-finding-gc",
        &blob_root,
    ));
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let mut replayed_ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("restart after release");
    let replayed = incorporate_and_acknowledge_finding_candidate(
        &repository,
        &mut replayed_ledger,
        &campaign,
        expected_snapshot,
        key,
        execution,
        observation,
        candidate,
    )
    .expect("replay incorporated and acknowledged candidate");
    assert!(replayed.publication().replayed);
    assert!(matches!(
        replayed.acknowledgement(),
        FindingCandidateRetentionOutcome::AlreadyReleased(_)
    ));

    let expected_candidate_closure = repository
        .authenticated_closure_ids([candidate.content_id()])
        .expect("authenticate candidate closure");
    let orphan_bytes = b"unreachable incorporated-finding neighbor".to_vec();
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store orphan");
    let graph = hash("crucible.test.incorporated-finding-gc-graph.v1", 0x76);
    let physical = CampaignGcPhysicalStore::new("incorporated-finding-gc", blobs.as_ref())
        .expect("physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut replayed_ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("plan after candidate acknowledgement");
    assert!(
        !prepared
            .roots()
            .iter()
            .any(|root| root == candidate.content_id())
    );
    let journal_root = tempfile::tempdir().expect("GC journal directory");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(journal_root.path().join("journal"), &prepared)
            .expect("create post-acknowledgement GC journal");
    apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(&repository, refs.as_ref(), &mut replayed_ledger, None, None),
        graph,
        &[physical],
    )
    .expect("apply post-acknowledgement GC");
    assert!(!blobs.contains(orphan).expect("orphan deleted"));
    for object in expected_candidate_closure {
        assert!(
            blobs
                .contains(object)
                .expect("incorporated candidate closure retained")
        );
    }
}

#[test]
fn finding_acknowledgement_and_gc_follow_directory_ref_before_ledger_lock_order() {
    const CAMPAIGN: &str = "pending-finding-gc-fixture";

    let storage = tempfile::tempdir().expect("lock-order storage");
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "finding-lock-order",
        storage.path().join("blobs"),
    ));
    let refs = Arc::new(LockOrderDirectoryRefs::new(storage.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let (lineage, attempt, observation, candidate) = publish_pending_finding_fixture(&repository);
    let expected_snapshot = repository
        .head(CAMPAIGN)
        .expect("observation-owning head")
        .snapshot_id();
    let publication = repository
        .incorporate_finding_candidate_bundle(CAMPAIGN, expected_snapshot, candidate)
        .expect("incorporate lock-order candidate");
    let campaign = CampaignName::new(CAMPAIGN).expect("campaign name");
    let request = pending_finding_request(lineage, attempt);
    let key = AttemptExecutionKey::new(lineage, attempt);
    let execution = ExecutionId::from_bytes([0x66; 16]).expect("execution");
    let completed = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution,
        observation,
        finding_candidate: CompletedFindingCandidate::Pending(candidate),
    };
    let mut directory_ledger =
        DirectoryAssignmentLedger::open(storage.path().join("ledger")).expect("directory ledger");
    assert_eq!(
        directory_ledger
            .compare_exchange_attempt(key, None, Some(completed))
            .expect("retain lock-order candidate"),
        AttemptStateCas::Advanced
    );

    let (ledger_requested_tx, ledger_requested_rx) = mpsc::channel();
    let shared_ledger = LockOrderDirectoryLedger {
        inner: Arc::new(Mutex::new(directory_ledger)),
        gate: Arc::new(Mutex::new(())),
        acquisition_requested: ledger_requested_tx,
    };
    let gate = shared_ledger.gate.clone();
    let blocker = gate.lock().expect("block ledger acquisition");
    let (publication_requested_tx, publication_requested_rx) = mpsc::channel();
    let (inventory_acquired_tx, inventory_acquired_rx) = mpsc::channel();
    refs.arm(publication_requested_tx, inventory_acquired_tx);

    let (gc_done_tx, gc_done_rx) = mpsc::channel();
    let gc_repository = repository.clone();
    let gc_refs = refs.clone();
    let gc_blobs = blobs.clone();
    let mut gc_ledger = shared_ledger.clone();
    let gc_thread = thread::spawn(move || {
        let physical = CampaignGcPhysicalStore::new("finding-lock-order", gc_blobs.as_ref())
            .expect("lock-order physical store");
        plan_single_host_campaign_gc(
            &gc_repository,
            gc_refs.as_ref(),
            &mut gc_ledger,
            None,
            None,
            hash("crucible.test.finding-lock-order.v1", 0x77),
            &[physical],
        )
        .expect("plan lock-order GC");
        gc_done_tx.send(()).expect("signal GC completion");
    });
    inventory_acquired_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("GC acquires directory ref inventory first");
    ledger_requested_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("GC requests ledger after ref inventory");

    let (ack_done_tx, ack_done_rx) = mpsc::channel();
    let ack_repository = repository.clone();
    let mut ack_ledger = shared_ledger;
    let ack_thread = thread::spawn(move || {
        let outcome = acknowledge_incorporated_finding_candidate(
            &ack_repository,
            &mut ack_ledger,
            &campaign,
            key,
            execution,
            observation,
            publication.finding,
            candidate,
        )
        .expect("acknowledge after concurrent GC");
        assert!(matches!(
            outcome,
            FindingCandidateRetentionOutcome::Released(_)
        ));
        ack_done_tx
            .send(())
            .expect("signal acknowledgement completion");
    });
    publication_requested_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("acknowledgement requests publication guard");
    assert_eq!(ledger_requested_rx.try_recv(), Err(TryRecvError::Empty));

    drop(blocker);
    gc_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("GC completes after ledger release");
    ack_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("acknowledgement completes after GC releases refs");
    gc_thread.join().expect("join GC thread");
    ack_thread.join().expect("join acknowledgement thread");
}

#[test]
fn completed_status_and_control_fail_closed_on_missing_candidate_descendant() {
    let storage = tempfile::tempdir().expect("missing candidate storage");
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "missing-candidate-descendant",
        storage.path().join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(storage.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs));
    let (lineage, attempt, observation, candidate) = publish_pending_finding_fixture(&repository);
    let request = pending_finding_request(lineage, attempt);
    let execution = ExecutionId::from_bytes([0x67; 16]).expect("execution");
    let completed = AttemptRuntimeState::Completed {
        execution_basis: request.execution_basis_digest(),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: request.daemon_epoch(),
        execution,
        observation,
        finding_candidate: CompletedFindingCandidate::Pending(candidate),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(
                AttemptExecutionKey::new(lineage, attempt),
                None,
                Some(completed),
            )
            .expect("retain missing candidate fixture"),
        AttemptStateCas::Advanced
    );

    let lineage_record = repository
        .load_lineage(lineage)
        .expect("load candidate lineage");
    let admission = RepositoryAttemptAdmission::new(
        Arc::clone(&repository),
        ExecutorCompatibilityProfile::from_lineage(&lineage_record),
    );
    let mut supervisor = LocalExecutorSupervisor::new(
        ledger,
        admission,
        request.daemon_epoch(),
        ExecutorCapacity::new(1, 1, 4096, 8192, 64).expect("executor capacity"),
    );
    let status = GetAttemptExecutionRequest::new(&request, execution).expect("status request");
    let completed_status = ExecutorStatusService::get_attempt_execution(&mut supervisor, &status)
        .expect("complete candidate status");
    assert_eq!(
        completed_status.disposition(),
        GetAttemptExecutionDisposition::Completed { observation }
    );
    assert_eq!(completed_status.finding_candidate(), Some(candidate));
    let checkpoint =
        CheckpointAttemptExecutionRequest::new(&request, execution).expect("checkpoint request");
    let completed_checkpoint =
        ExecutorControlService::checkpoint_attempt_execution(&mut supervisor, &checkpoint)
            .expect("complete candidate checkpoint response");
    assert_eq!(
        completed_checkpoint.disposition(),
        CheckpointAttemptExecutionDisposition::AlreadyCompleted { observation }
    );
    assert_eq!(completed_checkpoint.finding_candidate(), Some(candidate));
    let cancel = CancelAttemptExecutionRequest::new(&request, execution).expect("cancel request");
    let completed_cancel =
        ExecutorControlService::cancel_attempt_execution(&mut supervisor, &cancel)
            .expect("complete candidate cancel response");
    assert_eq!(
        completed_cancel.disposition(),
        CancelAttemptExecutionDisposition::AlreadyCompleted { observation }
    );
    assert_eq!(completed_cancel.finding_candidate(), Some(candidate));

    let bundle = repository
        .load_finding_candidate_bundle(candidate)
        .expect("load complete candidate before fault");
    let mut inventory = blobs
        .acquire_inventory_fence()
        .expect("acquire candidate fault inventory");
    assert_eq!(
        inventory
            .delete_candidate(bundle.minimized().content_id())
            .expect("delete one candidate descendant"),
        PlannedDeleteDisposition::Deleted
    );
    drop(inventory);

    assert!(matches!(
        ExecutorStatusService::get_attempt_execution(&mut supervisor, &status),
        Err(LocalExecutorError::CompletionValidation {
            reason: CompletionValidationFailure::UnavailableInput,
        })
    ));
    assert!(matches!(
        ExecutorControlService::checkpoint_attempt_execution(&mut supervisor, &checkpoint),
        Err(LocalExecutorError::CompletionValidation {
            reason: CompletionValidationFailure::UnavailableInput,
        })
    ));
    assert!(matches!(
        ExecutorControlService::cancel_attempt_execution(&mut supervisor, &cancel),
        Err(LocalExecutorError::CompletionValidation {
            reason: CompletionValidationFailure::UnavailableInput,
        })
    ));
}

#[test]
fn hot_checkpoint_fallback_is_a_fenced_gc_root_until_durable_removal() {
    let blobs = Arc::new(MemoryBlobBackend::new("hot-gc-primary", 8 * 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let scenario = ScenarioDefId::from_hash(hash("crucible.test.gc.hot-scenario.v1", 1));
    let scenario_artifact = repository
        .publish_scenario_artifact(scenario, 1, b"hot scenario".to_vec())
        .expect("publish hot scenario");
    let configuration =
        ConfigurationId::from_hash(hash("crucible.test.gc.hot-configuration.v1", 2));
    let configuration_artifact = repository
        .publish_configuration_artifact(
            scenario,
            scenario_artifact,
            configuration,
            1,
            b"hot configuration".to_vec(),
        )
        .expect("publish hot configuration");

    let lineage_digest = hash("crucible.test.gc.hot-lineage.v1", 3);
    let lineage = CampaignLineageId::parse(&format!(
        "crucible.campaign.lineage@campaign-fact.1.{}",
        lineage_digest.to_hex()
    ))
    .expect("lineage");
    let record = HotCheckpointFallbackRecord::new(
        QemuHotForkTemplateKey::new(
            lineage,
            ContentHash::from_bytes(b"hot configuration semantic basis"),
        ),
        HotCheckpointFallback::Thin(configuration_artifact),
    );
    let slot = HotCheckpointFallbackSlot::new(7).expect("fallback slot");
    let hot = MemoryHotCheckpointFallbackRetentionStore::new();
    assert_eq!(
        hot.compare_exchange_fallback(slot, None, Some(record))
            .expect("retain fallback"),
        HotCheckpointFallbackRetentionCas::Advanced
    );

    let mut ledger = MemoryAssignmentLedger::default();
    let graph = hash("crucible.test.gc.hot-store-graph.v1", 4);
    let physical =
        CampaignGcPhysicalStore::new("hot-gc-primary", blobs.as_ref()).expect("hot physical store");
    let retained = plan_single_host_campaign_gc_with_physical_and_hot_checkpoints(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        CampaignGcHotCheckpointRoots::new(&hot),
        graph,
        &[physical],
    )
    .expect("plan with retained fallback");
    assert_eq!(
        retained.roots().iter().collect::<Vec<_>>(),
        vec![configuration_artifact.content_id()]
    );
    assert!(retained.candidates().is_empty());

    assert_eq!(
        hot.compare_exchange_fallback(slot, Some(record), None)
            .expect("release fallback"),
        HotCheckpointFallbackRetentionCas::Advanced
    );
    let released = plan_single_host_campaign_gc_with_physical_and_hot_checkpoints(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        CampaignGcHotCheckpointRoots::new(&hot),
        graph,
        &[physical],
    )
    .expect("plan after fallback release");
    assert_eq!(released.candidates().len(), 2);

    let temp = tempfile::TempDir::new().expect("temporary hot GC journal");
    let (mut journal, disposition) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &released)
            .expect("create hot GC journal");
    assert_eq!(disposition, CampaignGcJournalCreateDisposition::Created);
    assert_eq!(
        hot.compare_exchange_fallback(slot, None, Some(record))
            .expect("restore fallback before apply"),
        HotCheckpointFallbackRetentionCas::Advanced
    );
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut journal,
            CampaignGcApplySources::new_with_hot_checkpoints(
                &repository,
                refs.as_ref(),
                &mut ledger,
                None,
                None,
                Some(&hot),
            ),
            graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::RootSetChanged)
    ));
    assert_eq!(blobs.object_count().expect("object count"), 2);
}

#[test]
fn direct_transfer_root_promoted_to_hot_root_revalidates_its_closure() {
    let blobs = Arc::new(MemoryBlobBackend::new(
        "combined-hot-transfer-gc",
        1024 * 1024,
    ));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());

    let transfer_scenario =
        ScenarioDefId::from_hash(hash("crucible.test.gc.transfer-scenario.v1", 1));
    let transfer_scenario_artifact = repository
        .publish_scenario_artifact(transfer_scenario, 1, b"transfer scenario".to_vec())
        .expect("transfer scenario artifact");
    let transfer_configuration =
        ConfigurationId::from_hash(hash("crucible.test.gc.transfer-configuration.v1", 2));
    let transfer_configuration_artifact = repository
        .publish_configuration_artifact(
            transfer_scenario,
            transfer_scenario_artifact,
            transfer_configuration,
            1,
            b"transfer configuration".to_vec(),
        )
        .expect("transfer configuration artifact");

    let hot_scenario = ScenarioDefId::from_hash(hash("crucible.test.gc.hot-scenario.v1", 3));
    let hot_scenario_artifact = repository
        .publish_scenario_artifact(hot_scenario, 1, b"hot scenario".to_vec())
        .expect("hot scenario artifact");
    let hot_configuration =
        ConfigurationId::from_hash(hash("crucible.test.gc.hot-configuration.v1", 4));
    let hot_configuration_artifact = repository
        .publish_configuration_artifact(
            hot_scenario,
            hot_scenario_artifact,
            hot_configuration,
            1,
            b"hot configuration".to_vec(),
        )
        .expect("hot configuration artifact");

    let hot = MemoryHotCheckpointFallbackRetentionStore::new();
    let lineage = CampaignLineageId::parse(&format!(
        "crucible.campaign.lineage@campaign-fact.1.{}",
        hash("crucible.test.gc.combined-lineage.v1", 5).to_hex()
    ))
    .expect("lineage");
    let hot_record = HotCheckpointFallbackRecord::new(
        QemuHotForkTemplateKey::new(
            lineage,
            ContentHash::from_bytes(b"combined hot semantic basis"),
        ),
        HotCheckpointFallback::Thin(hot_configuration_artifact),
    );
    let hot_slot = HotCheckpointFallbackSlot::new(8).expect("hot slot");
    assert_eq!(
        hot.compare_exchange_fallback(hot_slot, None, Some(hot_record))
            .expect("install hot fallback"),
        HotCheckpointFallbackRetentionCas::Advanced
    );

    let transfers = TestCampaignTransferRoots::default();
    let transfer_length = blobs
        .read(transfer_configuration_artifact.content_id(), None)
        .expect("transfer root")
        .logical_length();
    transfers.replace(vec![CampaignTransferRetentionRoot::new(
        transfer_configuration_artifact.content_id(),
        transfer_length,
    )]);
    let mut ledger = MemoryAssignmentLedger::default();
    let graph = hash("crucible.test.gc.combined-store-graph.v1", 6);
    let physical = CampaignGcPhysicalStore::new("combined-hot-transfer-gc", blobs.as_ref())
        .expect("physical store");
    let prepared = plan_single_host_campaign_gc_with_physical_and_hot_checkpoints(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers),
        graph,
        &[physical],
    )
    .expect("plan combined hot and transfer roots");
    assert!(
        prepared
            .roots()
            .iter()
            .any(|root| root == hot_configuration_artifact.content_id())
    );
    assert!(
        prepared
            .roots()
            .iter()
            .any(|root| root == transfer_configuration_artifact.content_id())
    );
    assert!(
        prepared
            .candidates()
            .iter()
            .any(|candidate| candidate.id() == transfer_scenario_artifact.content_id())
    );

    let temporary = tempfile::tempdir().expect("temporary GC journal");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temporary.path().join("journal"), &prepared)
            .expect("create GC journal");
    transfers.replace(Vec::new());
    let promoted_record = HotCheckpointFallbackRecord::new(
        QemuHotForkTemplateKey::new(
            lineage,
            ContentHash::from_bytes(b"promoted transfer semantic basis"),
        ),
        HotCheckpointFallback::Thin(transfer_configuration_artifact),
    );
    assert_eq!(
        hot.compare_exchange_fallback(
            HotCheckpointFallbackSlot::new(9).expect("promotion slot"),
            None,
            Some(promoted_record),
        )
        .expect("promote transfer root"),
        HotCheckpointFallbackRetentionCas::Advanced
    );

    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut journal,
            CampaignGcApplySources::new_with_retention_sources(
                &repository,
                refs.as_ref(),
                &mut ledger,
                None,
                CampaignGcHotCheckpointRoots::with_transfers(&hot, &transfers).into_sources(),
            ),
            graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::CandidateBecameReachable { id })
            if id == transfer_scenario_artifact.content_id()
    ));
    assert!(
        blobs
            .contains(transfer_scenario_artifact.content_id())
            .expect("promoted child retained")
    );
}

#[test]
fn write_back_journal_roots_are_planned_and_revalidated_before_gc_deletion() {
    let temp = tempfile::TempDir::new().expect("temporary write-back GC root");
    let staging_root = temp.path().join("staging");
    let archive_root = temp.path().join("archive");
    let journal_root = temp.path().join("write-back-journal");
    let write_back = StoreNodeId::new("write-back").expect("write-back node");
    let staging = StoreNodeId::new("staging").expect("staging node");
    let archive = StoreNodeId::new("archive").expect("archive node");
    let graph = Arc::new(
        StoreGraph::build(StoreGraphConfig {
            root: write_back.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    write_back,
                    StoreNodeSpec::WriteBack {
                        staging: staging.clone(),
                        destination: archive.clone(),
                        journal_root,
                        maximum_pending_objects: 16,
                        maximum_pending_bytes: 1024 * 1024,
                    },
                ),
                (
                    staging,
                    StoreNodeSpec::Directory {
                        root: staging_root.clone(),
                    },
                ),
                (
                    archive,
                    StoreNodeSpec::Directory {
                        root: archive_root.clone(),
                    },
                ),
            ]),
        })
        .expect("write-back store graph"),
    );
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(graph.clone(), refs.clone());

    let pending = ContentEnvelope::new(
        "crucible.test.gc-write-back-pending",
        1,
        BTreeSet::new(),
        b"pending".to_vec(),
    )
    .expect("pending envelope");
    let pending_id = pending.content_id(ObjectKind::Trace);
    graph
        .put_if_absent(
            pending_id,
            &BlobHandle::from_bytes(pending.canonical_bytes()),
        )
        .expect("stage pending root");
    let orphan = ContentEnvelope::new(
        "crucible.test.gc-write-back-orphan",
        1,
        BTreeSet::new(),
        b"orphan".to_vec(),
    )
    .expect("orphan envelope");
    let orphan_id = orphan.content_id(ObjectKind::Trace);
    let staging_leaf = DirectoryBlobBackend::new("staging", &staging_root);
    staging_leaf
        .put_if_absent(orphan_id, &BlobHandle::from_bytes(orphan.canonical_bytes()))
        .expect("store unjournaled orphan");
    let archive_leaf = DirectoryBlobBackend::new("archive", &archive_root);

    let mut ledger = MemoryAssignmentLedger::default();
    let archive_physical =
        CampaignGcPhysicalStore::new("archive", &archive_leaf).expect("archive physical");
    let staging_physical =
        CampaignGcPhysicalStore::new("staging", &staging_leaf).expect("staging physical");
    let graph_id = hash("crucible.test.gc.write-back-store-graph.v1", 0x44);
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        Some(graph.as_ref()),
        None,
        graph_id,
        &[archive_physical, staging_physical],
    )
    .expect("plan write-back-aware GC");
    assert_eq!(
        prepared.roots().iter().collect::<Vec<_>>(),
        vec![pending_id]
    );
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan_id
    );

    let (mut gc_journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("gc-journal"), &prepared)
            .expect("create GC journal");
    assert_eq!(
        graph
            .flush_write_back(1)
            .expect("complete pending transfer")
            .completed(),
        1
    );
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut gc_journal,
            CampaignGcApplySources::new(
                &repository,
                refs.as_ref(),
                &mut ledger,
                Some(graph.as_ref()),
                None,
            ),
            graph_id,
            &[archive_physical, staging_physical],
        ),
        Err(CampaignGcApplyError::RootSetChanged)
    ));
    assert!(staging_leaf.contains(orphan_id).expect("orphan retained"));
    assert_eq!(gc_journal.phase(), CampaignGcJournalPhase::Planned);
}

#[test]
fn external_journal_reopens_exact_plan_and_durable_phase() {
    let prepared = journal_plan_fixture(0x41);
    let different = journal_plan_fixture(0x42);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let root = temp.path().join("gc-journal");

    let (mut journal, disposition) =
        DirectoryCampaignGcJournal::create(&root, &prepared).expect("create journal");
    assert_eq!(disposition, CampaignGcJournalCreateDisposition::Created);
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(journal.plan(), prepared.plan());
    assert_eq!(journal.roots(), prepared.roots());
    assert_eq!(journal.candidates(), prepared.candidates());
    assert_eq!(
        journal.begin_apply().expect("begin apply"),
        CampaignGcJournalTransition::Advanced
    );
    assert_eq!(
        journal.begin_apply().expect("repeat begin apply"),
        CampaignGcJournalTransition::Existing
    );
    let retained_lock_description = journal
        .duplicate_lock_for_test()
        .expect("duplicate GC journal lock descriptor");
    drop(journal);

    let lock_probe = super::journal::try_acquire_lock_for_test(&root)
        .expect("logical owner drop releases retained GC lock description");
    drop(lock_probe);
    let mut reopened = DirectoryCampaignGcJournal::open(&root).expect("reopen applying journal");
    assert_eq!(reopened.phase(), CampaignGcJournalPhase::Applying);
    assert_eq!(
        reopened.mark_complete().expect("complete apply"),
        CampaignGcJournalTransition::Advanced
    );
    assert_eq!(
        reopened.mark_complete().expect("repeat completion"),
        CampaignGcJournalTransition::Existing
    );
    drop(reopened);

    let (complete, disposition) =
        DirectoryCampaignGcJournal::create(&root, &prepared).expect("reopen exact journal");
    assert_eq!(disposition, CampaignGcJournalCreateDisposition::Existing);
    assert_eq!(complete.phase(), CampaignGcJournalPhase::Complete);
    drop(complete);
    assert!(matches!(
        DirectoryCampaignGcJournal::create(&root, &different),
        Err(CampaignGcJournalError::PlanMismatch)
    ));
    drop(retained_lock_description);
}

#[test]
fn external_journal_rejects_incomplete_and_corrupt_state() {
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let incomplete = temp.path().join("incomplete");
    fs::create_dir(&incomplete).expect("create incomplete journal");
    assert!(matches!(
        DirectoryCampaignGcJournal::open(&incomplete),
        Err(CampaignGcJournalError::Incomplete)
    ));

    let prepared = journal_plan_fixture(0x51);
    let complete = temp.path().join("complete");
    let (journal, _) =
        DirectoryCampaignGcJournal::create(&complete, &prepared).expect("create complete journal");
    drop(journal);
    fs::write(complete.join("state-v1"), b"corrupt").expect("corrupt journal state");
    assert!(matches!(
        DirectoryCampaignGcJournal::open(&complete),
        Err(CampaignGcJournalError::InvalidState)
    ));
}

#[test]
fn apply_revalidates_every_basis_then_deletes_and_completes() {
    let mut fixture = apply_fixture(2);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &fixture.prepared)
            .expect("create apply journal");
    let physical = CampaignGcPhysicalStore::new("apply-primary", fixture.blobs.as_ref())
        .expect("apply physical store");

    let report = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut fixture.ledger,
            None,
            None,
        ),
        fixture.graph,
        &[physical],
    )
    .expect("apply exact plan");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 2);
    assert_eq!(
        report.logical_bytes(),
        fixture.prepared.candidates().logical_bytes()
    );
    assert_eq!(fixture.blobs.object_count().expect("object count"), 0);
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);

    let replay = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut fixture.ledger,
            None,
            None,
        ),
        fixture.graph,
        &[physical],
    )
    .expect("replay completed apply");
    assert_eq!(replay.status(), CampaignGcApplyStatus::AlreadyComplete);
    assert_eq!(replay.candidates(), report.candidates());
}

#[test]
fn stale_ref_and_blob_generations_fail_before_deletion() {
    let mut ref_fixture = apply_fixture(1);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut ref_journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("ref-journal"), &ref_fixture.prepared)
            .expect("create ref-stale journal");
    let orphan = ref_fixture
        .prepared
        .candidates()
        .iter()
        .next()
        .expect("orphan candidate")
        .id();
    ref_fixture
        .refs
        .compare_exchange(
            &RefName::new("retained/new-root").expect("new ref"),
            None,
            orphan,
        )
        .expect("advance ref generation");
    let physical = CampaignGcPhysicalStore::new("apply-primary", ref_fixture.blobs.as_ref())
        .expect("ref-stale physical store");
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut ref_journal,
            CampaignGcApplySources::new(
                &ref_fixture.repository,
                ref_fixture.refs.as_ref(),
                &mut ref_fixture.ledger,
                None,
                None,
            ),
            ref_fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::RefBasisChanged)
    ));
    assert_eq!(ref_journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(ref_fixture.blobs.object_count().expect("object count"), 1);

    let mut blob_fixture = apply_fixture(1);
    let (mut blob_journal, _) = DirectoryCampaignGcJournal::create(
        temp.path().join("blob-journal"),
        &blob_fixture.prepared,
    )
    .expect("create blob-stale journal");
    let additional_bytes = b"post-plan object";
    let additional = ContentId::for_bytes(ObjectKind::Trace, 1, additional_bytes);
    blob_fixture
        .blobs
        .put_if_absent(additional, &BlobHandle::from_bytes(additional_bytes))
        .expect("advance blob generation");
    let physical = CampaignGcPhysicalStore::new("apply-primary", blob_fixture.blobs.as_ref())
        .expect("blob-stale physical store");
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut blob_journal,
            CampaignGcApplySources::new(
                &blob_fixture.repository,
                blob_fixture.refs.as_ref(),
                &mut blob_fixture.ledger,
                None,
                None,
            ),
            blob_fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::PhysicalBasisChanged { .. })
    ));
    assert_eq!(blob_journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(blob_fixture.blobs.object_count().expect("object count"), 2);
}

#[test]
fn stale_ledger_generation_fails_before_deletion() {
    let blobs = Arc::new(MemoryBlobBackend::new("ledger-primary", 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let orphan_bytes = b"ledger stale orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store ledger stale orphan");
    let mut ledger = SyntheticRetentionLedger { generation: 1 };
    let graph = hash("crucible.test.gc.ledger-store-graph.v1", 0x65);
    let physical = CampaignGcPhysicalStore::new("ledger-primary", blobs.as_ref())
        .expect("ledger physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("plan ledger stale GC");
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &prepared)
            .expect("create ledger stale journal");
    ledger.generation = 2;

    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut journal,
            CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None,),
            graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::LedgerBasisChanged)
    ));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Planned);
    assert!(blobs.contains(orphan).expect("orphan retained"));
}

#[test]
fn interrupted_apply_retains_journal_and_requires_a_fresh_plan() {
    let mut fixture = apply_fixture(2);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &fixture.prepared)
            .expect("create interrupted journal");
    let failing = FailAfterFirstDeleteAdmin {
        inner: fixture.blobs.as_ref(),
    };
    let physical =
        CampaignGcPhysicalStore::new("apply-primary", &failing).expect("failing physical store");
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut journal,
            CampaignGcApplySources::new(
                &fixture.repository,
                fixture.refs.as_ref(),
                &mut fixture.ledger,
                None,
                None,
            ),
            fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::Blob { .. })
    ));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Applying);
    assert_eq!(fixture.blobs.object_count().expect("object count"), 1);
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut journal,
            CampaignGcApplySources::new(
                &fixture.repository,
                fixture.refs.as_ref(),
                &mut fixture.ledger,
                None,
                None,
            ),
            fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::InterruptedJournal)
    ));
    assert_eq!(fixture.blobs.object_count().expect("object count"), 1);
}

#[test]
fn directory_plan_journal_and_apply_survive_full_backend_restart() {
    let temp = tempfile::TempDir::new().expect("temporary GC root");
    let blob_root = temp.path().join("blobs");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let graph = hash("crucible.test.gc.directory-store-graph.v1", 0x71);

    let blobs = Arc::new(DirectoryBlobBackend::new("directory-primary", &blob_root));
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-directory-live",
        1,
        BTreeSet::new(),
        b"live".to_vec(),
    )
    .expect("live envelope");
    let live_id = live.content_id(ObjectKind::Trace);
    blobs
        .put_if_absent(live_id, &BlobHandle::from_bytes(live.canonical_bytes()))
        .expect("store live directory object");
    refs.compare_exchange(
        &RefName::new("retained/directory-gc").expect("directory ref"),
        None,
        live_id,
    )
    .expect("publish directory root");
    let orphan_bytes = b"directory orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store directory orphan");
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open directory ledger");
    let physical = CampaignGcPhysicalStore::new("directory-primary", blobs.as_ref())
        .expect("directory physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("plan directory GC");
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create directory journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(blobs);

    let blobs = Arc::new(DirectoryBlobBackend::new("directory-primary", &blob_root));
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let mut ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen directory ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen directory journal");
    let physical = CampaignGcPhysicalStore::new("directory-primary", blobs.as_ref())
        .expect("reopened physical store");
    let report = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None),
        graph,
        &[physical],
    )
    .expect("apply after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(blobs.contains(live_id).expect("live placement"));
    assert!(!blobs.contains(orphan).expect("orphan placement"));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn compressed_graph_admin_drives_plaintext_accounted_gc_across_restart() {
    let temp = tempfile::TempDir::new().expect("temporary compressed GC root");
    let blob_root = temp.path().join("compressed");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let compressed_node = StoreNodeId::new("compressed-primary").expect("compressed node");
    let graph_config = || StoreGraphConfig {
        root: compressed_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            compressed_node.clone(),
            StoreNodeSpec::CompressedDirectory {
                root: blob_root.clone(),
                maximum_logical_object_bytes: 1024 * 1024,
            },
        )]),
    };

    let (graph, admin) = StoreGraph::build_with_admin(graph_config()).expect("compressed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-compressed-live",
        1,
        BTreeSet::new(),
        vec![b'L'; 64 * 1024],
    )
    .expect("live envelope");
    let live_bytes = live.canonical_bytes();
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live_bytes.clone()))
        .expect("store live compressed object");
    refs.compare_exchange(
        &RefName::new("retained/compressed-gc").expect("compressed ref"),
        None,
        live_id,
    )
    .expect("publish compressed root");
    let orphan_bytes = vec![b'O'; 128 * 1024];
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.clone()))
        .expect("store compressed orphan");

    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open compressed ledger");
    let prepared = super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan compressed GC");
    assert_eq!(prepared.plan().physical().len(), 1);
    assert_eq!(prepared.plan().physical()[0].objects(), 2);
    assert_eq!(
        prepared.plan().physical()[0].logical_bytes(),
        u64::try_from(live_bytes.len() + orphan_bytes.len()).expect("logical byte total")
    );
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().logical_bytes(),
        u64::try_from(orphan_bytes.len()).expect("orphan logical bytes")
    );
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create compressed GC journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);

    let (graph, admin) =
        StoreGraph::build_with_admin(graph_config()).expect("restart compressed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen compressed ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen compressed GC journal");
    let report = super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply compressed GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 1);
    assert_eq!(
        report.logical_bytes(),
        u64::try_from(orphan_bytes.len()).expect("reported orphan bytes")
    );
    assert!(graph.contains(live_id).expect("live compressed placement"));
    assert!(!graph.contains(orphan).expect("orphan compressed placement"));
    assert_eq!(
        graph
            .read(live_id, None)
            .expect("read retained compressed object")
            .read_all(1024 * 1024)
            .expect("authenticate retained compressed object"),
        live_bytes
    );
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn encrypted_graph_admin_drives_plaintext_accounted_gc_across_restart() {
    run_encrypted_graph_gc_restart(false);
}

#[test]
fn compressed_encrypted_graph_admin_drives_plaintext_accounted_gc_across_restart() {
    run_encrypted_graph_gc_restart(true);
}

fn run_encrypted_graph_gc_restart(compressed: bool) {
    let temp = tempfile::TempDir::new().expect("temporary encrypted GC root");
    let blob_root = temp.path().join("encrypted");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let encrypted_node = StoreNodeId::new("encrypted-primary").expect("encrypted node");
    let key_id = StoreEncryptionKeyId::new("gc-key-1").expect("GC key ID");
    let graph_config = || StoreGraphConfig {
        root: encrypted_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            encrypted_node.clone(),
            if compressed {
                StoreNodeSpec::CompressedEncryptedDirectory {
                    root: blob_root.clone(),
                    maximum_logical_object_bytes: 1024 * 1024,
                    key_id: key_id.clone(),
                }
            } else {
                StoreNodeSpec::EncryptedDirectory {
                    root: blob_root.clone(),
                    maximum_logical_object_bytes: 1024 * 1024,
                    key_id: key_id.clone(),
                }
            },
        )]),
    };
    let graph_keys = || {
        let mut keys = StoreGraphKeyring::new();
        keys.insert(
            key_id.clone(),
            StoreEncryptionKey::new([0x6d; 32]).expect("GC key"),
        )
        .expect("insert GC key");
        keys
    };

    let keys = graph_keys();
    let (graph, admin) =
        StoreGraph::build_with_admin_and_keys(graph_config(), &keys).expect("encrypted graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-encrypted-live",
        1,
        BTreeSet::new(),
        vec![b'L'; 64 * 1024],
    )
    .expect("live envelope");
    let live_bytes = live.canonical_bytes();
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live_bytes.clone()))
        .expect("store live encrypted object");
    refs.compare_exchange(
        &RefName::new("retained/encrypted-gc").expect("encrypted ref"),
        None,
        live_id,
    )
    .expect("publish encrypted root");
    let orphan_bytes = vec![b'O'; 128 * 1024];
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.clone()))
        .expect("store encrypted orphan");

    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open encrypted ledger");
    let prepared = super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan encrypted GC");
    assert_eq!(prepared.plan().physical()[0].objects(), 2);
    assert_eq!(
        prepared.plan().physical()[0].logical_bytes(),
        u64::try_from(live_bytes.len() + orphan_bytes.len()).expect("logical byte total")
    );
    assert_eq!(prepared.candidates().len(), 1);
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create encrypted GC journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);
    drop(keys);

    let keys = graph_keys();
    let (graph, admin) = StoreGraph::build_with_admin_and_keys(graph_config(), &keys)
        .expect("restart encrypted graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen encrypted ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen encrypted GC journal");
    let report = super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply encrypted GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 1);
    assert_eq!(
        report.logical_bytes(),
        u64::try_from(orphan_bytes.len()).expect("reported orphan bytes")
    );
    assert!(graph.contains(live_id).expect("live encrypted placement"));
    assert!(!graph.contains(orphan).expect("orphan encrypted placement"));
    assert_eq!(
        graph
            .read(live_id, None)
            .expect("read retained encrypted object")
            .read_all(1024 * 1024)
            .expect("authenticate retained encrypted object"),
        live_bytes
    );
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn logical_quota_graph_gc_reclaims_admission_capacity_across_restart() {
    let temp = tempfile::TempDir::new().expect("temporary quota GC root");
    let blob_root = temp.path().join("objects");
    let quota_root = temp.path().join("quota");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let quota_node = StoreNodeId::new("quota-primary").expect("quota node");
    let directory_node = StoreNodeId::new("directory-child").expect("directory child");
    let graph_config = || StoreGraphConfig {
        root: quota_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota_node.clone(),
                StoreNodeSpec::LogicalQuota {
                    child: directory_node.clone(),
                    state_root: quota_root.clone(),
                    maximum_objects: 2,
                    maximum_logical_bytes: 1024 * 1024,
                },
            ),
            (
                directory_node.clone(),
                StoreNodeSpec::Directory {
                    root: blob_root.clone(),
                },
            ),
        ]),
    };

    let (graph, admin) = StoreGraph::build_with_admin(graph_config()).expect("quota GC graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-quota-live",
        1,
        BTreeSet::new(),
        b"quota live".to_vec(),
    )
    .expect("quota live envelope");
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live.canonical_bytes()))
        .expect("store quota live object");
    refs.compare_exchange(
        &RefName::new("retained/quota-gc").expect("quota ref"),
        None,
        live_id,
    )
    .expect("publish quota root");
    let orphan_bytes = b"quota orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store quota orphan");
    let rejected_bytes = b"quota initially full";
    let rejected = ContentId::for_bytes(ObjectKind::Trace, 1, rejected_bytes);
    assert!(matches!(
        graph.put_if_absent(rejected, &BlobHandle::from_bytes(rejected_bytes)),
        Err(StoreError::Quota)
    ));

    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &quota_node);
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open quota GC ledger");
    let prepared = super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan quota GC");
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create quota GC journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);

    let (graph, admin) =
        StoreGraph::build_with_admin(graph_config()).expect("restart quota GC graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("reopen quota GC ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen quota GC journal");
    let report = super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply quota GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(graph.contains(live_id).expect("quota live placement"));
    assert!(!graph.contains(orphan).expect("quota orphan placement"));
    graph
        .put_if_absent(rejected, &BlobHandle::from_bytes(rejected_bytes))
        .expect("GC reclaimed quota admission capacity");
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn packed_graph_admin_drives_restart_safe_logical_gc_without_deleting_live_pack_bytes() {
    let temp = tempfile::TempDir::new().expect("temporary packed GC root");
    let pack_root = temp.path().join("packs");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let packed_node = StoreNodeId::new("packed-primary").expect("packed node");
    let graph_config = || StoreGraphConfig {
        root: packed_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            packed_node.clone(),
            StoreNodeSpec::Packed {
                root: pack_root.clone(),
                target_pack_bytes: 64 * 1024,
            },
        )]),
    };

    let (graph, admin) = StoreGraph::build_with_admin(graph_config()).expect("packed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-packed-live",
        1,
        BTreeSet::new(),
        b"live".to_vec(),
    )
    .expect("live envelope");
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live.canonical_bytes()))
        .expect("store live packed object");
    refs.compare_exchange(
        &RefName::new("retained/packed-gc").expect("packed ref"),
        None,
        live_id,
    )
    .expect("publish packed root");
    let orphan_bytes = b"packed orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store packed orphan");

    let packed = PackedBlobBackend::open("packed-primary", &pack_root, 64 * 1024)
        .expect("packed maintenance leaf");
    let repack = packed.plan_repack().expect("packed coalescing plan");
    let repacked = packed
        .apply_repack(&repack)
        .expect("coalesce packed objects");
    assert_eq!(repacked.after().packs(), 1);
    assert_eq!(repacked.after().logical_objects(), 2);

    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open packed ledger");
    assert_eq!(admin.physical().len(), 1);
    let prepared = super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan packed GC");
    assert_eq!(
        prepared.plan().store_graph(),
        CampaignHash::from_bytes(admin.configuration_id().as_bytes())
    );
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create packed GC journal");
    drop(journal);

    let verified = StoreNodeId::new("verified-root").expect("verified root");
    let (different_graph, different_admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: verified.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                verified,
                StoreNodeSpec::Verified {
                    child: packed_node.clone(),
                },
            ),
            (
                packed_node.clone(),
                StoreNodeSpec::Packed {
                    root: pack_root.clone(),
                    target_pack_bytes: 64 * 1024,
                },
            ),
        ]),
    })
    .expect("different composition over same packed leaf");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen planned journal");
    assert!(matches!(
        super::apply_single_host_campaign_gc(
            &mut journal,
            &repository,
            refs.as_ref(),
            &mut ledger,
            None,
            None,
            &different_admin,
        ),
        Err(CampaignGcApplyError::StoreGraphChanged)
    ));
    assert!(graph.contains(orphan).expect("orphan retained on mismatch"));
    drop(journal);
    drop(different_admin);
    drop(different_graph);

    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);
    drop(packed);

    let (graph, admin) =
        StoreGraph::build_with_admin(graph_config()).expect("restart packed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("reopen packed ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen packed GC journal");
    let report = super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply packed GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(graph.contains(live_id).expect("live packed placement"));
    assert!(!graph.contains(orphan).expect("orphan packed placement"));
    let packed = PackedBlobBackend::open("packed-primary", &pack_root, 64 * 1024)
        .expect("reopen packed accounting");
    let accounting = packed.accounting().expect("packed post-GC accounting");
    assert_eq!(accounting.logical_objects(), 1);
    assert_eq!(accounting.packs(), 1);
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

struct ApplyFixture {
    blobs: Arc<MemoryBlobBackend>,
    refs: Arc<MemoryRefBackend>,
    repository: CampaignRepository,
    ledger: MemoryAssignmentLedger,
    prepared: CampaignGcPreparedPlan,
    graph: CampaignHash,
}

fn apply_fixture(orphan_count: u8) -> ApplyFixture {
    let blobs = Arc::new(MemoryBlobBackend::new("apply-primary", 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    for index in 0..orphan_count {
        let bytes = [index; 8];
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        blobs
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("store apply orphan");
    }
    let mut ledger = MemoryAssignmentLedger::default();
    let graph = hash("crucible.test.gc.apply-store-graph.v1", 0x61);
    let physical = CampaignGcPhysicalStore::new("apply-primary", blobs.as_ref())
        .expect("apply fixture physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("prepare apply fixture");
    ApplyFixture {
        blobs,
        refs,
        repository,
        ledger,
        prepared,
        graph,
    }
}

struct FailAfterFirstDeleteAdmin<'a> {
    inner: &'a MemoryBlobBackend,
}

impl BlobStoreAdmin for FailAfterFirstDeleteAdmin<'_> {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        Ok(Box::new(FailAfterFirstDeleteFence {
            inner: self.inner.acquire_inventory_fence()?,
            deletes: 0,
        }))
    }
}

struct FailAfterFirstDeleteFence<'a> {
    inner: Box<dyn BlobInventoryFence + 'a>,
    deletes: usize,
}

struct SyntheticRetentionLedger {
    generation: u8,
}

impl AssignmentRetentionAdmin for SyntheticRetentionLedger {
    type Error = std::convert::Infallible;

    fn acquire_retention_fence(
        &mut self,
    ) -> Result<Box<dyn AssignmentRetentionFence<BackendError = Self::Error> + '_>, Self::Error>
    {
        Ok(Box::new(SyntheticRetentionFence {
            generation: self.generation,
        }))
    }
}

struct SyntheticRetentionFence {
    generation: u8,
}

impl AssignmentRetentionFence for SyntheticRetentionFence {
    type BackendError = std::convert::Infallible;

    fn visit_roots(
        &mut self,
        _visitor: &mut dyn FnMut(
            AssignmentRetentionRoot,
        ) -> Result<(), AssignmentRetentionVisitorError>,
    ) -> Result<AssignmentRetentionSummary, AssignmentRetentionInventoryError<Self::BackendError>>
    {
        Ok(AssignmentRetentionSummary::new(
            AssignmentRetentionGeneration::from_bytes([self.generation; 32]),
            0,
            0,
            0,
            0,
        ))
    }

    fn load_attempt(
        &mut self,
        _key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::BackendError> {
        Ok(None)
    }

    fn compare_exchange_attempt(
        &mut self,
        _key: AttemptExecutionKey,
        _expected: Option<AttemptRuntimeState>,
        _next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::BackendError> {
        Ok(AttemptStateCas::Conflict { current: None })
    }
}

impl BlobInventoryFence for FailAfterFirstDeleteFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        self.inner.visit_inventory(visitor)
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        if self.deletes == 1 {
            return Err(StoreError::Quota);
        }
        let disposition = self.inner.delete_candidate(id)?;
        self.deletes += 1;
        Ok(disposition)
    }
}

fn journal_plan_fixture(graph_byte: u8) -> CampaignGcPreparedPlan {
    let blobs = Arc::new(MemoryBlobBackend::new("journal-primary", 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let orphan_bytes = b"journal orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store journal orphan");
    let mut ledger = MemoryAssignmentLedger::default();
    let physical = CampaignGcPhysicalStore::new("journal-primary", blobs.as_ref())
        .expect("journal physical store");
    plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        hash("crucible.test.gc.journal-store-graph.v1", graph_byte),
        &[physical],
    )
    .expect("prepare journal plan")
}

fn content_id_manifest_order(left: &ContentId, right: &ContentId) -> std::cmp::Ordering {
    left.kind()
        .as_str()
        .cmp(right.kind().as_str())
        .then_with(|| left.schema_version().cmp(&right.schema_version()))
        .then_with(|| left.digest().cmp(&right.digest()))
}
