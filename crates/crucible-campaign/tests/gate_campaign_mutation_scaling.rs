//! CPERF-9 campaign mutation scaling and restart conformance.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- conformance fixtures fail at the violated invariant.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crucible_campaign::{
    ActiveAttemptPolicy, BooleanDomain, BranchBudget, BranchRequest, BranchRequestCause,
    CampaignCommandId, CampaignControlAction, CampaignHash, CampaignLineage, CampaignMode,
    CampaignPolicy, CampaignRepository, CampaignRepositoryError, CampaignSeed,
    CandidateGeneratorAlgorithm, CandidateGeneratorSpec, CandidateSource, ChoiceClassContext,
    ChoiceCoordinate, ChoiceDomain, ChoiceOpportunity, ChoicePolicy, ChoiceSource, ChoiceValue,
    ConfigurationId, ControlRequest, ExplorerPolicy, FairnessPolicy, ProgressiveWideningPolicy,
    PuctPolicy, RetentionPolicy, ScenarioDefId, SelectableDeclaration, StopCondition,
    WeightedGenerator,
};
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend, MemoryBlobBackend,
    MemoryRefBackend, MutableRefBackend, PutReceipt, RefCasOutcome, RefName, RefPublicationGuard,
    RefScanPage, StoreError,
};

const CAMPAIGN: &str = "mutation-scaling";
const MUTATIONS: u64 = 10_000;
const MAX_INCREMENTAL_READS: usize = 4_096;
const MAX_LOCATOR_REPLAY_READS: usize = 512;

struct ReadCountingBackend {
    inner: Arc<MemoryBlobBackend>,
    reads: AtomicUsize,
    hidden: Mutex<Option<ContentId>>,
    last_put: Mutex<Option<ContentId>>,
}

impl ReadCountingBackend {
    fn reset(&self) {
        self.reads.store(0, Ordering::SeqCst);
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    fn hide(&self, id: ContentId) {
        *self.hidden.lock().expect("hidden object") = Some(id);
    }

    fn show_all(&self) {
        *self.hidden.lock().expect("hidden object") = None;
    }

    fn last_put(&self) -> ContentId {
        self.last_put
            .lock()
            .expect("last put")
            .expect("mutation published an object")
    }
}

impl ImmutableBlobBackend for ReadCountingBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        if *self.hidden.lock().map_err(|_| StoreError::Poisoned {
            operation: "campaign-mutation-hidden-object",
        })? == Some(id)
        {
            return Ok(false);
        }
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if *self.hidden.lock().map_err(|_| StoreError::Poisoned {
            operation: "campaign-mutation-hidden-object",
        })? == Some(id)
        {
            return Err(StoreError::NotFound { id });
        }
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let receipt = self.inner.put_if_absent(id, source)?;
        *self.last_put.lock().map_err(|_| StoreError::Poisoned {
            operation: "campaign-mutation-last-put",
        })? = Some(id);
        Ok(receipt)
    }
}

struct ConflictOnceRefBackend {
    inner: MemoryRefBackend,
    conflict_next_update: Mutex<bool>,
}

impl ConflictOnceRefBackend {
    fn new() -> Self {
        Self {
            inner: MemoryRefBackend::new(),
            conflict_next_update: Mutex::new(false),
        }
    }

    fn arm(&self) {
        *self.conflict_next_update.lock().expect("conflict flag") = true;
    }
}

impl MutableRefBackend for ConflictOnceRefBackend {
    fn capabilities(&self) -> crucible_cas::content_store::RefBackendCapabilities {
        self.inner.capabilities()
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
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
        let mut conflict = self
            .conflict_next_update
            .lock()
            .map_err(|_| StoreError::Poisoned {
                operation: "campaign-mutation-conflict-flag",
            })?;
        if expected.is_some() && *conflict {
            *conflict = false;
            return Ok(RefCasOutcome::Conflict {
                expected,
                current: self.inner.read_ref(name)?,
            });
        }
        self.inner.compare_exchange(name, expected, next)
    }
}

#[test]
fn ten_thousand_instrumented_mutations_cover_the_cperf9_contract() {
    let (repository, reads, refs, lineage, policy) = fixture();
    let genesis = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    let genesis_metrics = repository
        .validation_checkpoint_metrics(CAMPAIGN)
        .expect("genesis validation metrics");
    let (nested_policy, nested_leaf) = publish_nested_policy(&repository, &lineage);
    let activation = ControlRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive(
            "gate.campaign-mutation-scaling",
            b"activate-nested-policy",
        )),
        expected_snapshot: genesis.snapshot_id(),
        action: CampaignControlAction::ActivatePolicy(
            nested_policy.id().expect("nested policy id"),
        ),
    };
    let activated = repository
        .apply_control(CAMPAIGN, &activation)
        .expect("activate prepublished nested policy");
    let activated_metrics = repository
        .validation_checkpoint_metrics(CAMPAIGN)
        .expect("nested policy validation metrics");
    assert!(
        activated_metrics.closure_objects >= genesis_metrics.closure_objects + 128,
        "complete prepublished generator graph must be charged"
    );

    let (opportunity, domain) = publish_branch_basis(&repository, &lineage);
    let discovered = repository
        .discover_choice_opportunity(
            CAMPAIGN,
            activated.new_snapshot,
            lineage.genesis_content(),
            opportunity.id().expect("opportunity id"),
        )
        .expect("make prepublished graph reachable");
    let discovered_metrics = repository
        .validation_checkpoint_metrics(CAMPAIGN)
        .expect("discovery validation metrics");
    assert!(
        discovered_metrics.closure_objects >= genesis_metrics.closure_objects + 3,
        "newly reachable opportunity, declaration, and domain must be charged"
    );

    let mut snapshot = discovered.new_snapshot;
    let mut first_request = None;
    let mut first_request_result = None;
    let mut first_control = None;
    let mut first_control_result = None;
    let mut maximum_incremental_reads = 0;

    for ordinal in 0..MUTATIONS {
        reads.reset();
        if ordinal % 2 == 0 {
            let request = branch_request(&lineage, &opportunity, &domain, ordinal);
            let result = repository
                .submit_branch_request(CAMPAIGN, snapshot, &request)
                .expect("submit scaled branch request");
            if first_request.is_none() {
                first_request = Some(request.clone());
                first_request_result = Some(result.clone());
            }
            snapshot = result.new_snapshot;
        } else {
            let control_ordinal = ordinal / 2;
            let action = if control_ordinal % 2 == 0 {
                CampaignControlAction::Resume
            } else {
                CampaignControlAction::Pause(ActiveAttemptPolicy::Drain)
            };
            let request = ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "gate.campaign-mutation-scaling.control",
                    &ordinal.to_be_bytes(),
                )),
                expected_snapshot: snapshot,
                action,
            };
            let result = repository
                .apply_control(CAMPAIGN, &request)
                .expect("apply scaled control");
            if first_control.is_none() {
                first_control = Some(request.clone());
                first_control_result = Some(result.clone());
            }
            snapshot = result.new_snapshot;
        }

        let mutation_reads = reads.reads();
        maximum_incremental_reads = maximum_incremental_reads.max(mutation_reads);
        assert!(
            mutation_reads <= MAX_INCREMENTAL_READS,
            "mutation {ordinal} rewalked retained history: {mutation_reads} reads"
        );
    }

    let hot_metrics = repository
        .validation_checkpoint_metrics(CAMPAIGN)
        .expect("hot validation checkpoint");
    assert_eq!(hot_metrics.retained_heads, 1, "checkpoint cache is bounded");
    assert_eq!(hot_metrics.ancestry_depth, MUTATIONS as usize + 3);
    assert!(hot_metrics.closure_objects > hot_metrics.ancestry_depth);
    assert!(
        hot_metrics.checkpoint_bytes <= 256,
        "validation checkpoints must remain fixed and small"
    );
    assert!(maximum_incremental_reads > 0);
    assert_eq!(
        repository.head(CAMPAIGN).expect("final head").snapshot_id(),
        snapshot
    );

    // A failed ref CAS must leave the authoritative head and its validated
    // checkpoint unchanged; the exact retry then succeeds from that parent.
    let conflict_request = ControlRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive(
            "gate.campaign-mutation-scaling",
            b"conflicted-successor",
        )),
        expected_snapshot: snapshot,
        action: CampaignControlAction::Resume,
    };
    refs.arm();
    assert!(matches!(
        repository.apply_control(CAMPAIGN, &conflict_request),
        Err(CampaignRepositoryError::RefConflict { .. })
    ));
    let rejected_child = reads.last_put();
    assert!(
        !repository.has_retained_validation_checkpoint(rejected_child),
        "rejected CAS child was promoted into the validation cache"
    );
    assert!(
        repository.has_retained_validation_checkpoint(snapshot.content_id()),
        "authoritative parent checkpoint was discarded by rejected CAS"
    );
    assert_eq!(
        repository
            .head(CAMPAIGN)
            .expect("head after conflict")
            .snapshot_id(),
        snapshot
    );
    reads.reset();
    let retried = repository
        .apply_control(CAMPAIGN, &conflict_request)
        .expect("retry conflicted successor");
    assert!(reads.reads() <= MAX_INCREMENTAL_READS);

    // New repository instances discard all process-local checkpoints. Each
    // instance must perform the same complete restart/import validation, then
    // retain one bounded checkpoint for subsequent reads.
    reads.reset();
    let cold = CampaignRepository::new(reads.clone(), refs.clone());
    assert_eq!(
        cold.head(CAMPAIGN)
            .expect("cold complete validation")
            .snapshot_id(),
        retried.new_snapshot
    );
    let cold_validation_reads = reads.reads();
    assert!(
        cold_validation_reads > maximum_incremental_reads,
        "restart did not perform complete validation: {cold_validation_reads} reads"
    );
    assert_eq!(
        cold.validation_checkpoint_metrics(CAMPAIGN)
            .expect("cold checkpoint")
            .retained_heads,
        1
    );

    reads.reset();
    let discarded = CampaignRepository::new(reads.clone(), refs.clone());
    discarded
        .head(CAMPAIGN)
        .expect("complete validation after checkpoint discard");
    assert!(reads.reads() >= cold_validation_reads);

    // A process with no checkpoint must authenticate the complete historical
    // nested closure. Losing a deep generator leaf fails closed even though the
    // current ref and every snapshot remain present.
    reads.hide(nested_leaf);
    let missing_history = CampaignRepository::new(reads.clone(), refs.clone());
    assert!(matches!(
        missing_history.head(CAMPAIGN),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { id })) if id == nested_leaf
    ));
    reads.show_all();

    // Exact locator indexes return old results before stale-head rejection and
    // do not scan the ten-thousand-transition ancestry.
    let first_request = first_request.expect("first branch request");
    let expected_request = first_request_result.expect("first branch result");
    reads.reset();
    let replayed_request = cold
        .submit_branch_request(CAMPAIGN, discovered.new_snapshot, &first_request)
        .expect("deep request replay");
    assert!(replayed_request.replayed);
    assert_eq!(replayed_request.new_snapshot, expected_request.new_snapshot);
    assert!(
        reads.reads() <= MAX_LOCATOR_REPLAY_READS,
        "request replay scanned history: {} reads",
        reads.reads()
    );

    let first_control = first_control.expect("first control request");
    let expected_control = first_control_result.expect("first control result");
    reads.reset();
    let replayed_control = cold
        .apply_control(CAMPAIGN, &first_control)
        .expect("deep control replay");
    assert!(replayed_control.replayed);
    assert_eq!(replayed_control.new_snapshot, expected_control.new_snapshot);
    assert!(
        reads.reads() <= MAX_LOCATOR_REPLAY_READS,
        "control replay scanned history: {} reads",
        reads.reads()
    );
}

fn fixture() -> (
    CampaignRepository,
    Arc<ReadCountingBackend>,
    Arc<ConflictOnceRefBackend>,
    CampaignLineage,
    CampaignPolicy,
) {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("gate", b"scenario"));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive("gate", b"genesis"));
    let memory = Arc::new(MemoryBlobBackend::new(
        "campaign-mutation-scaling",
        1024 * 1024 * 1024,
    ));
    let reads = Arc::new(ReadCountingBackend {
        inner: memory,
        reads: AtomicUsize::new(0),
        hidden: Mutex::new(None),
        last_put: Mutex::new(None),
    });
    let refs = Arc::new(ConflictOnceRefBackend::new());
    let repository = CampaignRepository::new(reads.clone(), refs.clone());
    let scenario_content = repository
        .publish_scenario_artifact(scenario, 1, b"scenario".to_vec())
        .expect("scenario artifact");
    let genesis_content = repository
        .publish_configuration_artifact(scenario, scenario_content, genesis, 1, b"genesis".to_vec())
        .expect("genesis artifact");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([("control".to_owned(), 1)]),
        1,
        1,
    )
    .expect("lineage");
    let widening = ProgressiveWideningPolicy::new(
        crucible_campaign::ExactRational::new(1, 1).expect("rational"),
        crucible_campaign::ExactRational::new(1, 2).expect("rational"),
        1,
        100,
        1,
    )
    .expect("widening");
    let policy = CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::<String, ChoicePolicy>::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("policy");

    (repository, reads, refs, lineage, policy)
}

fn publish_nested_policy(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
) -> (CampaignPolicy, ContentId) {
    const GENERATOR_DEPTH: u32 = 128;

    let leaf =
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("leaf generator");
    let leaf_id = repository
        .publish_generator(&leaf)
        .expect("publish leaf generator");
    let mut generator = leaf_id;
    for ordinal in 2..=GENERATOR_DEPTH {
        let parent = CandidateGeneratorSpec::new(
            ordinal,
            CandidateGeneratorAlgorithm::OrderedMixture {
                components: vec![
                    WeightedGenerator::new(generator, 1).expect("generator component"),
                ],
            },
        )
        .expect("nested generator");
        generator = repository
            .publish_generator(&parent)
            .expect("publish nested generator");
    }

    let policy = CampaignPolicy::new(
        lineage.scenario(),
        CampaignSeed::from_bytes([9; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 64,
        },
        BTreeMap::from([(
            "product.network.retry".to_owned(),
            ChoicePolicy::new("product.network.retry", generator, true)
                .expect("nested choice policy"),
        )]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("nested policy");
    repository
        .publish_policy(&policy)
        .expect("publish nested policy");

    (policy, leaf_id.content_id())
}

fn publish_branch_basis(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
) -> (ChoiceOpportunity, ChoiceDomain) {
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.network.retry",
        ChoiceSource::Workload {
            producer: "network-product".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from(["network-recovery".to_owned()]))
            .expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish declaration");
    let opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("gate", b"mutation-scaling"),
            producer: CampaignHash::derive("gate", b"network-product"),
        },
        "mutation-scaling",
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");

    (opportunity, domain)
}

fn branch_request(
    lineage: &CampaignLineage,
    opportunity: &ChoiceOpportunity,
    domain: &ChoiceDomain,
    ordinal: u64,
) -> BranchRequest {
    BranchRequest::new(
        opportunity.branch_point_id(lineage.genesis()),
        lineage.genesis_content(),
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
            "gate.campaign-mutation-scaling.request",
            &ordinal.to_be_bytes(),
        ))),
        BranchBudget::new(2, 2).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("branch request")
}
