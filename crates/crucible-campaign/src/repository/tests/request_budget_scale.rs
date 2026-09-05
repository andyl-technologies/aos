//! Distinct-request mutation scale and instrumented request-cap index reads.

use super::*;
use crucible_cas::content_store::{BackendCapabilities, ByteRange, PutReceipt};
use std::sync::atomic::{AtomicUsize, Ordering};

struct ReadCountingBackend {
    inner: Arc<dyn ImmutableBlobBackend>,
    reads: AtomicUsize,
}

impl ImmutableBlobBackend for ReadCountingBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }
    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }
    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read(id, range)
    }
    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }
}

#[test]
fn ten_thousand_distinct_request_transitions_keep_indexed_cap_queries_bounded() {
    const REQUESTS: u64 = 2_500;
    const CAMPAIGN: &str = "request-index-scale";

    let (original, lineage, policy, _) = fixture_with_quota(1024 * 1024 * 1024);
    let reads = Arc::new(ReadCountingBackend {
        inner: original.blobs.clone(),
        reads: AtomicUsize::new(0),
    });
    let repository = CampaignRepository::new(reads.clone(), original.refs.clone());
    let head = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create");
    repository
        .apply_control(
            CAMPAIGN,
            &command(
                "fund-index-scale",
                head.snapshot_id(),
                CampaignControlAction::GrantBudget(
                    BudgetGrant::new(2 * REQUESTS, 2 * REQUESTS).expect("grant"),
                ),
            ),
        )
        .expect("fund");

    for ordinal in 0..REQUESTS {
        let template = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            &format!("request-index-{ordinal}"),
        );
        let request = BranchRequest::new(
            template.branch_point(),
            template.parent(),
            template.opportunity(),
            template.domain(),
            template.source().clone(),
            template.cause(),
            BranchBudget::new(2, 1).expect("request cap"),
            template.stop().clone(),
        )
        .expect("request");
        let head = repository.head(CAMPAIGN).expect("head");
        // Discovery, request, proposal, and admission are four real transitions.
        repository
            .submit_known_branch_request(CAMPAIGN, head.snapshot_id(), &request)
            .expect("discover and submit");
        let head = repository.head(CAMPAIGN).expect("proposal head");
        let proposal = finite_proposal(&request, &policy, &head, ChoiceValue::Boolean(false), 1);
        let issued = repository
            .issue_proposal(CAMPAIGN, head.snapshot_id(), &proposal)
            .expect("issue");
        let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
        let admitted = repository
            .admit_proposal(
                CAMPAIGN,
                issued.new_snapshot,
                issued.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("admit distinct attempt");

        let snapshot = repository
            .read_snapshot(admitted.new_snapshot.content_id())
            .expect("snapshot");
        reads.reads.store(0, Ordering::SeqCst);
        assert_eq!(
            repository
                .request_execution_bases_at(&snapshot, request.id().expect("request id"))
                .expect("indexed count"),
            1
        );
        let count = reads.reads.load(Ordering::SeqCst);
        assert!(
            count <= MERKLE_UPDATE_NODE_UPPER + 2,
            "one ledger, at most one outer trie path, and one nested root: {count} reads"
        );
    }

    let head = repository.head(CAMPAIGN).expect("scaled head");
    let ledger = repository
        .read_budget_ledger(head.snapshot().budget_ledger().expect("ledger id"))
        .expect("ledger");
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(ledger.request_spending().expect("index"))
            .expect("request index")
            .entry_count(),
        REQUESTS
    );
    assert_eq!(
        (ledger.spent_proposals(), ledger.spent_attempts()),
        (REQUESTS, REQUESTS)
    );

    // Every request is still Ready by source/proposal semantics, but all have
    // spent their own attempt cap. Aggregate funding remains plentiful.
    let (engine, artifact, mut state) = CanonicalFrontierPlanner::basis()
        .expect("basis")
        .into_parts();
    repository
        .blobs
        .put_if_absent(
            artifact.dependency_lock(),
            &BlobHandle::from_bytes(CanonicalFrontierPlanner::dependency_lock_bytes().to_vec()),
        )
        .expect("dependency");
    let mut after = None;
    let mut settled = false;
    for _ in 0..=(REQUESTS / 64) {
        let head = repository.head(CAMPAIGN).expect("scan head");
        reads.reads.store(0, Ordering::SeqCst);
        let invocation = repository
            .prepare_planner_invocation(
                CAMPAIGN,
                head.snapshot_id(),
                &engine,
                &artifact,
                &state,
                after,
                64,
                PlanningBudget::new(1, 1, 128, 1_048_576, 1024).expect("planning budget"),
            )
            .expect("invocation");
        let count = reads.reads.load(Ordering::SeqCst);
        assert!(
            count <= 256 * MERKLE_UPDATE_NODE_UPPER,
            "a bounded 64-position page must not rewalk retained history: {count} reads"
        );
        let request = repository
            .build_planner_request(head.snapshot_id(), invocation.id().expect("invocation id"))
            .expect("request");
        let output = CanonicalFrontierPlanner
            .plan(&request)
            .expect("plan capped frontier");
        repository
            .accept_planner_step(
                CAMPAIGN,
                request.expected_snapshot(),
                output.proposal(),
                output.proposal().usage_claim(),
            )
            .expect("accept page");
        state = output.proposal().next_state().clone();
        match output.proposal().disposition() {
            PlannerProposalDisposition::ContinueScan { cursor } => after = cursor.after(),
            PlannerProposalDisposition::NoWork => {
                assert_eq!(
                    output
                        .proposal()
                        .explanation()
                        .terms_micros()
                        .get("budget-blocked"),
                    Some(&0)
                );
                settled = true;
                break;
            }
            other => panic!("a local cap was ignored: {other:?}"),
        }
    }
    assert!(settled);
    let before = repository
        .budget_projection(CAMPAIGN)
        .expect("final budget");
    let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        cold.budget_projection(CAMPAIGN)
            .expect("cold index and planner validation"),
        before
    );
    assert_eq!(
        (before.remaining_proposals(), before.remaining_attempts()),
        (u128::from(REQUESTS), u128::from(REQUESTS))
    );
}

#[test]
fn invocation_head_anchors_do_not_trust_a_new_missing_dependency() {
    let (repository, lineage, policy) = fixture();
    let head = repository
        .create("missing-basis", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let (engine, artifact, state) = CanonicalFrontierPlanner::basis()
        .expect("basis")
        .into_parts();
    assert!(matches!(
        repository
            .prepare_planner_invocation(
                "missing-basis",
                head.snapshot_id(),
                &engine,
                &artifact,
                &state,
                None,
                64,
                PlanningBudget::new(1, 1, 128, 1_048_576, 1024).expect("budget"),
            )
            ,
        Err(CampaignRepositoryError::Store(StoreError::NotFound { id }))
            if id == artifact.dependency_lock()
    ));
    repository
        .blobs
        .put_if_absent(
            artifact.dependency_lock(),
            &BlobHandle::from_bytes(CanonicalFrontierPlanner::dependency_lock_bytes().to_vec()),
        )
        .expect("dependency");
    // A conservative cached bound must fall back to the exact union near the
    // limit, not reject a small valid invocation or discard the global bound.
    repository
        .validated_heads
        .lock()
        .expect("head cache")
        .get_mut(&head.snapshot_id().content_id())
        .expect("validated head")
        .closure_objects = MAX_CAMPAIGN_CLOSURE_OBJECTS;
    repository
        .prepare_planner_invocation(
            "missing-basis",
            head.snapshot_id(),
            &engine,
            &artifact,
            &state,
            None,
            64,
            PlanningBudget::new(1, 1, 128, 1_048_576, 1024).expect("budget"),
        )
        .expect("complete basis");
}
