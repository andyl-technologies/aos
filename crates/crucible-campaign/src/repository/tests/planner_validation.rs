//! Authenticated planner reuse, bounded custody, and fresh closure refusal.

use super::*;

#[derive(Clone, Copy)]
enum ReadFault {
    Missing,
    Corrupt,
}

struct CountingBackend {
    inner: Arc<MemoryBlobBackend>,
    reads: Mutex<BTreeMap<ContentId, usize>>,
    fault: Mutex<Option<(ContentId, usize, ReadFault)>>,
}

impl CountingBackend {
    fn reset(&self) {
        self.reads.lock().expect("read counts").clear();
        *self.fault.lock().expect("fault") = None;
    }

    fn count(&self, id: ContentId) -> usize {
        self.reads
            .lock()
            .expect("read counts")
            .get(&id)
            .copied()
            .unwrap_or(0)
    }

    fn total(&self) -> usize {
        self.reads.lock().expect("read counts").values().sum()
    }

    fn fail_after(&self, id: ContentId, successful_reads: usize, fault: ReadFault) {
        *self.fault.lock().expect("fault") = Some((id, successful_reads, fault));
    }
}

impl ImmutableBlobBackend for CountingBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> crucible_cas::content_store::BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(
        &self,
        id: ContentId,
        range: Option<crucible_cas::content_store::ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        let count = {
            let mut reads = self.reads.lock().expect("read counts");
            let count = reads.entry(id).or_default();
            *count += 1;
            *count
        };
        let fault = *self.fault.lock().expect("fault");
        if let Some((target, successful_reads, fault)) = fault
            && target == id
            && count > successful_reads
        {
            return match fault {
                ReadFault::Missing => Err(StoreError::NotFound { id }),
                ReadFault::Corrupt => {
                    let mut bytes = self.inner.read(id, range)?.read_all(64 * 1024 * 1024)?;
                    bytes[0] ^= 1;
                    Ok(BlobHandle::from_bytes(bytes))
                }
            };
        }
        self.inner.read(id, range)
    }

    fn put_if_absent(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<crucible_cas::content_store::PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }

    fn put_many_if_absent(
        &self,
        objects: &[(ContentId, BlobHandle)],
    ) -> Result<Vec<crucible_cas::content_store::PutReceipt>, StoreError> {
        self.inner.put_many_if_absent(objects)
    }
}

struct CanonicalSupervisor;

impl crate::PlannerExecutionSupervisor<CanonicalFrontierPlanner> for CanonicalSupervisor {
    type Error = std::convert::Infallible;

    fn execute(
        &mut self,
        engine: &mut CanonicalFrontierPlanner,
        request: &PlannerRequest,
    ) -> Result<crate::SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        Ok(crate::SupervisedPlannerExecution::new(
            engine.plan(request),
            request.invocation().scan_page().input_objects() + 1,
        ))
    }
}

struct Corpus {
    repository: Arc<CampaignRepository>,
    backend: Arc<CountingBackend>,
    planner: PlannerAuthorityKey,
    debugger: DebuggerAuthorityKey,
    head: ContentId,
    steps: Vec<ContentId>,
}

impl Corpus {
    fn cold(&self) -> CampaignRepository {
        CampaignRepository::with_component_authorities(
            self.backend.clone(),
            self.repository.refs.clone(),
            self.planner.clone(),
            self.debugger.clone(),
        )
        .expect("cold authorized repository")
    }
}

fn corpus(step_count: usize) -> Corpus {
    let (original, lineage, base_policy, inner, planner, debugger) = authorized_fixture();
    let backend = Arc::new(CountingBackend {
        inner,
        reads: Mutex::new(BTreeMap::new()),
        fault: Mutex::new(None),
    });
    let repository = Arc::new(
        CampaignRepository::with_component_authorities(
            backend.clone(),
            original.refs.clone(),
            planner.clone(),
            debugger.clone(),
        )
        .expect("counted repository"),
    );
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            base_policy.scenario(),
            base_policy.campaign_seed(),
            base_policy.mode(),
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 100,
            },
        ),
        CampaignPolicy::rules(
            base_policy.choice_policies().clone(),
            base_policy.objectives().clone(),
            base_policy.guidance().clone(),
            base_policy.stop_conditions().clone(),
            base_policy.fairness(),
            base_policy.retention(),
            base_policy.admits_scenario_defaults(),
        ),
    )
    .expect("exhaustive policy");
    let name = "planner-validation-reuse";
    let created = repository
        .create_funded(name, &lineage, &policy, &BTreeMap::new())
        .expect("campaign");
    repository
        .apply_control(
            name,
            &command(
                "resume-validation",
                created.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume");
    for ordinal in 0..step_count {
        let request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            &format!("validation-{ordinal}"),
        );
        let head = repository.head(name).expect("request head");
        repository
            .submit_known_branch_request(name, head.snapshot_id(), &request)
            .expect("submit request");
    }
    let (engine, artifact, state) = repository
        .publish_canonical_frontier_planner_basis()
        .expect("basis")
        .into_parts();
    let client = crate::PlannerClient::new(
        crate::AuthorizedPlannerService::new(
            CanonicalFrontierPlanner,
            CanonicalSupervisor,
            planner.clone(),
        ),
        planner.clone(),
    );
    let mut driver = crate::CampaignPlannerDriver::new(
        repository.clone(),
        client,
        engine,
        artifact,
        state,
        4,
        PlanningBudget::new(2, 2, 64, 1024 * 1024, 10_000).expect("budget"),
    )
    .expect("driver")
    .require_exhaustive_policy();
    let mut steps = Vec::new();
    for _ in 0..step_count {
        let crate::CampaignPlannerStepOutcome::Advanced { result, .. } =
            driver.step(name).expect("canonical planner")
        else {
            panic!("expected authentic advancing planner step");
        };
        steps.push(result.step.content_id());
    }
    // Retain one genuine unplanned source as well as the admitted attempts,
    // so both frontier and queue EOF comparisons cover nonempty identities.
    let pending = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "validation-pending",
    );
    let current = repository.head(name).expect("pending request head");
    repository
        .submit_known_branch_request(name, current.snapshot_id(), &pending)
        .expect("unplanned source");
    let head = repository
        .head(name)
        .expect("final head")
        .snapshot_id()
        .content_id();
    backend.reset();
    Corpus {
        repository,
        backend,
        planner,
        debugger,
        head,
        steps,
    }
}

fn positions(repository: &CampaignRepository, head: ContentId) -> Vec<PlanningScanPosition> {
    let view = repository
        .read_snapshot(head)
        .expect("snapshot")
        .snapshot
        .planning_view();
    let mut after = None;
    let mut positions = Vec::new();
    loop {
        let page = repository
            .planner_scan_page(&view, after, 1)
            .expect("authentic indexed page");
        positions.extend_from_slice(page.positions());
        if page.complete() {
            return positions;
        }
        after = page.positions().last().copied();
    }
}

fn queue(repository: &CampaignRepository) -> Vec<AttemptId> {
    let mut cursor = None;
    let mut attempts = Vec::new();
    for _ in 0..10_000 {
        let page = repository
            .project_claimable_attempts("planner-validation-reuse", cursor, 1)
            .expect("accounting page");
        attempts.extend_from_slice(page.attempts());
        match page.next() {
            Some(next) => cursor = Some(next),
            None => return attempts,
        }
    }
    panic!("small authentic corpus must reach queue EOF under bound");
}

#[test]
fn complete_validation_reuse_preserves_canonical_head_and_all_pages_with_fewer_reads() {
    let corpus = corpus(3);
    let disabled = corpus.cold();
    let mut disabled_context = PlannerValidationContext::with_limits(0, 0);
    let original = disabled
        .load_validation_checkpoint_with_planner_context(corpus.head, &mut disabled_context)
        .expect("disabled complete validation");
    let original_reads = corpus.backend.total();
    let original_positions = positions(&disabled, corpus.head);
    assert!(!original_positions.is_empty());

    let original_queue = queue(&disabled);
    assert!(
        !original_queue.is_empty(),
        "corpus must contain real admissions"
    );

    corpus.backend.reset();
    let enabled = corpus.cold();
    let mut context = PlannerValidationContext::default();
    let reused = enabled
        .load_validation_checkpoint_with_planner_context(corpus.head, &mut context)
        .expect("cached complete validation");
    let reused_reads = corpus.backend.total();
    assert_eq!(reused.ancestry_depth, original.ancestry_depth);
    assert_eq!(reused.closure_objects, original.closure_objects);
    assert_eq!(reused.lifecycle.visible, original.lifecycle.visible);
    assert_eq!(
        reused.lifecycle.sealed_prior,
        original.lifecycle.sealed_prior
    );
    assert_eq!(
        reused.lifecycle.active_attempt_policy,
        original.lifecycle.active_attempt_policy
    );
    assert_eq!(reused.genesis, original.genesis);
    assert!(original.derived_branch.is_none());
    assert!(reused.derived_branch.is_none());
    assert_eq!(positions(&enabled, corpus.head), original_positions);
    assert_eq!(queue(&enabled), original_queue);
    assert_eq!(
        enabled
            .head("planner-validation-reuse")
            .expect("head")
            .snapshot_id()
            .content_id(),
        corpus.head
    );
    eprintln!(
        "planner-validation-reuse: disabled_reads={original_reads} enabled_reads={reused_reads} attempts={} indexed_positions={} ancestry_depth={} closure_objects={}",
        original_queue.len(),
        original_positions.len(),
        reused.ancestry_depth,
        reused.closure_objects
    );
    assert!(
        reused_reads < original_reads,
        "enabled={reused_reads}, disabled={original_reads}"
    );
    assert_eq!(context.retained_usage(), (0, 0));
}

#[test]
fn validated_tuple_reuse_is_identity_bound_fifo_and_payload_bounded() {
    let corpus = corpus(17);
    let repository = corpus.cold();
    let mut context = PlannerValidationContext::default();
    for id in &corpus.steps {
        let validated = repository
            .read_planner_step_with_context(*id, Some(&mut context))
            .expect("checked step");
        assert_eq!(
            validated.step.id().expect("step identity").content_id(),
            *id
        );
        assert_eq!(
            validated.retained.request.invocation(),
            &validated.retained.invocation
        );
    }
    assert_eq!(context.retained_usage().0, 16);
    assert!(context.retained_usage().1 <= 1024 * 1024);
    assert!(context.step(corpus.steps[0]).is_none());
    let newest = *corpus.steps.last().expect("last step");
    let reads = corpus.backend.total();
    let cached = repository
        .read_planner_step_with_context(newest, Some(&mut context))
        .expect("cache hit");
    assert_eq!(corpus.backend.total(), reads);
    assert_eq!(cached.step.id().expect("identity").content_id(), newest);

    let mut small = PlannerValidationContext::with_limits(2, 1024 * 1024);
    for id in &corpus.steps[..2] {
        repository
            .read_planner_step_with_context(*id, Some(&mut small))
            .expect("small cache");
    }
    assert!(small.step(corpus.steps[0]).is_some());
    repository
        .read_planner_step_with_context(corpus.steps[2], Some(&mut small))
        .expect("FIFO insertion");
    assert!(
        small.step(corpus.steps[0]).is_none(),
        "lookup must not promote FIFO order"
    );
    assert!(small.step(corpus.steps[1]).is_some());

    let mut one = PlannerValidationContext::with_limits(1, 1024 * 1024);
    repository
        .read_planner_step_with_context(newest, Some(&mut one))
        .expect("tuple charge");
    let payload_bytes = one.retained_usage().1;
    assert!(payload_bytes > 0);
    let mut undersized = PlannerValidationContext::with_limits(16, payload_bytes - 1);
    repository
        .read_planner_step_with_context(newest, Some(&mut undersized))
        .expect("uncached oversized tuple");
    assert_eq!(undersized.retained_usage(), (0, 0));

    // Both actual tuples fit individually, but the pair exceeds this private
    // byte budget before the independent sixteen-entry limit is reached.
    let mut charges = Vec::new();
    for id in &corpus.steps[..2] {
        one.clear();
        repository
            .read_planner_step_with_context(*id, Some(&mut one))
            .expect("canonical tuple charge");
        charges.push(one.retained_usage().1);
    }
    let byte_limit = charges[0].max(charges[1]);
    let mut byte_limited = PlannerValidationContext::with_limits(16, byte_limit);
    for id in &corpus.steps[..2] {
        repository
            .read_planner_step_with_context(*id, Some(&mut byte_limited))
            .expect("byte-limited tuple");
    }
    assert!(byte_limited.step(corpus.steps[0]).is_none());
    assert!(byte_limited.step(corpus.steps[1]).is_some());
    assert_eq!(byte_limited.retained_usage(), (1, charges[1]));

    let request_id = cached.step.request().content_id();
    let mut replacement = PlannerValidationContext::default();
    repository
        .read_planner_request_with_context(request_id, Some(&mut replacement))
        .expect("checked request entry");
    let request_charge = replacement.retained_usage().1;
    let request_reads = corpus.backend.count(request_id);
    repository
        .read_planner_step_with_context(newest, Some(&mut replacement))
        .expect("checked step replaces request");
    assert_eq!(corpus.backend.count(request_id), request_reads);
    assert_eq!(replacement.retained_usage(), (1, payload_bytes));
    assert!(replacement.retained_usage().1 > request_charge);
}

#[test]
fn fresh_closure_refuses_missing_or_corrupt_cached_requests_after_ancestry() {
    let corpus = corpus(2);
    let repository = corpus.cold();
    let request = repository
        .read_planner_step_with_request(corpus.steps[1])
        .expect("step")
        .step
        .request()
        .content_id();
    corpus.backend.reset();
    let mut context = PlannerValidationContext::default();
    repository
        .validate_snapshot_ancestry_with_planner_context(
            corpus.head,
            &mut ChoiceValidationCache::default(),
            MAX_SNAPSHOT_ANCESTRY,
            Some(&mut context),
        )
        .expect("ancestry");
    let ancestry_reads = corpus.backend.count(request);
    assert!(ancestry_reads > 0);
    assert!(context.request(request).is_some());

    for fault in [ReadFault::Missing, ReadFault::Corrupt] {
        corpus.backend.reset();
        corpus.backend.fail_after(request, ancestry_reads, fault);
        let cold = corpus.cold();
        let mut context = PlannerValidationContext::default();
        assert!(
            cold.load_validation_checkpoint_with_planner_context(corpus.head, &mut context)
                .is_err()
        );
        assert_eq!(corpus.backend.count(request), ancestry_reads + 1);
        assert_eq!(context.retained_usage(), (0, 0));
        assert!(
            cold.validated_heads
                .lock()
                .expect("validated head cache")
                .is_empty()
        );
    }
    corpus.backend.reset();
    assert!(corpus.cold().validate_complete_head(corpus.head).is_ok());
}

#[test]
fn failed_initial_authentication_retains_no_tuple_or_head_checkpoint() {
    let corpus = corpus(2);
    let repository = corpus.cold();
    let validated = repository
        .read_planner_step_with_request(corpus.steps[1])
        .expect("valid tuple");
    let request = validated.step.request().content_id();
    let invocation = validated
        .retained
        .request
        .invocation_id()
        .expect("invocation identity")
        .content_id();
    let bundled_input = validated
        .retained
        .request
        .input_bundle()
        .object_ids()
        .next()
        .expect("served input");
    for id in [request, invocation, bundled_input] {
        for fault in [ReadFault::Missing, ReadFault::Corrupt] {
            for entries in [0, 16] {
                corpus.backend.reset();
                corpus.backend.fail_after(id, 0, fault);
                let cold = corpus.cold();
                let mut context = PlannerValidationContext::with_limits(entries, 1024 * 1024);
                assert!(
                    cold.load_validation_checkpoint_with_planner_context(corpus.head, &mut context)
                        .is_err()
                );
                assert_eq!(context.retained_usage(), (0, 0));
                assert!(
                    cold.validated_heads
                        .lock()
                        .expect("validated head cache")
                        .is_empty()
                );
            }
        }
    }
}

#[test]
fn failed_step_validation_does_not_retain_its_successful_request_prefix() {
    let corpus = corpus(2);
    let repository = corpus.cold();
    let validated = repository
        .read_planner_step_with_request(corpus.steps[1])
        .expect("valid step");
    let next_state = validated.step.next_state().content_id();
    corpus.backend.reset();
    corpus.backend.fail_after(next_state, 0, ReadFault::Missing);

    let mut context = PlannerValidationContext::default();
    assert!(
        repository
            .read_planner_step_with_context(corpus.steps[1], Some(&mut context))
            .is_err()
    );
    assert!(corpus.backend.count(validated.step.request().content_id()) > 0);
    assert_eq!(context.retained_usage(), (0, 0));
}
