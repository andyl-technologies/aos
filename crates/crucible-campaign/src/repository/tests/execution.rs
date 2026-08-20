//! Attempt admission, observation, executor, and projection repository tests.

use super::*;

#[test]
fn attempt_admission_assigns_one_basis_and_deduplicates_later_causes() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("admission", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "admission-first",
    );
    let requested = repository
        .submit_known_branch_request("admission", genesis.snapshot_id(), &request)
        .expect("request");
    let request_head = repository.head("admission").expect("request head");
    let proposal = finite_proposal(
        &request,
        &policy,
        &request_head,
        ChoiceValue::Boolean(false),
        1,
    );
    let proposed = repository
        .issue_proposal("admission", requested.new_snapshot, &proposal)
        .expect("proposal");
    let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
    let admitted = repository
        .admit_proposal(
            "admission",
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admission");
    assert!(!admitted.replayed);
    let basis = repository
        .load_attempt_admission(admitted.admission)
        .expect("basis");
    assert_eq!(
        basis.role(),
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(proposed.proposal),
            cause: request.cause(),
            admission_ordinal: AdmissionOrdinal::new(1),
        }
    );
    let basis_head = repository.head("admission").expect("basis head");
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(basis_head.snapshot().roots().accounting)
            .expect("accounting root")
            .entry_count(),
        7
    );

    let valid_admission_snapshot = repository
        .read_snapshot(admitted.new_snapshot.content_id())
        .expect("valid admission snapshot");
    let mut forged_roots = valid_admission_snapshot.snapshot.roots();
    forged_roots.accounting = repository
        .merkle
        .insert(
            forged_roots.accounting,
            map_key_content("accounting.forged", admitted.admission.content_id()),
            admitted.admission.content_id(),
        )
        .expect("forged accounting root")
        .content_id();
    let forged = CampaignSnapshot::successor(
        valid_admission_snapshot
            .snapshot
            .parent()
            .expect("admission parent"),
        valid_admission_snapshot.snapshot.lineage(),
        valid_admission_snapshot.snapshot.active_policy(),
        forged_roots,
        valid_admission_snapshot
            .snapshot
            .transition()
            .expect("admission transition"),
    )
    .expect("forged admission successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged admission successor");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "attempt-admission-transition-accounting-root-mismatch"
        })
    ));

    let replay = repository
        .admit_proposal(
            "admission",
            genesis.snapshot_id(),
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("replay admission");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, admitted.new_snapshot);
    let wrong_path = BranchPath::new(Vec::new()).expect("wrong path");
    assert!(matches!(
        repository.admit_proposal(
            "admission",
            genesis.snapshot_id(),
            proposed.proposal,
            &selection,
            &wrong_path,
            &attempt,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-admission-input-closure-mismatch"
        })
    ));

    let second_proposal = finite_proposal(
        &request,
        &policy,
        &basis_head,
        ChoiceValue::Boolean(true),
        2,
    );
    let second_proposed = repository
        .issue_proposal("admission", basis_head.snapshot_id(), &second_proposal)
        .expect("second proposal");
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&repository, &request, &second_proposal);
    let second_admitted = repository
        .admit_proposal(
            "admission",
            second_proposed.new_snapshot,
            second_proposed.proposal,
            &second_selection,
            &second_path,
            &second_attempt,
        )
        .expect("second admission");
    assert_eq!(
        repository
            .load_attempt_admission(second_admitted.admission)
            .expect("second basis")
            .role(),
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(second_proposed.proposal),
            cause: request.cause(),
            admission_ordinal: AdmissionOrdinal::new(2),
        }
    );
    let second_head = repository.head("admission").expect("second head");
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(second_head.snapshot().roots().accounting)
            .expect("second accounting root")
            .entry_count(),
        12
    );

    let duplicate_request = BranchRequest::new(
        request.branch_point(),
        request.parent(),
        request.opportunity(),
        request.domain(),
        request.source().clone(),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"admission-duplicate",
        ))),
        request.budget(),
        request.stop().clone(),
    )
    .expect("duplicate request");
    let duplicate_requested = repository
        .submit_known_branch_request("admission", second_head.snapshot_id(), &duplicate_request)
        .expect("duplicate request transition");
    let duplicate_request_head = repository
        .head("admission")
        .expect("duplicate request head");
    let duplicate_proposal = finite_proposal(
        &duplicate_request,
        &policy,
        &duplicate_request_head,
        ChoiceValue::Boolean(false),
        1,
    );
    let duplicate_proposed = repository
        .issue_proposal(
            "admission",
            duplicate_requested.new_snapshot,
            &duplicate_proposal,
        )
        .expect("duplicate proposal");
    let (duplicate_selection, duplicate_path, duplicate_attempt) =
        branch_attempt(&repository, &duplicate_request, &duplicate_proposal);
    assert_eq!(
        duplicate_attempt.id().expect("duplicate attempt id"),
        admitted.attempt
    );
    let deduplicated = repository
        .admit_proposal(
            "admission",
            duplicate_proposed.new_snapshot,
            duplicate_proposed.proposal,
            &duplicate_selection,
            &duplicate_path,
            &duplicate_attempt,
        )
        .expect("deduplicated admission");
    assert_eq!(
        repository
            .load_attempt_admission(deduplicated.admission)
            .expect("additional cause")
            .role(),
        AttemptAdmissionRole::AdditionalCause {
            proposal: duplicate_proposed.proposal,
        }
    );
    let deduplicated_head = repository.head("admission").expect("deduplicated head");
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(deduplicated_head.snapshot().roots().accounting)
            .expect("deduplicated accounting root")
            .entry_count(),
        15
    );
    assert_eq!(
        repository
            .merkle
            .get(
                deduplicated_head.snapshot().roots().accounting,
                admission_sequence_key(),
            )
            .expect("sequence lookup"),
        Some(second_admitted.admission.content_id())
    );
}

#[test]
fn attempt_admission_enforces_request_budget_without_materializing_accounting() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("admission-budget", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let base = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "admission-budget",
    );
    let request = BranchRequest::new(
        base.branch_point(),
        base.parent(),
        base.opportunity(),
        base.domain(),
        base.source().clone(),
        base.cause(),
        BranchBudget::new(2, 1).expect("limited budget"),
        base.stop().clone(),
    )
    .expect("limited request");
    let requested = repository
        .submit_known_branch_request("admission-budget", genesis.snapshot_id(), &request)
        .expect("request");
    let request_head = repository.head("admission-budget").expect("request head");
    let first = finite_proposal(
        &request,
        &policy,
        &request_head,
        ChoiceValue::Boolean(false),
        1,
    );
    let first_proposed = repository
        .issue_proposal("admission-budget", requested.new_snapshot, &first)
        .expect("first proposal");
    let (first_selection, first_path, first_attempt) =
        branch_attempt(&repository, &request, &first);
    repository
        .admit_proposal(
            "admission-budget",
            first_proposed.new_snapshot,
            first_proposed.proposal,
            &first_selection,
            &first_path,
            &first_attempt,
        )
        .expect("first admission");

    let first_head = repository.head("admission-budget").expect("first head");
    let second = finite_proposal(
        &request,
        &policy,
        &first_head,
        ChoiceValue::Boolean(true),
        2,
    );
    let second_proposed = repository
        .issue_proposal("admission-budget", first_head.snapshot_id(), &second)
        .expect("second proposal");
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&repository, &request, &second);
    assert!(matches!(
        repository.admit_proposal(
            "admission-budget",
            second_proposed.new_snapshot,
            second_proposed.proposal,
            &second_selection,
            &second_path,
            &second_attempt,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-request-attempt-budget-exhausted"
        })
    ));
    assert_eq!(
        repository
            .head("admission-budget")
            .expect("unchanged head")
            .snapshot_id(),
        second_proposed.new_snapshot
    );
}

#[test]
fn observations_publish_exact_roots_replay_and_retain_determinism_conflicts() {
    let (repository, lineage, policy) = fixture();
    let (genesis, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "observation");
    let observation_id = observation.id().expect("observation id");
    let accepted = repository
        .publish_observation("observation", admitted.new_snapshot, &observation)
        .expect("publish observation");
    assert_eq!(accepted.disposition, ObservationDisposition::Canonical);
    assert!(!accepted.replayed);
    assert_eq!(accepted.observation, observation_id);

    let canonical = repository
        .read_snapshot(accepted.new_snapshot.content_id())
        .expect("canonical observation snapshot");
    let roots = canonical.snapshot.roots();
    assert_eq!(
        repository
            .merkle
            .get(
                roots.observations,
                map_key_content("observations.attempt", observation.attempt().content_id()),
            )
            .expect("attempt observation lookup"),
        Some(observation_id.content_id())
    );
    assert_eq!(
        repository
            .merkle
            .get(
                roots.graph,
                map_key_hash("graph.configuration", observation.child().as_hash()),
            )
            .expect("graph child lookup"),
        Some(observation.child_content().content_id())
    );
    assert_eq!(
        repository
            .merkle
            .get(
                roots.corpus,
                map_key_hash("corpus.configuration", observation.child().as_hash()),
            )
            .expect("corpus child lookup"),
        Some(observation.child_content().content_id())
    );
    assert_eq!(
        repository
            .merkle
            .get(
                roots.coverage,
                map_key_content("coverage.projection", observation.coverage().content_id()),
            )
            .expect("coverage lookup"),
        Some(observation.coverage().content_id())
    );
    assert_eq!(
        repository
            .merkle
            .get(roots.accounting, observation_sequence_key())
            .expect("strict observation sequence"),
        Some(observation_id.content_id())
    );
    assert_eq!(
        repository
            .load_observation(observation_id)
            .expect("load observation"),
        observation
    );

    let mut forged_roots = roots;
    forged_roots.coverage = repository
        .merkle
        .insert(
            forged_roots.coverage,
            map_key_content("coverage.forged", observation.measurements().content_id()),
            observation.measurements().content_id(),
        )
        .expect("forged coverage root")
        .content_id();
    let forged = CampaignSnapshot::successor(
        admitted.new_snapshot,
        canonical.snapshot.lineage(),
        canonical.snapshot.active_policy(),
        forged_roots,
        canonical
            .snapshot
            .transition()
            .expect("observation transition"),
    )
    .expect("forged observation successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged observation successor");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "observation-transition-coverage-root"
        })
    ));
    let replay = repository
        .publish_observation("observation", genesis, &observation)
        .expect("replay canonical observation");
    assert!(replay.replayed);
    assert_eq!(
        replay,
        ObservationResult {
            replayed: true,
            ..accepted.clone()
        }
    );

    let conflicting_measurements = MeasurementSet::new(BTreeMap::from([(
        "latency".to_owned(),
        MeasurementSeries::new(
            vec![MetricValue::Unsigned(8)],
            MetricValue::Unsigned(8),
            BTreeSet::new(),
        )
        .expect("conflicting measurement series"),
    )]))
    .expect("conflicting measurement set");
    let conflicting_measurements = repository
        .publish_measurement_set(&conflicting_measurements)
        .expect("publish conflicting measurements");
    let conflict = Observation::new(
        observation.attempt(),
        observation.child(),
        observation.child_content(),
        observation.path(),
        observation.stop().clone(),
        conflicting_measurements,
        observation.properties(),
        observation.coverage(),
        observation.discovered_choices().clone(),
    )
    .expect("conflicting observation");
    let conflict_id = conflict.id().expect("conflict id");
    let conflicted = repository
        .publish_observation("observation", accepted.new_snapshot, &conflict)
        .expect("retain observation conflict");
    assert_eq!(
        conflicted.disposition,
        ObservationDisposition::DeterminismConflict {
            canonical: observation_id
        }
    );
    let conflict_snapshot = repository
        .read_snapshot(conflicted.new_snapshot.content_id())
        .expect("conflict snapshot");
    assert_eq!(conflict_snapshot.snapshot.roots().graph, roots.graph);
    assert_eq!(conflict_snapshot.snapshot.roots().corpus, roots.corpus);
    assert_eq!(conflict_snapshot.snapshot.roots().coverage, roots.coverage);
    assert_eq!(
        conflict_snapshot.snapshot.roots().accounting,
        roots.accounting
    );
    assert_eq!(
        repository
            .merkle
            .get(
                conflict_snapshot.snapshot.roots().observations,
                observation_conflict_key(observation.attempt(), conflict_id),
            )
            .expect("conflict lookup"),
        Some(conflict_id.content_id())
    );
    let replayed_conflict = repository
        .publish_observation("observation", genesis, &conflict)
        .expect("replay observation conflict");
    assert!(replayed_conflict.replayed);
    assert_eq!(replayed_conflict.new_snapshot, conflicted.new_snapshot);
    assert_eq!(replayed_conflict.disposition, conflicted.disposition);
}

#[test]
fn executor_candidate_publication_is_immutable_and_does_not_advance_the_campaign() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "observation-candidate");
    let head_before = repository
        .head("observation-candidate")
        .expect("admitted head");
    let candidate = ObservationCandidate::new(
        repository
            .load_configuration_artifact(observation.child_content())
            .expect("candidate child"),
        repository
            .load_measurement_set(observation.measurements())
            .expect("candidate measurements"),
        repository
            .load_property_verdict_set(observation.properties())
            .expect("candidate properties"),
        repository
            .load_coverage_projection(observation.coverage())
            .expect("candidate coverage"),
        observation
            .discovered_choices()
            .iter()
            .map(|id| {
                repository
                    .load_choice_opportunity(*id)
                    .expect("candidate discovered choice")
            })
            .collect(),
        observation.clone(),
    )
    .expect("valid candidate");

    let published = repository
        .publish_observation_candidate(&candidate)
        .expect("publish immutable candidate");
    assert_eq!(published, observation.id().expect("observation id"));
    assert_eq!(
        repository
            .head("observation-candidate")
            .expect("unchanged campaign head")
            .snapshot_id(),
        head_before.snapshot_id()
    );

    let incorporated = repository
        .publish_observation(
            "observation-candidate",
            admitted.new_snapshot,
            candidate.observation(),
        )
        .expect("coordinator incorporates candidate");
    assert_eq!(incorporated.observation, published);
}

#[test]
fn executor_candidate_publishes_a_fresh_next_choice_body() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, basis) =
        admitted_observation_fixture(&repository, &lineage, &policy, "fresh-candidate-choice");
    let prior_id = *basis.discovered_choices().first().expect("fixture choice");
    let prior = repository
        .load_choice_opportunity(prior_id)
        .expect("load fixture choice");
    let declaration = repository
        .load_selectable(prior.declaration())
        .expect("load declaration");
    let domain = repository
        .load_choice_domain(prior.domain())
        .expect("load domain");
    let fresh = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        prior.coordinate(),
        "fresh-executor-discovery",
        prior.model_prior(),
    )
    .expect("fresh opportunity");
    let fresh_id = fresh.id().expect("fresh opportunity id");
    assert!(matches!(
        repository.load_choice_opportunity(fresh_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));

    let observation = Observation::new(
        basis.attempt(),
        basis.child(),
        basis.child_content(),
        basis.path(),
        basis.stop().clone(),
        basis.measurements(),
        basis.properties(),
        basis.coverage(),
        BTreeSet::from([fresh_id]),
    )
    .expect("fresh-choice observation");
    let candidate = ObservationCandidate::new(
        repository
            .load_configuration_artifact(observation.child_content())
            .expect("candidate child"),
        repository
            .load_measurement_set(observation.measurements())
            .expect("candidate measurements"),
        repository
            .load_property_verdict_set(observation.properties())
            .expect("candidate properties"),
        repository
            .load_coverage_projection(observation.coverage())
            .expect("candidate coverage"),
        vec![fresh.clone()],
        observation,
    )
    .expect("fresh candidate");

    repository
        .publish_observation_candidate(&candidate)
        .expect("publish candidate and fresh choice");
    assert_eq!(
        repository
            .load_choice_opportunity(fresh_id)
            .expect("load published fresh choice"),
        fresh
    );
    let published = repository
        .publish_observation(
            "fresh-candidate-choice",
            admitted.new_snapshot,
            candidate.observation(),
        )
        .expect("admit candidate observation");
    let head = repository
        .head("fresh-candidate-choice")
        .expect("choice-index head");
    assert_eq!(head.snapshot_id(), published.new_snapshot);
    let (page, _, _) = repository
        .scan_choice_page(head.snapshot().roots().graph, None, 16)
        .expect("choice index page");
    assert!(page.entries().iter().any(|(key, value)| {
        *key == choice_index_order_key(fresh_id) && *value == fresh_id.content_id()
    }));
}

#[test]
fn invalid_executor_candidate_is_rejected_before_any_bundle_write() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let (_, _, observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "invalid-observation-candidate",
    );
    let child = ConfigurationArtifact::new(
        lineage.scenario(),
        lineage.scenario_content(),
        ConfigurationId::from_hash(CampaignHash::derive(
            "test-invalid-candidate-child",
            b"child",
        )),
        1,
        b"unpublished-invalid-child".to_vec(),
    )
    .expect("candidate child");
    let candidate = ObservationCandidate::new(
        child,
        repository
            .load_measurement_set(observation.measurements())
            .expect("candidate measurements"),
        repository
            .load_property_verdict_set(observation.properties())
            .expect("candidate properties"),
        repository
            .load_coverage_projection(observation.coverage())
            .expect("candidate coverage"),
        observation
            .discovered_choices()
            .iter()
            .map(|id| {
                repository
                    .load_choice_opportunity(*id)
                    .expect("candidate discovered choice")
            })
            .collect(),
        observation,
    )
    .expect("valid candidate");
    let objects_before = blobs.object_count().expect("objects before rejection");

    assert!(matches!(
        repository.publish_observation_candidate(&candidate),
        Err(CampaignRepositoryError::Integrity {
            reason: "observation-candidate-bundle-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before
    );
}

#[test]
fn observation_ref_conflict_leaves_the_admitted_head_authoritative() {
    let (fixture_repository, lineage, policy, blobs) = counted_fixture();
    drop(fixture_repository);
    let refs = Arc::new(ConflictAfterCreateRefBackend::new());
    let repository = CampaignRepository::new(blobs, refs.clone());
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "observation-cas");
    let checkpoint_count = repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .len();
    refs.arm();

    assert!(matches!(
        repository.publish_observation("observation-cas", admitted.new_snapshot, &observation,),
        Err(CampaignRepositoryError::RefConflict { .. })
    ));
    assert_eq!(
        repository
            .head("observation-cas")
            .expect("authoritative admitted head")
            .snapshot_id(),
        admitted.new_snapshot
    );
    assert_eq!(
        repository
            .validated_heads
            .lock()
            .expect("validation checkpoints")
            .len(),
        checkpoint_count
    );
}

#[test]
fn claimable_attempt_pages_are_bounded_snapshot_bound_and_restart_rebuildable() {
    fn collect(
        repository: &CampaignRepository,
        name: &str,
        scan_limit: usize,
    ) -> (CampaignSnapshotId, Vec<AttemptId>) {
        let mut cursor = None;
        let mut snapshot = None;
        let mut attempts = Vec::new();
        loop {
            let page = repository
                .project_claimable_attempts(name, cursor, scan_limit)
                .expect("project claimable attempts");
            assert!(page.scanned_entries() <= scan_limit);
            if let Some(expected) = snapshot {
                assert_eq!(page.snapshot(), expected);
            } else {
                snapshot = Some(page.snapshot());
            }
            attempts.extend_from_slice(page.attempts());
            cursor = page.next();
            if cursor.is_none() {
                break;
            }
        }
        (snapshot.expect("at least one page"), attempts)
    }

    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "claimable-attempts");

    assert_eq!(
        DaemonEpoch::from_bytes([0; 16]),
        Err(CampaignCodecError::InvalidValue {
            reason: "daemon epoch is all zero"
        })
    );
    let first_epoch = DaemonEpoch::from_bytes([1; 16]).expect("first daemon epoch");
    assert!(matches!(
        AttemptQueue::new(first_epoch, 0),
        Err(AttemptQueueError::ZeroCapacity)
    ));
    let claimable_page = repository
        .project_claimable_attempts("claimable-attempts", None, 10_000)
        .expect("claimable page before completion");
    let mut queue = AttemptQueue::new(first_epoch, 1).expect("bounded attempt queue");
    let first_slot = WorkerSlotId::new(0);
    let first_reservation = queue
        .reserve_from_page(&claimable_page, first_slot)
        .expect("reserve first attempt")
        .expect("claimable attempt");
    assert_eq!(first_reservation.attempt(), admitted.attempt);
    assert_eq!(first_reservation.daemon_epoch(), first_epoch);
    assert_eq!(first_reservation.worker_slot(), first_slot);
    assert_eq!(first_reservation.generation(), 1);
    assert_eq!(
        queue
            .reserve_from_page(&claimable_page, first_slot)
            .expect("repeat exact slot reservation"),
        Some(first_reservation)
    );
    assert_eq!(queue.reservation_count(), 1);

    queue
        .release(first_reservation)
        .expect("release exact reservation");
    let second_reservation = queue
        .reserve_from_page(&claimable_page, WorkerSlotId::new(1))
        .expect("reserve after release")
        .expect("claimable attempt after release");
    assert_eq!(second_reservation.generation(), 2);

    let second_epoch = DaemonEpoch::from_bytes([2; 16]).expect("second daemon epoch");
    let mut restarted_queue = AttemptQueue::new(second_epoch, 1).expect("restarted attempt queue");
    assert_eq!(
        restarted_queue.release(second_reservation),
        Err(AttemptQueueError::ReservationMismatch)
    );
    let restarted_reservation = restarted_queue
        .reserve_from_page(&claimable_page, WorkerSlotId::new(0))
        .expect("reserve in new daemon epoch")
        .expect("claimable attempt in new daemon epoch");
    assert_eq!(restarted_reservation.daemon_epoch(), second_epoch);
    assert_eq!(restarted_reservation.generation(), 1);

    let (small_snapshot, small) = collect(&repository, "claimable-attempts", 1);
    let (large_snapshot, large) = collect(&repository, "claimable-attempts", 10_000);
    assert_eq!(small_snapshot, admitted.new_snapshot);
    assert_eq!(large_snapshot, admitted.new_snapshot);
    assert_eq!(small, vec![admitted.attempt]);
    assert_eq!(large, small);

    let stale_cursor = repository
        .project_claimable_attempts("claimable-attempts", None, 1)
        .expect("first bounded queue page")
        .next()
        .expect("accounting root spans multiple one-entry pages");
    let observed = repository
        .publish_observation("claimable-attempts", admitted.new_snapshot, &observation)
        .expect("publish canonical observation");
    assert!(matches!(
        repository.project_claimable_attempts(
            "claimable-attempts",
            Some(stale_cursor),
            1,
        ),
        Err(CampaignRepositoryError::Stale { expected, current })
            if expected == admitted.new_snapshot && current == observed.new_snapshot
    ));

    let (rebuilt_snapshot, rebuilt) = collect(&repository, "claimable-attempts", 3);
    assert_eq!(rebuilt_snapshot, observed.new_snapshot);
    assert!(rebuilt.is_empty());
    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let (restart_snapshot, restart_claimable) = collect(&restarted, "claimable-attempts", 2);
    assert_eq!(restart_snapshot, observed.new_snapshot);
    assert_eq!(restart_claimable, rebuilt);
    let completed_page = restarted
        .project_claimable_attempts("claimable-attempts", None, 10_000)
        .expect("post-completion page");
    let third_epoch = DaemonEpoch::from_bytes([3; 16]).expect("third daemon epoch");
    let mut completed_queue = AttemptQueue::new(third_epoch, 1).expect("post-completion queue");
    assert_eq!(
        completed_queue
            .reserve_from_page(&completed_page, WorkerSlotId::new(0))
            .expect("post-completion reservation attempt"),
        None
    );
}

#[test]
fn executor_responses_authenticate_request_attempt_and_lineage() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "executor-response-validation",
    );
    let observed = repository
        .publish_observation(
            "executor-response-validation",
            admitted.new_snapshot,
            &observation,
        )
        .expect("publish executor observation");
    let resources =
        AttemptResourceLimits::new(2, 512 * 1024 * 1024, 0, 50_000).expect("executor limits");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x81; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x82; 16]).expect("daemon epoch"),
        lineage.id().expect("lineage id"),
        admitted.attempt,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("executor request");
    repository
        .validate_executor_request(&request)
        .expect("valid executor request");
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    repository
        .validate_executor_request_with_profile(&request, &profile)
        .expect("exact executor profile");
    let mismatched_profile = ExecutorCompatibilityProfile::new(
        lineage.crucible_version(),
        "different-qemu-build",
        lineage.protocol_versions().clone(),
        lineage.scenario_schema(),
        lineage.exact_closure_schema(),
    )
    .expect("mismatched executor profile");
    assert!(matches!(
        repository.validate_executor_request_with_profile(&request, &mismatched_profile),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-compatibility-profile-mismatch"
        })
    ));
    let completed = SubmitAttemptResponse::new(
        &request,
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: observed.observation,
        },
    )
    .expect("completed response");
    repository
        .validate_executor_response(&request, &completed)
        .expect("valid completed response");

    let (_, other_admitted, other_observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "executor-response-other-attempt",
    );
    let other_observed = repository
        .publish_observation(
            "executor-response-other-attempt",
            other_admitted.new_snapshot,
            &other_observation,
        )
        .expect("publish other observation");
    let wrong_attempt = SubmitAttemptResponse::new(
        &request,
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: other_observed.observation,
        },
    )
    .expect("wrong-attempt response");
    assert!(matches!(
        repository.validate_executor_response(&request, &wrong_attempt),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-completion-attempt-mismatch"
        })
    ));

    let wrong_scenario = lineage.scenario();
    let wrong_genesis =
        ConfigurationId::from_hash(CampaignHash::derive("test", b"wrong-executor-genesis"));
    let wrong_scenario_content = repository
        .publish_scenario_artifact(wrong_scenario, 1, b"different scenario content".to_vec())
        .expect("wrong scenario artifact");
    let wrong_genesis_content = repository
        .publish_configuration_artifact(
            wrong_scenario,
            wrong_scenario_content,
            wrong_genesis,
            1,
            b"wrong genesis".to_vec(),
        )
        .expect("wrong genesis artifact");
    let wrong_lineage = CampaignLineage::new(
        wrong_scenario,
        wrong_scenario_content,
        wrong_genesis,
        wrong_genesis_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([("control".to_owned(), 1)]),
        1,
        1,
    )
    .expect("wrong lineage");
    repository
        .put_lineage(&wrong_lineage)
        .expect("publish wrong lineage");
    let wrong_lineage_request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x83; 16]).expect("wrong-lineage assignment"),
        request.daemon_epoch(),
        wrong_lineage.id().expect("wrong lineage id"),
        request.attempt(),
        resources,
        request.retention(),
    )
    .expect("wrong-lineage request");
    let wrong_lineage_response = SubmitAttemptResponse::new(
        &wrong_lineage_request,
        SubmitAttemptDisposition::Accepted {
            execution: ExecutionId::from_bytes([0x84; 16]).expect("execution"),
        },
    )
    .expect("wrong-lineage response");
    assert!(matches!(
        repository.validate_executor_request(&wrong_lineage_request),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-attempt-lineage-mismatch"
        })
    ));
    assert!(matches!(
        repository.validate_executor_response(&wrong_lineage_request, &wrong_lineage_response),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-attempt-lineage-mismatch"
        })
    ));
    let wrong_lineage_completed = SubmitAttemptResponse::new(
        &wrong_lineage_request,
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: observed.observation,
        },
    )
    .expect("wrong-lineage completed response");
    assert!(matches!(
        repository.validate_executor_response(&wrong_lineage_request, &wrong_lineage_completed),
        Err(CampaignRepositoryError::Integrity {
            reason: "executor-attempt-lineage-mismatch"
        })
    ));
}

#[test]
fn executor_validation_errors_preserve_retry_and_authorization_meaning() {
    let missing = ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"missing-input");
    assert_eq!(
        CampaignRepositoryError::Store(StoreError::NotFound { id: missing }).executor_rejection(),
        ExecutorRejection::UnavailableInput
    );
    assert_eq!(
        CampaignRepositoryError::Store(StoreError::Unauthorized).executor_rejection(),
        ExecutorRejection::Unauthorized
    );
    assert_eq!(
        integrity("invalid-executor-closure").executor_rejection(),
        ExecutorRejection::Incompatible
    );
    assert_eq!(
        CampaignRepositoryError::Poisoned.executor_rejection(),
        ExecutorRejection::UnavailableInput
    );
}

#[test]
fn observation_growth_bound_rebases_and_remains_restart_readable() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "observation-growth");
    assert_eq!(
        observation_successor_growth(crate::observation::MAX_DISCOVERED_CHOICES)
            .expect("maximum observation growth"),
        MAX_OBSERVATION_SUCCESSOR_GROWTH
    );
    let growth = observation_successor_growth(observation.discovered_choices().len())
        .expect("fixture observation growth");
    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .get_mut(&admitted.new_snapshot.content_id())
        .expect("admitted checkpoint")
        .closure_objects = MAX_CLOSURE_OBJECTS - growth;

    let accepted = repository
        .publish_observation("observation-growth", admitted.new_snapshot, &observation)
        .expect("full-validation observation rebase");
    let checkpoint_objects = repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .get(&accepted.new_snapshot.content_id())
        .expect("rebased observation checkpoint")
        .closure_objects;
    assert!(checkpoint_objects < MAX_OBSERVATION_SUCCESSOR_GROWTH);

    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .clear();
    assert_eq!(
        repository
            .head("observation-growth")
            .expect("restart-style full validation")
            .snapshot_id(),
        accepted.new_snapshot
    );
}

#[test]
fn observation_evidence_preflight_rejects_nested_invalid_records_without_writes() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let (_, admitted, observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "observation-nested-evidence",
    );
    let invalid_path = BranchPath::new(Vec::new())
        .expect("empty path")
        .id()
        .expect("empty path id");
    let nested = Observation::new(
        observation.attempt(),
        observation.child(),
        observation.child_content(),
        invalid_path,
        observation.stop().clone(),
        observation.measurements(),
        observation.properties(),
        observation.coverage(),
        observation.discovered_choices().clone(),
    )
    .expect("structurally valid nested observation");
    let nested_id = nested.id().expect("nested observation id");
    repository
        .put_observation(&nested)
        .expect("store incomplete nested observation fixture");
    let evidence = MeasurementSet::new(BTreeMap::from([(
        "nested-observation".to_owned(),
        MeasurementSeries::new(
            vec![MetricValue::Unsigned(1)],
            MetricValue::Unsigned(1),
            BTreeSet::from([nested_id.content_id()]),
        )
        .expect("nested evidence series"),
    )]))
    .expect("nested evidence set");
    let objects_before = blobs.object_count().expect("objects before rejection");

    assert!(matches!(
        repository.publish_measurement_set(&evidence),
        Err(CampaignRepositoryError::Integrity {
            reason: "observation-attempt-or-child-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before
    );
    assert_eq!(
        repository
            .head("observation-nested-evidence")
            .expect("unchanged admitted head")
            .snapshot_id(),
        admitted.new_snapshot
    );
}

#[test]
fn choice_validation_cache_is_compact_shared_and_checks_copied_contracts() {
    let (repository, lineage, _) = fixture();
    let alternatives = (0_u32..1_024)
        .map(|index| {
            let id = AlternativeId::from_hash(CampaignHash::derive(
                "test-cache-alternative",
                &index.to_be_bytes(),
            ));
            (
                id,
                DiscreteAlternative::new(
                    id,
                    format!("alternative-{index:04}"),
                    Some("x".repeat(512)),
                )
                .expect("cache alternative"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let default = *alternatives.keys().next().expect("first alternative");
    let domain =
        ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives).expect("large shared domain"));
    let declaration = SelectableDeclaration::new(
        "cache.shared.domain",
        ChoiceSource::Workload {
            producer: "cache-producer".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Discrete(default),
        ChoiceClassContext::new(BTreeSet::new()).expect("cache class"),
        BTreeSet::new(),
        true,
    )
    .expect("cache declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish shared domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish shared declaration");

    let mut cache = ChoiceValidationCache::default();
    let mut representative = None;
    for index in 0_u32..256 {
        let opportunity = ChoiceOpportunity::new(
            lineage.scenario(),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive("test-cache-scheduler", &index.to_be_bytes()),
                producer: CampaignHash::derive("test-cache-producer", b"shared"),
            },
            format!("cache-{index:04}"),
            None,
        )
        .expect("shared-domain opportunity");
        let envelope = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceOpportunity,
            crate::object::content_children(opportunity.content_children())
                .expect("opportunity children"),
            crate::codec::encode(&opportunity),
        )
        .expect("opportunity envelope");
        repository
            .validate_opportunity_references_cached(&envelope, &mut cache)
            .expect("validate shared pair");
        representative.get_or_insert(opportunity);
    }
    assert_eq!(cache.contracts.len(), 1);
    assert_eq!(cache.insertion_order.len(), 1);

    let mut forged_bytes =
        crate::codec::encode(representative.as_ref().expect("representative opportunity"));
    let source = b"cache-producer";
    let replacement = b"forge-producer";
    let offset = forged_bytes
        .windows(source.len())
        .position(|window| window == source)
        .expect("encoded source");
    forged_bytes[offset..offset + source.len()].copy_from_slice(replacement);
    let forged = crate::codec::decode::<ChoiceOpportunity>(&forged_bytes)
        .expect("structurally valid forged opportunity");
    let forged_envelope = ObjectEnvelope::for_record(
        crate::CampaignRecordKind::ChoiceOpportunity,
        crate::object::content_children(forged.content_children())
            .expect("forged opportunity children"),
        forged_bytes,
    )
    .expect("forged opportunity envelope");
    assert!(matches!(
        repository.validate_opportunity_references_cached(&forged_envelope, &mut cache),
        Err(CampaignRepositoryError::Integrity {
            reason: "choice-opportunity-cached-reference-mismatch"
        })
    ));
}

#[test]
fn strict_observations_commit_in_global_admission_order() {
    let (repository, lineage, policy) = fixture();
    let (_, first_admitted, first_observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "observation-order");
    let second_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "observation-order-second",
    );
    let second_requested = repository
        .submit_known_branch_request(
            "observation-order",
            first_admitted.new_snapshot,
            &second_request,
        )
        .expect("second request");
    let second_proposal = finite_proposal(
        &second_request,
        &policy,
        &repository
            .head("observation-order")
            .expect("second request head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let second_proposed = repository
        .issue_proposal(
            "observation-order",
            second_requested.new_snapshot,
            &second_proposal,
        )
        .expect("second proposal");
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&repository, &second_request, &second_proposal);
    let second_admitted = repository
        .admit_proposal(
            "observation-order",
            second_proposed.new_snapshot,
            second_proposed.proposal,
            &second_selection,
            &second_path,
            &second_attempt,
        )
        .expect("second admission");
    let second_observation = Observation::new(
        second_admitted.attempt,
        first_observation.child(),
        first_observation.child_content(),
        second_path.id().expect("second path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        first_observation.measurements(),
        first_observation.properties(),
        first_observation.coverage(),
        BTreeSet::from([second_request.opportunity()]),
    )
    .expect("second observation");

    assert!(matches!(
        repository.publish_observation(
            "observation-order",
            second_admitted.new_snapshot,
            &second_observation,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "strict-observation-order-gap"
        })
    ));
    assert_eq!(
        repository
            .head("observation-order")
            .expect("head after rejected gap")
            .snapshot_id(),
        second_admitted.new_snapshot
    );
    let first_published = repository
        .publish_observation(
            "observation-order",
            second_admitted.new_snapshot,
            &first_observation,
        )
        .expect("first ordered observation");
    let second_published = repository
        .publish_observation(
            "observation-order",
            first_published.new_snapshot,
            &second_observation,
        )
        .expect("second ordered observation");
    assert_eq!(
        second_published.disposition,
        ObservationDisposition::Canonical
    );
}

#[test]
fn finite_expansion_pages_are_snapshot_bound_admission_backed_and_owner_recomputed() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("finite-expansion", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let first_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "finite-expansion",
    );
    let first_requested = repository
        .submit_known_branch_request("finite-expansion", genesis.snapshot_id(), &first_request)
        .expect("first request");
    let second_request = BranchRequest::new(
        first_request.branch_point(),
        first_request.parent(),
        first_request.opportunity(),
        first_request.domain(),
        first_request.source().clone(),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"finite-expansion-second",
        ))),
        first_request.budget(),
        first_request.stop().clone(),
    )
    .expect("second request");
    let second_requested = repository
        .submit_known_branch_request(
            "finite-expansion",
            first_requested.new_snapshot,
            &second_request,
        )
        .expect("second request transition");

    let first_page_id = repository
        .project_finite_expansion(
            second_requested.new_snapshot,
            first_request.branch_point(),
            None,
            1,
        )
        .expect("first projection page");
    let first_page = repository
        .load_expansion_state(first_page_id)
        .expect("load first page");
    assert_eq!(first_page.continuations().len(), 1);
    assert_eq!(
        first_page
            .continuations()
            .values()
            .copied()
            .collect::<Vec<_>>(),
        vec![ContinuationState::Ready]
    );
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(first_page.request_root())
            .expect("request projection root")
            .entry_count(),
        2
    );
    let cursor = first_page.next_after().expect("second page cursor");
    assert_eq!(
        first_page
            .continuations()
            .last_key_value()
            .map(|entry| *entry.0),
        Some(cursor)
    );

    let second_page_id = repository
        .project_finite_expansion(
            second_requested.new_snapshot,
            first_request.branch_point(),
            Some(cursor),
            1,
        )
        .expect("second projection page");
    let second_page = repository
        .load_expansion_state(second_page_id)
        .expect("load second page");
    assert_eq!(second_page.continuations().len(), 1);
    assert_eq!(second_page.next_after(), None);
    assert_eq!(first_page.request_root(), second_page.request_root());
    let whole_page_id = repository
        .project_finite_expansion(
            second_requested.new_snapshot,
            first_request.branch_point(),
            None,
            10,
        )
        .expect("whole projection page");
    let whole_page = repository
        .load_expansion_state(whole_page_id)
        .expect("load whole page");
    let paged_requests = first_page
        .continuations()
        .keys()
        .chain(second_page.continuations().keys())
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(
        paged_requests,
        whole_page
            .continuations()
            .keys()
            .copied()
            .collect::<Vec<_>>()
    );
    assert_ne!(
        first_page
            .continuations()
            .first_key_value()
            .map(|entry| *entry.0),
        second_page
            .continuations()
            .first_key_value()
            .map(|entry| *entry.0)
    );

    let foreign = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "finite-expansion-foreign",
    );
    assert!(matches!(
        repository.project_finite_expansion(
            second_requested.new_snapshot,
            first_request.branch_point(),
            Some(foreign.id().expect("foreign request id")),
            1,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "expansion-page-cursor-is-not-in-request-root"
        })
    ));

    let request_head = repository.head("finite-expansion").expect("request head");
    let first_proposal = finite_proposal(
        &first_request,
        &policy,
        &request_head,
        ChoiceValue::Boolean(false),
        1,
    );
    let first_proposed = repository
        .issue_proposal(
            "finite-expansion",
            request_head.snapshot_id(),
            &first_proposal,
        )
        .expect("first proposal");
    let pending_id = repository
        .project_finite_expansion(
            first_proposed.new_snapshot,
            first_request.branch_point(),
            None,
            10,
        )
        .expect("pending projection");
    let pending = repository
        .load_expansion_state(pending_id)
        .expect("load pending projection");
    assert_eq!(
        pending
            .continuations()
            .get(&first_request.id().expect("first request id")),
        Some(&ContinuationState::Open)
    );
    assert_eq!(pending.statistics().admitted_children, 0);

    let (selection, path, attempt) = branch_attempt(&repository, &first_request, &first_proposal);
    let first_admitted = repository
        .admit_proposal(
            "finite-expansion",
            first_proposed.new_snapshot,
            first_proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("first admission");
    let ready_id = repository
        .project_finite_expansion(
            first_admitted.new_snapshot,
            first_request.branch_point(),
            None,
            10,
        )
        .expect("ready projection");
    let ready = repository
        .load_expansion_state(ready_id)
        .expect("load ready projection");
    assert_eq!(
        ready
            .continuations()
            .get(&first_request.id().expect("first request id")),
        Some(&ContinuationState::Ready)
    );
    assert_eq!(ready.statistics().admitted_children, 1);

    let admitted_head = repository.head("finite-expansion").expect("admitted head");
    let second_proposal = finite_proposal(
        &first_request,
        &policy,
        &admitted_head,
        ChoiceValue::Boolean(true),
        2,
    );
    let second_proposed = repository
        .issue_proposal(
            "finite-expansion",
            admitted_head.snapshot_id(),
            &second_proposal,
        )
        .expect("second proposal");
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&repository, &first_request, &second_proposal);
    let second_admitted = repository
        .admit_proposal(
            "finite-expansion",
            second_proposed.new_snapshot,
            second_proposed.proposal,
            &second_selection,
            &second_path,
            &second_attempt,
        )
        .expect("second admission");
    let exhausted_id = repository
        .project_finite_expansion(
            second_admitted.new_snapshot,
            first_request.branch_point(),
            None,
            10,
        )
        .expect("exhausted projection");
    let exhausted = repository
        .load_expansion_state(exhausted_id)
        .expect("load exhausted projection");
    assert_eq!(
        exhausted
            .continuations()
            .get(&first_request.id().expect("first request id")),
        Some(&ContinuationState::Exhausted)
    );
    assert_eq!(exhausted.statistics().admitted_children, 2);
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(exhausted.proposal_root())
            .expect("proposal projection root")
            .entry_count(),
        2
    );
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(exhausted.admission_root())
            .expect("admission projection root")
            .entry_count(),
        2
    );

    let empty = repository.merkle.empty().expect("empty root").content_id();
    let forged = ExpansionState::new(
        exhausted.source_snapshot(),
        exhausted.input_view(),
        exhausted.branch_point(),
        empty,
        exhausted.proposal_root(),
        exhausted.admission_root(),
        exhausted.observation_root(),
        exhausted.statistics(),
        exhausted.page_after(),
        exhausted.page_size(),
        exhausted.next_after(),
        exhausted.continuations().clone(),
    )
    .expect("structurally valid forged projection");
    let forged_content = repository
        .put_expansion_state(&forged)
        .expect("put forged projection");
    assert!(matches!(
        repository.load_expansion_state(
            ExpansionStateId::from_content_id(forged_content).expect("forged expansion id")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "expansion-state-owner-recomputation-mismatch"
        })
    ));
}
