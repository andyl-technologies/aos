//! Frontier ceiling and restart scale regressions.

use super::*;
use std::time::Instant;

#[test]
fn admitted_attempt_planner_queue_profile() -> Result<(), Box<dyn Error>> {
    const ATTEMPTS: usize = 32;
    const SCAN_LIMIT: usize = 7;

    let fixture = GateFixture::new(
        "admitted-attempt-profile",
        CampaignMode::Strict,
        tree_search_explorer()?,
        &BTreeMap::new(),
    )?;
    let campaign = "admitted-attempt-profile";
    let head = fixture.create_funded_running(campaign, &BTreeMap::new(), ATTEMPTS as u64)?;
    let (domain, alternatives) = discrete_domain(campaign, ATTEMPTS)?;
    let request = request_for_source(
        &fixture,
        &domain,
        ChoiceValue::Discrete(alternatives[0]),
        CandidateSource::finite(
            alternatives
                .iter()
                .copied()
                .map(ChoiceValue::Discrete)
                .collect(),
        )?,
        BranchRequestCause::Operator(command_id(campaign, "request")),
        campaign,
        BranchBudget::new(ATTEMPTS as u64, ATTEMPTS as u64)?,
    )?;
    discover_and_submit(&fixture, campaign, head.snapshot_id(), &request)?;
    let baseline_objects = fixture.blobs.object_count()?;
    let baseline_bytes = fixture.blobs.logical_bytes()?;

    let mut planner = planner_driver(&fixture)?;
    let mut planner_ns = 0;
    let mut maximum_planner_step_ns = 0;
    let mut planner_step_samples = Vec::with_capacity(ATTEMPTS);
    #[cfg(feature = "test-support")]
    let mut checkpoint_samples = Vec::with_capacity(ATTEMPTS);
    #[cfg(feature = "test-support")]
    let mut prior_checkpoint = planner.validation_checkpoint_metrics(campaign)?;
    #[cfg(feature = "test-support")]
    let mut prior_stored_objects = baseline_objects;
    for _ in 0..ATTEMPTS {
        let started = Instant::now();
        let CampaignPlannerStepOutcome::Advanced {
            disposition:
                PlannerDisposition::Issue {
                    issued_proposals, ..
                },
            ..
        } = planner.step(campaign)?
        else {
            return Err("profile planner did not issue the next attempt".into());
        };
        let step_ns = started.elapsed().as_nanos();
        planner_ns += step_ns;
        maximum_planner_step_ns = maximum_planner_step_ns.max(step_ns);
        planner_step_samples.push(step_ns);
        assert_eq!(issued_proposals.len(), 1);

        #[cfg(feature = "test-support")]
        {
            let metrics = planner.validation_checkpoint_metrics(campaign)?;
            let stored_objects = fixture.blobs.object_count()?;
            let checkpoint_growth = metrics.closure_objects - prior_checkpoint.closure_objects;
            let stored_growth = stored_objects - prior_stored_objects;
            assert_eq!(metrics.ancestry_depth, prior_checkpoint.ancestry_depth + 1);
            assert!(
                stored_growth <= checkpoint_growth,
                "all newly stored objects must fit within the checkpoint's closure growth bound"
            );
            prior_checkpoint = metrics;
            prior_stored_objects = stored_objects;
            checkpoint_samples.push((metrics.ancestry_depth, metrics.closure_objects));
        }
    }
    let snapshot = fixture.repository.head(campaign)?.snapshot_id();

    let queue_start = Instant::now();
    let mut cursor = None;
    let mut scanned_entries = 0;
    let mut pages = 0;
    let mut attempts = BTreeSet::new();
    let mut queue = AttemptQueue::new(DaemonEpoch::from_bytes([0x93; 16])?, 1)?;
    loop {
        let page = fixture
            .repository
            .project_claimable_attempts(campaign, cursor, SCAN_LIMIT)?;
        assert_eq!(page.snapshot(), snapshot);
        assert!(page.scanned_entries() <= SCAN_LIMIT);
        assert!(page.attempts().len() <= SCAN_LIMIT);
        scanned_entries += page.scanned_entries();
        pages += 1;
        for attempt in page.attempts() {
            assert!(
                attempts.insert(*attempt),
                "duplicate attempt in queue projection"
            );
        }
        if !page.attempts().is_empty() {
            let reservation = queue
                .reserve_from_page(&page, WorkerSlotId::new(0))?
                .ok_or("claimable page did not yield a reservation")?;
            assert_eq!(reservation.attempt(), page.attempts()[0]);
            queue.release(reservation)?;
        }
        cursor = page.next();
        if cursor.is_none() {
            break;
        }
    }
    let queue_ns = queue_start.elapsed().as_nanos();
    assert_eq!(attempts.len(), ATTEMPTS);
    assert!(pages > 1, "queue projection must cross a page boundary");
    assert_eq!(queue.reservation_count(), 0);

    let reopened = CampaignRepository::with_component_authorities(
        fixture.blobs.clone(),
        fixture.refs.clone(),
        fixture.planner_authority.clone(),
        fixture.debugger_authority.clone(),
    )?;
    let cold_start = Instant::now();
    let mut cold_cursor = None;
    let mut cold_attempts = BTreeSet::new();
    let mut cold_pages = 0;
    loop {
        let page = reopened.project_claimable_attempts(campaign, cold_cursor, SCAN_LIMIT)?;
        assert_eq!(page.snapshot(), snapshot);
        assert!(page.scanned_entries() <= SCAN_LIMIT);
        cold_attempts.extend(page.attempts().iter().copied());
        cold_pages += 1;
        cold_cursor = page.next();
        if cold_cursor.is_none() {
            break;
        }
    }
    let cold_projection_ns = cold_start.elapsed().as_nanos();
    assert_eq!(cold_attempts, attempts);
    assert_eq!(cold_pages, pages);

    for (index, sample) in planner_step_samples.into_iter().enumerate() {
        println!(
            "campaign_planner_queue_step ordinal={} ns={sample}",
            index + 1
        );
    }
    #[cfg(feature = "test-support")]
    for (index, (depth, objects)) in checkpoint_samples.into_iter().enumerate() {
        println!(
            "campaign_planner_queue_checkpoint ordinal={} ancestry={depth} objects={objects}",
            index + 1
        );
    }
    println!("campaign_planner_queue_snapshot id={snapshot}");
    println!(
        "campaign_planner_queue_profile attempts={ATTEMPTS} pages={pages} scanned_entries={scanned_entries} cold_pages={cold_pages} planner_ns={planner_ns} maximum_planner_step_ns={maximum_planner_step_ns} queue_ns={queue_ns} cold_projection_ns={cold_projection_ns} retained_objects={} retained_bytes={}",
        fixture.blobs.object_count()? - baseline_objects,
        fixture.blobs.logical_bytes()? - baseline_bytes,
    );

    Ok(())
}

#[test]
fn exhaustive_all_above_the_policy_ceiling_rejects_without_writes() -> Result<(), Box<dyn Error>> {
    let all = CandidateGeneratorSpec::new(
        STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )?;
    let all_id = all.id()?;
    let generators = BTreeMap::from([(all_id, all)]);
    let fixture = GateFixture::new(
        "exhaustive-ceiling",
        CampaignMode::Strict,
        ExplorerPolicy::Exhaustive {
            maximum_cardinality: 9,
        },
        &generators,
    )?;
    let campaign = "exhaustive-ceiling";
    let head = fixture.create_funded_running(campaign, &generators, 16)?;
    let (domain, alternatives) = discrete_domain("exhaustive-ceiling", 10)?;
    let request = request_for_source(
        &fixture,
        &domain,
        ChoiceValue::Discrete(alternatives[0]),
        CandidateSource::generated(all_id),
        BranchRequestCause::ExhaustivePolicy(fixture.policy.id()?),
        "exhaustive-ceiling",
        BranchBudget::new(10, 10)?,
    )?;
    let discovered = fixture.repository.discover_operator_choice_opportunity(
        campaign,
        head.snapshot_id(),
        request.parent(),
        request.opportunity(),
    )?;
    let objects_before = fixture.blobs.object_count()?;
    let service = RepositoryCampaignService::new(&fixture.repository, AllowGatePrincipal);
    let submission = SubmitCampaignBranchRequest::new(
        CampaignPrincipal::new("lazy-frontier-gate")?,
        CampaignName::new(campaign)?,
        discovered.new_snapshot,
        request,
    )?;
    assert!(matches!(
        service.submit_branch_request(&submission),
        Err(RepositoryCampaignServiceError::Repository(
            CampaignRepositoryError::Integrity {
                reason: "exhaustive-branch-request-domain-exceeds-policy"
            }
        ))
    ));
    assert_eq!(fixture.blobs.object_count()?, objects_before);
    assert_eq!(
        fixture.repository.head(campaign)?.snapshot_id(),
        discovered.new_snapshot
    );

    Ok(())
}

struct CompletionRun {
    final_snapshot: CampaignSnapshotId,
    planning_view: CampaignViewId,
    planner_step: PlannerStepId,
    accepted_second_first: bool,
}

fn run_shuffled_completion(
    mode: CampaignMode,
    reverse_delivery: bool,
) -> Result<CompletionRun, Box<dyn Error>> {
    let fixture = GateFixture::new(
        "shuffled-completion",
        mode,
        tree_search_explorer()?,
        &BTreeMap::new(),
    )?;
    let campaign = "shuffled-completion";
    let head = fixture.create_funded_running(campaign, &BTreeMap::new(), 16)?;
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1)?);
    let request = request_for_source(
        &fixture,
        &domain,
        ChoiceValue::Boolean(false),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))?,
        BranchRequestCause::Operator(command_id(campaign, "request")),
        "shuffled-completion",
        BranchBudget::new(2, 2)?,
    )?;
    let requested = discover_and_submit(&fixture, campaign, head.snapshot_id(), &request)?;

    let first_proposal = proposal(
        &fixture,
        &fixture.repository,
        campaign,
        &request,
        ChoiceValue::Boolean(false),
        1,
    )?;
    let first_issued =
        fixture
            .repository
            .issue_proposal(campaign, requested.new_snapshot, &first_proposal)?;
    let (first_selection, first_path, first_attempt) =
        branch_attempt(&fixture.repository, &request, &first_proposal)?;
    let first_admitted = fixture.repository.admit_proposal(
        campaign,
        first_issued.new_snapshot,
        first_issued.proposal,
        &first_selection,
        &first_path,
        &first_attempt,
    )?;
    let first_admission_replay = fixture.repository.admit_proposal(
        campaign,
        first_issued.new_snapshot,
        first_issued.proposal,
        &first_selection,
        &first_path,
        &first_attempt,
    )?;
    assert!(first_admission_replay.replayed);
    assert_eq!(first_admission_replay.admission, first_admitted.admission);
    assert_eq!(first_admission_replay.attempt, first_admitted.attempt);

    let second_proposal = proposal(
        &fixture,
        &fixture.repository,
        campaign,
        &request,
        ChoiceValue::Boolean(true),
        2,
    )?;
    let second_issued = fixture.repository.issue_proposal(
        campaign,
        first_admitted.new_snapshot,
        &second_proposal,
    )?;
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&fixture.repository, &request, &second_proposal)?;
    let second_admitted = fixture.repository.admit_proposal(
        campaign,
        second_issued.new_snapshot,
        second_issued.proposal,
        &second_selection,
        &second_path,
        &second_attempt,
    )?;

    let first_observation = observation(
        &fixture,
        &first_admitted,
        &first_path,
        request.opportunity(),
        "shuffled-first",
    )?;
    let second_observation = observation(
        &fixture,
        &second_admitted,
        &second_path,
        request.opportunity(),
        "shuffled-second",
    )?;

    let (first_result, accepted_second_first) = if reverse_delivery {
        match fixture.repository.publish_observation(
            campaign,
            second_admitted.new_snapshot,
            &second_observation,
        ) {
            Ok(second_first) if mode == CampaignMode::Streaming => {
                let first = fixture.repository.publish_observation(
                    campaign,
                    second_first.new_snapshot,
                    &first_observation,
                )?;
                (first, true)
            }
            Err(CampaignRepositoryError::Integrity {
                reason: "strict-completion-order-gap",
            }) if mode == CampaignMode::Strict => {
                assert_eq!(
                    fixture.repository.head(campaign)?.snapshot_id(),
                    second_admitted.new_snapshot
                );
                let first = fixture.repository.publish_observation(
                    campaign,
                    second_admitted.new_snapshot,
                    &first_observation,
                )?;
                fixture.repository.publish_observation(
                    campaign,
                    first.new_snapshot,
                    &second_observation,
                )?;
                (first, false)
            }
            result => {
                return Err(format!("unexpected reverse completion result: {result:?}").into());
            }
        }
    } else {
        let first = fixture.repository.publish_observation(
            campaign,
            second_admitted.new_snapshot,
            &first_observation,
        )?;
        fixture.repository.publish_observation(
            campaign,
            first.new_snapshot,
            &second_observation,
        )?;
        (first, false)
    };

    let first_replay = fixture.repository.publish_observation(
        campaign,
        first_result.prior_snapshot,
        &first_observation,
    )?;
    assert!(first_replay.replayed);
    assert_eq!(first_replay.new_snapshot, first_result.new_snapshot);
    assert_eq!(first_replay.observation, first_result.observation);

    let settled = fixture.repository.head(campaign)?;
    let final_snapshot = settled.snapshot_id();
    let planning_view = settled.snapshot().planning_view().id()?;
    let mut driver = planner_driver(&fixture)?;
    let CampaignPlannerStepOutcome::Advanced {
        result,
        disposition: PlannerDisposition::NoWork,
    } = driver.step(campaign)?
    else {
        return Err("completed frontier did not settle with a no-work planner step".into());
    };

    Ok(CompletionRun {
        final_snapshot,
        planning_view,
        planner_step: result.step,
        accepted_second_first,
    })
}

#[test]
fn shuffled_completion_preserves_strict_steps_and_streaming_acceptance()
-> Result<(), Box<dyn Error>> {
    let strict_ordered = run_shuffled_completion(CampaignMode::Strict, false)?;
    let strict_reversed = run_shuffled_completion(CampaignMode::Strict, true)?;
    assert!(!strict_reversed.accepted_second_first);
    assert_eq!(
        strict_reversed.final_snapshot,
        strict_ordered.final_snapshot
    );
    assert_eq!(strict_reversed.planning_view, strict_ordered.planning_view);
    assert_eq!(strict_reversed.planner_step, strict_ordered.planner_step);

    let streaming_reversed = run_shuffled_completion(CampaignMode::Streaming, true)?;
    assert!(streaming_reversed.accepted_second_first);

    Ok(())
}

#[test]
fn progressive_source_waits_widens_exhausts_and_recovers_after_restart()
-> Result<(), Box<dyn Error>> {
    let generator = CandidateGeneratorSpec::new(
        PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 3,
            feedback_interval: 1,
        },
    )?;
    let generator_id = generator.id()?;
    let generators = BTreeMap::from([(generator_id, generator)]);
    let fixture = GateFixture::new(
        "progressive-frontier",
        CampaignMode::Strict,
        tree_search_explorer()?,
        &generators,
    )?;
    let campaign = "progressive-frontier";
    let head = fixture.create_funded_running(campaign, &generators, 64)?;
    let domain = integer_domain(8)?;
    let request = generated_integer_request(&fixture, &domain, generator_id, "progressive", 9)?;
    let requested = discover_and_submit(&fixture, campaign, head.snapshot_id(), &request)?;
    assert_eq!(
        requested.summary.validated_cardinality(),
        BranchAcceptanceCount::Exact(9)
    );

    let values = [0, 4, 8, 2, 6, 1, 3, 5, 7];
    let mut current = requested.new_snapshot;
    let mut observations = Vec::new();
    for (index, value) in values.iter().take(3).enumerate() {
        let (admitted, path) = issue_and_admit(
            &fixture,
            &fixture.repository,
            campaign,
            &request,
            current,
            ChoiceValue::Integer(IntegerValue::Unsigned(*value)),
            index as u64 + 1,
        )?;
        current = admitted.new_snapshot;
        observations.push(observation(
            &fixture,
            &admitted,
            &path,
            request.opportunity(),
            &format!("progressive-{index}"),
        )?);
    }

    let request_id = request.id()?;
    let expansion =
        fixture
            .repository
            .project_finite_expansion(current, request.branch_point(), None, 16)?;
    assert_eq!(
        fixture
            .repository
            .load_expansion_state(expansion)?
            .continuations()
            .get(&request_id),
        Some(&ContinuationState::WaitingForFeedback(FeedbackWait::new(
            0, 1
        )?))
    );
    let waiting_restart = CampaignRepository::with_component_authorities(
        fixture.blobs.clone(),
        fixture.refs.clone(),
        fixture.planner_authority.clone(),
        fixture.debugger_authority.clone(),
    )?;
    let rebuilt_wait =
        waiting_restart.project_finite_expansion(current, request.branch_point(), None, 16)?;
    assert_eq!(
        waiting_restart
            .load_expansion_state(rebuilt_wait)?
            .continuations()
            .get(&request_id),
        Some(&ContinuationState::WaitingForFeedback(FeedbackWait::new(
            0, 1
        )?))
    );

    let mut credited = 0_usize;
    for (index, value) in values.iter().enumerate().skip(3) {
        let required_visits = index - 2;
        while credited < required_visits {
            let observed = fixture.repository.publish_observation(
                campaign,
                current,
                &observations[credited],
            )?;
            current = observed.new_snapshot;
            credited += 1;
        }

        let ready = fixture.repository.project_finite_expansion(
            current,
            request.branch_point(),
            None,
            16,
        )?;
        assert_eq!(
            fixture
                .repository
                .load_expansion_state(ready)?
                .continuations()
                .get(&request_id),
            Some(&ContinuationState::Ready)
        );

        let restarted_ready = (index == 3)
            .then(|| {
                CampaignRepository::with_component_authorities(
                    fixture.blobs.clone(),
                    fixture.refs.clone(),
                    fixture.planner_authority.clone(),
                    fixture.debugger_authority.clone(),
                )
            })
            .transpose()?;
        let generation_owner = restarted_ready.as_ref().unwrap_or(&fixture.repository);
        if index == 3 {
            let cold_ready = generation_owner.project_finite_expansion(
                current,
                request.branch_point(),
                None,
                16,
            )?;
            assert_eq!(
                generation_owner
                    .load_expansion_state(cold_ready)?
                    .continuations()
                    .get(&request_id),
                Some(&ContinuationState::Ready)
            );
        }

        let (admitted, path) = issue_and_admit(
            &fixture,
            generation_owner,
            campaign,
            &request,
            current,
            ChoiceValue::Integer(IntegerValue::Unsigned(*value)),
            index as u64 + 1,
        )?;
        current = admitted.new_snapshot;
        observations.push(observation(
            &fixture,
            &admitted,
            &path,
            request.opportunity(),
            &format!("progressive-{index}"),
        )?);

        let state = fixture.repository.project_finite_expansion(
            current,
            request.branch_point(),
            None,
            16,
        )?;
        let state = fixture.repository.load_expansion_state(state)?;
        if index + 1 == values.len() {
            assert_eq!(
                state.continuations().get(&request_id),
                Some(&ContinuationState::Exhausted)
            );
        } else {
            assert!(matches!(
                state.continuations().get(&request_id),
                Some(ContinuationState::WaitingForFeedback(_))
            ));
        }
    }

    let restarted = CampaignRepository::with_component_authorities(
        fixture.blobs.clone(),
        fixture.refs.clone(),
        fixture.planner_authority.clone(),
        fixture.debugger_authority.clone(),
    )?;
    let rebuilt = restarted.project_finite_expansion(current, request.branch_point(), None, 16)?;
    assert_eq!(
        restarted
            .load_expansion_state(rebuilt)?
            .continuations()
            .get(&request_id),
        Some(&ContinuationState::Exhausted)
    );

    Ok(())
}
