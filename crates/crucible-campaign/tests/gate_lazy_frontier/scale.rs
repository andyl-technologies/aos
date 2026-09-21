//! Frontier ceiling and restart scale regressions.

use super::*;

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
