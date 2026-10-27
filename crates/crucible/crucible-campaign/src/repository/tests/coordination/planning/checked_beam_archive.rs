//! Checked archive replay for a settled Beam survivor cohort.

use super::*;
use crate::repository::tests::transfer::inspection_io::assert_checked_mirror_archive;

#[test]
fn checked_mirror_replays_settled_beam_survivor_selection() {
    let (repository, lineage, base_policy) = fixture();
    let metric = "boundary.latency";
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            base_policy.scenario(),
            base_policy.campaign_seed(),
            base_policy.mode(),
            ExplorerPolicy::Beam {
                width: 1,
                novelty_reserve: 0,
            },
        ),
        CampaignPolicy::rules(
            base_policy.choice_policies().clone(),
            BTreeMap::from([(
                metric.to_owned(),
                Objective::new(metric, ObjectiveGoal::Minimize, 1_000_000).expect("Beam objective"),
            )]),
            base_policy.guidance().clone(),
            base_policy.stop_conditions().clone(),
            base_policy.fairness(),
            base_policy.retention(),
            base_policy.admits_scenario_defaults(),
        ),
    )
    .expect("Beam policy")
    .with_intervention_learning_policy(InterventionLearningPolicy::IncludeInGuidance)
    .expect("intervention-guided Beam policy");

    const CAMPAIGN: &str = "checked-settled-beam-archive";
    let genesis = repository
        .create_funded(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create Beam campaign");
    let producing_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "checked-beam-producing-request",
    );
    let requested = repository
        .submit_known_branch_request(CAMPAIGN, genesis.snapshot_id(), &producing_request)
        .expect("submit producing request");

    let selected_proposal = finite_proposal(
        &producing_request,
        &policy,
        &repository.head(CAMPAIGN).expect("selected proposal head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let selected_issued = repository
        .issue_proposal(CAMPAIGN, requested.new_snapshot, &selected_proposal)
        .expect("issue selected sibling");
    let (selected_selection, selected_path, selected_attempt) =
        branch_attempt(&repository, &producing_request, &selected_proposal);
    let selected_admission = repository
        .admit_proposal(
            CAMPAIGN,
            selected_issued.new_snapshot,
            selected_issued.proposal,
            &selected_selection,
            &selected_path,
            &selected_attempt,
        )
        .expect("admit selected sibling");

    let filtered_proposal = finite_proposal(
        &producing_request,
        &policy,
        &repository.head(CAMPAIGN).expect("filtered proposal head"),
        ChoiceValue::Boolean(true),
        2,
    );
    let filtered_issued = repository
        .issue_proposal(
            CAMPAIGN,
            selected_admission.new_snapshot,
            &filtered_proposal,
        )
        .expect("issue filtered sibling");
    let (filtered_selection, filtered_path, filtered_attempt) =
        branch_attempt(&repository, &producing_request, &filtered_proposal);
    let filtered_admission = repository
        .admit_proposal(
            CAMPAIGN,
            filtered_issued.new_snapshot,
            filtered_issued.proposal,
            &filtered_selection,
            &filtered_path,
            &filtered_attempt,
        )
        .expect("admit filtered sibling");

    let selected_configuration =
        ConfigurationId::from_hash(CampaignHash::derive("test-checked-beam-child", b"selected"));
    let selected_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            selected_configuration,
            1,
            b"selected child".to_vec(),
        )
        .expect("publish selected child");
    let selected_continuation = branch_request(
        &repository,
        &lineage,
        selected_content,
        selected_configuration,
        "checked-beam-selected-continuation",
    );
    let filtered_configuration =
        ConfigurationId::from_hash(CampaignHash::derive("test-checked-beam-child", b"filtered"));
    let filtered_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            filtered_configuration,
            1,
            b"filtered child".to_vec(),
        )
        .expect("publish filtered child");
    let filtered_continuation = branch_request(
        &repository,
        &lineage,
        filtered_content,
        filtered_configuration,
        "checked-beam-filtered-continuation",
    );

    let selected_measurements = repository
        .publish_measurement_set(
            &MeasurementSet::test_evaluation(metric.as_bytes(), BTreeSet::new())
                .expect("selected measurements"),
        )
        .expect("publish selected measurements");
    let filtered_measurements = repository
        .publish_measurement_set(
            &MeasurementSet::test_evaluation(b"empty", BTreeSet::new())
                .expect("empty measurements"),
        )
        .expect("publish filtered measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let properties_id = repository
        .publish_property_verdict_set(&properties)
        .expect("publish properties");
    let coverage = repository
        .publish_coverage_projection(
            &CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage"),
        )
        .expect("publish coverage");
    let selected_observation = Observation::new(
        selected_admission.attempt,
        Observation::outcome(
            selected_configuration,
            selected_content,
            selected_path.id().expect("selected path"),
            StopOutcome::Reached(StopCondition::NextChoice),
            selected_measurements,
            properties_id,
            coverage,
        ),
        BTreeSet::from([selected_continuation.opportunity()]),
    )
    .expect("selected observation");
    let filtered_observation = Observation::new(
        filtered_admission.attempt,
        Observation::outcome(
            filtered_configuration,
            filtered_content,
            filtered_path.id().expect("filtered path"),
            StopOutcome::Reached(StopCondition::NextChoice),
            filtered_measurements,
            properties_id,
            coverage,
        ),
        BTreeSet::from([filtered_continuation.opportunity()]),
    )
    .expect("filtered observation");
    let selected_observed = repository
        .publish_observation(
            CAMPAIGN,
            filtered_admission.new_snapshot,
            &selected_observation,
        )
        .expect("publish selected observation");
    let filtered_observed = repository
        .publish_observation(
            CAMPAIGN,
            selected_observed.new_snapshot,
            &filtered_observation,
        )
        .expect("publish filtered observation");

    let selected_evaluation = evaluate_objectives(
        &policy,
        &selected_observation,
        &properties,
        BTreeMap::from([(metric.to_owned(), ObjectiveValue::Unsigned(7))]),
    )
    .expect("evaluate selected observation");
    let selected_evaluated = repository
        .publish_objective_evaluation(
            CAMPAIGN,
            filtered_observed.new_snapshot,
            &selected_evaluation,
        )
        .expect("publish selected evaluation");
    let filtered_evaluation =
        evaluate_objectives(&policy, &filtered_observation, &properties, BTreeMap::new())
            .expect("evaluate missing boundary metric");
    let filtered_evaluated = repository
        .publish_objective_evaluation(
            CAMPAIGN,
            selected_evaluated.new_snapshot,
            &filtered_evaluation,
        )
        .expect("publish filtered evaluation");

    let selected_requested = repository
        .submit_known_branch_request(
            CAMPAIGN,
            filtered_evaluated.new_snapshot,
            &selected_continuation,
        )
        .expect("submit selected continuation");
    let filtered_requested = repository
        .submit_known_branch_request(
            CAMPAIGN,
            selected_requested.new_snapshot,
            &filtered_continuation,
        )
        .expect("submit filtered continuation");
    let settled_snapshot = filtered_requested.new_snapshot;

    let basis = repository
        .publish_canonical_beam_planner_basis()
        .expect("publish Beam planner basis");
    let invocation = repository
        .prepare_planner_invocation(
            CAMPAIGN,
            settled_snapshot,
            basis.engine(),
            basis.artifact(),
            basis.initial_state(),
            None,
            100,
            PlanningBudget::new(4, 4, 100, 4 * 1024 * 1024, 10_000).expect("Beam planning budget"),
        )
        .expect("prepare Beam invocation");
    let request = repository
        .build_planner_request(
            settled_snapshot,
            invocation.id().expect("Beam invocation ID"),
        )
        .expect("build settled Beam request");

    let candidate_inputs = request
        .input_bundle()
        .candidate_inputs(&request)
        .expect("decode settled Beam candidate inputs");
    let beam_candidates = candidate_inputs
        .values()
        .filter_map(|input| input.beam.as_ref())
        .collect::<Vec<_>>();
    assert!(!beam_candidates.is_empty());
    let selection_id = beam_candidates
        .iter()
        .find_map(|candidate| candidate.selection())
        .expect("retained request contains a settled Beam selection");
    let selection_envelope = request
        .input_bundle()
        .object(selection_id.content_id())
        .expect("decode retained Beam selection")
        .expect("retained Beam selection is embedded");
    let selection = SurvivorSelection::from_canonical_bytes(selection_envelope.body())
        .expect("decode survivor selection");
    assert!(!selection.selected().is_empty());

    for object_id in request.input_bundle().object_ids() {
        let object = request
            .input_bundle()
            .object(object_id)
            .expect("decode retained Beam input")
            .expect("retained Beam input is embedded");
        repository
            .put_envelope(object)
            .expect("materialize retained Beam input");
    }
    let request_id = repository
        .put_planner_request(&request)
        .expect("publish retained settled Beam request");
    assert_checked_mirror_archive(&repository, settled_snapshot, request_id);
}
