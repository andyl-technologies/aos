//! Checked Mirror replay for a retained request with authenticated PUCT guidance.

use super::*;

#[test]
fn checked_mirror_archive_replays_retained_puct_guidance() {
    const NAME: &str = "checked-puct-archive";

    let (repository, lineage, base_policy) = fixture();
    let policy = base_policy
        .with_intervention_learning_policy(InterventionLearningPolicy::IncludeInGuidance)
        .expect("intervention-guided PUCT policy");
    let genesis = repository
        .create_funded(NAME, &lineage, &policy, &BTreeMap::new())
        .expect("create PUCT archive campaign");

    let first_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "checked-puct-archive-first",
    );
    let first = repository
        .submit_known_branch_request(NAME, genesis.snapshot_id(), &first_request)
        .expect("submit first PUCT request");
    let second_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "checked-puct-archive-second",
    );
    let second = repository
        .submit_known_branch_request(NAME, first.new_snapshot, &second_request)
        .expect("submit second PUCT request");

    let mut requests = [first_request, second_request];
    requests.sort_by_key(|request| {
        PlanningScanPosition::new(request.branch_point(), request.id().expect("request ID"))
    });
    let guided_request = requests[1].clone();
    let guided_request_id = guided_request.id().expect("guided request ID");

    let completed_proposal = finite_proposal(
        &guided_request,
        &policy,
        &repository.head(NAME).expect("request head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let proposed = repository
        .issue_proposal(NAME, second.new_snapshot, &completed_proposal)
        .expect("issue completed-edge proposal");
    let (selection, path, attempt) =
        branch_attempt(&repository, &guided_request, &completed_proposal);
    let admitted = repository
        .admit_proposal(
            NAME,
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit completed-edge attempt");

    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "test.checked-puct-archive",
        b"completed-child",
    ));
    let child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            child,
            1,
            b"checked PUCT archive child".to_vec(),
        )
        .expect("publish completed child");
    let measurements = repository
        .publish_measurement_set(
            &MeasurementSet::test_evaluation(b"empty", BTreeSet::new()).expect("measurements"),
        )
        .expect("publish measurements");
    let properties = repository
        .publish_property_verdict_set(
            &PropertyVerdictSet::new(BTreeMap::new()).expect("properties"),
        )
        .expect("publish properties");
    let coverage = repository
        .publish_coverage_projection(
            &CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage"),
        )
        .expect("publish coverage");
    let observation = Observation::new(
        admitted.attempt,
        Observation::outcome(
            child,
            child_content,
            path.id().expect("path ID"),
            StopOutcome::Reached(StopCondition::NextChoice),
            measurements,
            properties,
            coverage,
        ),
        BTreeSet::from([guided_request.opportunity()]),
    )
    .expect("completed observation");
    let observed = repository
        .publish_observation(NAME, admitted.new_snapshot, &observation)
        .expect("publish completed observation");

    let basis = repository
        .publish_canonical_puct_planner_basis()
        .expect("publish PUCT planner basis");
    let invocation = repository
        .prepare_planner_invocation(
            NAME,
            observed.new_snapshot,
            basis.engine(),
            basis.artifact(),
            basis.initial_state(),
            None,
            2,
            PlanningBudget::new(1, 1, 32, 1024 * 1024, 100).expect("planner budget"),
        )
        .expect("prepare PUCT invocation");
    let request = repository
        .build_planner_request(
            observed.new_snapshot,
            invocation.id().expect("planner invocation ID"),
        )
        .expect("build retained PUCT request");

    let ranked = request
        .ranked_candidates()
        .expect("rank authenticated PUCT candidates");
    let guided = ranked
        .iter()
        .find(|candidate| candidate.proposal().request() == guided_request_id)
        .expect("subsequent Ready offer for completed-edge request");
    assert!(guided.proposal().ordinal() > completed_proposal.ordinal());
    assert_eq!(
        guided.proposal().guidance_basis(),
        request.invocation().input_view()
    );
    assert_eq!(
        guided.guidance().input_view(),
        request.invocation().input_view()
    );
    assert_eq!(guided.guidance().statistics().parent_visits(), 1);
    assert_eq!(guided.guidance().statistics().edge_visits(), 0);
    assert!(guided.score().total_micros() > 0);

    let bundled_guidance = request
        .input_bundle()
        .object_ids()
        .filter_map(|id| {
            let envelope = request
                .input_bundle()
                .object(id)
                .expect("decode retained input")
                .expect("retained input object");
            (envelope.record_kind() == crate::CampaignRecordKind::PlannerCandidateGuidance).then(
                || {
                    crate::PlannerCandidateGuidance::from_canonical_bytes(envelope.body())
                        .expect("canonical candidate guidance")
                },
            )
        })
        .find(|guidance| guidance.position().source() == guided_request_id)
        .expect("guided request bundle record");
    assert_eq!(&bundled_guidance, guided.guidance());

    let retained = repository
        .put_planner_request(&request)
        .expect("publish retained PUCT request");
    crate::repository::tests::transfer::inspection_io::assert_checked_mirror_archive(
        &repository,
        observed.new_snapshot,
        retained,
    );
}
