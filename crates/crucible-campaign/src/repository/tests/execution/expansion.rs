//! Finite expansion and branch guidance budget tests.

use super::*;

#[test]
fn finite_expansion_pages_are_snapshot_bound_admission_backed_and_owner_recomputed() {
    let (repository, lineage, base_policy) = fixture();
    let objective_name = "recovery.score";
    let policy = CampaignPolicy::new(
        base_policy.scenario(),
        base_policy.campaign_seed(),
        base_policy.mode(),
        base_policy.explorer().clone(),
        base_policy.choice_policies().clone(),
        BTreeMap::from([(
            objective_name.to_owned(),
            Objective::new(objective_name, ObjectiveGoal::Maximize, 1_000_000).expect("objective"),
        )]),
        base_policy.guidance().clone(),
        base_policy.stop_conditions().clone(),
        base_policy.fairness(),
        base_policy.retention(),
        base_policy.admits_scenario_defaults(),
    )
    .expect("objective-guided finite-expansion policy");
    let genesis = repository
        .create_funded("finite-expansion", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let model = ProbabilityModelId::from_hash(CampaignHash::derive(
        "test.finite-expansion-model.v1",
        b"network retry",
    ));
    let first_request = modeled_branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "finite-expansion",
        model,
        BTreeMap::from([
            (ChoiceValue::Boolean(false), 1),
            (ChoiceValue::Boolean(true), 3),
        ]),
    );
    assert_eq!(first_request.source().model_prior(), Some(model));
    let discovered = repository
        .discover_choice_opportunity(
            "finite-expansion",
            genesis.snapshot_id(),
            first_request.parent(),
            first_request.opportunity(),
        )
        .expect("discover modeled opportunity");
    let wrong_model = ProbabilityModelId::from_hash(CampaignHash::derive(
        "test.finite-expansion-model.v1",
        b"wrong network retry",
    ));
    let mismatched_request = BranchRequest::new(
        first_request.branch_point(),
        first_request.parent(),
        first_request.opportunity(),
        first_request.domain(),
        CandidateSource::modeled_finite(
            wrong_model,
            BTreeMap::from([
                (ChoiceValue::Boolean(false), 1),
                (ChoiceValue::Boolean(true), 3),
            ]),
        )
        .expect("mismatched modeled source"),
        first_request.cause(),
        first_request.budget(),
        first_request.stop().clone(),
    )
    .expect("mismatched modeled request");
    assert!(matches!(
        repository.submit_branch_request(
            "finite-expansion",
            discovered.new_snapshot,
            &mismatched_request,
        ),
        Err(CampaignRepositoryError::Codec(
            CampaignCodecError::InvalidValue {
                reason: "branch request modeled prior disagrees with its opportunity"
            }
        ))
    ));
    assert_eq!(
        repository
            .head("finite-expansion")
            .expect("head after rejected modeled prior")
            .snapshot_id(),
        discovered.new_snapshot
    );
    let first_requested = repository
        .submit_branch_request("finite-expansion", discovered.new_snapshot, &first_request)
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
    let crate::SelectionOrigin::CampaignBranch {
        edge: first_edge, ..
    } = selection.origin()
    else {
        panic!("first campaign branch selection")
    };
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

    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "test-observation-child",
        b"finite-expansion-static-observation",
    ));
    let child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            child,
            1,
            b"finite expansion child".to_vec(),
        )
        .expect("publish finite expansion child");
    let measurements = repository
        .publish_measurement_set(&MeasurementSet::new(BTreeMap::new()).expect("empty measurements"))
        .expect("publish finite expansion measurements");
    let properties = repository
        .publish_property_verdict_set(
            &PropertyVerdictSet::new(BTreeMap::new()).expect("empty properties"),
        )
        .expect("publish finite expansion properties");
    let shared_coverage = CampaignHash::derive("test.finite-expansion.coverage", b"shared");
    let root_unique_coverage =
        CampaignHash::derive("test.finite-expansion.coverage", b"root-unique");
    let nested_unique_coverage =
        CampaignHash::derive("test.finite-expansion.coverage", b"nested-unique");
    let coverage = repository
        .publish_coverage_projection(
            &CoverageProjection::new(
                BTreeSet::from([shared_coverage, root_unique_coverage]),
                BTreeSet::new(),
            )
            .expect("root coverage"),
        )
        .expect("publish finite expansion coverage");
    let observation = Observation::new(
        first_admitted.attempt,
        child,
        child_content,
        path.id().expect("first path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        coverage,
        BTreeSet::from([first_request.opportunity()]),
    )
    .expect("finite expansion observation");
    let observed = repository
        .publish_observation(
            "finite-expansion",
            first_admitted.new_snapshot,
            &observation,
        )
        .expect("publish finite expansion observation");
    let observed_snapshot = repository
        .read_snapshot(observed.new_snapshot.content_id())
        .expect("observation snapshot");
    let configuration_path_index = repository
        .merkle
        .get(
            observed_snapshot.snapshot.roots().observations,
            configuration_path_index_key(child_content),
        )
        .expect("configuration path index lookup")
        .expect("configuration path index");
    assert_eq!(
        repository
            .merkle
            .get(
                configuration_path_index,
                path_index_order_key(path.id().expect("first path id")),
            )
            .expect("configuration path membership"),
        Some(path.id().expect("first path id").content_id())
    );

    let mut forged_path_roots = observed_snapshot.snapshot.roots();
    forged_path_roots.observations = repository
        .merkle
        .insert(
            forged_path_roots.observations,
            configuration_path_index_key(child_content),
            MerkleMap::empty_content_id().expect("empty path index"),
        )
        .expect("forge empty configuration path index")
        .content_id();
    let forged_path_snapshot = CampaignSnapshot::successor(
        first_admitted.new_snapshot,
        observed_snapshot.snapshot.lineage(),
        observed_snapshot.snapshot.active_policy(),
        forged_path_roots,
        observed_snapshot
            .snapshot
            .transition()
            .expect("observation transition"),
    )
    .expect("forged path-index successor");
    let forged_path_content = repository
        .put_snapshot(&forged_path_snapshot)
        .expect("put forged path-index successor");
    assert!(matches!(
        repository.validate_complete_head(forged_path_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "observation-transition-observations-root"
        })
    ));

    let replayed_observation = repository
        .publish_observation(
            "finite-expansion",
            first_admitted.new_snapshot,
            &observation,
        )
        .expect("replay finite expansion observation before staleness");
    assert!(replayed_observation.replayed);
    assert_eq!(replayed_observation.new_snapshot, observed.new_snapshot);

    let conflicting_child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            child,
            1,
            b"finite expansion conflicting child".to_vec(),
        )
        .expect("publish conflicting finite expansion child");
    let conflicting_observation = Observation::new(
        first_admitted.attempt,
        child,
        conflicting_child_content,
        path.id().expect("first path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        coverage,
        BTreeSet::from([first_request.opportunity()]),
    )
    .expect("finite expansion conflicting observation");
    let conflict = repository
        .publish_observation(
            "finite-expansion",
            observed.new_snapshot,
            &conflicting_observation,
        )
        .expect("publish finite expansion conflict");
    assert_eq!(
        conflict.disposition,
        ObservationDisposition::DeterminismConflict {
            canonical: observation.id().expect("canonical observation id")
        }
    );
    let observed_id = repository
        .project_finite_expansion(
            conflict.new_snapshot,
            first_request.branch_point(),
            None,
            10,
        )
        .expect("observation-bearing static projection");
    let observed_state = repository
        .load_expansion_state(observed_id)
        .expect("load observation-bearing static projection");
    assert_eq!(
        observed_state
            .continuations()
            .get(&first_request.id().expect("first request id")),
        Some(&ContinuationState::Ready)
    );
    assert_eq!(observed_state.statistics().admitted_children, 1);
    assert_eq!(observed_state.statistics().completed_visits, 1);
    assert_eq!(
        observed_state.observation_root(),
        repository
            .head("finite-expansion")
            .expect("observed head")
            .snapshot()
            .roots()
            .observations
    );

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .load_expansion_state(observed_id)
            .expect("restart-load observation-bearing static projection"),
        observed_state
    );
    assert_eq!(
        restarted
            .project_finite_expansion(
                conflict.new_snapshot,
                first_request.branch_point(),
                None,
                10,
            )
            .expect("restart-project observation-bearing static projection"),
        observed_id
    );

    let nested_opportunity = repository
        .load_choice_opportunity(first_request.opportunity())
        .expect("nested opportunity");
    let nested_domain = repository
        .load_choice_domain(first_request.domain())
        .expect("nested domain");
    let nested_branch_point = nested_opportunity.branch_point_id(child);
    let nested_request = BranchRequest::new(
        nested_branch_point,
        child_content,
        first_request.opportunity(),
        first_request.domain(),
        CandidateSource::weighted_finite(BTreeMap::from([
            (ChoiceValue::Boolean(false), 9),
            (ChoiceValue::Boolean(true), 1),
        ]))
        .expect("nested weighted finite source"),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test.finite-expansion-nested-request",
            b"nested",
        ))),
        first_request.budget(),
        first_request.stop().clone(),
    )
    .expect("nested branch request");
    let nested_requested = repository
        .submit_known_branch_request("finite-expansion", conflict.new_snapshot, &nested_request)
        .expect("submit nested branch request");
    let nested_request_head = repository
        .head("finite-expansion")
        .expect("nested request head");
    let nested_proposal = finite_proposal(
        &nested_request,
        &policy,
        &nested_request_head,
        ChoiceValue::Boolean(false),
        1,
    );
    let nested_proposed = repository
        .issue_proposal(
            "finite-expansion",
            nested_requested.new_snapshot,
            &nested_proposal,
        )
        .expect("nested proposal");
    let nested_selection = Selection::new_campaign_branch(
        &nested_opportunity,
        &nested_domain,
        nested_proposal.value().clone(),
        nested_branch_point,
    )
    .expect("nested branch selection");
    let crate::SelectionOrigin::CampaignBranch {
        edge: nested_edge, ..
    } = nested_selection.origin()
    else {
        panic!("nested campaign branch selection")
    };
    let unauthenticated_nested_path = BranchPath::new(vec![crate::BranchPathSegment::new(
        nested_branch_point,
        nested_edge,
    )])
    .expect("unauthenticated nested path");
    let unauthenticated_nested_attempt = Attempt::new(
        AttemptStart::Branch {
            edge: nested_edge,
            parent: nested_request.parent(),
            selection: nested_selection.id().expect("nested selection id"),
        },
        unauthenticated_nested_path
            .id()
            .expect("unauthenticated nested path id"),
        nested_request.stop().clone(),
    )
    .expect("unauthenticated nested attempt");
    assert!(matches!(
        repository.admit_proposal(
            "finite-expansion",
            nested_proposed.new_snapshot,
            nested_proposed.proposal,
            &nested_selection,
            &unauthenticated_nested_path,
            &unauthenticated_nested_attempt,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-admission-path-prefix-is-not-authoritative"
        })
    ));
    assert_eq!(
        repository
            .head("finite-expansion")
            .expect("head after rejected nested prefix")
            .snapshot_id(),
        nested_proposed.new_snapshot
    );

    let mut nested_segments = path.segments().expect("scoped first path").to_vec();
    nested_segments.push(crate::BranchPathSegment::new(
        nested_branch_point,
        nested_edge,
    ));
    let nested_path = BranchPath::new(nested_segments).expect("cumulative nested path");
    let nested_attempt = Attempt::new(
        AttemptStart::Branch {
            edge: nested_edge,
            parent: nested_request.parent(),
            selection: nested_selection.id().expect("nested selection id"),
        },
        nested_path.id().expect("nested path id"),
        nested_request.stop().clone(),
    )
    .expect("nested attempt");
    let admission_restarted =
        CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let nested_admitted = admission_restarted
        .admit_proposal(
            "finite-expansion",
            nested_proposed.new_snapshot,
            nested_proposed.proposal,
            &nested_selection,
            &nested_path,
            &nested_attempt,
        )
        .expect("admit nested proposal");
    let nested_child = ConfigurationId::from_hash(CampaignHash::derive(
        "test-observation-child",
        b"finite-expansion-nested-observation",
    ));
    let nested_child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            nested_child,
            1,
            b"finite expansion nested child".to_vec(),
        )
        .expect("publish nested child");
    let nested_coverage = repository
        .publish_coverage_projection(
            &CoverageProjection::new(
                BTreeSet::from([shared_coverage, nested_unique_coverage]),
                BTreeSet::new(),
            )
            .expect("nested coverage"),
        )
        .expect("publish nested coverage");
    let nested_observation = Observation::new(
        nested_admitted.attempt,
        nested_child,
        nested_child_content,
        nested_path.id().expect("nested path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        nested_coverage,
        BTreeSet::from([first_request.opportunity()]),
    )
    .expect("nested observation");
    let nested_observed = repository
        .publish_observation(
            "finite-expansion",
            nested_admitted.new_snapshot,
            &nested_observation,
        )
        .expect("publish nested observation");
    let before_objective = repository
        .project_branch_puct(nested_observed.new_snapshot, nested_branch_point)
        .expect("project nested PUCT before objective publication");
    assert!(before_objective.edge_objective_reward_micros().is_empty());
    let nested_properties = repository
        .load_property_verdict_set(nested_observation.properties())
        .expect("nested objective properties");
    let nested_evaluation = evaluate_objectives(
        &policy,
        &nested_observation,
        &nested_properties,
        BTreeMap::from([(objective_name.to_owned(), ObjectiveValue::Signed(-3))]),
    )
    .expect("nested objective evaluation");
    let evaluated = repository
        .publish_objective_evaluation(
            "finite-expansion",
            nested_observed.new_snapshot,
            &nested_evaluation,
        )
        .expect("publish nested objective evaluation");
    let nested_root_id = repository
        .project_finite_expansion(
            nested_observed.new_snapshot,
            first_request.branch_point(),
            None,
            10,
        )
        .expect("project root after nested observation");
    let nested_root_state = repository
        .load_expansion_state(nested_root_id)
        .expect("load root after nested observation");
    assert_eq!(nested_root_state.statistics().completed_visits, 2);
    let nested_id = repository
        .project_finite_expansion(nested_observed.new_snapshot, nested_branch_point, None, 10)
        .expect("project nested observation");
    let nested_state = repository
        .load_expansion_state(nested_id)
        .expect("load nested observation projection");
    assert_eq!(nested_state.statistics().admitted_children, 1);
    assert_eq!(nested_state.statistics().completed_visits, 1);
    let root_edge_visits = repository
        .project_branch_edge_visits(nested_observed.new_snapshot, first_request.branch_point())
        .expect("project root edge visits");
    assert_eq!(
        root_edge_visits.branch_point(),
        first_request.branch_point()
    );
    assert_eq!(root_edge_visits.parent_visits(), 2);
    assert_eq!(
        root_edge_visits.edge_visits(),
        &BTreeMap::from([(first_edge, 2)])
    );
    let nested_edge_visits = repository
        .project_branch_edge_visits(nested_observed.new_snapshot, nested_branch_point)
        .expect("project nested edge visits");
    assert_eq!(nested_edge_visits.parent_visits(), 1);
    assert_eq!(
        nested_edge_visits.edge_visits(),
        &BTreeMap::from([(nested_edge, 1)])
    );
    let root_puct = repository
        .project_branch_puct(evaluated.new_snapshot, first_request.branch_point())
        .expect("project root PUCT statistics");
    assert_eq!(root_puct.branch_point(), first_request.branch_point());
    assert_eq!(root_puct.policy(), policy.id().expect("policy id"));
    assert_eq!(root_puct.parent_visits(), 2);
    assert_eq!(root_puct.edge_statistics().len(), 1);
    assert_eq!(
        root_puct.edge_prior_weights(),
        &BTreeMap::from([(first_edge, 1)])
    );
    let root_edge_statistics = root_puct
        .edge_statistics()
        .get(&first_edge)
        .expect("root edge PUCT statistics");
    assert_eq!(root_edge_statistics.edge_visits(), 2);
    assert_eq!(
        root_edge_statistics.prior_micros(),
        crate::GUIDANCE_MICROS_PER_UNIT
    );
    assert_eq!(
        root_puct.edge_objective_reward_micros(),
        &BTreeMap::from([(first_edge, -3_000_000)])
    );
    assert_eq!(root_edge_statistics.reward_sum_micros(), -3_000_000);
    assert!(root_edge_statistics.is_novel());
    assert!(root_edge_statistics.is_fairness_reserved());
    // The conflict above repeats the root-only identity but is not canonical;
    // the shared canonical identity is non-novel, while both path-unique
    // identities backpropagate to this root edge.
    assert_eq!(
        root_puct.edge_novelty_events(),
        &BTreeMap::from([(first_edge, 2)])
    );
    assert_eq!(
        root_puct.edge_scores()[&first_edge].novelty_bonus_micros(),
        1
    );
    assert!(root_puct.edge_scores().contains_key(&first_edge));
    let nested_puct = repository
        .project_branch_puct(evaluated.new_snapshot, nested_branch_point)
        .expect("project nested PUCT statistics");
    assert_eq!(
        nested_puct.edge_prior_weights(),
        &BTreeMap::from([(nested_edge, 9)])
    );
    assert_eq!(
        nested_puct.edge_novelty_events(),
        &BTreeMap::from([(nested_edge, 1)])
    );
    assert!(nested_puct.edge_statistics()[&nested_edge].is_novel());
    assert_eq!(
        nested_puct.edge_objective_reward_micros(),
        &BTreeMap::from([(nested_edge, -3_000_000)])
    );
    assert_eq!(
        nested_puct.edge_scores()[&nested_edge].mean_reward_micros(),
        -3_000_000
    );
    let nested_restarted =
        CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        nested_restarted
            .load_expansion_state(nested_root_id)
            .expect("restart-load root after nested observation"),
        nested_root_state
    );
    assert_eq!(
        nested_restarted
            .project_finite_expansion(nested_observed.new_snapshot, nested_branch_point, None, 10,)
            .expect("restart-project nested observation"),
        nested_id
    );
    assert_eq!(
        nested_restarted
            .project_branch_edge_visits(nested_observed.new_snapshot, first_request.branch_point(),)
            .expect("restart-project root edge visits"),
        root_edge_visits
    );
    assert_eq!(
        nested_restarted
            .project_branch_puct(evaluated.new_snapshot, first_request.branch_point())
            .expect("restart-project root PUCT statistics"),
        root_puct
    );
    assert_eq!(
        nested_restarted
            .project_branch_puct(evaluated.new_snapshot, nested_branch_point)
            .expect("restart-project nested PUCT statistics"),
        nested_puct
    );

    let admitted_head = repository.head("finite-expansion").expect("admitted head");
    let second_proposal = finite_proposal(
        &first_request,
        &policy,
        &admitted_head,
        ChoiceValue::Boolean(true),
        2,
    );
    let loaded = repository
        .read_snapshot(admitted_head.snapshot_id().content_id())
        .expect("weighted-guidance snapshot");
    let mut candidate_cache = Default::default();
    let weighted_guidance = repository
        .planner_candidate_guidance(
            &loaded,
            &root_puct,
            &second_proposal,
            2,
            &mut candidate_cache,
        )
        .expect("weighted prospective guidance");
    assert_eq!(weighted_guidance.statistics().prior_micros(), 750_000);
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
    let frontier_head = repository.head("finite-expansion").expect("frontier head");
    let frontier_request = QueryCampaignFrontierRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("finite-expansion").expect("campaign"),
        frontier_head.snapshot_id(),
        None,
        8,
    )
    .expect("frontier request");
    let client = crate::CampaignClient::new(RepositoryCampaignService::new(
        &repository,
        AllowCampaignQueries,
    ));
    let frontier = client
        .query_campaign_frontier(&frontier_request)
        .expect("authenticated frontier page");
    assert_eq!(frontier.entries().len(), 3);
    assert_eq!(
        frontier
            .entries()
            .iter()
            .find(|entry| entry.request() == first_request.id().expect("first request"))
            .map(|entry| entry.state()),
        Some(ContinuationState::Exhausted)
    );
    assert_eq!(frontier.next_after(), None);
    let first_request_id = first_request.id().expect("first request");
    let frontier_object = client
        .get_campaign_frontier_object(
            &GetCampaignFrontierObjectRequest::new(
                CampaignPrincipal::new("operator:alice").expect("principal"),
                CampaignName::new("finite-expansion").expect("campaign"),
                frontier_head.snapshot_id(),
                first_request_id,
            )
            .expect("frontier object request"),
        )
        .expect("authenticated frontier object");
    assert_eq!(frontier_object.object(), &first_request);
    assert_eq!(frontier_object.projection().request(), first_request_id);
    assert_eq!(
        frontier_object.projection().state(),
        ContinuationState::Exhausted
    );
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

    let forged_observation = ExpansionState::new(
        observed_state.source_snapshot(),
        observed_state.input_view(),
        observed_state.branch_point(),
        observed_state.request_root(),
        observed_state.proposal_root(),
        observed_state.admission_root(),
        empty,
        observed_state.statistics(),
        observed_state.page_after(),
        observed_state.page_size(),
        observed_state.next_after(),
        observed_state.continuations().clone(),
    )
    .expect("structurally valid forged observation root");
    let forged_observation_content = repository
        .put_expansion_state(&forged_observation)
        .expect("put forged observation projection");
    assert!(matches!(
        repository.load_expansion_state(
            ExpansionStateId::from_content_id(forged_observation_content)
                .expect("forged observation expansion id")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "expansion-state-owner-recomputation-mismatch"
        })
    ));

    let forged_statistics = ExpansionState::new(
        observed_state.source_snapshot(),
        observed_state.input_view(),
        observed_state.branch_point(),
        observed_state.request_root(),
        observed_state.proposal_root(),
        observed_state.admission_root(),
        observed_state.observation_root(),
        crate::ExpansionStatistics {
            completed_visits: 2,
            ..observed_state.statistics()
        },
        observed_state.page_after(),
        observed_state.page_size(),
        observed_state.next_after(),
        observed_state.continuations().clone(),
    )
    .expect("structurally valid forged visit count");
    let forged_statistics_content = repository
        .put_expansion_state(&forged_statistics)
        .expect("put forged visit-count projection");
    assert!(matches!(
        repository.load_expansion_state(
            ExpansionStateId::from_content_id(forged_statistics_content)
                .expect("forged visit-count expansion id")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "expansion-state-owner-recomputation-mismatch"
        })
    ));
}

#[test]
fn branch_guidance_work_budgets_accept_only_the_exact_boundary() {
    assert_eq!(
        super::super::projection::charge_branch_edge_visit_credits(
            crate::MAX_BRANCH_EDGE_VISIT_PROJECTION_CREDITS - 1,
            1,
        )
        .expect("exact aggregate credit boundary"),
        crate::MAX_BRANCH_EDGE_VISIT_PROJECTION_CREDITS
    );
    assert!(matches!(
        super::super::projection::charge_branch_edge_visit_credits(
            crate::MAX_BRANCH_EDGE_VISIT_PROJECTION_CREDITS,
            1,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-edge-visit-projection-count"
        })
    ));
    assert_eq!(
        super::super::projection::charge_branch_prior_normalization_visits(
            crate::MAX_BRANCH_PRIOR_NORMALIZATION_VISITS - 1,
            1,
        )
        .expect("exact prior-normalization boundary"),
        crate::MAX_BRANCH_PRIOR_NORMALIZATION_VISITS
    );
    assert!(matches!(
        super::super::projection::charge_branch_prior_normalization_visits(
            crate::MAX_BRANCH_PRIOR_NORMALIZATION_VISITS,
            1,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-prior-normalization-visit-count"
        })
    ));
    assert_eq!(
        super::super::projection::charge_branch_novelty_work(
            crate::MAX_BRANCH_NOVELTY_PROJECTION_BYTES - 1,
            1,
        )
        .expect("exact novelty byte boundary"),
        crate::MAX_BRANCH_NOVELTY_PROJECTION_BYTES
    );
    assert!(matches!(
        super::super::projection::charge_branch_novelty_work(
            crate::MAX_BRANCH_NOVELTY_PROJECTION_BYTES,
            1,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-novelty-projection-byte-limit"
        })
    ));
    assert_eq!(
        super::super::projection::charge_branch_novelty_identity_visits(
            crate::MAX_BRANCH_NOVELTY_IDENTITY_VISITS - 1,
            1,
        )
        .expect("exact novelty identity boundary"),
        crate::MAX_BRANCH_NOVELTY_IDENTITY_VISITS
    );
    assert!(matches!(
        super::super::projection::charge_branch_novelty_identity_visits(
            crate::MAX_BRANCH_NOVELTY_IDENTITY_VISITS,
            1,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-novelty-identity-visit-limit"
        })
    ));
    assert_eq!(
        super::super::projection::charge_branch_finding_work(
            crate::MAX_BRANCH_FINDING_PROJECTION_BYTES - 1,
            1,
        )
        .expect("exact finding byte boundary"),
        crate::MAX_BRANCH_FINDING_PROJECTION_BYTES
    );
    assert!(matches!(
        super::super::projection::charge_branch_finding_work(
            crate::MAX_BRANCH_FINDING_PROJECTION_BYTES,
            1,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-finding-projection-byte-limit"
        })
    ));
    assert_eq!(
        super::super::projection::charge_branch_finding_occurrence_visits(
            crate::MAX_BRANCH_FINDING_OCCURRENCE_VISITS - 1,
            1,
        )
        .expect("exact finding occurrence boundary"),
        crate::MAX_BRANCH_FINDING_OCCURRENCE_VISITS
    );
    assert!(matches!(
        super::super::projection::charge_branch_finding_occurrence_visits(
            crate::MAX_BRANCH_FINDING_OCCURRENCE_VISITS,
            1,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-finding-occurrence-visit-limit"
        })
    ));
    assert_eq!(
        super::super::projection::charge_branch_objective_evaluations(
            crate::MAX_BRANCH_OBJECTIVE_EVALUATIONS - 1,
        )
        .expect("exact objective evaluation boundary"),
        crate::MAX_BRANCH_OBJECTIVE_EVALUATIONS
    );
    assert!(matches!(
        super::super::projection::charge_branch_objective_evaluations(
            crate::MAX_BRANCH_OBJECTIVE_EVALUATIONS,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-objective-evaluation-count"
        })
    ));
    assert_eq!(
        super::super::projection::charge_branch_objective_work(
            crate::MAX_BRANCH_OBJECTIVE_PROJECTION_BYTES - 1,
            1,
        )
        .expect("exact objective byte boundary"),
        crate::MAX_BRANCH_OBJECTIVE_PROJECTION_BYTES
    );
    assert!(matches!(
        super::super::projection::charge_branch_objective_work(
            crate::MAX_BRANCH_OBJECTIVE_PROJECTION_BYTES,
            1,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-objective-projection-byte-limit"
        })
    ));
    assert_eq!(
        super::super::projection::charge_planner_guidance_domain_work(
            crate::MAX_PLANNER_GUIDANCE_DOMAIN_BYTES - 1,
            1,
        )
        .expect("exact planner guidance domain boundary"),
        crate::MAX_PLANNER_GUIDANCE_DOMAIN_BYTES
    );
    assert!(matches!(
        super::super::projection::charge_planner_guidance_domain_work(
            crate::MAX_PLANNER_GUIDANCE_DOMAIN_BYTES,
            1,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-guidance-domain-byte-limit"
        })
    ));
}
