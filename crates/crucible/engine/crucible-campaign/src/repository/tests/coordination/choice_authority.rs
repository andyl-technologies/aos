//! Scoped choice knowledge, canonical component authority, and exact lazy branch admission.

use super::*;

#[test]
fn choice_discovery_is_exact_replayable_and_required_before_branching() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("choice-discovery", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "choice-discovery",
    );
    assert!(matches!(
        repository.submit_branch_request("choice-discovery", genesis.snapshot_id(), &request),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-request-opportunity-is-not-authoritative-campaign-knowledge"
        })
    ));
    assert_eq!(
        repository
            .head("choice-discovery")
            .expect("unchanged genesis")
            .snapshot_id(),
        genesis.snapshot_id()
    );

    let discovered = repository
        .discover_choice_opportunity(
            "choice-discovery",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover choice");
    assert!(!discovered.replayed);
    assert_eq!(discovered.prior_snapshot, genesis.snapshot_id());
    assert_eq!(discovered.parent, request.parent());
    assert_eq!(discovered.branch_point, request.branch_point());
    let discovery_snapshot = repository
        .read_snapshot(discovered.new_snapshot.content_id())
        .expect("discovery snapshot");
    assert_eq!(
        repository
            .merkle
            .get(
                discovery_snapshot.snapshot.roots().graph,
                authoritative_choice_key(request.opportunity()),
            )
            .expect("authoritative choice membership"),
        Some(request.opportunity().content_id())
    );
    let opportunity = repository
        .load_choice_opportunity(request.opportunity())
        .expect("load discovered opportunity");
    let object_request = crate::GetCampaignChoiceObjectRequest::new(
        crate::CampaignPrincipal::new("operator:alice").expect("principal"),
        crate::CampaignName::new("choice-discovery").expect("campaign"),
        discovered.new_snapshot,
        request.opportunity(),
        crate::CampaignChoiceObjectKind::Domain,
    )
    .expect("choice object request");
    let object_response = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &repository,
        PermitAlice,
    ))
    .get_campaign_choice_object(&object_request)
    .expect("authenticated choice domain");
    assert_eq!(object_response.opportunity(), &opportunity);
    assert!(matches!(
        object_response.object(),
        crate::CampaignChoiceObject::Domain(domain) if domain.id().expect("domain id") == opportunity.domain()
    ));
    let (choice_page, index_proof, page_proof) = repository
        .scan_choice_page(discovery_snapshot.snapshot.roots().graph, None, 1)
        .expect("authenticated choice page");
    assert_eq!(
        choice_page.entries(),
        &[(
            choice_index_order_key(request.opportunity()),
            request.opportunity().content_id(),
        )]
    );
    assert!(index_proof.node_count() > 0);
    assert!(page_proof.node_count() > 0);
    let choice_index = repository
        .merkle
        .get(
            discovery_snapshot.snapshot.roots().graph,
            choice_index_anchor_key(),
        )
        .expect("choice-index anchor")
        .expect("choice-index root");
    assert_eq!(
        repository
            .merkle
            .get(choice_index, choice_index_order_key(request.opportunity()),)
            .expect("choice-index membership"),
        Some(request.opportunity().content_id())
    );
    assert_eq!(
        repository
            .merkle
            .get(
                discovery_snapshot.snapshot.roots().graph,
                branch_point_opportunity_key(request.branch_point(), request.opportunity()),
            )
            .expect("scoped choice membership"),
        Some(request.opportunity().content_id())
    );

    let accepted = repository
        .submit_branch_request("choice-discovery", discovered.new_snapshot, &request)
        .expect("submit known request");
    let historical_response = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &repository,
        PermitAlice,
    ))
    .get_campaign_choice_object(&object_request)
    .expect("load choice domain from an exact historical snapshot");
    assert_eq!(
        historical_response
            .snapshot_body()
            .id()
            .expect("snapshot id"),
        discovered.new_snapshot
    );
    let replay = repository
        .discover_choice_opportunity(
            "choice-discovery",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("replay discovery before stale check");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, discovered.new_snapshot);
    assert_eq!(
        repository
            .head("choice-discovery")
            .expect("branch head remains current")
            .snapshot_id(),
        accepted.new_snapshot
    );

    let mut forged_roots = discovery_snapshot.snapshot.roots();
    forged_roots.graph = repository
        .merkle
        .insert(
            forged_roots.graph,
            map_key_content("graph.forged-choice", request.opportunity().content_id()),
            request.opportunity().content_id(),
        )
        .expect("forged discovery graph")
        .content_id();
    let forged = CampaignSnapshot::successor(
        genesis.snapshot_id(),
        discovery_snapshot.snapshot.lineage(),
        discovery_snapshot.snapshot.active_policy(),
        forged_roots,
        discovery_snapshot
            .snapshot
            .transition()
            .expect("discovery transition"),
        crate::test_budget_ledger_id(),
    )
    .expect("forged discovery successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged discovery successor");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "choice-discovery-graph-root-mismatch"
        })
    ));
}

#[test]
fn choice_authority_is_scoped_to_the_exact_parent_branch_point() {
    let (repository, lineage, policy) = fixture();
    let (genesis, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "choice-parent-scope");
    let observed = repository
        .publish_observation("choice-parent-scope", admitted.new_snapshot, &observation)
        .expect("publish child observation");

    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "genesis-only-choice",
    );
    let discovered = repository
        .discover_choice_opportunity(
            "choice-parent-scope",
            observed.new_snapshot,
            request.parent(),
            request.opportunity(),
        )
        .expect("discover choice only at genesis");
    let opportunity = repository
        .load_choice_opportunity(request.opportunity())
        .expect("load opportunity");
    let cross_parent = BranchRequest::new(
        BranchRequest::identity(
            opportunity.branch_point_id(observation.child()),
            observation.child_content(),
            request.opportunity(),
            request.domain(),
        ),
        request.source().clone(),
        request.cause(),
        request.budget(),
        request.stop().clone(),
    )
    .expect("cross-parent request");
    assert!(matches!(
        repository.submit_branch_request(
            "choice-parent-scope",
            discovered.new_snapshot,
            &cross_parent,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-request-opportunity-is-not-authoritative-campaign-knowledge"
        })
    ));
    assert_eq!(
        repository
            .head("choice-parent-scope")
            .expect("unchanged scoped head")
            .snapshot_id(),
        discovered.new_snapshot
    );
    assert_ne!(genesis, observed.new_snapshot);
}

#[test]
fn authority_adapters_bind_canonical_messages_without_prevalidation_writes() {
    let shared = [41; 32];
    assert!(matches!(
        CampaignRepository::with_component_authorities(
            Arc::new(MemoryBlobBackend::new("equal-authority", 1024)),
            Arc::new(MemoryRefBackend::new()),
            PlannerAuthorityKey::from_bytes(shared).expect("shared planner authority"),
            DebuggerAuthorityKey::from_bytes(shared).expect("shared debugger authority"),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "component-authority-keys-must-be-distinct"
        })
    ));
    let (repository, lineage, policy, blobs, planner_key, debugger_key) = authorized_fixture();
    assert!(PlannerAuthorityKey::from_bytes([0; 32]).is_err());
    assert!(DebuggerAuthorityKey::from_bytes([0; 32]).is_err());

    let debugger_genesis = repository
        .create("debugger-authority", &lineage, &policy, &BTreeMap::new())
        .expect("create debugger campaign");
    let operator_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "debugger-authority",
    );
    let session = DebugSessionId::from_hash(CampaignHash::derive(
        "test-debug-session",
        b"debugger-authority",
    ));
    let debugger_request = BranchRequest::new(
        BranchRequest::identity(
            operator_request.branch_point(),
            operator_request.parent(),
            operator_request.opportunity(),
            operator_request.domain(),
        ),
        operator_request.source().clone(),
        BranchRequestCause::Debugger(session),
        operator_request.budget(),
        operator_request.stop().clone(),
    )
    .expect("debugger request");
    assert!(matches!(
        repository.submit_operator_branch_request(
            "debugger-authority",
            debugger_genesis.snapshot_id(),
            &debugger_request,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-request-cause-requires-authority-specific-adapter"
        })
    ));
    let discovered = repository
        .discover_choice_opportunity(
            "debugger-authority",
            debugger_genesis.snapshot_id(),
            debugger_request.parent(),
            debugger_request.opportunity(),
        )
        .expect("discover debugger choice");

    let wrong_debugger_key =
        DebuggerAuthorityKey::from_bytes([29; 32]).expect("wrong debugger key");
    let wrong_debugger = DebuggerSubmission::authorize(
        &wrong_debugger_key,
        discovered.new_snapshot,
        session,
        debugger_request.clone(),
    )
    .expect("wrong debugger submission");
    let objects_before_debugger_rejection = blobs
        .object_count()
        .expect("debugger objects before rejection");
    assert!(matches!(
        repository.submit_debugger_branch_request("debugger-authority", &wrong_debugger),
        Err(CampaignRepositoryError::Integrity {
            reason: "debugger-submission-authentication-failed"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("debugger objects after rejection"),
        objects_before_debugger_rejection
    );

    let debugger_submission = DebuggerSubmission::authorize(
        &debugger_key,
        discovered.new_snapshot,
        session,
        debugger_request,
    )
    .expect("authorize debugger submission");
    let debugger_bytes = debugger_submission.canonical_bytes();
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.debugger-submission-vector.v1",
            &debugger_bytes,
        )
        .to_hex(),
        // The v3 active scan-index anchor changes the authenticated snapshot precondition.
        "2fec8c39c706f7be694e061175b30cb714fd48f72d5926f3e665e808a6c07151",
    );
    let decoded_debugger =
        DebuggerSubmission::from_canonical_bytes(&debugger_bytes).expect("decode debugger");
    assert_eq!(decoded_debugger, debugger_submission);
    assert!(decoded_debugger.verify(&debugger_key));
    assert!(!decoded_debugger.verify(&wrong_debugger_key));
    let mut tampered_debugger_bytes = debugger_bytes;
    let last = tampered_debugger_bytes
        .last_mut()
        .expect("debugger submission has an authentication tag");
    *last ^= 1;
    let tampered_debugger = DebuggerSubmission::from_canonical_bytes(&tampered_debugger_bytes)
        .expect("tampered tag remains structurally canonical");
    assert!(!tampered_debugger.verify(&debugger_key));
    let accepted_debugger = repository
        .submit_debugger_branch_request("debugger-authority", &decoded_debugger)
        .expect("accept debugger submission");
    assert_eq!(accepted_debugger.prior_snapshot, discovered.new_snapshot);

    let planner_genesis = repository
        .create("planner-authority", &lineage, &policy, &BTreeMap::new())
        .expect("create planner campaign");
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let initial_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("initial state");
    let (engine, artifact, invocation) = planner_basis(
        &repository,
        "planner-authority",
        planner_genesis.snapshot_id(),
        initial_state.clone(),
    );
    let planner_request = PlannerRequest::new(
        planner_genesis.snapshot_id(),
        invocation.clone(),
        engine.clone(),
        artifact,
        policy.clone(),
        initial_state,
        repository
            .head("planner-authority")
            .expect("planner head")
            .snapshot()
            .planning_view(),
        CampaignPlanningBundle::new(Vec::new()).expect("empty planner bundle"),
    )
    .expect("planner request");
    let next_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![1],
    )
    .expect("next state");
    let proposal = no_work_proposal(invocation.id().expect("invocation id"), next_state);
    let measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: 0,
        input_bytes: 0,
        fuel: 5,
    };
    let wrong_planner_key = PlannerAuthorityKey::from_bytes([31; 32]).expect("wrong planner key");
    let wrong_planner = PlannerSubmission::authorize(
        &wrong_planner_key,
        planner_genesis.snapshot_id(),
        proposal.clone(),
        measured,
    )
    .expect("wrong planner submission");
    let wrong_response =
        PlannerResponse::authorize(&wrong_planner_key, &planner_request, wrong_planner)
            .expect("wrong planner response");
    let objects_before_planner_rejection = blobs
        .object_count()
        .expect("planner objects before rejection");
    assert!(matches!(
        repository.accept_planner_response("planner-authority", &planner_request, &wrong_response,),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-response-authentication-failed"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("planner objects after rejection"),
        objects_before_planner_rejection
    );
    assert_eq!(
        repository
            .head("planner-authority")
            .expect("unchanged planner head")
            .snapshot_id(),
        planner_genesis.snapshot_id()
    );

    let planner_submission = PlannerSubmission::authorize(
        &planner_key,
        planner_genesis.snapshot_id(),
        proposal.clone(),
        measured,
    )
    .expect("authorize planner submission");
    let planner_bytes = planner_submission.canonical_bytes();
    assert_eq!(
        CampaignHash::derive("crucible.test.planner-submission-vector.v1", &planner_bytes,)
            .to_hex(),
        // The v3 active scan-index anchor changes the authenticated snapshot precondition.
        "1d7d211325d9dc315b60e5712bd957727d6cfa4fd89984acfbddb408801caa00",
    );
    let decoded_planner =
        PlannerSubmission::from_canonical_bytes(&planner_bytes).expect("decode planner");
    assert_eq!(decoded_planner, planner_submission);
    assert!(decoded_planner.verify(&planner_key));
    assert!(!decoded_planner.verify(&wrong_planner_key));
    let planner_response =
        PlannerResponse::authorize(&planner_key, &planner_request, decoded_planner)
            .expect("planner response");
    let different_request = PlannerRequest::new(
        CampaignSnapshotId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            3,
            b"different planner request snapshot",
        ))
        .expect("different snapshot"),
        planner_request.invocation().clone(),
        planner_request.engine().clone(),
        planner_request.policy_artifact().clone(),
        planner_request.policy().clone(),
        planner_request.planner_state().clone(),
        *planner_request.input_view(),
        planner_request.input_bundle().clone(),
    )
    .expect("different planner request");
    let objects_before_request_mismatch = blobs
        .object_count()
        .expect("objects before planner request mismatch");
    assert!(matches!(
        repository.accept_planner_response(
            "planner-authority",
            &different_request,
            &planner_response,
        ),
        Err(CampaignRepositoryError::Codec(
            CampaignCodecError::InvalidValue {
                reason: "planner response request digest mismatch"
            }
        ))
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after planner request mismatch"),
        objects_before_request_mismatch
    );
    let accepted_planner = repository
        .accept_planner_response("planner-authority", &planner_request, &planner_response)
        .expect("accept planner submission");
    assert_eq!(
        accepted_planner.prior_snapshot,
        planner_genesis.snapshot_id()
    );
    let accepted_step = repository
        .load_planner_step_at(accepted_planner.new_snapshot, accepted_planner.step)
        .expect("accepted request-bound step");
    assert_eq!(
        accepted_step.request_digest(),
        planner_request.request_digest()
    );
    assert_eq!(
        repository
            .load_planner_request(accepted_step.request())
            .expect("retained planner request"),
        planner_request
    );
    assert!(matches!(
        repository.load_planner_step(accepted_planner.step),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-requires-snapshot-owner"
        })
    ));

    let replay_request = PlannerRequest::new(
        accepted_planner.new_snapshot,
        planner_request.invocation().clone(),
        planner_request.engine().clone(),
        planner_request.policy_artifact().clone(),
        planner_request.policy().clone(),
        planner_request.planner_state().clone(),
        *planner_request.input_view(),
        planner_request.input_bundle().clone(),
    )
    .expect("byte-distinct valid replay request");
    let replay_submission = PlannerSubmission::authorize(
        &planner_key,
        accepted_planner.new_snapshot,
        proposal,
        measured,
    )
    .expect("authorize replay submission");
    let replay_response =
        PlannerResponse::authorize(&planner_key, &replay_request, replay_submission)
            .expect("authorize replay response");
    let objects_before_replay_conflict = blobs.object_count().expect("objects before conflict");
    assert!(matches!(
        repository.accept_planner_response("planner-authority", &replay_request, &replay_response,),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-result-conflict"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after conflict"),
        objects_before_replay_conflict
    );
    assert_eq!(
        repository
            .head("planner-authority")
            .expect("head after replay conflict")
            .snapshot_id(),
        accepted_planner.new_snapshot
    );

    let forged_step = PlannerStep::new(
        None,
        accepted_step.invocation(),
        accepted_step.request(),
        accepted_step.request_digest(),
        accepted_step.policy(),
        accepted_step.engine(),
        accepted_step.policy_artifact(),
        accepted_step.input_view(),
        PlannerDisposition::NoWork,
        accepted_step.next_state(),
        accepted_step.usage_claim(),
        accepted_step.accounting(),
        accepted_step.evidence().clone(),
    )
    .expect("forged wrong-parent-request step");
    let forged_step_content = repository
        .put_planner_step(&forged_step)
        .expect("put forged planner step");
    let forged_fact = repository
        .put_fact(&CampaignFact::PlannerAdvanced(
            PlannerStepId::from_content_id(forged_step_content).expect("forged step id"),
        ))
        .expect("put forged planner fact");
    let accepted_snapshot = repository
        .read_snapshot(accepted_planner.new_snapshot.content_id())
        .expect("accepted snapshot");
    let forged_snapshot = CampaignSnapshot::successor(
        accepted_planner.new_snapshot,
        accepted_snapshot.snapshot.lineage(),
        accepted_snapshot.snapshot.active_policy(),
        accepted_snapshot.snapshot.roots(),
        CampaignFactId::from_content_id(forged_fact).expect("forged fact id"),
        crate::test_budget_ledger_id(),
    )
    .expect("forged successor");
    let forged_content = repository
        .put_snapshot(&forged_snapshot)
        .expect("put forged successor");
    let forged_validation = repository.validate_complete_head(forged_content);
    assert!(
        matches!(
            forged_validation,
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-step-transition-request-snapshot-mismatch"
            })
        ),
        "unexpected forged successor result: {forged_validation:?}"
    );
}

#[test]
fn branch_request_is_one_lazy_exact_indexed_delta_and_replays() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("lazy", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "retry-choice",
    );

    let discovered = repository
        .discover_choice_opportunity(
            "lazy",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover request opportunity");
    let accepted = repository
        .submit_branch_request("lazy", discovered.new_snapshot, &request)
        .expect("submit request");
    assert!(!accepted.replayed);
    assert_eq!(accepted.prior_snapshot, discovered.new_snapshot);
    assert_eq!(accepted.request, request.id().expect("request id"));
    assert_eq!(
        accepted.summary.validated_cardinality(),
        BranchAcceptanceCount::Exact(2)
    );
    assert_eq!(
        accepted.summary.deduplicated_existing_edges(),
        BranchAcceptanceCount::Exact(0)
    );
    assert_eq!(
        accepted.summary.remaining_lazy_candidates(),
        BranchAcceptanceCount::Exact(2)
    );
    assert_eq!(accepted.summary.maximum_proposals(), 2);
    assert_eq!(accepted.summary.maximum_attempts(), 2);
    assert_eq!(
        accepted.acceptance_fact,
        CampaignFact::BranchRequestAccepted {
            request: accepted.request,
            summary: accepted.summary,
        }
    );
    assert_eq!(
        accepted.snapshot.transition(),
        Some(
            CampaignFactId::from_content_id(
                accepted
                    .acceptance_fact
                    .id()
                    .expect("acceptance fact ID")
                    .content_id()
            )
            .expect("acceptance transition ID")
        )
    );

    let requested = repository.head("lazy").expect("requested head");
    let prior_roots = repository
        .read_snapshot(discovered.new_snapshot.content_id())
        .expect("discovery snapshot")
        .snapshot
        .roots();
    let next_roots = requested.snapshot().roots();
    assert_eq!(prior_roots.graph, next_roots.graph);
    assert_eq!(prior_roots.observations, next_roots.observations);
    assert_eq!(prior_roots.corpus, next_roots.corpus);
    assert_eq!(prior_roots.coverage, next_roots.coverage);
    assert_eq!(prior_roots.findings, next_roots.findings);
    assert_eq!(prior_roots.pins, next_roots.pins);
    assert_ne!(prior_roots.accounting, next_roots.accounting);
    let BranchRequestCause::Operator(command_id) = request.cause() else {
        panic!("operator request")
    };
    assert_eq!(
        repository
            .merkle
            .get(
                next_roots.accounting,
                map_key_hash("accounting.command", command_id.as_hash()),
            )
            .expect("command index"),
        requested
            .snapshot()
            .transition()
            .map(CampaignFactId::content_id)
    );
    assert_ne!(prior_roots.exploration, next_roots.exploration);
    let entries = repository
        .merkle
        .verify_closure_objects(next_roots.exploration)
        .expect("exploration closure");
    let frontier_index = repository
        .merkle
        .get(next_roots.exploration, frontier_index_anchor_key())
        .expect("frontier anchor lookup")
        .expect("frontier index");
    let branch_request_index = repository
        .merkle
        .get(next_roots.exploration, branch_request_index_anchor_key())
        .expect("branch-request anchor lookup")
        .expect("branch-request index");
    let scan_index = repository
        .merkle
        .get(next_roots.exploration, planner_scan_index_anchor_key())
        .expect("scan index lookup")
        .expect("scan index");
    assert_eq!(
        entries.values,
        BTreeSet::from([
            accepted.request.content_id(),
            frontier_index,
            branch_request_index,
            scan_index,
        ])
    );

    let resume = command(
        "resume-after-request",
        accepted.new_snapshot,
        CampaignControlAction::Resume,
    );
    repository.apply_control("lazy", &resume).expect("resume");
    let replay = repository
        .submit_known_branch_request("lazy", genesis.snapshot_id(), &request)
        .expect("replay request");
    assert!(replay.replayed);
    assert_eq!(replay.prior_snapshot, accepted.prior_snapshot);
    assert_eq!(replay.new_snapshot, accepted.new_snapshot);
    assert_eq!(replay.summary, accepted.summary);
    assert_eq!(replay.snapshot, accepted.snapshot);
    assert_eq!(replay.acceptance_fact, accepted.acceptance_fact);

    let service = crate::RepositoryCampaignService::new(&repository, PermitAlice);
    let client = crate::CampaignClient::new(service);
    let service_replay = client
        .submit_branch_request(
            &crate::SubmitCampaignBranchRequest::new(
                crate::CampaignPrincipal::new("operator:alice").expect("principal"),
                crate::CampaignName::new("lazy").expect("campaign name"),
                genesis.snapshot_id(),
                request.clone(),
            )
            .expect("service branch request"),
        )
        .expect("service replay");
    assert!(service_replay.replayed());
    assert_eq!(service_replay.prior_snapshot(), accepted.prior_snapshot);
    assert_eq!(service_replay.new_snapshot(), accepted.new_snapshot);

    let reused_command = BranchRequest::new(
        BranchRequest::identity(
            request.branch_point(),
            request.parent(),
            request.opportunity(),
            request.domain(),
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
            .expect("changed finite source"),
        request.cause(),
        BranchBudget::new(1, 1).expect("changed budget"),
        StopCondition::Terminal,
    )
    .expect("changed request");
    let current = repository.head("lazy").expect("current head");
    assert!(matches!(
        repository.submit_known_branch_request("lazy", current.snapshot_id(), &reused_command),
        Err(CampaignRepositoryError::CommandReuse)
    ));

    let BranchRequestCause::Operator(command_id) = request.cause() else {
        panic!("operator request")
    };
    let reused_control = ControlRequest {
        command: command_id,
        expected_snapshot: current.snapshot_id(),
        action: CampaignControlAction::Complete,
    };
    assert!(matches!(
        repository.apply_control("lazy", &reused_control),
        Err(CampaignRepositoryError::CommandReuse)
    ));
}
