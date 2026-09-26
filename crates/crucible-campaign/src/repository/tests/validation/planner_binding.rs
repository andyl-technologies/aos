//! Planner binding and unowned-fact rejection regressions.

use super::*;

#[test]
fn planner_invocations_bind_artifact_and_state_to_one_engine() {
    let (repository, _, policy) = fixture();
    let engine_a = PlannerEngine::new("engine-a", 1, 1, BTreeSet::new()).expect("engine A");
    let engine_b = PlannerEngine::new("engine-b", 1, 1, BTreeSet::new()).expect("engine B");
    for engine in [&engine_a, &engine_b] {
        repository
            .put_envelope(
                ObjectEnvelope::for_record(
                    crate::CampaignRecordKind::PlannerEngine,
                    BTreeSet::new(),
                    crate::codec::encode(engine),
                )
                .expect("engine envelope"),
            )
            .expect("put engine");
    }

    let dependency_bytes = b"planner dependency".to_vec();
    let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
    repository
        .blobs
        .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
        .expect("put dependency");
    let artifact = PolicyArtifact::new(
        engine_a.id().expect("engine A id"),
        1,
        dependency,
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("artifact");
    repository
        .put_envelope(
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PolicyArtifact,
                crate::object::content_children(artifact.content_children())
                    .expect("artifact children"),
                crate::codec::encode(&artifact),
            )
            .expect("artifact envelope"),
        )
        .expect("put artifact");
    let state = PlannerState::new(
        engine_b.id().expect("engine B id"),
        "test-state",
        1,
        Vec::new(),
    )
    .expect("state");
    repository
        .put_envelope(
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlannerState,
                crate::object::content_children([("engine", state.engine().content_id())])
                    .expect("state children"),
                crate::codec::encode(&state),
            )
            .expect("state envelope"),
        )
        .expect("put state");
    repository.put_policy(&policy).expect("put policy");

    let empty = repository.merkle.empty().expect("empty root").content_id();
    let view =
        CampaignPlanningView::new(empty, empty, empty, empty, empty, empty, empty).expect("view");
    repository
        .put_envelope(
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlanningView,
                crate::object::content_children(view.content_children()).expect("view children"),
                view.canonical_bytes(),
            )
            .expect("view envelope"),
        )
        .expect("put view");
    let invocation = PlannerInvocation::new(
        engine_a.id().expect("engine A id"),
        artifact.id().expect("artifact id"),
        policy.id().expect("policy id"),
        state.id().expect("state id"),
        view.id().expect("view id"),
        PlanningScanPage::new(None, 1, Vec::new(), true, 0).expect("scan page"),
        PlanningBudget::new(1, 1, 1, 1, 1).expect("budget"),
    )
    .expect("invocation");
    let invocation_content = repository
        .put_envelope(
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlannerInvocation,
                crate::object::content_children(invocation.content_children())
                    .expect("invocation children"),
                crate::codec::encode(&invocation),
            )
            .expect("invocation envelope"),
        )
        .expect("put invocation");
    assert!(matches!(
        repository.verify_campaign_closure(invocation_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-engine-mismatch"
        })
    ));
}

#[test]
fn unowned_fact_reference_families_fail_closed() {
    let (repository, _, _) = fixture();
    let budget_ledger = crate::CampaignBudgetLedger::empty(
        MerkleMap::empty_content_id().expect("empty spending root"),
    )
    .expect("budget ledger");
    let budget_ledger_content = repository
        .put_budget_ledger(budget_ledger)
        .expect("put budget ledger");
    assert!(
        crate::BranchRequestId::from_content_id(budget_ledger_content.content_id()).is_err(),
        "a current branch-request identity must reject another record's schema"
    );
}
