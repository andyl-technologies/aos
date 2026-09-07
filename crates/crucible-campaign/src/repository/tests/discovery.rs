//! Initial-discovery admission, budget, and immutable restart regressions.

use super::*;

#[test]
fn initial_discovery_import_recomputes_stop_ordinal_and_lifecycle() {
    let (repository, lineage, policy) = fixture();
    let head = repository
        .create("discovery", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    repository
        .apply_control(
            "discovery",
            &command(
                "grant",
                head.snapshot_id(),
                CampaignControlAction::GrantBudget(BudgetGrant::new(0, 1).expect("grant")),
            ),
        )
        .expect("grant");
    let head = repository.head("discovery").expect("head");
    repository
        .apply_control(
            "discovery",
            &command("start", head.snapshot_id(), CampaignControlAction::Resume),
        )
        .expect("start");
    let head = repository.head("discovery").expect("running");
    let parent = repository.read_snapshot(head.content_id()).expect("parent");
    let (path, attempt, admission) = repository
        .initial_discovery_basis(&parent)
        .expect("basis")
        .expect("ready");
    let wrong_stop =
        Attempt::new(attempt.start(), attempt.path(), StopCondition::Terminal).expect("wrong stop");
    let wrong_ordinal = AttemptAdmission::new(
        attempt.id().expect("attempt id"),
        AttemptAdmissionRole::ExecutionBasis {
            proposal: None,
            cause: BranchRequestCause::ExhaustivePolicy(policy.id().expect("policy id")),
            admission_ordinal: AdmissionOrdinal::new(2),
        },
    );
    for (candidate, basis) in [
        (
            &wrong_stop,
            AttemptAdmission::new(wrong_stop.id().expect("wrong id"), admission.role()),
        ),
        (&attempt, wrong_ordinal),
    ] {
        let forged = forged_discovery_successor(&repository, &parent, &path, candidate, basis);
        repository
            .validate_complete_head(forged)
            .expect_err("forged discovery must fail cold validation");
        assert_eq!(
            repository
                .head("discovery")
                .expect("ref unchanged")
                .snapshot_id(),
            head.snapshot_id()
        );
    }

    repository
        .apply_control(
            "discovery",
            &command(
                "pause",
                head.snapshot_id(),
                CampaignControlAction::Pause(ActiveAttemptPolicy::Drain),
            ),
        )
        .expect("pause");
    let paused = repository.head("discovery").expect("paused");
    let parent = repository
        .read_snapshot(paused.content_id())
        .expect("paused parent");
    let forged = forged_discovery_successor(&repository, &parent, &path, &attempt, admission);
    repository
        .validate_complete_head(forged)
        .expect_err("paused parent cannot admit discovery on import");
}

fn forged_discovery_successor(
    repository: &CampaignRepository,
    parent: &LoadedSnapshot,
    path: &BranchPath,
    attempt: &Attempt,
    admission: AttemptAdmission,
) -> ContentId {
    repository.put_branch_path(path).expect("path");
    repository.put_attempt(attempt).expect("attempt");
    let content = repository
        .put_attempt_admission(&admission)
        .expect("admission");
    let mut roots = parent.snapshot.roots();
    for (key, value) in attempt_admission_upserts(content, admission).expect("upserts") {
        roots.accounting = repository
            .merkle
            .insert(roots.accounting, key, value)
            .expect("accounting")
            .content_id();
    }
    roots.coordination = repository
        .coordination_with_parent_result(parent.envelope.content_id(), parent)
        .expect("coordination");
    let fact = repository
        .put_fact(&CampaignFact::AttemptAdmitted(
            admission.id().expect("admission id"),
        ))
        .expect("fact");
    let next = CampaignSnapshot::successor(
        parent.snapshot.id().expect("parent id"),
        parent.snapshot.lineage(),
        parent.snapshot.active_policy(),
        roots,
        CampaignFactId::from_content_id(fact).expect("fact id"),
    )
    .expect("successor");
    repository
        .put_snapshot(&next)
        .expect("unreferenced forged snapshot")
}

#[test]
fn initial_discovery_requires_running_state_and_attempt_budget() {
    let (repository, lineage, policy) = fixture();
    let mut head = repository
        .create("discovery", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    assert_eq!(
        repository
            .admit_initial_discovery_if_ready("discovery")
            .expect("inactive"),
        None
    );
    repository
        .apply_control(
            "discovery",
            &command("start", head.snapshot_id(), CampaignControlAction::Resume),
        )
        .expect("start");
    head = repository.head("discovery").expect("running head");
    assert_eq!(
        repository
            .admit_initial_discovery_if_ready("discovery")
            .expect("no budget"),
        None
    );
    assert_eq!(
        repository
            .head("discovery")
            .expect("unchanged")
            .snapshot_id(),
        head.snapshot_id()
    );

    repository
        .apply_control(
            "discovery",
            &command(
                "proposals",
                head.snapshot_id(),
                CampaignControlAction::GrantBudget(BudgetGrant::new(1, 0).expect("proposal grant")),
            ),
        )
        .expect("grant proposals");
    assert_eq!(
        repository
            .admit_initial_discovery_if_ready("discovery")
            .expect("no attempt grant"),
        None
    );
    head = repository.head("discovery").expect("budget head");
    repository
        .apply_control(
            "discovery",
            &command(
                "attempt",
                head.snapshot_id(),
                CampaignControlAction::GrantBudget(BudgetGrant::new(0, 1).expect("attempt grant")),
            ),
        )
        .expect("grant attempt");
    let before = repository.head("discovery").expect("before admission");
    let id = repository
        .admit_initial_discovery_if_ready("discovery")
        .expect("admission")
        .expect("initial attempt");
    let attempt = repository.load_attempt(id).expect("attempt closure");
    assert_eq!(
        attempt.start(),
        AttemptStart::Discover {
            configuration: lineage.genesis_content()
        }
    );
    assert_eq!(attempt.stop(), &StopCondition::NextChoice);
    assert!(
        repository
            .read_branch_path(attempt.path().content_id())
            .expect("path")
            .edges()
            .is_empty()
    );
    let after = repository.head("discovery").expect("after admission");
    let budget = repository.budget_projection("discovery").expect("budget");
    assert_eq!(budget.granted_attempts, 1);
    assert_eq!(budget.spent_attempts, 1);
    assert_eq!(budget.remaining_attempts(), 0);
    assert_eq!(budget.spent_proposals, 0);
    let mut unchanged = before.snapshot().roots();
    unchanged.accounting = after.snapshot().roots().accounting;
    unchanged.coordination = after.snapshot().roots().coordination;
    assert_eq!(unchanged, after.snapshot().roots());
    assert_eq!(
        repository
            .admit_initial_discovery_if_ready("discovery")
            .expect("replay"),
        None
    );
    assert_eq!(
        repository
            .head("discovery")
            .expect("same head")
            .snapshot_id(),
        after.snapshot_id()
    );

    // Discard all validation caches so import/restart recomputes the owner
    // delta and cannot pass solely because local publication trusted itself.
    let repository =
        CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    repository
        .validate_complete_head(after.content_id())
        .expect("cold closure validation");
    assert_eq!(
        repository
            .admit_initial_discovery_if_ready("discovery")
            .expect("cold replay"),
        None
    );
}

#[test]
fn initial_discovery_pause_retains_the_unspent_grant() {
    let (repository, lineage, policy) = fixture();
    let head = repository
        .create("discovery", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    repository
        .apply_control(
            "discovery",
            &command(
                "grant",
                head.snapshot_id(),
                CampaignControlAction::GrantBudget(BudgetGrant::new(0, 1).expect("grant")),
            ),
        )
        .expect("grant while inactive");
    let head = repository.head("discovery").expect("head");
    assert_eq!(
        repository
            .admit_initial_discovery_if_ready("discovery")
            .expect("inactive"),
        None
    );
    repository
        .apply_control(
            "discovery",
            &command("start", head.snapshot_id(), CampaignControlAction::Resume),
        )
        .expect("start");
    let head = repository.head("discovery").expect("running");
    repository
        .apply_control(
            "discovery",
            &command(
                "pause",
                head.snapshot_id(),
                CampaignControlAction::Pause(ActiveAttemptPolicy::Drain),
            ),
        )
        .expect("pause");
    assert_eq!(
        repository
            .admit_initial_discovery_if_ready("discovery")
            .expect("paused"),
        None
    );
    let head = repository.head("discovery").expect("paused head");
    repository
        .apply_control(
            "discovery",
            &command("resume", head.snapshot_id(), CampaignControlAction::Resume),
        )
        .expect("resume");
    assert!(
        repository
            .admit_initial_discovery_if_ready("discovery")
            .expect("admit after resume")
            .is_some()
    );
}

#[test]
fn explicit_discovery_is_idempotent_and_cold_recomputable() {
    let (repository, lineage, policy) = fixture();
    let head = running_discovery_head(&repository, "explicit", &lineage, &policy, true);
    let request = DiscoveryRequest::new(
        crate::CampaignCommandId::from_hash(CampaignHash::derive("test", b"discover")),
        head.snapshot_id(),
        lineage.genesis_content(),
        StopCondition::Terminal,
    )
    .expect("request");

    let accepted = repository
        .submit_discovery_request("explicit", &request)
        .expect("accept discovery");
    assert!(!accepted.replayed);
    let attempt = repository
        .load_attempt(accepted.attempt)
        .expect("accepted attempt");
    assert_eq!(attempt.stop(), &StopCondition::Terminal);
    assert_eq!(
        repository
            .read_attempt_admission(accepted.admission.content_id())
            .expect("accepted admission")
            .role(),
        AttemptAdmissionRole::ExecutionBasis {
            proposal: None,
            cause: BranchRequestCause::Operator(request.command),
            admission_ordinal: AdmissionOrdinal::new(1),
        }
    );

    let replay = repository
        .submit_discovery_request("explicit", &request)
        .expect("replay discovery");
    assert_eq!(
        replay,
        CampaignDiscoveryResult {
            replayed: true,
            ..accepted.clone()
        }
    );
    let changed = DiscoveryRequest::new(
        request.command,
        request.expected_snapshot,
        request.configuration,
        StopCondition::NextChoice,
    )
    .expect("changed request");
    assert!(matches!(
        repository.submit_discovery_request("explicit", &changed),
        Err(CampaignRepositoryError::CommandReuse)
    ));

    let cold = CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    cold.validate_complete_head(accepted.new_snapshot.content_id())
        .expect("cold discovery validation");
    let cold_replay = cold
        .submit_discovery_request("explicit", &request)
        .expect("cold replay");
    assert!(cold_replay.replayed);
    assert_eq!(cold_replay.attempt, accepted.attempt);
    assert_eq!(cold_replay.admission, accepted.admission);
}

#[test]
fn explicit_discovery_rejects_invalid_configuration_stop_and_budget() {
    let (repository, lineage, policy) = fixture();
    let no_budget = running_discovery_head(&repository, "no-budget", &lineage, &policy, false);
    let request = DiscoveryRequest::new(
        crate::CampaignCommandId::from_hash(CampaignHash::derive("test", b"no-budget")),
        no_budget.snapshot_id(),
        lineage.genesis_content(),
        StopCondition::Terminal,
    )
    .expect("request");
    assert!(matches!(
        repository.submit_discovery_request("no-budget", &request),
        Err(CampaignRepositoryError::Budget(_))
    ));

    let head = running_discovery_head(&repository, "invalid", &lineage, &policy, true);
    let other_configuration = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            ConfigurationId::from_hash(CampaignHash::derive("test", b"other")),
            1,
            b"other".to_vec(),
        )
        .expect("other configuration");
    let wrong_configuration = DiscoveryRequest::new(
        crate::CampaignCommandId::from_hash(CampaignHash::derive("test", b"wrong-config")),
        head.snapshot_id(),
        other_configuration,
        StopCondition::Terminal,
    )
    .expect("wrong configuration request");
    assert!(matches!(
        repository.submit_discovery_request("invalid", &wrong_configuration),
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "explicit-discovery-configuration-is-not-in-campaign-graph"
        })
    ));

    let undeclared_stop = DiscoveryRequest::new(
        crate::CampaignCommandId::from_hash(CampaignHash::derive("test", b"wrong-stop")),
        head.snapshot_id(),
        lineage.genesis_content(),
        StopCondition::NamedBoundary(String::from("not-declared")),
    )
    .expect("named stop request");
    assert!(matches!(
        repository.submit_discovery_request("invalid", &undeclared_stop),
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "explicit-discovery-stop-boundary-is-not-in-active-policy"
        })
    ));
}

#[test]
fn explicit_discovery_cold_validation_rejects_a_tampered_configuration() {
    let (repository, lineage, policy) = fixture();
    let head = running_discovery_head(&repository, "tampered", &lineage, &policy, true);
    let parent = repository
        .read_snapshot(head.content_id())
        .expect("parent snapshot");
    let command = crate::CampaignCommandId::from_hash(CampaignHash::derive("test", b"tampered"));
    let valid = DiscoveryRequest::new(
        command,
        head.snapshot_id(),
        lineage.genesis_content(),
        StopCondition::Terminal,
    )
    .expect("valid request");
    let (path, attempt, admission) = repository
        .discovery_request_basis(&parent, &valid)
        .expect("valid basis");
    let other_configuration = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            ConfigurationId::from_hash(CampaignHash::derive("test", b"tampered-other")),
            1,
            b"tampered-other".to_vec(),
        )
        .expect("other configuration");
    let tampered = DiscoveryRequest::new(
        command,
        head.snapshot_id(),
        other_configuration,
        StopCondition::Terminal,
    )
    .expect("tampered request");

    repository.put_branch_path(&path).expect("path");
    repository.put_attempt(&attempt).expect("attempt");
    let admission_content = repository
        .put_attempt_admission(&admission)
        .expect("admission");
    let transition_content = repository
        .put_fact(&CampaignFact::DiscoveryRequested(tampered))
        .expect("tampered fact");
    let mut upserts = attempt_admission_upserts(admission_content, admission).expect("upserts");
    upserts.insert(
        map_key_hash("accounting.command", command.as_hash()),
        transition_content,
    );
    let mut roots = parent.snapshot.roots();
    for (key, value) in upserts {
        roots.accounting = repository
            .merkle
            .insert(roots.accounting, key, value)
            .expect("accounting")
            .content_id();
    }
    roots.coordination = repository
        .coordination_with_parent_result(parent.envelope.content_id(), &parent)
        .expect("coordination");
    let forged = repository
        .budgeted_successor(
            head.snapshot_id(),
            head.snapshot().lineage(),
            head.snapshot().active_policy(),
            roots,
            CampaignFactId::from_content_id(transition_content).expect("transition id"),
        )
        .expect("forged successor");
    let forged_content = repository.put_snapshot(&forged).expect("forged snapshot");

    let cold = CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    assert!(matches!(
        cold.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "explicit-discovery-configuration-is-not-in-campaign-graph"
        })
    ));
}

#[test]
fn explicit_discovery_ref_conflict_does_not_promote_the_successor() {
    let (fixture_repository, lineage, policy, blobs) = counted_fixture();
    drop(fixture_repository);
    let refs = Arc::new(ConflictAfterCreateRefBackend::new());
    let repository = CampaignRepository::new(blobs, refs.clone());
    let head = running_discovery_head(&repository, "conflict", &lineage, &policy, true);
    let request = DiscoveryRequest::new(
        crate::CampaignCommandId::from_hash(CampaignHash::derive("test", b"conflict")),
        head.snapshot_id(),
        lineage.genesis_content(),
        StopCondition::Terminal,
    )
    .expect("request");
    refs.arm();

    assert!(matches!(
        repository.submit_discovery_request("conflict", &request),
        Err(CampaignRepositoryError::RefConflict { .. })
    ));
    assert_eq!(
        repository
            .head("conflict")
            .expect("unchanged")
            .snapshot_id(),
        head.snapshot_id()
    );
    let checkpoints = repository
        .validated_heads
        .lock()
        .expect("validation checkpoints");
    assert!(checkpoints.contains_key(&head.content_id()));
    assert_eq!(checkpoints.len(), 1);
}

fn running_discovery_head(
    repository: &CampaignRepository,
    name: &str,
    lineage: &CampaignLineage,
    policy: &CampaignPolicy,
    funded: bool,
) -> CampaignHead {
    let head = repository
        .create(name, lineage, policy, &BTreeMap::new())
        .expect("create");
    let head = if funded {
        repository
            .apply_control(
                name,
                &command(
                    &format!("{name}-grant"),
                    head.snapshot_id(),
                    CampaignControlAction::GrantBudget(
                        BudgetGrant::new(0, 1).expect("attempt grant"),
                    ),
                ),
            )
            .expect("grant attempt");
        repository.head(name).expect("funded head")
    } else {
        head
    };
    repository
        .apply_control(
            name,
            &command(
                &format!("{name}-start"),
                head.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("start");
    repository.head(name).expect("running head")
}
