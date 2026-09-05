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
