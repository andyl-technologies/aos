//! Authenticated lifecycle history and reproducibility-preserving policy activation.

use super::*;

#[test]
fn create_and_control_form_linear_authenticated_history() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("network-recovery", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    assert_eq!(
        repository.state("network-recovery").expect("state"),
        CampaignState::Created
    );

    let resume = command(
        "resume",
        genesis.snapshot_id(),
        CampaignControlAction::Resume,
    );
    let resumed = repository
        .apply_control("network-recovery", &resume)
        .expect("resume");
    assert_eq!(resumed.prior_snapshot, genesis.snapshot_id());
    assert_eq!(
        repository.state("network-recovery").expect("state"),
        CampaignState::Running
    );

    let pause = command(
        "pause",
        resumed.new_snapshot,
        CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
    );
    let paused = repository
        .apply_control("network-recovery", &pause)
        .expect("pause");
    assert_eq!(
        repository.state("network-recovery").expect("state"),
        CampaignState::Paused
    );
    let (_, lifecycle) = repository
        .head_with_lifecycle("network-recovery")
        .expect("paused lifecycle intent");
    assert_eq!(lifecycle.state(), CampaignState::Paused);
    assert_eq!(
        lifecycle.active_attempt_policy(),
        Some(crate::ActiveAttemptPolicy::Drain)
    );
    assert_ne!(paused.new_snapshot, resumed.new_snapshot);

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let (_, restarted_lifecycle) = restarted
        .head_with_lifecycle("network-recovery")
        .expect("restart lifecycle intent");
    assert_eq!(restarted_lifecycle, lifecycle);
}

#[test]
fn policy_activation_cannot_change_campaign_reproducibility_mode() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("policy-mode", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let streaming = CampaignPolicy::new(
        CampaignPolicy::identity(
            policy.scenario(),
            policy.campaign_seed(),
            CampaignMode::Streaming,
            policy.explorer().clone(),
        ),
        CampaignPolicy::rules(
            policy.choice_policies().clone(),
            policy.objectives().clone(),
            policy.guidance().clone(),
            policy.stop_conditions().clone(),
            policy.fairness(),
            policy.retention(),
            policy.admits_scenario_defaults(),
        ),
    )
    .expect("streaming policy");
    let streaming = CampaignPolicyId::from_content_id(
        repository
            .publish_policy(&streaming)
            .expect("publish streaming policy"),
    )
    .expect("streaming policy id");
    let activate = command(
        "policy-mode-change",
        genesis.snapshot_id(),
        CampaignControlAction::ActivatePolicy(streaming),
    );

    assert!(matches!(
        repository.apply_control("policy-mode", &activate),
        Err(CampaignRepositoryError::Integrity {
            reason: "activated-policy-mode-mismatch"
        })
    ));
    assert_eq!(
        repository
            .head("policy-mode")
            .expect("unchanged policy head")
            .snapshot_id(),
        genesis.snapshot_id()
    );

    let parent = repository
        .read_snapshot(genesis.content_id())
        .expect("policy parent");
    let control = CampaignFact::ControlRequested(activate.clone());
    let control_content = repository.put_fact(&control).expect("put forged control");
    let mut accounting = repository
        .merkle
        .insert(
            parent.snapshot.roots().accounting,
            map_key_hash("accounting.command", activate.command.as_hash()),
            control_content,
        )
        .expect("forged command accounting");
    let activation = CampaignFact::PolicyActivated(
        PolicyActivation::new(policy.id().expect("prior policy"), streaming)
            .expect("forged activation"),
    );
    let activation_content = repository
        .put_fact(&activation)
        .expect("put forged activation");
    accounting = repository
        .insert_fact(accounting, &activation, activation_content)
        .expect("forged activation accounting");
    let mut roots = parent.snapshot.roots();
    roots.accounting = accounting.content_id();
    let forged = CampaignSnapshot::successor(
        genesis.snapshot_id(),
        parent.snapshot.lineage(),
        streaming,
        roots,
        CampaignFactId::from_content_id(control_content).expect("control fact id"),
        crate::test_budget_ledger_id(),
    )
    .expect("forged mode-change successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged mode-change successor");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "activated-policy-mode-mismatch"
        })
    ));
}
