//! Versioned campaign budget enforcement and hostile-import regressions.

use super::*;
use crate::{CampaignBudgetError, CampaignBudgetLedger};

fn grant(
    repository: &CampaignRepository,
    name: &str,
    command_name: &str,
    proposals: u64,
    attempts: u64,
) -> CampaignHead {
    let head = repository.head(name).expect("head");
    repository
        .apply_control(
            name,
            &command(
                command_name,
                head.snapshot_id(),
                CampaignControlAction::GrantBudget(
                    BudgetGrant::new(proposals, attempts).expect("grant"),
                ),
            ),
        )
        .expect("apply grant");
    repository.head(name).expect("funded head")
}

#[test]
fn campaign_allowances_gate_new_work_but_never_charge_replay() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let created = repository
        .create("budget", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    assert!(created.snapshot().budget_ledger().is_some());
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "budget-request",
    );
    repository
        .submit_known_branch_request("budget", created.snapshot_id(), &request)
        .expect("request");
    let head = repository.head("budget").expect("head");
    let unfunded = finite_proposal(&request, &policy, &head, ChoiceValue::Boolean(false), 1);
    let before = blobs.object_count().expect("object count");
    assert!(matches!(
        repository.issue_proposal("budget", head.snapshot_id(), &unfunded),
        Err(CampaignRepositoryError::Budget(
            CampaignBudgetError::ProposalAllowanceExhausted
        ))
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("rejected proposal writes nothing"),
        before
    );
    assert_eq!(
        repository.head("budget").expect("unchanged").snapshot_id(),
        head.snapshot_id()
    );

    let funded = grant(&repository, "budget", "proposal-allowance", 1, 0);
    let proposal = finite_proposal(&request, &policy, &funded, ChoiceValue::Boolean(false), 1);
    let issued = repository
        .issue_proposal("budget", funded.snapshot_id(), &proposal)
        .expect("issue");
    let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
    let before = blobs.object_count().expect("object count");
    assert!(matches!(
        repository.admit_proposal(
            "budget",
            issued.new_snapshot,
            issued.proposal,
            &selection,
            &path,
            &attempt
        ),
        Err(CampaignRepositoryError::Budget(
            CampaignBudgetError::AttemptAllowanceExhausted
        ))
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("rejected admission writes nothing"),
        before
    );
    assert_eq!(
        repository.head("budget").expect("unadmitted").snapshot_id(),
        issued.new_snapshot
    );

    let funded = grant(&repository, "budget", "attempt-allowance", 0, 1);
    let admitted = repository
        .admit_proposal(
            "budget",
            funded.snapshot_id(),
            issued.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit");
    let budget = repository.budget_projection("budget").expect("budget");
    assert_eq!((budget.spent_proposals, budget.spent_attempts), (1, 1));
    assert_eq!(
        (budget.remaining_proposals(), budget.remaining_attempts()),
        (0, 0)
    );
    assert!(
        repository
            .issue_proposal("budget", created.snapshot_id(), &proposal)
            .expect("proposal replay")
            .replayed
    );
    assert!(
        repository
            .admit_proposal(
                "budget",
                created.snapshot_id(),
                issued.proposal,
                &selection,
                &path,
                &attempt
            )
            .expect("admission replay")
            .replayed
    );
    assert_eq!(
        repository
            .budget_projection("budget")
            .expect("unchanged spending"),
        budget
    );
    assert_eq!(
        repository.head("budget").expect("same head").snapshot_id(),
        admitted.new_snapshot
    );

    let cold = CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    assert_eq!(
        cold.budget_projection("budget").expect("cold budget"),
        budget
    );
}

#[test]
fn imported_successors_cannot_inflate_or_drop_the_budget_contract() {
    let (repository, lineage, policy) = fixture();
    repository
        .create("budget", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let funded = grant(&repository, "budget", "grant", 1, 1);
    let snapshot = funded.snapshot();
    let bare = CampaignSnapshot::successor(
        snapshot.parent().expect("parent"),
        snapshot.lineage(),
        snapshot.active_policy(),
        snapshot.roots(),
        snapshot.transition().expect("transition"),
    )
    .expect("legacy-shaped successor");
    let inflated = CampaignBudgetLedger::empty()
        .with_grant(BudgetGrant::new(2, 2).expect("grant"))
        .expect("inflated")
        .with_request_spending(MerkleMap::empty_content_id().expect("empty index"))
        .expect("indexed ledger");
    let inflated_id = repository.put_budget_ledger(inflated).expect("ledger");
    let unindexed_id = repository
        .put_budget_ledger(
            CampaignBudgetLedger::empty()
                .with_grant(BudgetGrant::new(1, 1).expect("grant"))
                .expect("unindexed ledger"),
        )
        .expect("ledger");
    for (forged, reason) in [
        (bare.clone(), "campaign-budget-contract-downgrade"),
        (
            bare.clone().with_budget_ledger(unindexed_id),
            "campaign-request-budget-contract-downgrade",
        ),
        (
            bare.with_budget_ledger(inflated_id),
            "campaign-budget-successor-mismatch",
        ),
    ] {
        let content = repository.put_snapshot(&forged).expect("forged snapshot");
        let cold =
            CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
        assert!(
            matches!(cold.validate_complete_head(content), Err(CampaignRepositoryError::Integrity { reason: observed }) if observed == reason)
        );
    }
    assert_eq!(
        repository.head("budget").expect("unchanged").snapshot_id(),
        funded.snapshot_id()
    );
}

#[test]
fn legacy_genesis_upgrades_on_the_next_new_transition() {
    let (repository, lineage, policy) = fixture();
    let current = repository
        .create("legacy", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let legacy = CampaignSnapshot::genesis(
        current.snapshot().lineage(),
        current.snapshot().active_policy(),
        current.snapshot().roots(),
    )
    .expect("version two");
    let legacy_content = repository.put_snapshot(&legacy).expect("legacy genesis");
    repository
        .validate_complete_head(legacy_content)
        .expect("legacy remains readable");
    assert!(matches!(
        repository
            .refs
            .compare_exchange(
                &campaign_ref("legacy").expect("ref"),
                Some(current.content_id()),
                legacy_content
            )
            .expect("install legacy fixture"),
        RefCasOutcome::Advanced { .. }
    ));
    let upgraded = grant(&repository, "legacy", "upgrade-grant", 3, 2);
    assert_eq!(
        upgraded.snapshot().parent(),
        Some(legacy.id().expect("legacy id"))
    );
    assert!(upgraded.snapshot().budget_ledger().is_some());
    let cold = CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    let budget = cold
        .budget_projection("legacy")
        .expect("cold upgraded budget");
    assert_eq!((budget.granted_proposals, budget.granted_attempts), (3, 2));
}

#[test]
fn imported_genesis_cannot_create_unearned_allowance() {
    let (repository, lineage, policy) = fixture();
    let current = repository
        .create("budget", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let ledger = CampaignBudgetLedger::empty()
        .with_grant(BudgetGrant::new(1, 1).expect("grant"))
        .expect("ledger");
    let forged = current.snapshot().clone().with_budget_ledger(
        repository
            .put_budget_ledger(ledger)
            .expect("publish ledger"),
    );
    let content = repository
        .put_snapshot(&forged)
        .expect("publish hostile genesis");
    let cold = CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    assert!(matches!(
        cold.validate_complete_head(content),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-genesis-budget-is-not-empty"
        })
    ));
}

#[test]
fn snapshot_envelope_cannot_disguise_a_legacy_body_as_version_three() {
    let (repository, lineage, policy) = fixture();
    let current = repository
        .create("budget", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let legacy = CampaignSnapshot::genesis(
        current.snapshot().lineage(),
        current.snapshot().active_policy(),
        current.snapshot().roots(),
    )
    .expect("legacy body");
    let envelope = ObjectEnvelope::for_snapshot(&legacy).expect("legacy envelope");
    let disguised = ObjectEnvelope::for_record(
        crate::CampaignRecordKind::Snapshot,
        envelope.children().clone(),
        legacy.canonical_bytes(),
    )
    .expect("hostile envelope");
    assert!(matches!(
        ObjectEnvelope::from_canonical_bytes(&disguised.canonical_bytes()),
        Err(CampaignCodecError::InvalidValue {
            reason: "versioned campaign body and envelope versions differ"
        })
    ));
}

/// Installs an explicitly legacy fixture without changing its semantic roots.
fn install_legacy_snapshot(
    repository: &CampaignRepository,
    snapshot: CampaignSnapshot,
) -> CampaignHead {
    let current = repository.head("legacy").expect("current head");
    let content = repository.put_snapshot(&snapshot).expect("legacy snapshot");
    repository
        .validate_complete_head(content)
        .expect("authentic legacy history");
    assert!(matches!(
        repository
            .refs
            .compare_exchange(
                &campaign_ref("legacy").expect("ref"),
                Some(current.content_id()),
                content
            )
            .expect("install legacy"),
        RefCasOutcome::Advanced { .. }
    ));
    repository.head("legacy").expect("legacy head")
}

fn strip_current_ledger(repository: &CampaignRepository) -> CampaignHead {
    let current = repository.head("legacy").expect("current");
    let snapshot = current.snapshot();
    let legacy = match snapshot.parent() {
        Some(parent) => CampaignSnapshot::successor(
            parent,
            snapshot.lineage(),
            snapshot.active_policy(),
            snapshot.roots(),
            snapshot.transition().expect("transition"),
        ),
        None => CampaignSnapshot::genesis(
            snapshot.lineage(),
            snapshot.active_policy(),
            legacy_genesis_roots(repository, snapshot.roots()),
        ),
    }
    .expect("version two snapshot");
    install_legacy_snapshot(repository, legacy)
}

fn strip_request_spending_index(repository: &CampaignRepository) -> CampaignHead {
    let current = repository.head("legacy").expect("current");
    let budget = repository.budget_projection("legacy").expect("totals");
    let ledger = CampaignBudgetLedger::from_accounted_totals(
        budget.granted_proposals,
        budget.granted_attempts,
        budget.spent_proposals,
        budget.spent_attempts,
    );
    let base = if current.snapshot().parent().is_none() {
        CampaignSnapshot::genesis(
            current.snapshot().lineage(),
            current.snapshot().active_policy(),
            legacy_genesis_roots(repository, current.snapshot().roots()),
        )
        .expect("legacy genesis")
    } else {
        current.snapshot().clone()
    };
    let snapshot = base.with_budget_ledger(
        repository
            .put_budget_ledger(ledger)
            .expect("aggregate-only ledger"),
    );
    install_legacy_snapshot(repository, snapshot)
}

#[test]
fn request_spending_index_upgrades_legacy_admissions_and_rejects_forged_counts() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    repository
        .create("legacy", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    strip_request_spending_index(&repository);
    grant(&repository, "legacy", "legacy-funding", 4, 2);
    strip_request_spending_index(&repository);
    let first = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "legacy-index",
    );
    let second = BranchRequest::new(
        first.branch_point(),
        first.parent(),
        first.opportunity(),
        first.domain(),
        first.source().clone(),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test.legacy-index",
            b"second-cause",
        ))),
        first.budget(),
        first.stop().clone(),
    )
    .expect("second cause");
    let head = repository.head("legacy").expect("head");
    repository
        .discover_choice_opportunity(
            "legacy",
            head.snapshot_id(),
            first.parent(),
            first.opportunity(),
        )
        .expect("discover legacy choice");
    strip_request_spending_index(&repository);
    for request in [&first, &second] {
        let head = repository.head("legacy").expect("head");
        repository
            .submit_branch_request("legacy", head.snapshot_id(), request)
            .expect("submit");
        let head = strip_request_spending_index(&repository);
        let proposal = finite_proposal(request, &policy, &head, ChoiceValue::Boolean(false), 1);
        let issued = repository
            .issue_proposal("legacy", head.snapshot_id(), &proposal)
            .expect("issue");
        let head = strip_request_spending_index(&repository);
        let (selection, path, attempt) = branch_attempt(&repository, request, &proposal);
        repository
            .admit_proposal(
                "legacy",
                head.snapshot_id(),
                issued.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("admit");
        strip_request_spending_index(&repository);
    }
    let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let head = cold.head("legacy").expect("cold legacy head");
    let old_ledger = cold
        .read_budget_ledger(head.snapshot().budget_ledger().expect("ledger id"))
        .expect("legacy ledger");
    assert_eq!(old_ledger.request_spending(), None);
    assert_eq!(
        (old_ledger.spent_proposals(), old_ledger.spent_attempts()),
        (2, 1)
    );
    let upgraded = grant(&cold, "legacy", "upgrade-index", 1, 0);
    let ledger = cold
        .read_budget_ledger(upgraded.snapshot().budget_ledger().expect("ledger id"))
        .expect("indexed ledger");
    assert!(ledger.request_spending().is_some());
    assert_eq!(
        cold.indexed_request_execution_bases(ledger, first.id().expect("first id"))
            .expect("first count"),
        Some(1)
    );
    assert_eq!(
        cold.indexed_request_execution_bases(ledger, second.id().expect("second id"))
            .expect("second count"),
        Some(0)
    );
    CampaignRepository::new(cold.blobs.clone(), cold.refs.clone())
        .validate_complete_head(upgraded.content_id())
        .expect("cold upgraded index");

    let forged_ledger = ledger
        .with_request_spending(MerkleMap::empty_content_id().expect("empty index"))
        .expect("forged index");
    let forged = upgraded.snapshot().clone().with_budget_ledger(
        cold.put_budget_ledger(forged_ledger)
            .expect("forged ledger"),
    );
    let content = cold.put_snapshot(&forged).expect("forged snapshot");
    let before = blobs.object_count().expect("before rejection");
    assert!(matches!(
        CampaignRepository::new(cold.blobs.clone(), cold.refs.clone())
            .validate_complete_head(content),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-budget-successor-mismatch"
        })
    ));
    assert_eq!(blobs.object_count().expect("after rejection"), before);
    assert_eq!(
        cold.head("legacy").expect("unchanged head").snapshot_id(),
        upgraded.snapshot_id()
    );
}

#[test]
fn legacy_unfunded_proposal_debt_survives_upgrade_and_later_grants() {
    let (repository, lineage, policy) = fixture();
    repository
        .create("legacy", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let genesis = strip_current_ledger(&repository);
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "legacy-branch",
    );
    repository
        .discover_choice_opportunity(
            "legacy",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover");
    let discovered = strip_current_ledger(&repository);
    repository
        .submit_branch_request("legacy", discovered.snapshot_id(), &request)
        .expect("branch request");
    let requested = strip_current_ledger(&repository);
    let proposal = finite_proposal(
        &request,
        &policy,
        &requested,
        ChoiceValue::Boolean(false),
        1,
    );

    // Reconstruct the old writer's exact proposal delta, which intentionally
    // had no aggregate allowance check. Cold validation must retain its debt.
    repository
        .put_planning_view(&requested.snapshot().planning_view())
        .expect("planning view");
    let content = repository.put_proposal(&proposal).expect("legacy proposal");
    let mut roots = requested.snapshot().roots();
    let prior_exploration = roots.exploration;
    for key in [
        map_key_content("exploration.proposal", content),
        proposal_ordinal_key(proposal.request(), proposal.ordinal()),
        proposal_value_key(proposal.request(), proposal.value()),
    ] {
        roots.exploration = repository
            .merkle
            .insert(roots.exploration, key, content)
            .expect("proposal index")
            .content_id();
    }
    let frontier = repository
        .frontier_index_after(
            prior_exploration,
            &[(
                proposal.request(),
                proposal.branch_point(),
                ContinuationState::Open,
            )],
            true,
        )
        .expect("frontier")
        .expect("indexed frontier");
    roots.exploration = repository
        .merkle
        .insert(roots.exploration, frontier_index_anchor_key(), frontier)
        .expect("frontier anchor")
        .content_id();
    let loaded = repository
        .read_snapshot(requested.content_id())
        .expect("parent");
    roots.coordination = repository
        .coordination_with_parent_result(requested.content_id(), &loaded)
        .expect("parent result");
    let fact = repository
        .put_fact(&CampaignFact::ProposalIssued(
            proposal.id().expect("proposal id"),
        ))
        .expect("fact");
    let legacy = CampaignSnapshot::successor(
        requested.snapshot_id(),
        requested.snapshot().lineage(),
        requested.snapshot().active_policy(),
        roots,
        CampaignFactId::from_content_id(fact).expect("fact id"),
    )
    .expect("legacy proposal snapshot");
    install_legacy_snapshot(&repository, legacy);
    let cold = CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    let debt = cold.budget_projection("legacy").expect("legacy projection");
    assert_eq!(
        (
            debt.granted_proposals,
            debt.spent_proposals,
            debt.remaining_proposals()
        ),
        (0, 1, 0)
    );

    grant(&cold, "legacy", "repay-debt", 1, 0);
    let repaid = cold
        .budget_projection("legacy")
        .expect("upgraded projection");
    assert_eq!(
        (
            repaid.granted_proposals,
            repaid.spent_proposals,
            repaid.remaining_proposals()
        ),
        (1, 1, 0)
    );
    let head = cold.head("legacy").expect("upgraded head");
    assert!(head.snapshot().budget_ledger().is_some());
    let next = finite_proposal(&request, &policy, &head, ChoiceValue::Boolean(true), 2);
    assert!(matches!(
        cold.issue_proposal("legacy", head.snapshot_id(), &next),
        Err(CampaignRepositoryError::Budget(
            CampaignBudgetError::ProposalAllowanceExhausted
        ))
    ));
    let funded = grant(&cold, "legacy", "fund-new-work", 1, 0);
    let next = finite_proposal(&request, &policy, &funded, ChoiceValue::Boolean(true), 2);
    cold.issue_proposal("legacy", funded.snapshot_id(), &next)
        .expect("new funded proposal");
    assert_eq!(
        cold.budget_projection("legacy")
            .expect("budget")
            .spent_proposals,
        2
    );
}
