//! Selection replay mismatch classification tests.

// crucible-lint: allow panic-shortcut -- exact fixture failures localize replay classifier regressions.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use super::*;
use crate::choice::BooleanDomain;

#[test]
fn replay_mismatch_reports_the_first_failed_base_predicate() {
    let expected_domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("expected domain"));
    let replayed_domain = ChoiceDomain::Boolean(BooleanDomain::new(2).expect("replayed domain"));
    let declaration = SelectableDeclaration::new(
        "scheduler.retry",
        ChoiceSource::Scheduler {
            producer: String::from("replay-test"),
        },
        expected_domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        ScenarioDefId::from_hash(CampaignHash::derive("replay-test", b"scenario")),
        &declaration,
        &expected_domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("replay-test", b"scheduler"),
            producer: CampaignHash::derive("replay-test", b"producer"),
        },
        "retry-0",
        None,
    )
    .expect("choice opportunity");
    let selection = Selection::new(
        &opportunity,
        &expected_domain,
        ChoiceValue::Boolean(true),
        SelectionOrigin::LockedReplay,
    )
    .expect("selection");

    assert_eq!(
        selection
            .replay_mismatch(&opportunity, &expected_domain)
            .expect("matching replay classification"),
        None
    );

    let mismatch = selection
        .replay_mismatch(&opportunity, &replayed_domain)
        .expect("mismatch classification")
        .expect("domain identity must disagree");
    let opportunity_id = opportunity.id().expect("opportunity ID");

    assert_eq!(mismatch.kind(), SelectionReplayMismatchKind::DomainIdentity);
    assert_eq!(mismatch.expected_opportunity(), opportunity_id);
    assert_eq!(mismatch.replayed_opportunity(), opportunity_id);
    assert_eq!(
        mismatch.expected_domain(),
        expected_domain.id().expect("expected domain ID")
    );
    assert_eq!(
        mismatch.replayed_domain(),
        replayed_domain.id().expect("replayed domain ID")
    );
    assert_eq!(mismatch.replayed_opportunity_domain(), opportunity.domain());
    assert!(mismatch.value_in_replayed_domain());
}
