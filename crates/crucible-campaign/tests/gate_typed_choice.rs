//! Gate coverage for typed campaign choices and exact replay provenance.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use crucible_campaign::{
    BooleanDomain, BranchPointId, CampaignCodecError, CampaignHash, ChoiceClassContext,
    ChoiceCoordinate, ChoiceDomain, ChoiceOpportunity, ChoiceSource, ChoiceValue, ScenarioDefId,
    SelectableDeclaration, Selection,
};

#[test]
fn typed_choice_gate_binds_domain_value_and_branch_provenance() -> Result<(), CampaignCodecError> {
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1)?);
    let declaration = SelectableDeclaration::new(
        "network.recovery-enabled",
        ChoiceSource::Guest {
            node: String::from("router-a"),
            protocol_version: 1,
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new())?,
        BTreeSet::new(),
        true,
    )?;
    let opportunity = ChoiceOpportunity::new(
        ScenarioDefId::from_hash(CampaignHash::derive("typed-choice-scenario", b"scenario")),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("typed-choice-scheduler", b"scheduler"),
            producer: CampaignHash::derive("typed-choice-producer", b"producer"),
        },
        "recovery-1",
        None,
    )?;
    let branch_point =
        BranchPointId::from_hash(CampaignHash::derive("typed-choice-branch", b"branch"));
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        ChoiceValue::Boolean(true),
        branch_point,
    )?;

    let decoded = Selection::from_canonical_bytes(&selection.canonical_bytes())?;
    decoded.validate_branch_replay(&opportunity, &domain, branch_point)?;
    assert!(
        decoded
            .validate_branch_replay(
                &opportunity,
                &domain,
                BranchPointId::from_hash(CampaignHash::derive(
                    "typed-choice-branch",
                    b"other-branch",
                )),
            )
            .is_err()
    );

    Ok(())
}
