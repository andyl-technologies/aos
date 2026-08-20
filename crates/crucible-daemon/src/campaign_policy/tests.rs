#![allow(clippy::expect_used)]

use super::*;

fn principal(name: &str) -> CampaignPrincipal {
    CampaignPrincipal::new(name).expect("principal")
}

fn campaign(name: &str) -> CampaignName {
    CampaignName::new(name).expect("campaign")
}

fn credentials(process_id: i32, user_id: u32, group_id: u32) -> UnixPeerCampaignCredentials {
    UnixPeerCampaignCredentials::for_test(process_id, user_id, group_id)
}

#[test]
fn policy_binds_effective_credentials_without_trusting_pid() {
    let operator = principal("operator:alice");
    let policy = UnixPeerCampaignPolicy::new(
        [UnixPeerCampaignBinding::new(
            UnixPeerCampaignIdentity::new(1000, 100),
            operator.clone(),
        )],
        [CampaignAccessGrant::new(
            operator.clone(),
            CampaignServiceOperation::GetCampaign,
            CampaignAccessScope::AllCampaigns,
        )],
    )
    .expect("policy");

    assert_eq!(
        policy
            .resolve_campaign_principal(credentials(10, 1000, 100))
            .expect("first process"),
        operator
    );
    assert_eq!(
        policy
            .resolve_campaign_principal(credentials(99_999, 1000, 100))
            .expect("reused identity"),
        operator
    );
    assert_eq!(
        policy.resolve_campaign_principal(credentials(10, 1001, 100)),
        Err(CampaignAuthorizationError::Unauthorized)
    );
    assert_eq!(
        policy.resolve_campaign_principal(credentials(10, 1000, 101)),
        Err(CampaignAuthorizationError::Unauthorized)
    );
}

#[test]
fn policy_requires_exact_operation_and_campaign_scope() {
    let operator = principal("operator:alice");
    let auditor = principal("operator:auditor");
    let first = campaign("first");
    let second = campaign("second");
    let policy = UnixPeerCampaignPolicy::new(
        [
            UnixPeerCampaignBinding::new(
                UnixPeerCampaignIdentity::new(1000, 100),
                operator.clone(),
            ),
            UnixPeerCampaignBinding::new(UnixPeerCampaignIdentity::new(1001, 100), auditor.clone()),
        ],
        [
            CampaignAccessGrant::new(
                operator.clone(),
                CampaignServiceOperation::GetCampaign,
                CampaignAccessScope::Campaign(first.clone()),
            ),
            CampaignAccessGrant::new(
                auditor.clone(),
                CampaignServiceOperation::GetCampaignSnapshot,
                CampaignAccessScope::AllCampaigns,
            ),
        ],
    )
    .expect("policy");

    assert_eq!(
        policy.authorize(
            &operator,
            CampaignServiceOperation::GetCampaign,
            &first,
            CampaignHash::derive("campaign-policy-test", b"first"),
        ),
        Ok(())
    );
    assert_eq!(
        policy.authorize(
            &operator,
            CampaignServiceOperation::GetCampaign,
            &second,
            CampaignHash::derive("campaign-policy-test", b"second"),
        ),
        Err(CampaignAuthorizationError::Unauthorized)
    );
    assert_eq!(
        policy.authorize(
            &operator,
            CampaignServiceOperation::ApplyCampaignCommand,
            &first,
            CampaignHash::derive("campaign-policy-test", b"mutation"),
        ),
        Err(CampaignAuthorizationError::Unauthorized)
    );
    assert_eq!(
        policy.authorize(
            &auditor,
            CampaignServiceOperation::GetCampaignSnapshot,
            &second,
            CampaignHash::derive("campaign-policy-test", b"snapshot"),
        ),
        Ok(())
    );
    assert_eq!(policy.binding_count(), 2);
    assert_eq!(policy.grant_count(), 2);
}

#[test]
fn policy_configuration_rejects_ambiguity_and_unreachable_grants() {
    let operator = principal("operator:alice");
    let identity = UnixPeerCampaignIdentity::new(1000, 100);
    assert!(matches!(
        UnixPeerCampaignPolicy::new(
            [
                UnixPeerCampaignBinding::new(identity, operator.clone()),
                UnixPeerCampaignBinding::new(identity, principal("operator:bob")),
            ],
            [],
        ),
        Err(UnixPeerCampaignPolicyError::DuplicateIdentity)
    ));

    let grant = CampaignAccessGrant::new(
        operator.clone(),
        CampaignServiceOperation::GetCampaign,
        CampaignAccessScope::AllCampaigns,
    );
    assert!(matches!(
        UnixPeerCampaignPolicy::new(
            [UnixPeerCampaignBinding::new(identity, operator.clone())],
            [grant.clone(), grant],
        ),
        Err(UnixPeerCampaignPolicyError::DuplicateGrant)
    ));
    assert!(matches!(
        UnixPeerCampaignPolicy::new(
            [],
            [CampaignAccessGrant::new(
                operator,
                CampaignServiceOperation::GetCampaign,
                CampaignAccessScope::AllCampaigns,
            )],
        ),
        Err(UnixPeerCampaignPolicyError::UnknownGrantPrincipal)
    ));
}

#[test]
fn policy_counts_are_checked_before_retention_grows_past_the_bound() {
    let operator = principal("operator:alice");
    let bindings = (0..=MAX_CAMPAIGN_PEER_BINDINGS).map(|index| {
        UnixPeerCampaignBinding::new(
            UnixPeerCampaignIdentity::new(index as u32, 100),
            operator.clone(),
        )
    });
    assert!(matches!(
        UnixPeerCampaignPolicy::new(bindings, []),
        Err(UnixPeerCampaignPolicyError::TooManyBindings)
    ));

    let bindings = [UnixPeerCampaignBinding::new(
        UnixPeerCampaignIdentity::new(1000, 100),
        operator.clone(),
    )];
    let grants = (0..=MAX_CAMPAIGN_ACCESS_GRANTS).map(|index| {
        CampaignAccessGrant::new(
            operator.clone(),
            CampaignServiceOperation::GetCampaign,
            CampaignAccessScope::Campaign(campaign(&format!("campaign-{index}"))),
        )
    });
    assert!(matches!(
        UnixPeerCampaignPolicy::new(bindings, grants),
        Err(UnixPeerCampaignPolicyError::TooManyGrants)
    ));
}

#[test]
fn empty_policy_is_explicitly_deny_all() {
    let policy = UnixPeerCampaignPolicy::new([], []).expect("deny-all policy");
    assert_eq!(policy.binding_count(), 0);
    assert_eq!(policy.grant_count(), 0);
    assert_eq!(
        policy.resolve_campaign_principal(credentials(1, 0, 0)),
        Err(CampaignAuthorizationError::Unauthorized)
    );
    assert_eq!(
        policy.authorize(
            &principal("operator:alice"),
            CampaignServiceOperation::GetCampaign,
            &campaign("first"),
            CampaignHash::derive("campaign-policy-test", b"deny"),
        ),
        Err(CampaignAuthorizationError::Unauthorized)
    );
}
