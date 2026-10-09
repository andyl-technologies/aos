//! Identity regression cases and contract checks.

use super::*;

#[tokio::test]
async fn reporter_apply_recovers_after_mutation_and_revokes_an_inactive_principal() {
    let (service, db, _lease, admin_auth) = injected_service(vec![], vec![]).await;
    let org_id = db
        .create_org("reporter-recovery", "Reporter recovery")
        .await
        .unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "packages", "private", &[], true)
        .await
        .unwrap();
    let reporter_id = db
        .create_user("deployment-reporter@example.test", None)
        .await
        .unwrap();

    let planned = service
        .plan_configure_ability_deployment_reporter(
            Some(&admin_auth),
            pb::PlanConfigureAbilityDeploymentReporterRequest {
                registry: "reporter-recovery/packages".into(),
                deployment: "production".into(),
                principal_kind: "user".into(),
                principal_ref: "deployment-reporter@example.test".into(),
                enabled: true,
                expected_resource_version: 0,
                idempotency_key: "plan-reporter-recovery".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();

    // Simulate a crash after the CAS mutation and before generic plan completion.
    db.configure_ability_deployment_reporter(
        registry_id,
        "production",
        "user",
        reporter_id,
        "deployment-reporter@example.test",
        true,
        0,
        &planned.plan_id,
    )
    .await
    .unwrap();
    assert!(db.delete_user(reporter_id).await.unwrap());

    let apply = pb::ApplyTopologyPlanRequest {
        plan_id: planned.plan_id,
        idempotency_key: "apply-reporter-recovery".into(),
        confirmation_hash: planned.confirmation_hash,
    };
    let recovered = service
        .configure_ability_deployment_reporter(Some(&admin_auth), apply.clone())
        .await
        .unwrap();
    let replayed = service
        .configure_ability_deployment_reporter(Some(&admin_auth), apply)
        .await
        .unwrap();
    assert_eq!(recovered, replayed);
    assert_eq!(recovered.resource_version, 1);
    assert_eq!(recovered.principal_ref, "deployment-reporter@example.test");
    assert!(recovered.enabled);

    let revoke = service
        .plan_configure_ability_deployment_reporter(
            Some(&admin_auth),
            pb::PlanConfigureAbilityDeploymentReporterRequest {
                registry: "reporter-recovery/packages".into(),
                deployment: "production".into(),
                principal_kind: "user".into(),
                principal_ref: "deployment-reporter@example.test".into(),
                enabled: false,
                expected_resource_version: recovered.resource_version,
                idempotency_key: "plan-revoke-inactive-reporter".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let revoked = service
        .configure_ability_deployment_reporter(
            Some(&admin_auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: revoke.plan_id,
                idempotency_key: "apply-revoke-inactive-reporter".into(),
                confirmation_hash: revoke.confirmation_hash,
            },
        )
        .await
        .unwrap();

    assert!(!revoked.enabled);
    assert_eq!(revoked.resource_version, 2);
}

#[tokio::test]
async fn binary_cache_lookup_accepts_stable_identity_and_canonical_slug() {
    let (service, db, _lease, _auth) = injected_service(vec![], vec![]).await;
    let org_id = db.create_org("locator", "Locator").await.unwrap();
    db.create_binary_cache(
        Some(org_id),
        "locator/build",
        "Build cache",
        "private",
        40,
        "zstd",
        false,
    )
    .await
    .unwrap();
    let stored = db
        .binary_cache_by_slug("locator/build")
        .await
        .unwrap()
        .unwrap();

    let by_slug = service
        .binary_cache_or_not_found("locator/build")
        .await
        .unwrap();
    let by_stable_id = service
        .binary_cache_or_not_found(&stored.stable_id)
        .await
        .unwrap();

    assert_eq!(by_slug.stable_id, stored.stable_id);
    assert_eq!(by_stable_id.stable_id, stored.stable_id);
}

#[tokio::test]
async fn registry_lookup_accepts_stable_identity_and_canonical_slug() {
    let (service, db, _lease, _auth) = injected_service(vec![], vec![]).await;
    let org_id = db
        .create_org("registry-locator", "Registry locator")
        .await
        .unwrap();
    db.create_managed_registry(org_id, "", "packages", "private", &[], false)
        .await
        .unwrap();
    let stored = db
        .registry_by_slug("registry-locator/packages")
        .await
        .unwrap()
        .unwrap();

    let by_slug = service
        .registry_or_not_found("registry-locator/packages")
        .await
        .unwrap();
    let by_stable_id = service
        .registry_or_not_found(&stored.stable_id)
        .await
        .unwrap();

    assert_eq!(by_slug.stable_id, stored.stable_id);
    assert_eq!(by_stable_id.stable_id, stored.stable_id);
}

#[tokio::test]
async fn access_tokens_use_native_permissions_and_stable_scopes() {
    let (service, _db, _lease, auth) = injected_service(vec![], vec![]).await;
    let plan = service
        .plan_issue_access_token(
            Some(&auth),
            pb::PlanIssueAccessTokenRequest {
                owner: "user:writer@example.test".into(),
                scope: "instance".into(),
                permissions: vec!["read".into(), "publish".into()],
                ttl_secs: 3600,
                expected_resource_version: String::new(),
                idempotency_key: "plan-access-token-test".into(),
                comment: "test publisher".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let issued = service
        .apply_issue_access_token(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: plan.plan_id,
                confirmation_hash: plan.confirmation_hash,
                idempotency_key: "apply-access-token-test".into(),
            },
        )
        .await
        .unwrap();

    assert!(issued.secret.starts_with("aos_"));
    let listed = service
        .list_access_tokens(
            Some(&auth),
            pb::ListAccessTokensRequest {
                scope: "instance".into(),
                page_size: 50,
                page_token: String::new(),
            },
        )
        .await
        .unwrap();
    let token = listed
        .tokens
        .iter()
        .find(|token| token.token_id == issued.token_id)
        .unwrap();
    assert_eq!(token.owner, "user:writer@example.test");
    assert_eq!(token.scope, "instance");
    assert_eq!(token.permissions, vec!["publish", "read"]);
    assert_eq!(token.comment, "test publisher");
    assert_eq!(token.resource_version, "active");
}

#[tokio::test]
async fn service_account_crud_preserves_identity_and_removes_memberships() {
    let (service, db, _lease, auth) = injected_service(vec![], vec![]).await;
    let org_id = db.create_org("robots", "Robots").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();

    let create_plan = service
        .plan_create_service_account(
            Some(&auth),
            pb::PlanCreateServiceAccountRequest {
                org_slug: org.slug.clone(),
                name: "publisher".into(),
                expected_resource_version: String::new(),
                idempotency_key: "plan-create-service-account".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let created = service
        .apply_create_service_account(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: create_plan.plan_id,
                confirmation_hash: create_plan.confirmation_hash,
                idempotency_key: "apply-create-service-account".into(),
            },
        )
        .await
        .unwrap()
        .service_account
        .unwrap();
    db.grant_membership(
        "service_account",
        created.id,
        &org.stable_id,
        Role::Developer.as_str(),
    )
    .await
    .unwrap();

    let update_plan = service
        .plan_update_service_account(
            Some(&auth),
            pb::PlanUpdateServiceAccountRequest {
                org_slug: org.slug.clone(),
                name: created.name.clone(),
                new_name: "releaser".into(),
                expected_resource_version: created.resource_version,
                idempotency_key: "plan-update-service-account".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let updated = service
        .apply_update_service_account(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: update_plan.plan_id,
                confirmation_hash: update_plan.confirmation_hash,
                idempotency_key: "apply-update-service-account".into(),
            },
        )
        .await
        .unwrap()
        .service_account
        .unwrap();
    assert_eq!(updated.id, created.id);
    assert_eq!(updated.name, "releaser");
    assert_eq!(
        db.service_account_reference(updated.id)
            .await
            .unwrap()
            .as_deref(),
        Some("robots/releaser")
    );

    let listed = service
        .list_service_accounts(
            Some(&auth),
            pb::ListServiceAccountsRequest {
                org_slug: org.slug.clone(),
                page_size: 50,
                page_token: String::new(),
            },
        )
        .await
        .unwrap();
    assert_eq!(listed.service_accounts.len(), 1);

    let delete_plan = service
        .plan_delete_service_account(
            Some(&auth),
            pb::PlanDeleteServiceAccountRequest {
                org_slug: org.slug,
                name: updated.name,
                expected_resource_version: updated.resource_version,
                idempotency_key: "plan-delete-service-account".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let deleted = service
        .apply_delete_service_account(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: delete_plan.plan_id,
                confirmation_hash: delete_plan.confirmation_hash,
                idempotency_key: "apply-delete-service-account".into(),
            },
        )
        .await
        .unwrap();
    assert!(deleted.deleted);
    assert!(db
        .list_memberships_for("service_account", created.id)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn identity_provider_and_domain_lifecycles_are_reviewed_and_versioned() {
    let (service, db, _lease, auth) = injected_service(vec![], vec![]).await;
    db.create_org("identity", "Identity").await.unwrap();

    let idp_request = pb::PlanSetIdentityProviderRequest {
        org_slug: "identity".into(),
        issuer: "https://idp.example.test".into(),
        authorization_endpoint: "https://idp.example.test/authorize".into(),
        token_endpoint: "https://idp.example.test/token".into(),
        jwks_uri: "https://idp.example.test/jwks".into(),
        client_id: "hub".into(),
        client_secret: "credential".into(),
        replace_client_secret: true,
        scopes: "openid email profile".into(),
        groups_claim: "groups".into(),
        role_map_json: r#"{"admins":"admin"}"#.into(),
        allow_jit: true,
        enforce_sso: true,
        default_role: "viewer".into(),
        expected_resource_version: "absent".into(),
        idempotency_key: "plan-idp-set".into(),
    };
    let idp_plan = service
        .plan_set_identity_provider(Some(&auth), idp_request.clone())
        .await
        .unwrap()
        .plan
        .unwrap();
    let replay = service
        .plan_set_identity_provider(Some(&auth), idp_request.clone())
        .await
        .unwrap()
        .plan
        .unwrap();
    assert_eq!(replay.plan_id, idp_plan.plan_id);
    let idp = service
        .apply_set_identity_provider(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: idp_plan.plan_id.clone(),
                confirmation_hash: idp_plan.confirmation_hash.clone(),
                idempotency_key: "apply-idp-set".into(),
            },
        )
        .await
        .unwrap()
        .identity_provider
        .unwrap();
    assert!(idp.client_secret_configured);
    assert!(idp.resource_version.starts_with("1@idp-incarnation-"));
    let replay = service
        .plan_set_identity_provider(Some(&auth), idp_request)
        .await
        .unwrap()
        .plan
        .unwrap();
    assert_eq!(replay.plan_id, idp_plan.plan_id);
    let org = db.org_by_slug("identity").await.unwrap().unwrap();
    let stored = db.idp_config(org.id).await.unwrap().unwrap();
    assert_eq!(
        stored.client_secret_enc.as_deref(),
        Some("sealed:credential")
    );

    let claim_request = pb::PlanClaimOrganizationDomainRequest {
        org_slug: "identity".into(),
        domain: "login.example.test".into(),
        expected_resource_version: "absent".into(),
        idempotency_key: "plan-domain-claim".into(),
    };
    let claim_plan = service
        .plan_claim_organization_domain(Some(&auth), claim_request.clone())
        .await
        .unwrap()
        .plan
        .unwrap();
    let claimed = service
        .apply_claim_organization_domain(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: claim_plan.plan_id.clone(),
                confirmation_hash: claim_plan.confirmation_hash.clone(),
                idempotency_key: "apply-domain-claim".into(),
            },
        )
        .await
        .unwrap()
        .domain
        .unwrap();
    assert_eq!(claimed.state, "pending");
    assert!(claimed
        .resource_version
        .starts_with("1@domain-incarnation-"));
    let replay = service
        .plan_claim_organization_domain(Some(&auth), claim_request)
        .await
        .unwrap()
        .plan
        .unwrap();
    assert_eq!(replay.plan_id, claim_plan.plan_id);

    let verify_request = pb::PlanVerifyOrganizationDomainRequest {
        org_slug: "identity".into(),
        domain: claimed.domain.clone(),
        expected_resource_version: claimed.resource_version.clone(),
        idempotency_key: "plan-domain-verify".into(),
    };
    let verify_plan = service
        .plan_verify_organization_domain(Some(&auth), verify_request.clone())
        .await
        .unwrap()
        .plan
        .unwrap();
    let verified = service
        .apply_verify_organization_domain(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: verify_plan.plan_id.clone(),
                confirmation_hash: verify_plan.confirmation_hash.clone(),
                idempotency_key: "apply-domain-verify".into(),
            },
        )
        .await
        .unwrap()
        .domain
        .unwrap();
    assert_eq!(verified.state, "verified");
    assert!(verified
        .resource_version
        .starts_with("2@domain-incarnation-"));
    assert!(verified.verified_at > 0);
    let replay = service
        .plan_verify_organization_domain(Some(&auth), verify_request)
        .await
        .unwrap()
        .plan
        .unwrap();
    assert_eq!(replay.plan_id, verify_plan.plan_id);
}

#[tokio::test]
async fn identity_revisions_reject_delete_recreate_aba() {
    let (service, db, _lease, auth) = injected_service(vec![], vec![]).await;
    db.create_org("identity-aba", "Identity ABA").await.unwrap();
    let idp_request = |idempotency_key: &str| pb::PlanSetIdentityProviderRequest {
        org_slug: "identity-aba".into(),
        issuer: "https://idp.example.test".into(),
        authorization_endpoint: "https://idp.example.test/authorize".into(),
        token_endpoint: "https://idp.example.test/token".into(),
        jwks_uri: "https://idp.example.test/jwks".into(),
        client_id: "hub".into(),
        client_secret: String::new(),
        replace_client_secret: false,
        scopes: "openid email".into(),
        groups_claim: String::new(),
        role_map_json: "{}".into(),
        allow_jit: false,
        enforce_sso: false,
        default_role: "viewer".into(),
        expected_resource_version: "absent".into(),
        idempotency_key: idempotency_key.into(),
    };
    let create = service
        .plan_set_identity_provider(Some(&auth), idp_request("idp-create"))
        .await
        .unwrap()
        .plan
        .unwrap();
    let idp = service
        .apply_set_identity_provider(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: create.plan_id,
                confirmation_hash: create.confirmation_hash,
                idempotency_key: "idp-create-apply".into(),
            },
        )
        .await
        .unwrap()
        .identity_provider
        .unwrap();
    let remove_request = |idempotency_key: &str| pb::PlanRemoveIdentityProviderRequest {
        org_slug: "identity-aba".into(),
        expected_resource_version: idp.resource_version.clone(),
        idempotency_key: idempotency_key.into(),
    };
    let stale_remove = service
        .plan_remove_identity_provider(Some(&auth), remove_request("idp-remove-stale"))
        .await
        .unwrap()
        .plan
        .unwrap();
    let winning_remove_request = remove_request("idp-remove-winning");
    let winning_remove = service
        .plan_remove_identity_provider(Some(&auth), winning_remove_request.clone())
        .await
        .unwrap()
        .plan
        .unwrap();
    service
        .apply_remove_identity_provider(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: winning_remove.plan_id.clone(),
                confirmation_hash: winning_remove.confirmation_hash.clone(),
                idempotency_key: "idp-remove-winning-apply".into(),
            },
        )
        .await
        .unwrap();
    let replay = service
        .plan_remove_identity_provider(Some(&auth), winning_remove_request)
        .await
        .unwrap()
        .plan
        .unwrap();
    assert_eq!(replay.plan_id, winning_remove.plan_id);

    let recreate = service
        .plan_set_identity_provider(Some(&auth), idp_request("idp-recreate"))
        .await
        .unwrap()
        .plan
        .unwrap();
    service
        .apply_set_identity_provider(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: recreate.plan_id,
                confirmation_hash: recreate.confirmation_hash,
                idempotency_key: "idp-recreate-apply".into(),
            },
        )
        .await
        .unwrap();
    let error = service
        .apply_remove_identity_provider(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: stale_remove.plan_id,
                confirmation_hash: stale_remove.confirmation_hash,
                idempotency_key: "idp-remove-stale-apply".into(),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, RpcError::FailedPrecondition(_)));

    let claim_request = |idempotency_key: &str| pb::PlanClaimOrganizationDomainRequest {
        org_slug: "identity-aba".into(),
        domain: "aba.example.test".into(),
        expected_resource_version: "absent".into(),
        idempotency_key: idempotency_key.into(),
    };
    let claim = service
        .plan_claim_organization_domain(Some(&auth), claim_request("domain-claim"))
        .await
        .unwrap()
        .plan
        .unwrap();
    let domain = service
        .apply_claim_organization_domain(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: claim.plan_id,
                confirmation_hash: claim.confirmation_hash,
                idempotency_key: "domain-claim-apply".into(),
            },
        )
        .await
        .unwrap()
        .domain
        .unwrap();
    let release_request = |idempotency_key: &str| pb::PlanReleaseOrganizationDomainRequest {
        org_slug: "identity-aba".into(),
        domain: domain.domain.clone(),
        expected_resource_version: domain.resource_version.clone(),
        idempotency_key: idempotency_key.into(),
    };
    let stale_release = service
        .plan_release_organization_domain(Some(&auth), release_request("domain-release-stale"))
        .await
        .unwrap()
        .plan
        .unwrap();
    let winning_release_request = release_request("domain-release-winning");
    let winning_release = service
        .plan_release_organization_domain(Some(&auth), winning_release_request.clone())
        .await
        .unwrap()
        .plan
        .unwrap();
    service
        .apply_release_organization_domain(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: winning_release.plan_id.clone(),
                confirmation_hash: winning_release.confirmation_hash.clone(),
                idempotency_key: "domain-release-winning-apply".into(),
            },
        )
        .await
        .unwrap();
    let replay = service
        .plan_release_organization_domain(Some(&auth), winning_release_request)
        .await
        .unwrap()
        .plan
        .unwrap();
    assert_eq!(replay.plan_id, winning_release.plan_id);

    let recreate = service
        .plan_claim_organization_domain(Some(&auth), claim_request("domain-recreate"))
        .await
        .unwrap()
        .plan
        .unwrap();
    service
        .apply_claim_organization_domain(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: recreate.plan_id,
                confirmation_hash: recreate.confirmation_hash,
                idempotency_key: "domain-recreate-apply".into(),
            },
        )
        .await
        .unwrap();
    let error = service
        .apply_release_organization_domain(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: stale_release.plan_id,
                confirmation_hash: stale_release.confirmation_hash,
                idempotency_key: "domain-release-stale-apply".into(),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, RpcError::FailedPrecondition(_)));
}

#[tokio::test]
async fn identity_domain_dns_transport_failure_is_publicly_retryable() {
    let (mut service, db, _lease, auth) = injected_service(vec![], vec![]).await;
    service.identity_domain_verifier = Some(Arc::new(UnavailableIdentityDomain));
    db.create_org("dns-unavailable", "DNS unavailable")
        .await
        .unwrap();

    let claim_plan = service
        .plan_claim_organization_domain(
            Some(&auth),
            pb::PlanClaimOrganizationDomainRequest {
                org_slug: "dns-unavailable".into(),
                domain: "login.example.test".into(),
                expected_resource_version: "absent".into(),
                idempotency_key: "plan-domain-claim-unavailable".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let claimed = service
        .apply_claim_organization_domain(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: claim_plan.plan_id,
                confirmation_hash: claim_plan.confirmation_hash,
                idempotency_key: "apply-domain-claim-unavailable".into(),
            },
        )
        .await
        .unwrap()
        .domain
        .unwrap();
    let verify_plan = service
        .plan_verify_organization_domain(
            Some(&auth),
            pb::PlanVerifyOrganizationDomainRequest {
                org_slug: "dns-unavailable".into(),
                domain: claimed.domain,
                expected_resource_version: claimed.resource_version,
                idempotency_key: "plan-domain-verify-unavailable".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();

    let error = service
        .apply_verify_organization_domain(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: verify_plan.plan_id,
                confirmation_hash: verify_plan.confirmation_hash,
                idempotency_key: "apply-domain-verify-unavailable".into(),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RpcError::Unavailable(message)
            if message == "DNS TXT verification is temporarily unavailable"
    ));
}

#[tokio::test]
async fn invitation_acceptance_atomically_creates_membership_for_matching_user() {
    let (service, db, _lease, auth) = injected_service(vec![], vec![]).await;
    let org_id = db.create_org("invites", "Invites").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();

    let plan = service
        .plan_create_invitation(
            Some(&auth),
            pb::PlanCreateInvitationRequest {
                org_slug: org.slug.clone(),
                email: "New.Member@Example.Test".into(),
                scope: org.stable_id.clone(),
                role: "developer".into(),
                ttl_secs: 3600,
                expected_resource_version: String::new(),
                idempotency_key: "plan-create-invitation".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let apply = pb::ApplyTopologyPlanRequest {
        plan_id: plan.plan_id,
        confirmation_hash: plan.confirmation_hash,
        idempotency_key: "apply-create-invitation".into(),
    };
    let created = service
        .apply_create_invitation(Some(&auth), apply.clone())
        .await
        .unwrap();
    assert!(created.secret.starts_with("aosi_"));
    let replayed = service
        .apply_create_invitation(Some(&auth), apply)
        .await
        .unwrap();
    assert_eq!(replayed.secret, created.secret);
    assert_eq!(
        replayed.invitation.as_ref().map(|item| item.invitation_id),
        created.invitation.as_ref().map(|item| item.invitation_id)
    );
    let invitation = created.invitation.unwrap();
    assert_eq!(invitation.email, "new.member@example.test");
    assert_eq!(invitation.state, "pending");
    assert_eq!(
        db.user_by_email("new.member@example.test").await.unwrap(),
        None,
        "creating an invitation must not create a user"
    );

    let invitee = db
        .create_user("new.member@example.test", None)
        .await
        .unwrap();
    let token = service
        .jwt_keys
        .mint(
            &TokenAuth {
                token_id: "invitee-session".into(),
                owner: Principal::user(invitee),
                scope: Scope::root(),
                permissions: Vec::new(),
            },
            3600,
        )
        .unwrap();
    let invitee_auth = format!("Bearer {token}");
    let accepted = service
        .accept_invitation(
            Some(&invitee_auth),
            pb::AcceptInvitationRequest {
                org_slug: org.slug.clone(),
                secret: created.secret.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(accepted.invitation.unwrap().state, "accepted");
    assert_eq!(accepted.membership.unwrap().role, "developer");
    assert_eq!(
        db.list_memberships_for("user", invitee).await.unwrap(),
        vec![(org.stable_id, "developer".to_string())]
    );
    assert!(service
        .accept_invitation(
            Some(&invitee_auth),
            pb::AcceptInvitationRequest {
                org_slug: org.slug,
                secret: created.secret,
            },
        )
        .await
        .is_err());

    let cancel_plan = service
        .plan_create_invitation(
            Some(&auth),
            pb::PlanCreateInvitationRequest {
                org_slug: "invites".into(),
                email: "cancelled@example.test".into(),
                scope: db.org_by_id(org_id).await.unwrap().unwrap().stable_id,
                role: "viewer".into(),
                ttl_secs: 3600,
                expected_resource_version: String::new(),
                idempotency_key: "plan-create-cancelled-invitation".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let cancellable_apply = pb::ApplyTopologyPlanRequest {
        plan_id: cancel_plan.plan_id,
        confirmation_hash: cancel_plan.confirmation_hash,
        idempotency_key: "apply-create-cancelled-invitation".into(),
    };
    let cancellable = service
        .apply_create_invitation(Some(&auth), cancellable_apply.clone())
        .await
        .unwrap()
        .invitation
        .unwrap();
    let cancellation = service
        .plan_cancel_invitation(
            Some(&auth),
            pb::PlanCancelInvitationRequest {
                org_slug: "invites".into(),
                invitation_id: cancellable.invitation_id,
                expected_resource_version: cancellable.resource_version,
                idempotency_key: "plan-cancel-invitation".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let cancelled = service
        .apply_cancel_invitation(
            Some(&auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: cancellation.plan_id,
                confirmation_hash: cancellation.confirmation_hash,
                idempotency_key: "apply-cancel-invitation".into(),
            },
        )
        .await
        .unwrap()
        .invitation
        .unwrap();
    assert_eq!(cancelled.state, "cancelled");
    assert!(matches!(
        service
            .apply_create_invitation(Some(&auth), cancellable_apply)
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
    let history = service
        .list_invitations(
            Some(&auth),
            pb::ListInvitationsRequest {
                org_slug: "invites".into(),
                page_size: 50,
                page_token: String::new(),
            },
        )
        .await
        .unwrap();
    assert_eq!(history.invitations.len(), 2);
    let states = history
        .invitations
        .iter()
        .map(|invitation| invitation.state.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        states,
        std::collections::BTreeSet::from(["accepted", "cancelled"])
    );
}

#[tokio::test]
async fn private_image_resolve_authenticates_before_channel_lookup() {
    let (service, db, _lease, _auth) = injected_service(vec![], vec![]).await;
    let org_id = db
        .create_org("hidden-images", "Hidden images")
        .await
        .unwrap();
    db.create_managed_registry(org_id, "", "system", "private", &[], false)
        .await
        .unwrap();

    let resolve = |channel: &str| aos_hub_api::ResolveImageRequest {
        slug: "hidden-images/system".into(),
        release: String::new(),
        channel: channel.into(),
        architecture: "x86_64".into(),
        format: "raw".into(),
        target: "bare-metal".into(),
        package: "aos-system".into(),
    };
    let existing_shape = service
        .resolve_image(None, resolve("stable"))
        .await
        .unwrap_err();
    let absent_shape = service
        .resolve_image(None, resolve("does-not-exist"))
        .await
        .unwrap_err();
    assert!(matches!(existing_shape, RpcError::Unauthenticated(_)));
    assert!(matches!(absent_shape, RpcError::Unauthenticated(_)));
    assert_eq!(existing_shape.code(), absent_shape.code());
    assert_eq!(existing_shape.message(), absent_shape.message());
}

#[test]
fn retention_reason_row_identity_is_refresh_local() {
    let reason_key = "registry_catalog:logical-reason";

    let first = super::retention_refresh_reason_id("refresh-one", reason_key);
    let repeated = super::retention_refresh_reason_id("refresh-one", reason_key);
    let successor = super::retention_refresh_reason_id("refresh-two", reason_key);

    assert_eq!(first, repeated);
    assert_ne!(first, successor);
    assert_eq!(first.len(), 64);
    assert_eq!(successor.len(), 64);
}
