//! Exact installed routing, cross-partition quota and current source scope tests.

use anyhow::Result;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::credentials::{
    SourceCredentialGrant, SourceCredentialScope, SourceCredentialSetV1,
};
use aos_assessment_runtime::provider::{ProviderLimits, ProviderOperation};
use aos_assessment_runtime::routes::{InstalledSourceRoute, InstalledSourceRoutesV1};

#[test]
fn go_and_known_exploitation_routes_use_the_shared_operation_provider_names() -> Result<()> {
    let now = Timestamp::parse("2026-10-09T00:00:00Z")?;
    let credentials = SourceCredentialSetV1 {
        schema: "aos.assessment-source-credentials/v1".into(),
        grants: vec![],
    };
    let operations = [
        ProviderOperation::ObserveGoReleases,
        ProviderOperation::RefreshKev { offset: 0 },
    ];
    let mut routes = InstalledSourceRoutesV1 {
        schema: "aos.assessment-source-routes/v1".into(),
        deployment_id: "deployment".into(),
        coordinator_id: "coordinator".into(),
        executor_id: "executor".into(),
        routes: operations
            .iter()
            .map(|operation| InstalledSourceRoute {
                partition: "partition".into(),
                provider: operation.provider().into(),
                budget_key: format!("global-{}", operation.provider()),
                credential_ref: None,
                expires_at: Timestamp::parse("2026-10-09T00:01:00Z").unwrap(),
                limits: ProviderLimits::default(),
            })
            .collect(),
    };
    routes
        .routes
        .sort_by(|left, right| left.provider.cmp(&right.provider));
    for operation in operations {
        assert_eq!(
            routes
                .resolve("partition", &operation, &credentials, &now)?
                .provider,
            operation.provider()
        );
    }
    use aos_assessment_runtime::routes::{InstalledSourceBudget, validate_source_budgets};
    let budgets: Vec<_> = routes
        .routes
        .iter()
        .map(|route| InstalledSourceBudget {
            key: route.budget_key.clone(),
            window_seconds: 3600,
            allowance: 100,
            min_interval_seconds: 0,
        })
        .collect();
    validate_source_budgets(&routes, &budgets)?;
    assert!(validate_source_budgets(&routes, &budgets[..1]).is_err());
    let mut invalid = budgets.clone();
    invalid[0].allowance = 0;
    assert!(validate_source_budgets(&routes, &invalid).is_err());
    invalid = budgets.clone();
    invalid[0].key = "arbitrary-quota-fork".into();
    assert!(validate_source_budgets(&routes, &invalid).is_err());
    Ok(())
}

#[test]
fn source_routes_share_account_quota_and_refuse_fallback_or_expired_project_authority() -> Result<()>
{
    let now = Timestamp::parse("2026-10-09T00:00:00Z")?;
    let expires = Timestamp::parse("2026-10-09T00:01:00Z")?;
    let operation = ProviderOperation::ObserveTags {
        repository: "example/fixture".into(),
        tag_prefix: "v".into(),
        page: 1,
    };
    let mut routes = InstalledSourceRoutesV1 {
        schema: "aos.assessment-source-routes/v1".into(),
        deployment_id: "deployment-1".into(),
        coordinator_id: "native-coordinator".into(),
        executor_id: "worker-executor".into(),
        routes: vec![],
    };
    let mut credentials = SourceCredentialSetV1 {
        schema: "aos.assessment-source-credentials/v1".into(),
        grants: vec![],
    };
    for partition in ["partition-a", "partition-b"] {
        let reference = format!("github-{partition}-v1");
        routes.routes.push(InstalledSourceRoute {
            partition: partition.into(),
            provider: "github-tags".into(),
            budget_key: "global-github-account".into(),
            credential_ref: Some(reference.clone()),
            expires_at: expires.clone(),
            limits: ProviderLimits::default(),
        });
        credentials.grants.push(SourceCredentialGrant {
            reference,
            partition: partition.into(),
            provider: "github-tags".into(),
            scope: SourceCredentialScope::GithubRepositories {
                repositories: vec!["example/fixture".into()],
            },
            secret_binding: "ASSESSMENT_SHARED_GITHUB_V1".into(),
            expires_at: expires.clone(),
        });
    }
    let bytes = serde_json::to_vec(&routes)?;
    assert_eq!(InstalledSourceRoutesV1::from_slice(&bytes)?, routes);
    assert_eq!(
        routes
            .resolve("partition-a", &operation, &credentials, &now)?
            .budget_key,
        "global-github-account"
    );
    assert!(
        routes
            .resolve("uninstalled-partition", &operation, &credentials, &now)
            .is_err()
    );
    assert!(
        routes
            .resolve("partition-a", &operation, &credentials, &expires)
            .is_err()
    );
    let unrelated = ProviderOperation::ObserveTags {
        repository: "another/private-project".into(),
        tag_prefix: "v".into(),
        page: 1,
    };
    assert!(
        routes
            .resolve("partition-a", &unrelated, &credentials, &now)
            .is_err()
    );
    routes.routes[1].budget_key = "partition-local-account".into();
    assert!(
        routes
            .resolve("partition-a", &operation, &credentials, &now)
            .is_err()
    );
    routes.routes[1].budget_key = "global-github-account".into();
    credentials.grants[0].expires_at = now.clone();
    assert!(
        routes
            .resolve("partition-a", &operation, &credentials, &now)
            .is_err()
    );
    let mut unknown = serde_json::to_value(&routes)?;
    unknown["routes"][0]["providerUrl"] = serde_json::json!("https://unrelated.invalid");
    assert!(InstalledSourceRoutesV1::from_slice(&serde_json::to_vec(&unknown)?).is_err());
    Ok(())
}

#[test]
fn anonymous_github_tag_and_release_routes_share_one_provider_quota_domain() -> Result<()> {
    let now = Timestamp::parse("2026-10-09T00:00:00Z")?;
    let mut routes = InstalledSourceRoutesV1 {
        schema: "aos.assessment-source-routes/v1".into(),
        deployment_id: "deployment".into(),
        coordinator_id: "coordinator".into(),
        executor_id: "executor".into(),
        routes: ["github-releases", "github-tags"]
            .into_iter()
            .map(|provider| InstalledSourceRoute {
                partition: "partition".into(),
                provider: provider.into(),
                budget_key: "global-public-github".into(),
                credential_ref: None,
                expires_at: Timestamp::parse("2026-10-09T00:01:00Z").unwrap(),
                limits: ProviderLimits::default(),
            })
            .collect(),
    };
    let credentials = SourceCredentialSetV1 {
        schema: "aos.assessment-source-credentials/v1".into(),
        grants: vec![],
    };
    let operation = ProviderOperation::ObserveTags {
        repository: "example/fixture".into(),
        tag_prefix: "v".into(),
        page: 1,
    };
    routes.resolve("partition", &operation, &credentials, &now)?;
    routes.routes[0].budget_key = "separate-release-quota".into();
    assert!(
        routes
            .resolve("partition", &operation, &credentials, &now)
            .is_err()
    );
    Ok(())
}
