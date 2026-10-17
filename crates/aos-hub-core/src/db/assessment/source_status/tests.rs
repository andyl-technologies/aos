//! Installed partition isolation and quota-preserving source status reads.

use aos_assessment_runtime::credentials::{SourceCredentialGrant, SourceCredentialScope};
use aos_assessment_runtime::provider::ProviderLimits;
use aos_assessment_runtime::routes::InstalledSourceRoute;
use aos_assessment_runtime::source_status::SourceDelayCause;

use crate::db::AssessmentSourceBudget;

use super::*;

#[tokio::test]
async fn absent_installation_does_not_invent_source_availability() -> Result<()> {
    let db = Database::open_in_memory().await?;
    let now = db.assessment_database_time().await?;
    assert!(db
        .assessment_source_status("public-partition", &now)
        .await?
        .is_empty());
    assert!(db.assessment_source_status("", &now).await.is_err());
    Ok(())
}

#[tokio::test]
async fn source_status_is_scoped_and_read_only_on_sqlite() -> Result<()> {
    qualify(Database::open_in_memory().await?).await
}

#[tokio::test]
#[cfg(feature = "postgres")]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn source_status_is_scoped_and_read_only_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
    qualify(Database::with_backend(Box::new(backend)).await?).await
}

async fn qualify(db: Database) -> Result<()> {
    let now = db.assessment_database_time().await?;
    let expires = Timestamp::from_unix_seconds(now.unix_seconds() + 3600)?;
    let budget_key = format!("private-account-{}", uuid::Uuid::new_v4());
    let routes = InstalledSourceRoutesV1 {
        schema: "aos.assessment-source-routes/v1".into(),
        deployment_id: "fixture-deployment".into(),
        coordinator_id: "fixture-coordinator".into(),
        executor_id: "fixture-executor".into(),
        routes: vec![
            InstalledSourceRoute {
                partition: "private-partition".into(),
                provider: "github-tags".into(),
                budget_key: "unrelated-private-account".into(),
                credential_ref: Some("private-version-reference".into()),
                expires_at: expires.clone(),
                limits: ProviderLimits::default(),
            },
            InstalledSourceRoute {
                partition: "public-partition".into(),
                provider: "osv".into(),
                budget_key: budget_key.clone(),
                credential_ref: None,
                expires_at: expires,
                limits: ProviderLimits::default(),
            },
        ],
    };
    let credentials = SourceCredentialSetV1 {
        schema: "aos.assessment-source-credentials/v1".into(),
        grants: vec![SourceCredentialGrant {
            reference: "private-version-reference".into(),
            partition: "private-partition".into(),
            provider: "github-tags".into(),
            scope: SourceCredentialScope::GithubRepositories {
                repositories: vec!["private/fixture".into()],
            },
            secret_binding: "PRIVATE_SOURCE_READ_KEY".into(),
            expires_at: now.clone(),
        }],
    };
    db.register_assessment_source_status(routes.clone(), credentials.clone())?;
    let missing = db
        .assessment_source_status("public-partition", &now)
        .await?;
    assert!(missing
        .iter()
        .all(|source| source.availability == SourceAvailability::Unconfigured {}));

    db.install_assessment_source_budget(&AssessmentSourceBudget {
        key: budget_key.clone(),
        window_seconds: 86400,
        allowance: 2,
        min_interval_seconds: 6,
    })
    .await?;
    let previous_day = now.unix_seconds() / 86400 * 86400 - 86400;
    let cooldown = now.unix_seconds() + 200;
    db.backend
        .execute(
            "UPDATE assessment_source_budgets SET window_start = ?2, consumed = 2,
            next_eligible_at = ?3, circuit_until = 0 WHERE budget_key = ?1",
            &vals![budget_key, previous_day, cooldown],
        )
        .await?;
    let before = quota(&db, &budget_key).await?;
    let public = db
        .assessment_source_status("public-partition", &now)
        .await?;
    assert_eq!(
        public
            .iter()
            .map(|source| source.provider.as_str())
            .collect::<Vec<_>>(),
        SOURCE_PROFILES
    );
    assert_eq!(
        public
            .iter()
            .find(|source| source.provider == "osv")
            .context("OSV status")?
            .availability,
        SourceAvailability::Waiting {
            retry_at: Timestamp::from_unix_seconds(cooldown)?,
            cause: SourceDelayCause::SpacingOrCooldown,
        }
    );
    assert_eq!(
        public
            .iter()
            .find(|source| source.provider == "github-tags")
            .context("GitHub status")?
            .availability,
        SourceAvailability::Unconfigured {}
    );
    let encoded = serde_json::to_string(&public)?;
    for private in [
        &budget_key,
        "private-version-reference",
        "PRIVATE_SOURCE_READ_KEY",
        "private/fixture",
    ] {
        assert!(!encoded.contains(private));
    }
    assert_eq!(quota(&db, &budget_key).await?, before);
    let private = db
        .assessment_source_status("private-partition", &now)
        .await?;
    assert_eq!(
        private
            .iter()
            .find(|source| source.provider == "github-tags")
            .context("private GitHub status")?
            .availability,
        SourceAvailability::AuthorityUnavailable {}
    );
    assert!(db
        .assessment_source_status("unconfigured-partition", &now)
        .await?
        .iter()
        .all(|source| source.availability == SourceAvailability::Unconfigured {}));

    db.register_assessment_source_status(routes.clone(), credentials.clone())?;
    assert_eq!(
        db.assessment_source_status("public-partition", &now)
            .await?,
        public
    );
    let mut changed = routes;
    changed.routes[1].budget_key = "replacement-account".into();
    assert!(db
        .register_assessment_source_status(changed, credentials)
        .is_err());
    assert_eq!(
        db.assessment_source_status("public-partition", &now)
            .await?,
        public
    );
    assert_eq!(quota(&db, &budget_key).await?, before);
    Ok(())
}

async fn quota(db: &Database, key: &str) -> Result<(u64, u32, u64, u64, u64)> {
    let row = db
        .backend
        .query_opt(
            "SELECT window_start, consumed, next_eligible_at, circuit_until, resource_version
            FROM assessment_source_budgets WHERE budget_key = ?1",
            &vals![@slice key],
        )
        .await?
        .context("installed quota")?;
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}
