//! Conditional cache selection uses admitted exact operation metadata in SQL.

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::{Context as _, Result};
use aos_assessment::observation::HttpValidators;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::ports::{Clock, EvidenceStore};
use aos_assessment_runtime::provider::*;
use aos_contract::Sha256Digest;

use crate::db::Database;

struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Result<Timestamp> {
        Ok(self.0.clone())
    }
}

#[derive(Default)]
struct Custody(Mutex<BTreeMap<Sha256Digest, Vec<u8>>>);

#[async_trait::async_trait]
impl EvidenceStore for Custody {
    async fn retain(&self, _: &str, bytes: &[u8]) -> Result<Sha256Digest> {
        let digest = Sha256Digest::of_bytes(bytes);
        self.0
            .lock()
            .expect("fixture custody")
            .insert(digest, bytes.to_vec());
        Ok(digest)
    }

    async fn read(&self, _: &str, digest: Sha256Digest, limit: u64) -> Result<Vec<u8>> {
        let bytes = self
            .0
            .lock()
            .expect("fixture custody")
            .get(&digest)
            .cloned()
            .context("raw custody")?;
        anyhow::ensure!(bytes.len() as u64 <= limit, "fixture evidence bound");
        Ok(bytes)
    }
}

struct Source;

#[async_trait::async_trait]
impl SourceTransport for Source {
    async fn fetch(&self, _: &ProviderWorkPlanV1, _: &SourceRequest) -> Result<SourceResponse> {
        Ok(SourceResponse {
            status: 200,
            body: b"[]".to_vec(),
            transferred_bytes: 2,
            validators: Some(HttpValidators {
                etag: Some("exact-source-etag".into()),
                last_modified: None,
            }),
            throttle: Default::default(),
        })
    }
}

#[tokio::test]
async fn conditional_observation_is_exact_scoped_and_requires_admitted_custody() -> Result<()> {
    cache_case(Database::open_in_memory().await?).await
}

#[tokio::test]
#[cfg(feature = "postgres")]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to disposable PostgreSQL"]
async fn conditional_observation_is_exact_scoped_on_postgresql() -> Result<()> {
    let path =
        std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE").context("disposable PostgreSQL URL file")?;
    let url = std::fs::read_to_string(path)?;
    let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
    cache_case(Database::with_backend(Box::new(backend)).await?).await
}

async fn cache_case(db: Database) -> Result<()> {
    let operation = ProviderOperation::ObserveReleases {
        repository: "example/fixture".into(),
        tag_prefix: "v".into(),
        page: 1,
    };
    let (db, registry_id, plan) =
        super::provider_state_tests::planned_database(db, operation).await?;
    let partition = &plan.authorization_partition;
    assert!(db
        .assessment_conditional_response(partition, &plan.operation, &plan.issued_at, 1024)
        .await?
        .is_none());
    db.admit_assessment_provider_plan(registry_id, &plan)
        .await?;
    let result = execute_source(
        &Source,
        &Custody::default(),
        &FixedClock(plan.issued_at.clone()),
        &plan,
        "fixture/v1",
        3600,
    )
    .await?;
    // Retention alone is not an observation head. Only checked admission creates
    // a conditional cache locator for this exact query and partition.
    assert!(db
        .assessment_conditional_response(partition, &plan.operation, &plan.issued_at, 1024)
        .await?
        .is_none());
    db.admit_assessment_provider_result(registry_id, &plan, &result)
        .await?;
    let cache = db
        .assessment_conditional_response(partition, &plan.operation, &plan.issued_at, 1024)
        .await?
        .context("admitted conditional cache")?;
    assert_eq!(cache.evidence.digest, Sha256Digest::of_bytes(b"[]"));
    assert_eq!(cache.evidence.byte_length, 2);
    assert_eq!(cache.validators.etag.as_deref(), Some("exact-source-etag"));
    assert!(db
        .assessment_conditional_response("other-partition", &plan.operation, &plan.issued_at, 1024)
        .await?
        .is_none());
    assert!(db
        .assessment_conditional_response(partition, &plan.operation, &plan.issued_at, 1)
        .await?
        .is_none());
    let earlier = Timestamp::from_unix_seconds(plan.issued_at.unix_seconds() - 1)?;
    assert!(db
        .assessment_conditional_response(partition, &plan.operation, &earlier, 1024)
        .await
        .is_err());
    let other_page = ProviderOperation::ObserveReleases {
        repository: "example/fixture".into(),
        tag_prefix: "v".into(),
        page: 2,
    };
    assert!(db
        .assessment_conditional_response(partition, &other_page, &plan.issued_at, 1024)
        .await?
        .is_none());
    let other_prefix = ProviderOperation::ObserveReleases {
        repository: "example/fixture".into(),
        tag_prefix: "release-".into(),
        page: 1,
    };
    assert!(db
        .assessment_conditional_response(partition, &other_prefix, &plan.issued_at, 1024)
        .await?
        .is_none());
    db.admit_assessment_provider_result(registry_id, &plan, &result)
        .await?;
    assert_eq!(
        db.assessment_conditional_response(partition, &plan.operation, &plan.issued_at, 1024)
            .await?,
        Some(cache)
    );
    Ok(())
}
