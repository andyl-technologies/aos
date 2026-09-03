//! Release-scoped publication admission and continuity.
//!
//! These operations turn ordinary ready registry publications into a
//! fail-closed release protocol. Each transition is an atomic `INSERT SELECT`
//! whose joins prove the complete predecessor chain inside the database.

use anyhow::{bail, Context, Result};

use crate::backend::CheckedStatement;

use super::{validate_key_bytes, Database};

/// Immutable identity admitted for one release bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReleaseBundle {
    /// SHA-256 identity of the canonical bundle inventory.
    pub bundle_digest: String,
    /// Registry containing the bundle's immutable objects.
    pub registry_id: i64,
    /// Human-facing immutable release identifier.
    pub release_id: String,
    /// SHA-256 identity of the signed release manifest.
    pub manifest_digest: String,
    /// Signed registry commit from which this release was assembled.
    pub registry_base_commit: String,
    /// Deployment allowed to issue the staging receipt.
    pub staging_deployment_id: String,
    /// Deployment allowed to issue the production receipt.
    pub production_deployment_id: String,
}

/// One environment publication of an admitted bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReleaseBundlePublication {
    /// Admitted bundle identity.
    pub bundle_digest: String,
    /// Registry repeated for same-registry enforcement.
    pub registry_id: i64,
    /// `staging` or `production`.
    pub environment: String,
    /// Ready generic registry publication proving exact uploaded bytes.
    pub publication_id: String,
    /// Deployment issuing the signed receipt.
    pub deployment_id: String,
    /// SHA-256 identity of the canonical signed receipt.
    pub receipt_digest: String,
    /// Canonical signed receipt bytes encoded as UTF-8 JSON.
    pub receipt_json: String,
    /// Exact staging receipt promoted into production.
    pub staging_receipt_digest: Option<String>,
}

/// Qualification result for the exact staged bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReleaseQualification {
    /// Admitted bundle identity.
    pub bundle_digest: String,
    /// Staging receipt whose public bytes were tested.
    pub staging_receipt_digest: String,
    /// SHA-256 identity of the canonical qualification receipt.
    pub qualification_digest: String,
    /// Canonical signed qualification receipt as UTF-8 JSON.
    pub receipt_json: String,
}

/// Completed staging-to-production promotion chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReleasePromotion {
    /// Admitted bundle identity.
    pub bundle_digest: String,
    /// Staging publication admitted for the bundle.
    pub staging_receipt_digest: String,
    /// Qualification admitted for that staging receipt.
    pub qualification_digest: String,
    /// Production publication admitted for the same bundle.
    pub production_receipt_digest: String,
}

/// One online timestamp metadata publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReleaseTimestampPublication {
    /// Registry containing the timestamp and referenced snapshot.
    pub registry_id: i64,
    /// SHA-256 identity of immutable snapshot metadata.
    pub snapshot_digest: String,
    /// Version declared by the referenced snapshot.
    pub snapshot_version: i64,
    /// Strictly increasing timestamp version.
    pub timestamp_version: i64,
    /// SHA-256 identity of canonical signed timestamp metadata.
    pub timestamp_digest: String,
    /// Ready generic publication containing the exact timestamp bytes.
    pub publication_id: String,
}

/// One compare-and-swap channel advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReleaseChannelOperation {
    /// Registry owning the channel.
    pub registry_id: i64,
    /// `edge`, `candidate`, or `stable`.
    pub channel: String,
    /// Generation the caller observed before the advance.
    pub prior_generation: i64,
    /// Inclusive rollout partition start.
    pub first_partition: i64,
    /// Inclusive rollout partition end.
    pub last_partition: i64,
    /// Release manifest selected by the channel.
    pub manifest_digest: String,
    /// Exact promoted production receipt authorizing the selection.
    pub production_receipt_digest: String,
    /// SHA-256 identity of the canonical channel operation.
    pub operation_digest: String,
    /// Canonical signed channel receipt as UTF-8 JSON.
    pub receipt_json: String,
}

impl Database {
    /// Admits an immutable release identity backed by a ready publication.
    ///
    /// Exact retries return successfully. Any reuse of a release or digest for
    /// different content is rejected by the database uniqueness constraints.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, a missing or non-ready backing
    /// publication, mismatched registry commit, conflicting replay, or storage
    /// failure.
    pub async fn admit_release_bundle(
        &self,
        input: &NewReleaseBundle,
        backing_publication_id: &str,
        now: i64,
    ) -> Result<()> {
        validate_bundle(input)?;
        validate_key_bytes(backing_publication_id, "backing publication id", 64)?;
        if self.release_bundle_matches(input).await? {
            return Ok(());
        }

        self.backend
            .checked_batch(&[CheckedStatement::exact(
                "INSERT INTO release_bundles
                   (bundle_digest, registry_id, release_id, manifest_digest,
                    registry_base_commit, staging_deployment_id,
                    production_deployment_id, created_at)
                 SELECT ?1, publication.registry_id, ?3, ?4, ?5, ?6, ?7, ?9
                   FROM registry_publications publication
                  WHERE publication.publication_id = ?8
                    AND publication.registry_id = ?2
                    AND publication.state = 'ready'
                    AND publication.default_commit = ?5",
                vals![
                    input.bundle_digest,
                    input.registry_id,
                    input.release_id,
                    input.manifest_digest,
                    input.registry_base_commit,
                    input.staging_deployment_id,
                    input.production_deployment_id,
                    backing_publication_id,
                    now
                ],
                1,
            )])
            .await
    }

    /// Records an exact staging or production publication.
    ///
    /// # Errors
    ///
    /// Returns an error unless the publication is ready, belongs to the
    /// bundle registry, uses the environment's pinned deployment, and a
    /// production publication names the bundle's exact staging receipt.
    pub async fn record_release_bundle_publication(
        &self,
        input: &NewReleaseBundlePublication,
        now: i64,
    ) -> Result<()> {
        validate_publication(input)?;
        if self.release_publication_matches(input).await? {
            return Ok(());
        }
        let expected_deployment = match input.environment.as_str() {
            "staging" => "bundle.staging_deployment_id",
            "production" => "bundle.production_deployment_id",
            _ => bail!("release publication environment is invalid"),
        };
        let predecessor = if input.environment == "staging" {
            "?8 IS NULL"
        } else {
            "?8 = (SELECT receipt_digest FROM release_bundle_publications staging WHERE staging.bundle_digest = ?1 AND staging.environment = 'staging')"
        };
        let sql = format!(
            "INSERT INTO release_bundle_publications
               (bundle_digest, registry_id, environment, publication_id,
                deployment_id, receipt_digest, receipt_json,
                staging_receipt_digest, committed_at)
             SELECT bundle.bundle_digest, bundle.registry_id, ?3, ?4, ?5, ?6,
                    ?7, ?8, ?9
               FROM release_bundles bundle
               JOIN registry_publications publication
                 ON publication.publication_id = ?4
                AND publication.registry_id = bundle.registry_id
              WHERE bundle.bundle_digest = ?1 AND bundle.registry_id = ?2
                AND publication.state = 'ready'
                AND ?5 = {expected_deployment} AND {predecessor}"
        );
        self.backend
            .checked_batch(&[CheckedStatement::exact(
                sql,
                vals![
                    input.bundle_digest,
                    input.registry_id,
                    input.environment,
                    input.publication_id,
                    input.deployment_id,
                    input.receipt_digest,
                    input.receipt_json,
                    input.staging_receipt_digest,
                    now
                ],
                1,
            )])
            .await
    }

    /// Records qualification of the exact staging receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, a staging receipt not belonging
    /// to the bundle, a conflicting retry, or storage failure.
    pub async fn record_release_qualification(
        &self,
        input: &NewReleaseQualification,
        now: i64,
    ) -> Result<()> {
        validate_qualification(input)?;
        if self.release_qualification_matches(input).await? {
            return Ok(());
        }
        self.backend
            .checked_batch(&[CheckedStatement::exact(
                "INSERT INTO release_qualifications
               (bundle_digest, staging_receipt_digest, qualification_digest,
                receipt_json, qualified_at)
             SELECT publication.bundle_digest, publication.receipt_digest,
                    ?3, ?4, ?5
               FROM release_bundle_publications publication
              WHERE publication.bundle_digest = ?1
                AND publication.environment = 'staging'
                AND publication.receipt_digest = ?2",
                vals![
                    input.bundle_digest,
                    input.staging_receipt_digest,
                    input.qualification_digest,
                    input.receipt_json,
                    now
                ],
                1,
            )])
            .await
    }

    /// Records a complete, internally continuous promotion chain.
    ///
    /// # Errors
    ///
    /// Returns an error unless staging, qualification, and production receipts
    /// all belong to the same bundle and name one another exactly.
    pub async fn record_release_promotion(
        &self,
        input: &NewReleasePromotion,
        now: i64,
    ) -> Result<()> {
        validate_promotion(input)?;
        if self.release_promotion_matches(input).await? {
            return Ok(());
        }
        self.backend
            .checked_batch(&[CheckedStatement::exact(
                "INSERT INTO release_promotions
               (bundle_digest, staging_receipt_digest, qualification_digest,
                production_receipt_digest, promoted_at)
             SELECT staging.bundle_digest, staging.receipt_digest,
                    qualification.qualification_digest, production.receipt_digest, ?5
               FROM release_bundle_publications staging
               JOIN release_qualifications qualification
                 ON qualification.bundle_digest = staging.bundle_digest
                AND qualification.staging_receipt_digest = staging.receipt_digest
               JOIN release_bundle_publications production
                 ON production.bundle_digest = staging.bundle_digest
                AND production.environment = 'production'
                AND production.staging_receipt_digest = staging.receipt_digest
              WHERE staging.bundle_digest = ?1 AND staging.environment = 'staging'
                AND staging.receipt_digest = ?2
                AND qualification.qualification_digest = ?3
                AND production.receipt_digest = ?4",
                vals![
                    input.bundle_digest,
                    input.staging_receipt_digest,
                    input.qualification_digest,
                    input.production_receipt_digest,
                    now
                ],
                1,
            )])
            .await
    }

    /// Records a strictly advancing timestamp publication.
    ///
    /// # Errors
    ///
    /// Returns an error unless the backing publication is ready and the
    /// timestamp version is exactly one greater than current state (or one for
    /// the first timestamp).
    pub async fn record_release_timestamp_publication(
        &self,
        input: &NewReleaseTimestampPublication,
        now: i64,
    ) -> Result<()> {
        validate_timestamp(input)?;
        if self.release_timestamp_matches(input).await? {
            return Ok(());
        }
        self.backend
            .checked_batch(&[CheckedStatement::exact(
                "INSERT INTO release_timestamp_publications
               (registry_id, snapshot_digest, snapshot_version,
                timestamp_version, timestamp_digest, publication_id,
                committed_at)
             SELECT publication.registry_id, ?2, ?3, ?4, ?5,
                    publication.publication_id, ?7
               FROM registry_publications publication
              WHERE publication.publication_id = ?6
                AND publication.registry_id = ?1 AND publication.state = 'ready'
                AND ?4 = COALESCE((SELECT MAX(timestamp_version) + 1
                    FROM release_timestamp_publications WHERE registry_id = ?1), 1)",
                vals![
                    input.registry_id,
                    input.snapshot_digest,
                    input.snapshot_version,
                    input.timestamp_version,
                    input.timestamp_digest,
                    input.publication_id,
                    now
                ],
                1,
            )])
            .await
    }

    /// Advances a release channel with a generation compare-and-swap.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, stale generation, a production
    /// receipt without a completed promotion, release mismatch, conflicting
    /// replay, or storage failure.
    pub async fn advance_release_channel(
        &self,
        input: &NewReleaseChannelOperation,
        now: i64,
    ) -> Result<()> {
        validate_channel(input)?;
        if self.release_channel_operation_matches(input).await? {
            return Ok(());
        }
        let new_generation = input.prior_generation + 1;
        self.backend
            .checked_batch(&[CheckedStatement::exact(
                "INSERT INTO release_channel_operations
               (registry_id, channel, prior_generation, new_generation,
                first_partition, last_partition, manifest_digest,
                production_receipt_digest, operation_digest, receipt_json,
                committed_at)
             SELECT bundle.registry_id, ?2, ?3, ?4, ?5, ?6,
                    bundle.manifest_digest, promotion.production_receipt_digest,
                    ?9, ?10, ?11
               FROM release_promotions promotion
               JOIN release_bundles bundle
                 ON bundle.bundle_digest = promotion.bundle_digest
              WHERE bundle.registry_id = ?1 AND bundle.manifest_digest = ?7
                AND promotion.production_receipt_digest = ?8
                AND ?3 = COALESCE((SELECT MAX(new_generation)
                    FROM release_channel_operations
                    WHERE registry_id = ?1 AND channel = ?2), 0)",
                vals![
                    input.registry_id,
                    input.channel,
                    input.prior_generation,
                    new_generation,
                    input.first_partition,
                    input.last_partition,
                    input.manifest_digest,
                    input.production_receipt_digest,
                    input.operation_digest,
                    input.receipt_json,
                    now
                ],
                1,
            )])
            .await
    }

    async fn release_bundle_matches(&self, input: &NewReleaseBundle) -> Result<bool> {
        let row = self
            .backend
            .query_opt(
                "SELECT registry_id, release_id, manifest_digest, registry_base_commit,
                    staging_deployment_id, production_deployment_id
               FROM release_bundles WHERE bundle_digest = ?1",
                &vals![input.bundle_digest],
            )
            .await?;
        row.map(|row| {
            Ok(row.get::<i64>(0)? == input.registry_id
                && row.get::<String>(1)? == input.release_id
                && row.get::<String>(2)? == input.manifest_digest
                && row.get::<String>(3)? == input.registry_base_commit
                && row.get::<String>(4)? == input.staging_deployment_id
                && row.get::<String>(5)? == input.production_deployment_id)
        })
        .transpose()
        .map(|matched| matched.unwrap_or(false))
    }

    async fn release_publication_matches(
        &self,
        input: &NewReleaseBundlePublication,
    ) -> Result<bool> {
        let row = self
            .backend
            .query_opt(
                "SELECT registry_id, publication_id, deployment_id, receipt_digest,
                    receipt_json, staging_receipt_digest
               FROM release_bundle_publications
              WHERE bundle_digest = ?1 AND environment = ?2",
                &vals![input.bundle_digest, input.environment],
            )
            .await?;
        row.map(|row| {
            Ok(row.get::<i64>(0)? == input.registry_id
                && row.get::<String>(1)? == input.publication_id
                && row.get::<String>(2)? == input.deployment_id
                && row.get::<String>(3)? == input.receipt_digest
                && row.get::<String>(4)? == input.receipt_json
                && row.get::<Option<String>>(5)? == input.staging_receipt_digest)
        })
        .transpose()
        .map(|matched| matched.unwrap_or(false))
    }

    async fn release_qualification_matches(&self, input: &NewReleaseQualification) -> Result<bool> {
        row_matches(&*self.backend,
            "SELECT staging_receipt_digest, qualification_digest, receipt_json FROM release_qualifications WHERE bundle_digest = ?1",
            vals![input.bundle_digest],
            [&input.staging_receipt_digest, &input.qualification_digest, &input.receipt_json]).await
    }

    async fn release_promotion_matches(&self, input: &NewReleasePromotion) -> Result<bool> {
        row_matches(&*self.backend,
            "SELECT staging_receipt_digest, qualification_digest, production_receipt_digest FROM release_promotions WHERE bundle_digest = ?1",
            vals![input.bundle_digest],
            [&input.staging_receipt_digest, &input.qualification_digest, &input.production_receipt_digest]).await
    }

    async fn release_timestamp_matches(
        &self,
        input: &NewReleaseTimestampPublication,
    ) -> Result<bool> {
        let row = self
            .backend
            .query_opt(
                "SELECT snapshot_digest, snapshot_version, timestamp_digest, publication_id
               FROM release_timestamp_publications
              WHERE registry_id = ?1 AND timestamp_version = ?2",
                &vals![input.registry_id, input.timestamp_version],
            )
            .await?;
        row.map(|row| {
            Ok(row.get::<String>(0)? == input.snapshot_digest
                && row.get::<i64>(1)? == input.snapshot_version
                && row.get::<String>(2)? == input.timestamp_digest
                && row.get::<String>(3)? == input.publication_id)
        })
        .transpose()
        .map(|matched| matched.unwrap_or(false))
    }

    async fn release_channel_operation_matches(
        &self,
        input: &NewReleaseChannelOperation,
    ) -> Result<bool> {
        let generation = input.prior_generation + 1;
        let row = self
            .backend
            .query_opt(
                "SELECT prior_generation, first_partition, last_partition,
                    manifest_digest, production_receipt_digest,
                    operation_digest, receipt_json
               FROM release_channel_operations
              WHERE registry_id = ?1 AND channel = ?2 AND new_generation = ?3",
                &vals![input.registry_id, input.channel, generation],
            )
            .await?;
        row.map(|row| {
            Ok(row.get::<i64>(0)? == input.prior_generation
                && row.get::<i64>(1)? == input.first_partition
                && row.get::<i64>(2)? == input.last_partition
                && row.get::<String>(3)? == input.manifest_digest
                && row.get::<String>(4)? == input.production_receipt_digest
                && row.get::<String>(5)? == input.operation_digest
                && row.get::<String>(6)? == input.receipt_json)
        })
        .transpose()
        .map(|matched| matched.unwrap_or(false))
    }
}

async fn row_matches<const N: usize>(
    backend: &dyn crate::backend::Backend,
    sql: &str,
    params: Vec<crate::value::Value>,
    expected: [&String; N],
) -> Result<bool> {
    let Some(row) = backend.query_opt(sql, &params).await? else {
        return Ok(false);
    };
    for (index, value) in expected.into_iter().enumerate() {
        if row
            .get::<String>(index)
            .context("reading release continuity row")?
            != *value
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_bundle(input: &NewReleaseBundle) -> Result<()> {
    if input.registry_id <= 0 {
        bail!("release bundle registry is invalid");
    }
    validate_key_bytes(&input.bundle_digest, "release bundle digest", 128)?;
    validate_key_bytes(&input.release_id, "release id", 128)?;
    validate_key_bytes(&input.manifest_digest, "release manifest digest", 128)?;
    validate_key_bytes(
        &input.registry_base_commit,
        "release registry base commit",
        128,
    )?;
    validate_key_bytes(&input.staging_deployment_id, "staging deployment id", 128)?;
    validate_key_bytes(
        &input.production_deployment_id,
        "production deployment id",
        128,
    )
}

fn validate_publication(input: &NewReleaseBundlePublication) -> Result<()> {
    if input.registry_id <= 0 || input.receipt_json.is_empty() {
        bail!("release publication is invalid");
    }
    validate_key_bytes(&input.bundle_digest, "release bundle digest", 128)?;
    validate_key_bytes(&input.publication_id, "publication id", 64)?;
    validate_key_bytes(&input.deployment_id, "deployment id", 128)?;
    validate_key_bytes(&input.receipt_digest, "publication receipt digest", 128)?;
    if let Some(digest) = input.staging_receipt_digest.as_deref() {
        validate_key_bytes(digest, "staging receipt digest", 128)?;
    }
    Ok(())
}

fn validate_qualification(input: &NewReleaseQualification) -> Result<()> {
    if input.receipt_json.is_empty() {
        bail!("release qualification receipt is empty");
    }
    validate_key_bytes(&input.bundle_digest, "release bundle digest", 128)?;
    validate_key_bytes(&input.staging_receipt_digest, "staging receipt digest", 128)?;
    validate_key_bytes(&input.qualification_digest, "qualification digest", 128)
}

fn validate_promotion(input: &NewReleasePromotion) -> Result<()> {
    validate_key_bytes(&input.bundle_digest, "release bundle digest", 128)?;
    validate_key_bytes(&input.staging_receipt_digest, "staging receipt digest", 128)?;
    validate_key_bytes(&input.qualification_digest, "qualification digest", 128)?;
    validate_key_bytes(
        &input.production_receipt_digest,
        "production receipt digest",
        128,
    )
}

fn validate_timestamp(input: &NewReleaseTimestampPublication) -> Result<()> {
    if input.registry_id <= 0 || input.snapshot_version <= 0 || input.timestamp_version <= 0 {
        bail!("release timestamp publication is invalid");
    }
    validate_key_bytes(&input.snapshot_digest, "snapshot digest", 128)?;
    validate_key_bytes(&input.timestamp_digest, "timestamp digest", 128)?;
    validate_key_bytes(&input.publication_id, "publication id", 64)
}

fn validate_channel(input: &NewReleaseChannelOperation) -> Result<()> {
    if input.registry_id <= 0
        || input.prior_generation < 0
        || input.first_partition < 0
        || input.first_partition > input.last_partition
        || input.last_partition > 255
        || input.receipt_json.is_empty()
    {
        bail!("release channel operation is invalid");
    }
    if !matches!(input.channel.as_str(), "edge" | "candidate" | "stable") {
        bail!("release channel is invalid");
    }
    validate_key_bytes(&input.manifest_digest, "release manifest digest", 128)?;
    validate_key_bytes(
        &input.production_receipt_digest,
        "production receipt digest",
        128,
    )?;
    validate_key_bytes(&input.operation_digest, "channel operation digest", 128)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::db::{NewRegistryPublication, RegistryPublicationRecord};

    async fn ready_publication(
        db: &Database,
        registry_id: i64,
        publication_id: &str,
        generation: &str,
        manifest_digest: char,
        commit: &str,
    ) -> RegistryPublicationRecord {
        db.create_registry_publication(&NewRegistryPublication {
            publication_id: publication_id.into(),
            registry_id,
            generation: generation.into(),
            manifest_digest: manifest_digest.to_string().repeat(64),
            refs_digest: "f".repeat(64),
            default_commit: Some(commit.into()),
            parent_publication_id: None,
        })
        .await
        .unwrap();
        db.backend
            .execute(
                "UPDATE registry_publications SET state = 'ready', completed_at = ?2
                 WHERE publication_id = ?1",
                &vals![publication_id, 10_i64],
            )
            .await
            .unwrap();
        db.registry_publication(publication_id)
            .await
            .unwrap()
            .unwrap()
    }

    fn bundle(registry_id: i64) -> NewReleaseBundle {
        NewReleaseBundle {
            bundle_digest: "a".repeat(64),
            registry_id,
            release_id: "2026.03.0".into(),
            manifest_digest: "b".repeat(64),
            registry_base_commit: "c".repeat(64),
            staging_deployment_id: "staging-deployment".into(),
            production_deployment_id: "production-deployment".into(),
        }
    }

    #[tokio::test]
    async fn exact_release_chain_is_idempotent_and_channel_is_cas() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db
            .register_registry("release-chain", &[], false)
            .await
            .unwrap();
        ready_publication(
            &db,
            registry_id,
            "release-source",
            "source-generation",
            '1',
            &"c".repeat(64),
        )
        .await;
        let bundle = bundle(registry_id);
        db.admit_release_bundle(&bundle, "release-source", 11)
            .await
            .unwrap();
        db.admit_release_bundle(&bundle, "release-source", 11)
            .await
            .unwrap();

        ready_publication(
            &db,
            registry_id,
            "release-staging",
            "staging-generation",
            '2',
            &"d".repeat(64),
        )
        .await;
        let staging = NewReleaseBundlePublication {
            bundle_digest: bundle.bundle_digest.clone(),
            registry_id,
            environment: "staging".into(),
            publication_id: "release-staging".into(),
            deployment_id: "staging-deployment".into(),
            receipt_digest: "3".repeat(64),
            receipt_json: "{\"environment\":\"staging\"}".into(),
            staging_receipt_digest: None,
        };
        db.record_release_bundle_publication(&staging, 12)
            .await
            .unwrap();
        db.record_release_bundle_publication(&staging, 12)
            .await
            .unwrap();

        let qualification = NewReleaseQualification {
            bundle_digest: bundle.bundle_digest.clone(),
            staging_receipt_digest: "3".repeat(64),
            qualification_digest: "4".repeat(64),
            receipt_json: "{\"qualified\":true}".into(),
        };
        db.record_release_qualification(&qualification, 13)
            .await
            .unwrap();
        ready_publication(
            &db,
            registry_id,
            "release-production",
            "production-generation",
            '5',
            &"e".repeat(64),
        )
        .await;
        let production = NewReleaseBundlePublication {
            bundle_digest: bundle.bundle_digest.clone(),
            registry_id,
            environment: "production".into(),
            publication_id: "release-production".into(),
            deployment_id: "production-deployment".into(),
            receipt_digest: "6".repeat(64),
            receipt_json: "{\"environment\":\"production\"}".into(),
            staging_receipt_digest: Some("3".repeat(64)),
        };
        db.record_release_bundle_publication(&production, 14)
            .await
            .unwrap();
        let promotion = NewReleasePromotion {
            bundle_digest: bundle.bundle_digest.clone(),
            staging_receipt_digest: "3".repeat(64),
            qualification_digest: "4".repeat(64),
            production_receipt_digest: "6".repeat(64),
        };
        db.record_release_promotion(&promotion, 15).await.unwrap();

        let edge = NewReleaseChannelOperation {
            registry_id,
            channel: "edge".into(),
            prior_generation: 0,
            first_partition: 0,
            last_partition: 31,
            manifest_digest: bundle.manifest_digest.clone(),
            production_receipt_digest: "6".repeat(64),
            operation_digest: "7".repeat(64),
            receipt_json: "{\"generation\":1}".into(),
        };
        db.advance_release_channel(&edge, 16).await.unwrap();
        db.advance_release_channel(&edge, 16).await.unwrap();
        let mut stale = edge.clone();
        stale.operation_digest = "8".repeat(64);
        assert!(db.advance_release_channel(&stale, 17).await.is_err());
    }

    #[tokio::test]
    async fn release_chain_rejects_wrong_deployment_and_discontinuous_promotion() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db
            .register_registry("release-reject", &[], false)
            .await
            .unwrap();
        ready_publication(
            &db,
            registry_id,
            "reject-source",
            "reject-source-generation",
            '1',
            &"c".repeat(64),
        )
        .await;
        let bundle = bundle(registry_id);
        db.admit_release_bundle(&bundle, "reject-source", 11)
            .await
            .unwrap();
        ready_publication(
            &db,
            registry_id,
            "reject-staging",
            "reject-staging-generation",
            '2',
            &"d".repeat(64),
        )
        .await;
        let wrong = NewReleaseBundlePublication {
            bundle_digest: bundle.bundle_digest.clone(),
            registry_id,
            environment: "staging".into(),
            publication_id: "reject-staging".into(),
            deployment_id: "production-deployment".into(),
            receipt_digest: "3".repeat(64),
            receipt_json: "{}".into(),
            staging_receipt_digest: None,
        };
        assert!(db
            .record_release_bundle_publication(&wrong, 12)
            .await
            .is_err());
        let promotion = NewReleasePromotion {
            bundle_digest: bundle.bundle_digest,
            staging_receipt_digest: "3".repeat(64),
            qualification_digest: "4".repeat(64),
            production_receipt_digest: "5".repeat(64),
        };
        assert!(db.record_release_promotion(&promotion, 13).await.is_err());
    }

    #[tokio::test]
    async fn timestamp_versions_advance_exactly_once() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db
            .register_registry("release-timestamp", &[], false)
            .await
            .unwrap();
        ready_publication(
            &db,
            registry_id,
            "timestamp-one",
            "timestamp-generation-one",
            '1',
            &"c".repeat(64),
        )
        .await;
        let first = NewReleaseTimestampPublication {
            registry_id,
            snapshot_digest: "2".repeat(64),
            snapshot_version: 1,
            timestamp_version: 1,
            timestamp_digest: "3".repeat(64),
            publication_id: "timestamp-one".into(),
        };
        db.record_release_timestamp_publication(&first, 11)
            .await
            .unwrap();
        db.record_release_timestamp_publication(&first, 11)
            .await
            .unwrap();
        ready_publication(
            &db,
            registry_id,
            "timestamp-three",
            "timestamp-generation-three",
            '4',
            &"d".repeat(64),
        )
        .await;
        let skipped = NewReleaseTimestampPublication {
            registry_id,
            snapshot_digest: "5".repeat(64),
            snapshot_version: 2,
            timestamp_version: 3,
            timestamp_digest: "6".repeat(64),
            publication_id: "timestamp-three".into(),
        };
        assert!(db
            .record_release_timestamp_publication(&skipped, 12)
            .await
            .is_err());
    }
}
