//! Release-scoped publication admission and continuity.
//!
//! These operations turn ordinary ready registry publications into a
//! fail-closed release protocol. Each transition is an atomic `INSERT SELECT`
//! whose joins prove the complete predecessor chain inside the database.
//!
//! # Channel advances
//!
//! A channel advance is a generation compare-and-swap over one partition
//! range. The evidence that authorizes it depends on which of the bundle's
//! pinned deployments executes the advance:
//!
//! ```text
//! executing deployment             required evidence
//! bundle.production_deployment_id  release_promotions row for the receipt
//! bundle.staging_deployment_id     committed staging publication receipt
//!   (only when it differs from production)
//! any other deployment             rejected
//! ```
//!
//! Channel names are a kind (`edge`, `candidate`, `stable`) with an optional
//! per-train suffix; see [`is_release_channel_name`].

use anyhow::{Context, Result, bail};
use aos_release::digest::Sha256Digest;

use crate::backend::CheckedStatement;

use super::{Database, validate_key_bytes};

/// Builds the timestamp continuity guard shared by staged and ordinary publication.
pub(super) fn timestamp_publication_admission(
    input: &NewReleaseTimestampPublication,
    now: i64,
) -> Result<CheckedStatement> {
    validate_timestamp(input)?;
    Ok(CheckedStatement::exact(
        "INSERT INTO release_timestamp_publications
               (registry_id, snapshot_digest, snapshot_version,
                timestamp_version, timestamp_digest, publication_id,
                committed_at)
                 SELECT publication.registry_id, ?2, ?3, ?4, ?5,
                    publication.publication_id, ?7
               FROM registry_publications publication
              WHERE publication.publication_id = ?6
                AND publication.registry_id = ?1
                AND publication.state IN ('preparing', 'writing_pointers', 'ready')
                AND EXISTS (SELECT 1 FROM registry_publication_objects declared
                    JOIN surface_objects object ON object.id = declared.surface_object_id
                   WHERE declared.publication_id = publication.publication_id
                     AND object.object_key = ?8
                     AND declared.object_kind = 'mutable_pointer'
                     AND ('sha256:' || declared.expected_hash) = ?5)
                AND EXISTS (SELECT 1 FROM registry_publication_objects declared
                    JOIN surface_objects object ON object.id = declared.surface_object_id
                   WHERE declared.publication_id = publication.publication_id
                     AND object.object_key = ?9
                     AND declared.object_kind = 'immutable'
                     AND ('sha256:' || declared.expected_hash) = ?2)
                AND ?4 = COALESCE((SELECT MAX(timestamp_version) + 1
                    FROM release_timestamp_publications WHERE registry_id = ?1), 1)",
        vals![
            input.registry_id,
            input.snapshot_digest,
            input.snapshot_version,
            input.timestamp_version,
            input.timestamp_digest,
            input.publication_id,
            now,
            input.timestamp_path,
            input.snapshot_path
        ],
        1,
    ))
}

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

/// Persisted immutable release identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseBundleRecord {
    /// Bundle digest.
    pub bundle_digest: String,
    /// Owning registry id.
    pub registry_id: i64,
    /// Immutable release id.
    pub release_id: String,
    /// Signed release-manifest digest.
    pub manifest_digest: String,
    /// Frozen registry base commit.
    pub registry_base_commit: String,
    /// Expected staging deployment.
    pub staging_deployment_id: String,
    /// Expected production deployment.
    pub production_deployment_id: String,
}

/// Persisted environment-signed publication receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseBundlePublicationRecord {
    /// Bundle digest.
    pub bundle_digest: String,
    /// Owning registry id.
    pub registry_id: i64,
    /// `staging` or `production`.
    pub environment: String,
    /// Generic registry publication id.
    pub publication_id: String,
    /// Deployment that issued the receipt.
    pub deployment_id: String,
    /// Receipt digest.
    pub receipt_digest: String,
    /// Canonical signed receipt JSON.
    pub receipt_json: String,
    /// Exact staging predecessor for production.
    pub staging_receipt_digest: Option<String>,
    /// Commit time as Unix seconds.
    pub committed_at: i64,
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
    /// Canonical signed staging receipt imported across environments.
    pub staging_receipt_json: String,
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
    /// Mutable surface path containing the exact timestamp bytes.
    pub timestamp_path: String,
    /// Immutable surface path containing the exact snapshot bytes.
    pub snapshot_path: String,
}

/// One compare-and-swap channel advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReleaseChannelOperation {
    /// Registry owning the channel.
    pub registry_id: i64,
    /// Deployment executing the advance; selects the authorizing evidence.
    pub deployment_id: String,
    /// Channel name accepted by [`is_release_channel_name`].
    pub channel: String,
    /// Generation the caller observed before the advance.
    pub prior_generation: i64,
    /// Inclusive rollout partition start.
    pub first_partition: i64,
    /// Inclusive rollout partition end.
    pub last_partition: i64,
    /// Release manifest selected by the channel.
    pub manifest_digest: String,
    /// This deployment's publication receipt authorizing the selection.
    ///
    /// On the production deployment this is the promoted production receipt;
    /// on the staging deployment it is the committed staging receipt. The
    /// signed channel receipt carries it as `publication_receipt_digest`.
    pub publication_receipt_digest: String,
    /// SHA-256 identity of the canonical channel operation.
    pub operation_digest: String,
    /// Canonical signed channel receipt as UTF-8 JSON.
    pub receipt_json: String,
}

/// Persisted compare-and-swap channel operation and signed receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseChannelOperationRecord {
    /// Expected prior generation.
    pub prior_generation: i64,
    /// Inclusive first changed partition.
    pub first_partition: i64,
    /// Inclusive final changed partition.
    pub last_partition: i64,
    /// Release manifest selected by the operation.
    pub manifest_digest: String,
    /// Publication receipt of the deployment that authorized the operation.
    pub publication_receipt_digest: String,
    /// Digest of the signed channel receipt.
    pub operation_digest: String,
    /// Canonical signed channel receipt.
    pub receipt_json: String,
}

/// SQL predicate proving that deployment `?5` may advance a channel to the
/// bundle aliased `bundle` using receipt `?4`.
///
/// The production deployment needs a completed promotion whose production
/// receipt is `?4`. The staging deployment needs its own committed staging
/// receipt `?4`, and qualifies only when it is distinct from the production
/// deployment: a shared deployment serves production consumers, so it keeps
/// the promotion requirement and fails closed on staging-only evidence.
const CHANNEL_ADVANCE_EVIDENCE: &str = "(
      (?5 = bundle.production_deployment_id
       AND EXISTS (SELECT 1 FROM release_promotions promotion
            WHERE promotion.bundle_digest = bundle.bundle_digest
              AND promotion.production_receipt_digest = ?4))
   OR (?5 = bundle.staging_deployment_id
       AND ?5 <> bundle.production_deployment_id
       AND EXISTS (SELECT 1 FROM release_bundle_publications staging
            WHERE staging.bundle_digest = bundle.bundle_digest
              AND staging.environment = 'staging'
              AND staging.deployment_id = ?5
              AND staging.receipt_digest = ?4)))";

/// Reports whether `name` is a release channel the Hub may advance.
///
/// A channel name is a kind, `edge`, `candidate`, or `stable`, optionally
/// followed by a per-train suffix:
///
/// ```text
/// ^(edge|candidate|stable)(-[0-9]{4}\.[0-9]{1,2})?$
/// ```
///
/// The suffix must also be a canonical calendar train: a year without a
/// leading zero and a month in `1..=12` without a leading zero. One train
/// therefore has exactly one channel name, so two spellings can never hold
/// independent generation histories.
///
/// # Examples
///
/// ```
/// use aos_hub_core::db::is_release_channel_name;
///
/// assert!(is_release_channel_name("stable"));
/// assert!(is_release_channel_name("stable-2026.3"));
/// assert!(!is_release_channel_name("stable-2026.13"));
/// assert!(!is_release_channel_name("nightly"));
/// ```
#[must_use]
pub fn is_release_channel_name(name: &str) -> bool {
    let (kind, train) = match name.split_once('-') {
        Some((kind, train)) => (kind, Some(train)),
        None => (name, None),
    };
    matches!(kind, "edge" | "candidate" | "stable") && train.is_none_or(is_release_train)
}

/// Accepts a canonical `YYYY.M` or `YYYY.MM` train suffix.
fn is_release_train(train: &str) -> bool {
    let Some((year, month)) = train.split_once('.') else {
        return false;
    };
    let canonical_digits = |digits: &str| {
        !digits.is_empty()
            && digits.bytes().all(|byte| byte.is_ascii_digit())
            && !digits.starts_with('0')
    };

    let year_is_valid = year.len() == 4 && canonical_digits(year);
    let month_is_valid = matches!(month.len(), 1 | 2)
        && canonical_digits(month)
        && month.parse::<u8>().is_ok_and(|month| month <= 12);
    year_is_valid && month_is_valid
}

impl Database {
    /// Returns an admitted release bundle.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, persisted-data corruption, or
    /// storage failure.
    pub async fn release_bundle(&self, bundle_digest: &str) -> Result<Option<ReleaseBundleRecord>> {
        validate_key_bytes(bundle_digest, "release bundle digest", 128)?;
        self.backend
            .query_opt(
                "SELECT bundle_digest, registry_id, release_id, manifest_digest,
                    registry_base_commit, staging_deployment_id,
                    production_deployment_id
               FROM release_bundles WHERE bundle_digest = ?1",
                &vals![bundle_digest],
            )
            .await?
            .map(|row| {
                Ok(ReleaseBundleRecord {
                    bundle_digest: row.get(0)?,
                    registry_id: row.get(1)?,
                    release_id: row.get(2)?,
                    manifest_digest: row.get(3)?,
                    registry_base_commit: row.get(4)?,
                    staging_deployment_id: row.get(5)?,
                    production_deployment_id: row.get(6)?,
                })
            })
            .transpose()
    }

    /// Returns one bundle's receipt for an isolated environment.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity or environment, persisted-data
    /// corruption, or storage failure.
    pub async fn release_bundle_publication(
        &self,
        bundle_digest: &str,
        environment: &str,
    ) -> Result<Option<ReleaseBundlePublicationRecord>> {
        validate_key_bytes(bundle_digest, "release bundle digest", 128)?;
        if !matches!(environment, "staging" | "production") {
            bail!("release publication environment is invalid");
        }
        self.backend
            .query_opt(
                "SELECT bundle_digest, registry_id, environment, publication_id,
                    deployment_id, receipt_digest, receipt_json,
                    staging_receipt_digest, committed_at
               FROM release_bundle_publications
              WHERE bundle_digest = ?1 AND environment = ?2",
                &vals![bundle_digest, environment],
            )
            .await?
            .map(|row| {
                Ok(ReleaseBundlePublicationRecord {
                    bundle_digest: row.get(0)?,
                    registry_id: row.get(1)?,
                    environment: row.get(2)?,
                    publication_id: row.get(3)?,
                    deployment_id: row.get(4)?,
                    receipt_digest: row.get(5)?,
                    receipt_json: row.get(6)?,
                    staging_receipt_digest: row.get(7)?,
                    committed_at: row.get(8)?,
                })
            })
            .transpose()
    }

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

    /// Records an exact staging publication.
    ///
    /// # Errors
    ///
    /// Returns an error unless the publication is ready, belongs to the
    /// bundle registry, and uses the pinned staging deployment.
    pub async fn record_release_bundle_publication(
        &self,
        input: &NewReleaseBundlePublication,
        now: i64,
    ) -> Result<()> {
        validate_publication(input)?;
        if self.release_publication_matches(input).await? {
            return Ok(());
        }
        if input.environment != "staging" || input.staging_receipt_digest.is_some() {
            bail!("release publication admission is staging-only");
        }
        let sql = "INSERT INTO release_bundle_publications
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
                AND ?5 = bundle.staging_deployment_id AND ?8 IS NULL";
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
               (bundle_digest, staging_receipt_digest, staging_receipt_json,
                qualification_digest, receipt_json, qualified_at)
             SELECT publication.bundle_digest, publication.receipt_digest,
                    publication.receipt_json, ?3, ?4, ?5
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

    /// Imports already-verified staging and qualification evidence.
    ///
    /// Isolated production has no local staging publication. Its service layer
    /// verifies both public envelopes before calling this operation.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed evidence, conflicting replay, a missing
    /// bundle, or storage failure.
    pub async fn import_release_qualification(
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
               (bundle_digest, staging_receipt_digest, staging_receipt_json,
                qualification_digest, receipt_json, qualified_at)
             SELECT bundle_digest, ?2, ?3, ?4, ?5, ?6
               FROM release_bundles WHERE bundle_digest = ?1",
                vals![
                    input.bundle_digest,
                    input.staging_receipt_digest,
                    input.staging_receipt_json,
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

    /// Atomically admits production and its complete promotion chain.
    ///
    /// # Errors
    ///
    /// Returns an error unless the production publication, deployment,
    /// staging receipt, and qualification all match the same bundle exactly.
    pub async fn promote_release_bundle(
        &self,
        publication: &NewReleaseBundlePublication,
        promotion: &NewReleasePromotion,
        now: i64,
    ) -> Result<()> {
        validate_publication(publication)?;
        validate_promotion(promotion)?;
        if publication.environment != "production"
            || publication.bundle_digest != promotion.bundle_digest
            || publication.staging_receipt_digest.as_deref()
                != Some(promotion.staging_receipt_digest.as_str())
        {
            bail!("production publication and promotion do not match");
        }
        if self.release_publication_matches(publication).await?
            && self.release_promotion_matches(promotion).await?
        {
            return Ok(());
        }
        self.backend
            .checked_batch(&[
                CheckedStatement::exact(
                    "INSERT INTO release_bundle_publications
                   (bundle_digest, registry_id, environment, publication_id,
                    deployment_id, receipt_digest, receipt_json,
                    staging_receipt_digest, committed_at)
                 SELECT bundle.bundle_digest, bundle.registry_id, 'production',
                        ?4, ?5, ?6, ?7, ?8, ?9
                   FROM release_bundles bundle
                   JOIN registry_publications publication
                     ON publication.publication_id = ?4
                    AND publication.registry_id = bundle.registry_id
                   JOIN release_qualifications qualification
                     ON qualification.bundle_digest = bundle.bundle_digest
                    AND qualification.staging_receipt_digest = ?8
                    AND qualification.qualification_digest = ?10
                  WHERE bundle.bundle_digest = ?1 AND bundle.registry_id = ?2
                    AND publication.state = 'ready'
                    AND ?5 = bundle.production_deployment_id",
                    vals![
                        publication.bundle_digest,
                        publication.registry_id,
                        publication.environment,
                        publication.publication_id,
                        publication.deployment_id,
                        publication.receipt_digest,
                        publication.receipt_json,
                        publication.staging_receipt_digest,
                        now,
                        promotion.qualification_digest
                    ],
                    1,
                ),
                CheckedStatement::exact(
                    "INSERT INTO release_promotions
                   (bundle_digest, staging_receipt_digest, qualification_digest,
                    production_receipt_digest, promoted_at)
                 SELECT ?1, ?2, ?3, ?4, ?5
                  WHERE EXISTS (SELECT 1 FROM release_bundle_publications production
                    WHERE production.bundle_digest = ?1 AND production.environment = 'production'
                      AND production.receipt_digest = ?4
                      AND production.staging_receipt_digest = ?2)",
                    vals![
                        promotion.bundle_digest,
                        promotion.staging_receipt_digest,
                        promotion.qualification_digest,
                        promotion.production_receipt_digest,
                        now
                    ],
                    1,
                ),
            ])
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
            .checked_batch(&[timestamp_publication_admission(input, now)?])
            .await
    }

    /// Advances a release channel with a generation compare-and-swap.
    ///
    /// The operation, the channel frontier, and every partition in the range
    /// are written in one checked batch. Each statement independently proves
    /// that `input.deployment_id` holds the evidence described in the module
    /// documentation, so no partial projection can survive a rejected advance.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, stale generation, a deployment
    /// that is neither of the bundle's pinned deployments, a receipt that is
    /// not this deployment's authorizing evidence (a production receipt without
    /// a completed promotion, or a missing staging commit), release mismatch,
    /// conflicting replay, or storage failure.
    pub async fn advance_release_channel(
        &self,
        input: &NewReleaseChannelOperation,
        now: i64,
    ) -> Result<()> {
        validate_channel(input)?;
        if self.release_channel_operation_matches(input).await? {
            if self.release_channel_projection_matches(input).await? {
                return Ok(());
            }
            bail!("release channel evidence exists but its public projection differs");
        }

        // Every statement binds ?1 registry, ?2 channel, ?3 manifest,
        // ?4 authorizing receipt, and ?5 executing deployment so that the
        // shared evidence predicate reads the same parameters everywhere.
        let new_generation = input.prior_generation + 1;
        let mut statements = vec![CheckedStatement::exact(
            format!(
                "INSERT INTO release_channel_advances
                   (registry_id, channel, prior_generation, new_generation,
                    first_partition, last_partition, manifest_digest,
                    publication_receipt_digest, operation_digest, receipt_json,
                    committed_at)
                 SELECT bundle.registry_id, ?2, ?6, ?7, ?8, ?9,
                        bundle.manifest_digest, ?4, ?10, ?11, ?12
                   FROM release_bundles bundle
                  WHERE bundle.registry_id = ?1 AND bundle.manifest_digest = ?3
                    AND {CHANNEL_ADVANCE_EVIDENCE}
                    AND ?6 = COALESCE((SELECT MAX(new_generation)
                        FROM release_channel_advances
                        WHERE registry_id = ?1 AND channel = ?2), 0)"
            ),
            vals![
                input.registry_id,
                input.channel,
                input.manifest_digest,
                input.publication_receipt_digest,
                input.deployment_id,
                input.prior_generation,
                new_generation,
                input.first_partition,
                input.last_partition,
                input.operation_digest,
                input.receipt_json,
                now
            ],
            1,
        )];
        statements.push(CheckedStatement::exact(
            format!(
                "UPDATE channels
                    SET frontier = (SELECT release_id FROM release_bundles
                        WHERE registry_id = ?1 AND manifest_digest = ?3), active = 1
                  WHERE registry_id = ?1 AND name = ?2
                    AND EXISTS (SELECT 1 FROM release_bundles bundle
                       WHERE bundle.registry_id = ?1 AND bundle.manifest_digest = ?3
                         AND {CHANNEL_ADVANCE_EVIDENCE})"
            ),
            vals![
                input.registry_id,
                input.channel,
                input.manifest_digest,
                input.publication_receipt_digest,
                input.deployment_id
            ],
            1,
        ));
        for bucket in input.first_partition..=input.last_partition {
            statements.push(CheckedStatement::exact(
                format!(
                    "INSERT INTO channel_partitions (channel_id, bucket, release)
                     SELECT channel.id, ?6, bundle.release_id
                       FROM channels channel
                       JOIN release_bundles bundle
                         ON bundle.registry_id = channel.registry_id
                        AND bundle.manifest_digest = ?3
                      WHERE channel.registry_id = ?1 AND channel.name = ?2
                        AND {CHANNEL_ADVANCE_EVIDENCE}
                     ON CONFLICT(channel_id, bucket) DO UPDATE SET release = excluded.release"
                ),
                vals![
                    input.registry_id,
                    input.channel,
                    input.manifest_digest,
                    input.publication_receipt_digest,
                    input.deployment_id,
                    bucket
                ],
                1,
            ));
        }
        self.backend.checked_batch(&statements).await
    }

    /// Returns a persisted channel operation at one exact new generation.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, invalid generation, corrupt
    /// persisted values, or storage failure.
    pub async fn release_channel_operation(
        &self,
        registry_id: i64,
        channel: &str,
        new_generation: i64,
    ) -> Result<Option<ReleaseChannelOperationRecord>> {
        if registry_id <= 0 || new_generation <= 0 || !is_release_channel_name(channel) {
            bail!("release channel operation identity is invalid");
        }
        self.backend
            .query_opt(
                "SELECT prior_generation, first_partition, last_partition,
                        manifest_digest, publication_receipt_digest,
                        operation_digest, receipt_json
                   FROM release_channel_advances
                  WHERE registry_id = ?1 AND channel = ?2 AND new_generation = ?3",
                &vals![registry_id, channel, new_generation],
            )
            .await?
            .map(|row| {
                Ok(ReleaseChannelOperationRecord {
                    prior_generation: row.get(0)?,
                    first_partition: row.get(1)?,
                    last_partition: row.get(2)?,
                    manifest_digest: row.get(3)?,
                    publication_receipt_digest: row.get(4)?,
                    operation_digest: row.get(5)?,
                    receipt_json: row.get(6)?,
                })
            })
            .transpose()
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
            "SELECT staging_receipt_digest, staging_receipt_json, qualification_digest, receipt_json FROM release_qualifications WHERE bundle_digest = ?1",
            vals![input.bundle_digest],
            [&input.staging_receipt_digest, &input.staging_receipt_json,
                &input.qualification_digest, &input.receipt_json]).await
    }

    async fn release_promotion_matches(&self, input: &NewReleasePromotion) -> Result<bool> {
        row_matches(&*self.backend,
            "SELECT staging_receipt_digest, qualification_digest, production_receipt_digest FROM release_promotions WHERE bundle_digest = ?1",
            vals![input.bundle_digest],
            [&input.staging_receipt_digest, &input.qualification_digest, &input.production_receipt_digest]).await
    }

    pub(super) async fn release_timestamp_matches(
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
                    manifest_digest, publication_receipt_digest,
                    operation_digest, receipt_json
               FROM release_channel_advances
              WHERE registry_id = ?1 AND channel = ?2 AND new_generation = ?3",
                &vals![input.registry_id, input.channel, generation],
            )
            .await?;
        row.map(|row| {
            Ok(row.get::<i64>(0)? == input.prior_generation
                && row.get::<i64>(1)? == input.first_partition
                && row.get::<i64>(2)? == input.last_partition
                && row.get::<String>(3)? == input.manifest_digest
                && row.get::<String>(4)? == input.publication_receipt_digest
                && row.get::<String>(5)? == input.operation_digest
                && row.get::<String>(6)? == input.receipt_json)
        })
        .transpose()
        .map(|matched| matched.unwrap_or(false))
    }

    /// Checks that persisted channel evidence still matches public partitions.
    ///
    /// # Errors
    ///
    /// Returns an error when persisted values are corrupt or storage fails.
    pub(crate) async fn release_channel_projection_matches(
        &self,
        input: &NewReleaseChannelOperation,
    ) -> Result<bool> {
        let expected = input.last_partition - input.first_partition + 1;
        let row = self
            .backend
            .query_opt(
                "SELECT channel.frontier, COUNT(partition.bucket)
                   FROM channels channel
                   JOIN release_bundles bundle
                     ON bundle.registry_id = channel.registry_id
                    AND bundle.manifest_digest = ?3
                   LEFT JOIN channel_partitions partition
                     ON partition.channel_id = channel.id
                    AND partition.bucket BETWEEN ?4 AND ?5
                    AND partition.release = bundle.release_id
                  WHERE channel.registry_id = ?1 AND channel.name = ?2
                    AND channel.active = 1
                  GROUP BY channel.id, channel.frontier, bundle.release_id
                 HAVING channel.frontier = bundle.release_id",
                &vals![
                    input.registry_id,
                    input.channel,
                    input.manifest_digest,
                    input.first_partition,
                    input.last_partition
                ],
            )
            .await?;
        row.map(|row| Ok(row.get::<i64>(1)? == expected))
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
    if input.staging_receipt_json.is_empty() || input.receipt_json.is_empty() {
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
    Sha256Digest::parse(&input.snapshot_digest)?;
    Sha256Digest::parse(&input.timestamp_digest)?;
    validate_key_bytes(&input.publication_id, "publication id", 64)?;
    if input.timestamp_path != "tuf/timestamp.json"
        || input.snapshot_path != format!("tuf/{}.snapshot.json", input.snapshot_version)
    {
        bail!("release timestamp publication paths are not canonical");
    }
    Ok(())
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
    if !is_release_channel_name(&input.channel) {
        bail!("release channel is invalid");
    }
    validate_key_bytes(&input.deployment_id, "deployment id", 128)?;
    validate_key_bytes(&input.manifest_digest, "release manifest digest", 128)?;
    validate_key_bytes(
        &input.publication_receipt_digest,
        "publication receipt digest",
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

    async fn attach_timestamp_objects(
        db: &Database,
        registry_id: i64,
        publication_id: &str,
        snapshot_version: i64,
        snapshot_hash: &str,
        timestamp_hash: &str,
    ) {
        let snapshot_path = format!("tuf/{snapshot_version}.snapshot.json");
        db.backend
            .execute(
                "INSERT INTO surface_objects
                 (registry_id, object_key, object_kind, partition_key,
                  content_hash, size, created_at, updated_at)
                 VALUES (?1, ?2, 'immutable', ?3, ?4, 10, 1, 1)",
                &vals![registry_id, snapshot_path, vec![7_u8; 32], snapshot_hash],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO surface_objects
                 (registry_id, object_key, object_kind, content_hash, size,
                  mutable_publication_id, created_at, updated_at)
                 VALUES (?1, 'tuf/timestamp.json', 'mutable_pointer', ?2, 10,
                         ?3, 1, 1)
                 ON CONFLICT(registry_id, object_key) DO UPDATE SET
                   content_hash = excluded.content_hash,
                   mutable_publication_id = excluded.mutable_publication_id,
                   updated_at = excluded.updated_at",
                &vals![registry_id, timestamp_hash, publication_id],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO registry_publication_objects
                 (publication_id, registry_id, surface_object_id, object_kind,
                  expected_hash, expected_size)
                 SELECT ?1, ?2, id, object_kind, content_hash, size
                   FROM surface_objects
                  WHERE registry_id = ?2
                    AND object_key IN (?3, 'tuf/timestamp.json')",
                &vals![publication_id, registry_id, snapshot_path],
            )
            .await
            .unwrap();
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
            staging_receipt_json: "{\"environment\":\"staging\"}".into(),
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
        let promotion = NewReleasePromotion {
            bundle_digest: bundle.bundle_digest.clone(),
            staging_receipt_digest: "3".repeat(64),
            qualification_digest: "4".repeat(64),
            production_receipt_digest: "6".repeat(64),
        };
        db.promote_release_bundle(&production, &promotion, 15)
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO channels (id, registry_id, name, frontier, active)
                 VALUES (?1, ?2, ?3, NULL, 1)",
                &vals![1_i64, registry_id, "edge"],
            )
            .await
            .unwrap();

        let edge = NewReleaseChannelOperation {
            registry_id,
            deployment_id: "production-deployment".into(),
            channel: "edge".into(),
            prior_generation: 0,
            first_partition: 0,
            last_partition: 31,
            manifest_digest: bundle.manifest_digest.clone(),
            publication_receipt_digest: "6".repeat(64),
            operation_digest: "7".repeat(64),
            receipt_json: "{\"generation\":1}".into(),
        };
        db.advance_release_channel(&edge, 16).await.unwrap();
        db.advance_release_channel(&edge, 16).await.unwrap();
        let channels = db.list_channels(registry_id).await.unwrap();
        let channel = channels
            .iter()
            .find(|channel| channel.name == "edge")
            .unwrap();
        assert_eq!(channel.frontier.as_deref(), Some("2026.03.0"));
        assert!(
            channel.partitions[..32]
                .iter()
                .all(|release| release.as_deref() == Some("2026.03.0"))
        );
        assert!(channel.partitions[32..].iter().all(Option::is_none));
        let mut stale = edge.clone();
        stale.operation_digest = "8".repeat(64);
        assert!(db.advance_release_channel(&stale, 17).await.is_err());
        db.backend
            .execute(
                "DELETE FROM channel_partitions WHERE channel_id = ?1 AND bucket = ?2",
                &vals![1_i64, 0_i64],
            )
            .await
            .unwrap();
        assert!(db.advance_release_channel(&edge, 18).await.is_err());
    }

    #[tokio::test]
    async fn isolated_production_imports_evidence_without_a_staging_row() {
        let staging_db = Database::open_in_memory().await.unwrap();
        let staging_registry_id = staging_db
            .register_registry("isolated-release", &[], false)
            .await
            .unwrap();
        ready_publication(
            &staging_db,
            staging_registry_id,
            "staging-source",
            "staging-source-generation",
            '1',
            &"c".repeat(64),
        )
        .await;
        let staging_bundle = bundle(staging_registry_id);
        staging_db
            .admit_release_bundle(&staging_bundle, "staging-source", 11)
            .await
            .unwrap();
        ready_publication(
            &staging_db,
            staging_registry_id,
            "staging-publication",
            "staging-publication-generation",
            '2',
            &"d".repeat(64),
        )
        .await;
        staging_db
            .record_release_bundle_publication(
                &NewReleaseBundlePublication {
                    bundle_digest: staging_bundle.bundle_digest.clone(),
                    registry_id: staging_registry_id,
                    environment: "staging".into(),
                    publication_id: "staging-publication".into(),
                    deployment_id: "staging-deployment".into(),
                    receipt_digest: "3".repeat(64),
                    receipt_json: "{\"signed\":\"staging\"}".into(),
                    staging_receipt_digest: None,
                },
                12,
            )
            .await
            .unwrap();
        let qualification = NewReleaseQualification {
            bundle_digest: staging_bundle.bundle_digest.clone(),
            staging_receipt_digest: "3".repeat(64),
            staging_receipt_json: "{\"signed\":\"staging\"}".into(),
            qualification_digest: "4".repeat(64),
            receipt_json: "{\"signed\":\"qualification\"}".into(),
        };
        staging_db
            .record_release_qualification(&qualification, 13)
            .await
            .unwrap();

        let production_db = Database::open_in_memory().await.unwrap();
        let production_registry_id = production_db
            .register_registry("isolated-release", &[], false)
            .await
            .unwrap();
        ready_publication(
            &production_db,
            production_registry_id,
            "production-source",
            "production-source-generation",
            '1',
            &"c".repeat(64),
        )
        .await;
        let production_bundle = bundle(production_registry_id);
        production_db
            .admit_release_bundle(&production_bundle, "production-source", 14)
            .await
            .unwrap();
        production_db
            .import_release_qualification(&qualification, 15)
            .await
            .unwrap();
        assert!(
            production_db
                .release_bundle_publication(&production_bundle.bundle_digest, "staging")
                .await
                .unwrap()
                .is_none()
        );
        ready_publication(
            &production_db,
            production_registry_id,
            "production-publication",
            "production-publication-generation",
            '5',
            &"e".repeat(64),
        )
        .await;
        let publication = NewReleaseBundlePublication {
            bundle_digest: production_bundle.bundle_digest.clone(),
            registry_id: production_registry_id,
            environment: "production".into(),
            publication_id: "production-publication".into(),
            deployment_id: "production-deployment".into(),
            receipt_digest: "6".repeat(64),
            receipt_json: "{\"signed\":\"production\"}".into(),
            staging_receipt_digest: Some("3".repeat(64)),
        };
        let mut discontinuous = NewReleasePromotion {
            bundle_digest: production_bundle.bundle_digest.clone(),
            staging_receipt_digest: "8".repeat(64),
            qualification_digest: "4".repeat(64),
            production_receipt_digest: "6".repeat(64),
        };
        assert!(
            production_db
                .promote_release_bundle(&publication, &discontinuous, 16)
                .await
                .is_err()
        );
        assert!(
            production_db
                .release_bundle_publication(&production_bundle.bundle_digest, "production")
                .await
                .unwrap()
                .is_none()
        );

        discontinuous.staging_receipt_digest = "3".repeat(64);
        production_db
            .promote_release_bundle(&publication, &discontinuous, 17)
            .await
            .unwrap();
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
        assert!(
            db.record_release_bundle_publication(&wrong, 12)
                .await
                .is_err()
        );
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
        attach_timestamp_objects(
            &db,
            registry_id,
            "timestamp-one",
            1,
            &"2".repeat(64),
            &"3".repeat(64),
        )
        .await;
        db.backend
            .execute(
                "UPDATE registry_publications
                    SET state = 'preparing', completed_at = NULL
                  WHERE publication_id = 'timestamp-one'",
                &[],
            )
            .await
            .unwrap();
        let first = NewReleaseTimestampPublication {
            registry_id,
            snapshot_digest: format!("sha256:{}", "2".repeat(64)),
            snapshot_version: 1,
            timestamp_version: 1,
            timestamp_digest: format!("sha256:{}", "3".repeat(64)),
            publication_id: "timestamp-one".into(),
            timestamp_path: "tuf/timestamp.json".into(),
            snapshot_path: "tuf/1.snapshot.json".into(),
        };
        db.record_release_timestamp_publication(&first, 11)
            .await
            .unwrap();
        db.record_release_timestamp_publication(&first, 11)
            .await
            .unwrap();
        let wrong_bytes = NewReleaseTimestampPublication {
            timestamp_version: 2,
            timestamp_digest: format!("sha256:{}", "4".repeat(64)),
            ..first.clone()
        };
        assert!(
            db.record_release_timestamp_publication(&wrong_bytes, 12)
                .await
                .is_err()
        );
        ready_publication(
            &db,
            registry_id,
            "timestamp-three",
            "timestamp-generation-three",
            '4',
            &"d".repeat(64),
        )
        .await;
        attach_timestamp_objects(
            &db,
            registry_id,
            "timestamp-three",
            2,
            &"5".repeat(64),
            &"6".repeat(64),
        )
        .await;
        let skipped = NewReleaseTimestampPublication {
            registry_id,
            snapshot_digest: format!("sha256:{}", "5".repeat(64)),
            snapshot_version: 2,
            timestamp_version: 3,
            timestamp_digest: format!("sha256:{}", "6".repeat(64)),
            publication_id: "timestamp-three".into(),
            timestamp_path: "tuf/timestamp.json".into(),
            snapshot_path: "tuf/2.snapshot.json".into(),
        };
        assert!(
            db.record_release_timestamp_publication(&skipped, 12)
                .await
                .is_err()
        );
    }

    const STAGING_RECEIPT: char = '3';
    const PRODUCTION_RECEIPT: char = '6';

    /// Admits the fixture bundle into a new registry named `slug`.
    async fn admitted_bundle(db: &Database, slug: &str) -> NewReleaseBundle {
        let registry_id = db.register_registry(slug, &[], false).await.unwrap();
        ready_publication(
            db,
            registry_id,
            &format!("{slug}-source"),
            &format!("{slug}-source-generation"),
            '1',
            &"c".repeat(64),
        )
        .await;
        let bundle = bundle(registry_id);
        db.admit_release_bundle(&bundle, &format!("{slug}-source"), 11)
            .await
            .unwrap();
        bundle
    }

    /// Commits the bundle's staging publication with the fixture receipt.
    async fn commit_staging(db: &Database, bundle: &NewReleaseBundle, slug: &str) {
        ready_publication(
            db,
            bundle.registry_id,
            &format!("{slug}-staging"),
            &format!("{slug}-staging-generation"),
            '2',
            &"d".repeat(64),
        )
        .await;
        db.record_release_bundle_publication(
            &NewReleaseBundlePublication {
                bundle_digest: bundle.bundle_digest.clone(),
                registry_id: bundle.registry_id,
                environment: "staging".into(),
                publication_id: format!("{slug}-staging"),
                deployment_id: bundle.staging_deployment_id.clone(),
                receipt_digest: STAGING_RECEIPT.to_string().repeat(64),
                receipt_json: "{\"environment\":\"staging\"}".into(),
                staging_receipt_digest: None,
            },
            12,
        )
        .await
        .unwrap();
    }

    /// Qualifies the staged bundle and promotes it with the fixture receipt.
    async fn promote(db: &Database, bundle: &NewReleaseBundle, slug: &str) {
        db.record_release_qualification(
            &NewReleaseQualification {
                bundle_digest: bundle.bundle_digest.clone(),
                staging_receipt_digest: STAGING_RECEIPT.to_string().repeat(64),
                staging_receipt_json: "{\"environment\":\"staging\"}".into(),
                qualification_digest: "4".repeat(64),
                receipt_json: "{\"qualified\":true}".into(),
            },
            13,
        )
        .await
        .unwrap();
        ready_publication(
            db,
            bundle.registry_id,
            &format!("{slug}-production"),
            &format!("{slug}-production-generation"),
            '5',
            &"e".repeat(64),
        )
        .await;
        db.promote_release_bundle(
            &NewReleaseBundlePublication {
                bundle_digest: bundle.bundle_digest.clone(),
                registry_id: bundle.registry_id,
                environment: "production".into(),
                publication_id: format!("{slug}-production"),
                deployment_id: bundle.production_deployment_id.clone(),
                receipt_digest: PRODUCTION_RECEIPT.to_string().repeat(64),
                receipt_json: "{\"environment\":\"production\"}".into(),
                staging_receipt_digest: Some(STAGING_RECEIPT.to_string().repeat(64)),
            },
            &NewReleasePromotion {
                bundle_digest: bundle.bundle_digest.clone(),
                staging_receipt_digest: STAGING_RECEIPT.to_string().repeat(64),
                qualification_digest: "4".repeat(64),
                production_receipt_digest: PRODUCTION_RECEIPT.to_string().repeat(64),
            },
            15,
        )
        .await
        .unwrap();
    }

    async fn create_channel(db: &Database, registry_id: i64, channel_id: i64, name: &str) {
        db.backend
            .execute(
                "INSERT INTO channels (id, registry_id, name, frontier, active)
                 VALUES (?1, ?2, ?3, NULL, 1)",
                &vals![channel_id, registry_id, name],
            )
            .await
            .unwrap();
    }

    fn advance(
        bundle: &NewReleaseBundle,
        deployment_id: &str,
        channel: &str,
        receipt: char,
    ) -> NewReleaseChannelOperation {
        NewReleaseChannelOperation {
            registry_id: bundle.registry_id,
            deployment_id: deployment_id.into(),
            channel: channel.into(),
            prior_generation: 0,
            first_partition: 0,
            last_partition: 255,
            manifest_digest: bundle.manifest_digest.clone(),
            publication_receipt_digest: receipt.to_string().repeat(64),
            operation_digest: format!("{deployment_id}-{channel}-{receipt}"),
            receipt_json: format!("{{\"channel\":\"{channel}\"}}"),
        }
    }

    async fn frontier(db: &Database, registry_id: i64, name: &str) -> Option<String> {
        db.list_channels(registry_id)
            .await
            .unwrap()
            .into_iter()
            .find(|channel| channel.name == name)
            .and_then(|channel| channel.frontier)
    }

    #[test]
    fn release_channel_names_follow_kind_and_train_syntax() {
        for accepted in [
            "edge",
            "candidate",
            "stable",
            "stable-2026.3",
            "stable-2026.12",
            "candidate-2026.10",
            "edge-2027.1",
        ] {
            assert!(is_release_channel_name(accepted), "rejected {accepted}");
        }

        for rejected in [
            "",
            "nightly",
            "Stable",
            "stable-",
            "stable-2026",
            "stable-2026.",
            "stable-2026.0",
            "stable-2026.03",
            "stable-2026.13",
            "stable-02026.3",
            "stable-0999.3",
            "stable-2026.3-rc",
            "stable-2026.3.1",
            "stable_2026.3",
            "nightly-2026.3",
            "stable-２０２６.3",
        ] {
            assert!(!is_release_channel_name(rejected), "accepted {rejected}");
        }
    }

    #[tokio::test]
    async fn staging_deployment_advances_after_its_staging_commit() {
        let db = Database::open_in_memory().await.unwrap();
        let bundle = admitted_bundle(&db, "staging-advance").await;
        create_channel(&db, bundle.registry_id, 1, "edge").await;
        let staged = advance(&bundle, "staging-deployment", "edge", STAGING_RECEIPT);

        assert!(
            db.advance_release_channel(&staged, 13).await.is_err(),
            "staging advance requires a committed staging publication"
        );
        assert_eq!(frontier(&db, bundle.registry_id, "edge").await, None);

        commit_staging(&db, &bundle, "staging-advance").await;
        for rejected in [
            advance(&bundle, "staging-deployment", "edge", '9'),
            advance(&bundle, "production-deployment", "edge", STAGING_RECEIPT),
            advance(&bundle, "unrelated-deployment", "edge", STAGING_RECEIPT),
        ] {
            assert!(
                db.advance_release_channel(&rejected, 14).await.is_err(),
                "accepted {rejected:?}"
            );
        }

        db.advance_release_channel(&staged, 14).await.unwrap();
        db.advance_release_channel(&staged, 14).await.unwrap();

        assert_eq!(
            frontier(&db, bundle.registry_id, "edge").await.as_deref(),
            Some("2026.03.0")
        );
        let recorded = db
            .release_channel_operation(bundle.registry_id, "edge", 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            recorded.publication_receipt_digest,
            STAGING_RECEIPT.to_string().repeat(64)
        );
    }

    #[tokio::test]
    async fn production_deployment_still_requires_a_promotion() {
        let db = Database::open_in_memory().await.unwrap();
        let bundle = admitted_bundle(&db, "production-advance").await;
        create_channel(&db, bundle.registry_id, 1, "stable").await;
        commit_staging(&db, &bundle, "production-advance").await;

        let staging_evidence = advance(&bundle, "production-deployment", "stable", STAGING_RECEIPT);
        assert!(
            db.advance_release_channel(&staging_evidence, 14)
                .await
                .is_err(),
            "production advance accepted staging-only evidence"
        );

        promote(&db, &bundle, "production-advance").await;
        let crossed = advance(&bundle, "staging-deployment", "stable", PRODUCTION_RECEIPT);
        assert!(
            db.advance_release_channel(&crossed, 16).await.is_err(),
            "staging advance accepted the production receipt"
        );

        let promoted = advance(
            &bundle,
            "production-deployment",
            "stable",
            PRODUCTION_RECEIPT,
        );
        db.advance_release_channel(&promoted, 16).await.unwrap();
        assert_eq!(
            frontier(&db, bundle.registry_id, "stable").await.as_deref(),
            Some("2026.03.0")
        );
    }

    #[tokio::test]
    async fn shared_deployment_keeps_the_promotion_requirement() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db
            .register_registry("shared-advance", &[], false)
            .await
            .unwrap();
        ready_publication(
            &db,
            registry_id,
            "shared-advance-source",
            "shared-advance-source-generation",
            '1',
            &"c".repeat(64),
        )
        .await;
        let shared = NewReleaseBundle {
            staging_deployment_id: "shared-deployment".into(),
            production_deployment_id: "shared-deployment".into(),
            ..bundle(registry_id)
        };
        db.admit_release_bundle(&shared, "shared-advance-source", 11)
            .await
            .unwrap();
        commit_staging(&db, &shared, "shared-advance").await;
        create_channel(&db, registry_id, 1, "edge").await;

        let staged = advance(&shared, "shared-deployment", "edge", STAGING_RECEIPT);
        assert!(db.advance_release_channel(&staged, 14).await.is_err());
        assert_eq!(frontier(&db, registry_id, "edge").await, None);
    }

    #[tokio::test]
    async fn per_train_channels_advance_and_malformed_names_are_rejected() {
        let db = Database::open_in_memory().await.unwrap();
        let bundle = admitted_bundle(&db, "train-advance").await;
        commit_staging(&db, &bundle, "train-advance").await;
        create_channel(&db, bundle.registry_id, 1, "candidate-2026.12").await;
        create_channel(&db, bundle.registry_id, 2, "stable-2026.13").await;

        let train = advance(
            &bundle,
            "staging-deployment",
            "candidate-2026.12",
            STAGING_RECEIPT,
        );
        db.advance_release_channel(&train, 14).await.unwrap();
        assert_eq!(
            frontier(&db, bundle.registry_id, "candidate-2026.12")
                .await
                .as_deref(),
            Some("2026.03.0")
        );

        for malformed in ["stable-2026.13", "nightly", "stable-"] {
            let operation = advance(&bundle, "staging-deployment", malformed, STAGING_RECEIPT);
            assert!(db.advance_release_channel(&operation, 14).await.is_err());
            assert!(
                db.release_channel_operation(bundle.registry_id, malformed, 1)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn per_train_ledger_migration_retains_baseline_operations() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub.db");
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch(super::super::MIGRATIONS[0])
                .unwrap();
            connection.execute_batch("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(1)").unwrap();
        }
        // Populate the actual v1 schema without running successor migrations.
        let backend = crate::backend::SqlxBackend::connect_sqlite(path.to_str().unwrap())
            .await
            .unwrap();
        let db = Database {
            backend: Box::new(backend),
        };
        let bundle = admitted_bundle(&db, "ledger-upgrade").await;
        commit_staging(&db, &bundle, "ledger-upgrade").await;
        create_channel(&db, bundle.registry_id, 1, "edge").await;
        drop(db);

        // The retained operation lives in the frozen baseline ledger.
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "INSERT INTO release_channel_operations
                   (registry_id, channel, prior_generation, new_generation,
                    first_partition, last_partition, manifest_digest,
                    production_receipt_digest, operation_digest, receipt_json,
                    committed_at)
                 VALUES (?1, 'edge', 0, 1, 0, 31, ?2, ?3, ?4, '{\"legacy\":1}', 13)",
                rusqlite::params![
                    bundle.registry_id,
                    bundle.manifest_digest,
                    STAGING_RECEIPT.to_string().repeat(64),
                    "8".repeat(64)
                ],
            )
            .unwrap();
        drop(connection);

        let db = Database::open(&path).await.unwrap();
        let version: i64 = db
            .backend
            .query_opt("SELECT version FROM schema_version", &[])
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(version, super::super::MIGRATIONS.len() as i64);
        let retained = db
            .release_channel_operation(bundle.registry_id, "edge", 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.operation_digest, "8".repeat(64));
        assert_eq!(
            retained.publication_receipt_digest,
            STAGING_RECEIPT.to_string().repeat(64)
        );

        // The copied history keeps the compare-and-swap continuous.
        let stale = advance(&bundle, "staging-deployment", "edge", STAGING_RECEIPT);
        assert!(db.advance_release_channel(&stale, 14).await.is_err());
        let next = NewReleaseChannelOperation {
            prior_generation: 1,
            ..stale
        };
        db.advance_release_channel(&next, 14).await.unwrap();
    }

    #[test]
    fn per_train_ledger_migration_replays_after_any_interruption() {
        let migration = crate::backend::split_statements(super::super::MIGRATIONS[1]);
        for cut in 0..=migration.len() {
            let connection = rusqlite::Connection::open_in_memory().unwrap();
            connection
                .execute_batch(super::super::MIGRATIONS[0])
                .unwrap();

            // This test checks statement replay, not release continuity, so
            // the retained row stands alone without its parent evidence.
            connection
                .execute_batch("PRAGMA foreign_keys = OFF")
                .unwrap();
            connection
                .execute_batch(
                    "INSERT INTO release_channel_operations
                       (registry_id, channel, prior_generation, new_generation,
                        first_partition, last_partition, manifest_digest,
                        production_receipt_digest, operation_digest,
                        receipt_json, committed_at)
                     VALUES (1, 'stable', 0, 1, 0, 255, 'manifest', 'receipt',
                             'operation', '{}', 1)",
                )
                .unwrap();

            // Interrupt after `cut` statements, then replay the whole script
            // the way the MySQL migrator does: rewritten statements, with
            // indexes skipped once the catalog shows them.
            for statement in &migration[..cut] {
                connection.execute_batch(statement).unwrap();
            }
            for statement in &migration {
                if let Some((_, index)) = super::super::mysql_migration_index_identity(statement) {
                    let exists: i64 = connection
                        .query_row(
                            "SELECT COUNT(*) FROM sqlite_master
                              WHERE type = 'index' AND name = ?1",
                            [index],
                            |row| row.get(0),
                        )
                        .unwrap();
                    if exists == 1 {
                        continue;
                    }
                }
                let replay = super::super::mysql_replay_safe_migration_sql(statement).replacen(
                    "INSERT IGNORE INTO ",
                    "INSERT OR IGNORE INTO ",
                    1,
                );
                connection
                    .execute_batch(&replay)
                    .unwrap_or_else(|error| panic!("replay after {cut}: {error}\n{replay}"));
            }

            let copied: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM release_channel_advances
                      WHERE channel = 'stable' AND publication_receipt_digest = 'receipt'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(copied, 1, "interruption after {cut} statements");
        }
    }
}
