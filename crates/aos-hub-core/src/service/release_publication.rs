//! Release-scoped Hub publication RPC implementation.

use std::time::{Duration, UNIX_EPOCH};

use aos_proto_types as pb;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::receipt::{
    ChannelReceiptV1, HubEnvironment, PublicationReceiptV1, QualificationReceiptV1,
    PUBLICATION_RECEIPT_V1,
};

use crate::db::{
    NewReleaseBundle, NewReleaseBundlePublication, NewReleaseChannelOperation, NewReleasePromotion,
    NewReleaseQualification, NewReleaseTimestampPublication,
};
use crate::domain::Permission;

use super::{RpcError, RpcService};

impl RpcService {
    /// Admits a closed bundle against an exact ready registry base.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, continuity, or persistence error.
    pub async fn begin_release_publication(
        &self,
        auth: Option<&str>,
        req: pb::BeginReleasePublicationRequest,
    ) -> Result<pb::ReleasePublicationState, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.registry).await?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;
        let input = NewReleaseBundle {
            bundle_digest: req.bundle_digest.clone(),
            registry_id: registry.id,
            release_id: req.release_id.clone(),
            manifest_digest: req.manifest_digest.clone(),
            registry_base_commit: req.registry_base_commit,
            staging_deployment_id: req.staging_deployment_id,
            production_deployment_id: req.production_deployment_id,
        };
        self.db
            .admit_release_bundle(
                &input,
                &req.backing_publication_id,
                crate::clock::now_unix_secs(),
            )
            .await
            .map_err(failed_precondition)?;
        Ok(pb::ReleasePublicationState {
            registry: registry.slug,
            bundle_digest: req.bundle_digest,
            release_id: req.release_id,
            manifest_digest: req.manifest_digest,
        })
    }

    /// Commits staging and returns its deployment-signed immutable receipt.
    ///
    /// # Errors
    ///
    /// Returns an authorization, deployment, signing, continuity, or storage error.
    pub async fn commit_release_publication(
        &self,
        auth: Option<&str>,
        req: pb::CommitReleasePublicationRequest,
    ) -> Result<pb::ReleaseReceipt, RpcError> {
        if req.environment != "staging" || !req.staging_receipt_digest.is_empty() {
            return Err(RpcError::invalid(
                "commit release publication is staging-only",
            ));
        }
        let (registry, bundle) = self
            .authorize_release(auth, &req.registry, &req.bundle_digest)
            .await?;
        if let Some(existing) = self
            .db
            .release_bundle_publication(&req.bundle_digest, "staging")
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(receipt_message(
                existing.receipt_digest,
                existing.receipt_json,
            ));
        }
        let authority = self.release_authority(&req.expected_deployment_id)?;
        let now = crate::clock::now_unix_secs();
        let receipt = PublicationReceiptV1 {
            schema_version: PUBLICATION_RECEIPT_V1.into(),
            environment: HubEnvironment::Staging,
            deployment_id: authority.deployment_id().into(),
            registry: registry.slug,
            release_id: bundle.release_id,
            manifest_digest: parse_digest(&bundle.manifest_digest)?,
            bundle_digest: parse_digest(&bundle.bundle_digest)?,
            operation_id: req.publication_id.clone(),
            staging_receipt_digest: None,
            committed_at: format_time(now)?,
        };
        receipt.validate().map_err(invalid)?;
        let signed = authority
            .issue_publication(&receipt)
            .await
            .map_err(RpcError::internal)?;
        self.db
            .record_release_bundle_publication(
                &NewReleaseBundlePublication {
                    bundle_digest: req.bundle_digest,
                    registry_id: registry.id,
                    environment: "staging".into(),
                    publication_id: req.publication_id,
                    deployment_id: authority.deployment_id().into(),
                    receipt_digest: signed.digest.clone(),
                    receipt_json: signed.envelope_json.clone(),
                    staging_receipt_digest: None,
                },
                now,
            )
            .await
            .map_err(failed_precondition)?;
        Ok(receipt_message(signed.digest, signed.envelope_json))
    }

    /// Verifies and records qualification of exact staged public bytes.
    ///
    /// # Errors
    ///
    /// Returns an authorization, signature, semantic, continuity, or storage error.
    pub async fn record_release_qualification(
        &self,
        auth: Option<&str>,
        req: pb::RecordReleaseQualificationRequest,
    ) -> Result<pb::ReleaseQualificationState, RpcError> {
        let (_, bundle) = self
            .authorize_release(auth, &req.registry, &req.bundle_digest)
            .await?;
        let receipt_bytes = req.qualification_receipt_json.as_bytes();
        let receipt: QualificationReceiptV1 =
            canonical::from_slice(receipt_bytes, "qualification receipt").map_err(invalid)?;
        receipt.validate().map_err(invalid)?;
        if canonical::to_vec(&receipt).map_err(RpcError::internal)? != receipt_bytes
            || receipt.staging_receipt_digest.to_string() != req.staging_receipt_digest
            || receipt.manifest_digest.to_string() != bundle.manifest_digest
            || Sha256Digest::of_bytes(req.signed_qualification_json.as_bytes()).to_string()
                != req.qualification_digest
        {
            return Err(RpcError::invalid(
                "qualification evidence does not match the release",
            ));
        }
        let authority = self
            .release_evidence
            .as_ref()
            .ok_or_else(authority_unavailable)?;
        authority
            .verify_qualification(&receipt, &req.signed_qualification_json)
            .await
            .map_err(failed_precondition)?;
        let staging = self
            .db
            .release_bundle_publication(&req.bundle_digest, "staging")
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("staging release receipt"))?;
        self.db
            .record_release_qualification(
                &NewReleaseQualification {
                    bundle_digest: req.bundle_digest.clone(),
                    staging_receipt_digest: req.staging_receipt_digest.clone(),
                    staging_receipt_json: staging.receipt_json,
                    qualification_digest: req.qualification_digest.clone(),
                    receipt_json: req.signed_qualification_json,
                },
                crate::clock::now_unix_secs(),
            )
            .await
            .map_err(failed_precondition)?;
        Ok(pb::ReleaseQualificationState {
            bundle_digest: req.bundle_digest,
            staging_receipt_digest: req.staging_receipt_digest,
            qualification_digest: req.qualification_digest,
        })
    }

    /// Promotes an exact qualified bundle and returns a production receipt.
    ///
    /// # Errors
    ///
    /// Returns an authorization, deployment, signing, continuity, or storage error.
    pub async fn promote_release_publication(
        &self,
        auth: Option<&str>,
        req: pb::PromoteReleasePublicationRequest,
    ) -> Result<pb::ReleaseReceipt, RpcError> {
        let (registry, bundle) = self
            .authorize_release(auth, &req.registry, &req.bundle_digest)
            .await?;
        let authority = self.release_authority(&req.expected_deployment_id)?;
        let staging_bytes = req.signed_staging_receipt_json.as_bytes();
        let staging: PublicationReceiptV1 =
            canonical::from_slice(staging_bytes, "staging receipt envelope")
                .and_then(|envelope: aos_release::receipt::SignedReceiptEnvelopeV1| {
                    canonical::from_slice(
                        &canonical::to_vec(&envelope.payload)?,
                        "staging receipt payload",
                    )
                })
                .map_err(invalid)?;
        staging.validate().map_err(invalid)?;
        if staging.environment != HubEnvironment::Staging
            || staging.deployment_id != bundle.staging_deployment_id
            || staging.registry != registry.slug
            || staging.release_id != bundle.release_id
            || staging.manifest_digest.to_string() != bundle.manifest_digest
            || staging.bundle_digest.to_string() != bundle.bundle_digest
            || staging.staging_receipt_digest.is_some()
            || Sha256Digest::of_bytes(staging_bytes).to_string() != req.staging_receipt_digest
        {
            return Err(RpcError::invalid(
                "signed staging receipt does not match the release",
            ));
        }
        authority
            .verify_publication(&staging, &req.signed_staging_receipt_json)
            .await
            .map_err(failed_precondition)?;

        let qualification_bytes = req.qualification_receipt_json.as_bytes();
        let qualification: QualificationReceiptV1 =
            canonical::from_slice(qualification_bytes, "qualification receipt").map_err(invalid)?;
        qualification.validate().map_err(invalid)?;
        if canonical::to_vec(&qualification).map_err(RpcError::internal)? != qualification_bytes
            || qualification.staging_receipt_digest.to_string() != req.staging_receipt_digest
            || qualification.manifest_digest.to_string() != bundle.manifest_digest
            || Sha256Digest::of_bytes(req.signed_qualification_json.as_bytes()).to_string()
                != req.qualification_digest
        {
            return Err(RpcError::invalid(
                "qualification evidence does not match the release",
            ));
        }
        authority
            .verify_qualification(&qualification, &req.signed_qualification_json)
            .await
            .map_err(failed_precondition)?;
        self.db
            .import_release_qualification(
                &NewReleaseQualification {
                    bundle_digest: req.bundle_digest.clone(),
                    staging_receipt_digest: req.staging_receipt_digest.clone(),
                    staging_receipt_json: req.signed_staging_receipt_json.clone(),
                    qualification_digest: req.qualification_digest.clone(),
                    receipt_json: req.signed_qualification_json.clone(),
                },
                crate::clock::now_unix_secs(),
            )
            .await
            .map_err(failed_precondition)?;
        if let Some(existing) = self
            .db
            .release_bundle_publication(&req.bundle_digest, "production")
            .await
            .map_err(RpcError::internal)?
        {
            if existing.publication_id != req.publication_id
                || existing.deployment_id != authority.deployment_id()
                || existing.staging_receipt_digest.as_deref()
                    != Some(req.staging_receipt_digest.as_str())
            {
                return Err(RpcError::FailedPrecondition(
                    "production release retry conflicts with the committed publication".into(),
                ));
            }
            return Ok(receipt_message(
                existing.receipt_digest,
                existing.receipt_json,
            ));
        }
        let now = crate::clock::now_unix_secs();
        let receipt = PublicationReceiptV1 {
            schema_version: PUBLICATION_RECEIPT_V1.into(),
            environment: HubEnvironment::Production,
            deployment_id: authority.deployment_id().into(),
            registry: registry.slug,
            release_id: bundle.release_id,
            manifest_digest: parse_digest(&bundle.manifest_digest)?,
            bundle_digest: parse_digest(&bundle.bundle_digest)?,
            operation_id: req.publication_id.clone(),
            staging_receipt_digest: Some(parse_digest(&req.staging_receipt_digest)?),
            committed_at: format_time(now)?,
        };
        receipt.validate().map_err(invalid)?;
        let signed = authority
            .issue_publication(&receipt)
            .await
            .map_err(RpcError::internal)?;
        self.db
            .promote_release_bundle(
                &NewReleaseBundlePublication {
                    bundle_digest: req.bundle_digest.clone(),
                    registry_id: registry.id,
                    environment: "production".into(),
                    publication_id: req.publication_id,
                    deployment_id: authority.deployment_id().into(),
                    receipt_digest: signed.digest.clone(),
                    receipt_json: signed.envelope_json.clone(),
                    staging_receipt_digest: Some(req.staging_receipt_digest.clone()),
                },
                &NewReleasePromotion {
                    bundle_digest: req.bundle_digest,
                    staging_receipt_digest: req.staging_receipt_digest,
                    qualification_digest: req.qualification_digest,
                    production_receipt_digest: signed.digest.clone(),
                },
                now,
            )
            .await
            .map_err(failed_precondition)?;
        Ok(receipt_message(signed.digest, signed.envelope_json))
    }

    /// Returns a public production receipt without operator-private data.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument, not-found, or storage error.
    pub async fn get_release_receipt(
        &self,
        _auth: Option<&str>,
        req: pb::GetReleaseReceiptRequest,
    ) -> Result<pb::ReleaseReceipt, RpcError> {
        if req.environment != "production" {
            return Err(RpcError::invalid(
                "only production release receipts are public",
            ));
        }
        let receipt = self
            .db
            .release_bundle_publication(&req.bundle_digest, "production")
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("release receipt"))?;
        Ok(receipt_message(
            receipt.receipt_digest,
            receipt.receipt_json,
        ))
    }

    /// Records a monotonic online timestamp publication.
    ///
    /// # Errors
    ///
    /// Returns an authorization, continuity, or storage error.
    pub async fn publish_release_timestamp(
        &self,
        auth: Option<&str>,
        req: pb::PublishReleaseTimestampRequest,
    ) -> Result<pb::ReleaseTimestampState, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.registry).await?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;
        self.db
            .record_release_timestamp_publication(
                &NewReleaseTimestampPublication {
                    registry_id: registry.id,
                    snapshot_digest: req.snapshot_digest.clone(),
                    snapshot_version: req.snapshot_version,
                    timestamp_version: req.timestamp_version,
                    timestamp_digest: req.timestamp_digest.clone(),
                    publication_id: req.publication_id,
                    timestamp_path: req.timestamp_path,
                    snapshot_path: req.snapshot_path,
                },
                crate::clock::now_unix_secs(),
            )
            .await
            .map_err(failed_precondition)?;
        Ok(pb::ReleaseTimestampState {
            snapshot_digest: req.snapshot_digest,
            snapshot_version: req.snapshot_version,
            timestamp_version: req.timestamp_version,
            timestamp_digest: req.timestamp_digest,
        })
    }

    /// Signs and atomically compare-and-swaps one channel partition range.
    ///
    /// # Errors
    ///
    /// Returns an authorization, signing, continuity, or storage error.
    pub async fn advance_release_channel(
        &self,
        auth: Option<&str>,
        req: pb::AdvanceReleaseChannelRequest,
    ) -> Result<pb::ReleaseReceipt, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.registry).await?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;
        let authority = self
            .release_evidence
            .as_ref()
            .ok_or_else(authority_unavailable)?;
        let now = crate::clock::now_unix_secs();
        let new_generation = req
            .prior_generation
            .checked_add(1)
            .ok_or_else(|| RpcError::invalid("channel generation overflowed"))?;
        if let Some(existing) = self
            .db
            .release_channel_operation(registry.id, &req.channel, new_generation)
            .await
            .map_err(RpcError::internal)?
        {
            if existing.prior_generation != req.prior_generation
                || existing.first_partition != req.first_partition
                || existing.last_partition != req.last_partition
                || existing.manifest_digest != req.manifest_digest
                || existing.production_receipt_digest != req.production_receipt_digest
            {
                return Err(RpcError::FailedPrecondition(
                    "release channel retry conflicts with the committed operation".into(),
                ));
            }
            self.db
                .advance_release_channel(
                    &NewReleaseChannelOperation {
                        registry_id: registry.id,
                        channel: req.channel,
                        prior_generation: req.prior_generation,
                        first_partition: req.first_partition,
                        last_partition: req.last_partition,
                        manifest_digest: req.manifest_digest,
                        production_receipt_digest: req.production_receipt_digest,
                        operation_digest: existing.operation_digest.clone(),
                        receipt_json: existing.receipt_json.clone(),
                    },
                    crate::clock::now_unix_secs(),
                )
                .await
                .map_err(failed_precondition)?;
            return Ok(receipt_message(
                existing.operation_digest,
                existing.receipt_json,
            ));
        }
        let receipt = ChannelReceiptV1 {
            schema_version: "aos.release.channel-receipt/v1".into(),
            channel: req.channel.clone(),
            first_partition: u16::try_from(req.first_partition).map_err(invalid)?,
            last_partition: u16::try_from(req.last_partition).map_err(invalid)?,
            prior_generation: u64::try_from(req.prior_generation).map_err(invalid)?,
            new_generation: u64::try_from(new_generation).map_err(invalid)?,
            manifest_digest: parse_digest(&req.manifest_digest)?,
            production_receipt_digest: parse_digest(&req.production_receipt_digest)?,
            committed_at: format_time(now)?,
        };
        receipt.validate().map_err(invalid)?;
        let signed = authority
            .issue_channel(&receipt)
            .await
            .map_err(RpcError::internal)?;
        self.db
            .advance_release_channel(
                &NewReleaseChannelOperation {
                    registry_id: registry.id,
                    channel: req.channel,
                    prior_generation: req.prior_generation,
                    first_partition: req.first_partition,
                    last_partition: req.last_partition,
                    manifest_digest: req.manifest_digest,
                    production_receipt_digest: req.production_receipt_digest,
                    operation_digest: signed.digest.clone(),
                    receipt_json: signed.envelope_json.clone(),
                },
                now,
            )
            .await
            .map_err(failed_precondition)?;
        Ok(receipt_message(signed.digest, signed.envelope_json))
    }

    async fn authorize_release(
        &self,
        auth: Option<&str>,
        registry_name: &str,
        bundle_digest: &str,
    ) -> Result<(crate::db::RegistryRecord, crate::db::ReleaseBundleRecord), RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(registry_name).await?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;
        let bundle = self
            .db
            .release_bundle(bundle_digest)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("release bundle"))?;
        if bundle.registry_id != registry.id {
            return Err(RpcError::not_found("release bundle"));
        }
        Ok((registry, bundle))
    }

    fn release_authority(
        &self,
        expected_deployment_id: &str,
    ) -> Result<&dyn crate::release_evidence::ReleaseEvidenceAuthority, RpcError> {
        let authority = self
            .release_evidence
            .as_deref()
            .ok_or_else(authority_unavailable)?;
        if authority.deployment_id() != expected_deployment_id {
            return Err(RpcError::FailedPrecondition(
                "release deployment identity does not match".into(),
            ));
        }
        Ok(authority)
    }
}

fn parse_digest(value: &str) -> Result<Sha256Digest, RpcError> {
    Sha256Digest::parse(value).map_err(invalid)
}

fn format_time(now: i64) -> Result<String, RpcError> {
    let seconds = u64::try_from(now).map_err(invalid)?;
    Ok(humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(seconds)).to_string())
}

fn receipt_message(receipt_digest: String, signed_receipt_json: String) -> pb::ReleaseReceipt {
    pb::ReleaseReceipt {
        receipt_digest,
        signed_receipt_json,
    }
}

fn failed_precondition(error: impl std::fmt::Display) -> RpcError {
    RpcError::FailedPrecondition(format!("{error:#}"))
}

fn invalid(error: impl std::fmt::Display) -> RpcError {
    RpcError::invalid(error.to_string())
}

fn authority_unavailable() -> RpcError {
    RpcError::FailedPrecondition("release evidence authority is not configured".into())
}
