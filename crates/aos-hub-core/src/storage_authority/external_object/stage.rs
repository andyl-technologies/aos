//! Closed external multipart controls; delegated parts never authorize final PUT.
//!
//! A context freezes one server-resolved placement and original logical owner.
//! UploadIds, manifests and positive receipts are retained by the physical guard.
//! Expiry authenticates a request; it never settles provider effects or grants.
//!
//! ```text
//! request = {version, domain, deployment_id, operation_id, issued_at,
//!            expires_at, context, write_lease, read_lease, operation}
//! create -> delegated parts -> frozen manifest -> close -> immutable read
//!        -> destination create/copy parts/guarded complete
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::direct_upload::{
    DirectManifestCommitment, DirectManifestPart, DirectPart, DirectPlacement,
    DirectUploadAdmission, DirectUploadIntent, WireInteger,
};
use crate::storage_authority::{control::StorageAuthorityObjectScope, StorageGuardStamp};
use crate::storage_work::StorageWorkKey;

/// Internal endpoint for authenticated external multipart controls.
pub const EXTERNAL_STAGE_PATH: &str = "/_internal/storage/external-stage/v1";
/// Application signature header, distinct from public logical admission.
pub const EXTERNAL_STAGE_SIGNATURE_HEADER: &str = "x-aos-external-stage-signature";
/// Maximum canonical request, checked before parsing.
pub const MAX_EXTERNAL_STAGE_REQUEST_BYTES: usize = 256 * 1024;
/// Maximum part/grant members in one compact control.
pub const MAX_EXTERNAL_STAGE_BATCH: usize = 64;
/// Maximum selected context retained repeatedly in compact source proof records.
pub const MAX_EXTERNAL_STAGE_CONTEXT_BYTES: usize = 8 * 1024;

const DOMAIN: &str = "aos.external-stage-control.v1";
const AUTH_DOMAIN: &[u8] = b"aos.external-stage-control-auth.v1\0";

/// Immutable original owner/source and one required physical placement.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalStageContext {
    /// Exact deployment included by the original placement/admission commitments.
    pub deployment_id: String,
    /// Retained logical session selected before provider Create.
    pub session_id: String,
    /// Stable authenticated principal owning the original admission.
    pub principal_id: String,
    /// Complete original immutable admission fingerprint.
    pub logical_fingerprint: String,
    /// Original logical eligibility deadline, never extended by request renewal.
    pub logical_expires_at: WireInteger,
    /// Source/owner/geometry declaration, including client business operation.
    pub intent: DirectUploadIntent,
    /// Exact required placement, credentials, private policy and cohorts.
    pub placement: DirectPlacement,
}

impl ExternalStageContext {
    /// Selects one exact retained placement without selecting current SQL rows.
    ///
    /// # Errors
    /// Returns an error for absent/duplicate placements or invalid context.
    pub fn from_admission(
        admission: &DirectUploadAdmission,
        placement_id: WireInteger,
        deployment_id: &str,
    ) -> Result<Self> {
        admission.validate(deployment_id)?;
        let mut selected = admission
            .placements
            .iter()
            .filter(|p| p.placement_id == placement_id);
        let placement = selected
            .next()
            .ok_or_else(|| anyhow::anyhow!("external stage placement absent"))?
            .clone();
        ensure!(
            selected.next().is_none(),
            "duplicate external stage placement"
        );
        let value = Self {
            deployment_id: deployment_id.into(),
            session_id: admission.session_id.clone(),
            principal_id: admission.principal_id.clone(),
            logical_fingerprint: admission.logical_fingerprint.clone(),
            logical_expires_at: admission.expires_at,
            intent: admission.intent.clone(),
            placement,
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks bounded identity and exact source geometry before guard admission.
    ///
    /// # Errors
    /// Returns an error for invalid IDs, geometry, revision or physical key.
    pub fn validate(&self) -> Result<()> {
        identifier(&self.deployment_id)?;
        identifier(&self.session_id)?;
        identifier(&self.principal_id)?;
        digest(&self.logical_fingerprint)?;
        ensure!(
            self.logical_expires_at.get() > 0 && self.logical_expires_at.get() <= i64::MAX as u64,
            "invalid original logical eligibility deadline"
        );
        self.intent.validate()?;
        self.placement.validate(&self.deployment_id)?;
        ensure!(
            self.placement.placement_id.get() > 0
                && self.placement.placement_resource_version.get() > 0
                && self.placement.write_spec_version.get() > 0
                && self.placement.binding_id.get() > 0
                && self.placement.binding_resource_version.get() > 0
                && self.placement.binding_write_revision.get() > 0,
            "invalid external stage placement revision"
        );
        let crate::direct_upload::DirectPhysicalContext::External {
            write_cohort,
            read_cohort,
        } = &self.placement.physical
        else {
            anyhow::bail!("external stage requires external physical authority");
        };
        ensure!(
            write_cohort.authority == read_cohort.authority
                && write_cohort.executor_identity == read_cohort.executor_identity
                && write_cohort.association == read_cohort.association
                && write_cohort.alias == read_cohort.alias,
            "external stage read/write domain differs"
        );
        self.scope(false)?.guard_name()?;
        self.scope(true)?.guard_name()?;
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_EXTERNAL_STAGE_CONTEXT_BYTES,
            "external stage context exceeds compact journal budget"
        );
        Ok(())
    }

    /// Derives the never-reused private stage key from retained session identity.
    ///
    /// # Errors
    /// Returns an error for noncanonical original session or staging coordinates.
    pub fn stage_key(&self) -> Result<String> {
        crate::direct_upload::direct_staging_key(&self.session_id, &self.placement)
    }

    /// Selects the permanent physical guard scope for stage or final destination.
    ///
    /// # Errors
    /// Returns an error for a deployment-R2 context or noncanonical full key.
    pub fn scope(&self, destination: bool) -> Result<StorageAuthorityObjectScope> {
        let crate::direct_upload::DirectPhysicalContext::External { write_cohort, .. } =
            &self.placement.physical
        else {
            anyhow::bail!("external stage requires external authority");
        };
        let scope = StorageAuthorityObjectScope {
            guard_namespace_id: write_cohort.authority.guard_namespace_id.clone(),
            physical_authority_id: write_cohort.authority.authority_id.clone(),
            full_key: if destination {
                self.placement.final_key.clone()
            } else {
                self.stage_key()?
            },
        };
        scope.guard_name()?;
        Ok(scope)
    }

    /// Commits the complete immutable context without mutable request timing.
    ///
    /// # Errors
    /// Returns an error for an invalid context or encoding failure.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }
}

/// Exact delegated UploadPart capability recorded before its URL can escape.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalStageGrant {
    /// Stable retained capability identity.
    pub grant_id: String,
    /// Exact irreversible grant revision.
    pub grant_revision: WireInteger,
    /// Immutable part bytes and provider-enforced checksum.
    pub part: DirectPart,
    /// Original signing timestamp; replay does not move it forward.
    pub issued_at: WireInteger,
    /// Exclusive bearer expiry; it never settles dispatched part requests.
    pub expires_at: WireInteger,
}

/// Closed server controls; no arbitrary method, URL, credential or client final PUT.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalStageOperation {
    /// Creates the unique private staging multipart session.
    CreateStage,
    /// Registers exact delegated part capabilities before presigning.
    RegisterParts {
        /// Exact provider session acknowledged by Create.
        upload_id: String,
        /// Bounded ordered capability batch.
        grants: Vec<ExternalStageGrant>,
    },
    /// Closes grants and appends an exact bounded ordered manifest chunk.
    FreezeParts {
        /// Exact created provider session.
        upload_id: String,
        /// Complete manifest commitment, unchanged across chunks.
        manifest: DirectManifestCommitment,
        /// One-based first part in this chunk.
        first_part: u32,
        /// Exact immutable descriptors and provider ETags.
        parts: Vec<DirectManifestPart>,
    },
    /// Positively closes the exact frozen stage UploadId.
    CompleteStage {
        /// Exact provider session.
        upload_id: String,
        /// Exact complete retained manifest commitment.
        manifest: DirectManifestCommitment,
    },
    /// Reads and hashes only the immutable positively closed stage.
    VerifyClosedStage {
        /// Exact acknowledged closed UploadId.
        upload_id: Option<String>,
        /// Immutable positive-close receipt commitment.
        close_receipt_digest: String,
    },
    /// Positively aborts an incomplete stage; completed object cleanup is excluded.
    AbortStage {
        /// Exact acknowledged incomplete provider session.
        upload_id: String,
    },
    /// Reserves the final key and creates a private destination multipart session.
    CreateDestination {
        /// Exact immutable full-SHA verified source receipt.
        verified_stage_receipt_digest: String,
    },
    /// Copies one canonical range from the immutable stage into the destination.
    CopyDestinationPart {
        /// Exact acknowledged private destination session.
        upload_id: String,
        /// Source's immutable independently verified receipt.
        verified_stage_receipt_digest: String,
        /// Exact source bytes/range and expected checksum.
        part: DirectPart,
    },
    /// Makes only the exact verified destination manifest visible.
    CompleteDestination {
        /// Exact immutable full-SHA verified source receipt.
        verified_stage_receipt_digest: String,
        /// Exact acknowledged destination session.
        upload_id: String,
        /// Exact destination-specific complete ordered manifest.
        manifest: DirectManifestCommitment,
    },
    /// Accounts for incomplete destination removal without deleting an object.
    AbortDestination {
        /// Exact immutable full-SHA verified source receipt.
        verified_stage_receipt_digest: String,
        /// Exact acknowledged destination session.
        upload_id: String,
    },
}

impl ExternalStageOperation {
    /// Indicates whether the operation addresses the final physical key.
    #[must_use]
    pub fn destination(&self) -> bool {
        matches!(
            self,
            Self::CreateDestination { .. }
                | Self::CopyDestinationPart { .. }
                | Self::CompleteDestination { .. }
                | Self::AbortDestination { .. }
        )
    }

    /// Checks a bounded control against its exact original object declaration.
    ///
    /// # Errors
    /// Returns an error for malformed provider IDs, grants, parts or commitments.
    pub fn validate(&self, context: &ExternalStageContext) -> Result<()> {
        let expected_placement = context.placement.public_ref(&context.deployment_id)?;
        if let Self::CompleteDestination {
            verified_stage_receipt_digest,
            ..
        }
        | Self::AbortDestination {
            verified_stage_receipt_digest,
            ..
        } = self
        {
            digest(verified_stage_receipt_digest)?;
        }
        match self {
            ExternalStageOperation::RegisterParts { upload_id, grants } => {
                provider_id(upload_id)?;
                ensure!(
                    !grants.is_empty() && grants.len() <= MAX_EXTERNAL_STAGE_BATCH,
                    "external stage grant batch invalid"
                );
                let mut identities = std::collections::BTreeSet::new();
                for grant in grants {
                    ensure!(
                        identities.insert(&grant.grant_id),
                        "duplicate delegated grant identity"
                    );
                    identifier(&grant.grant_id)?;
                    ensure!(
                        grant.grant_revision.get() > 0 && grant.expires_at > grant.issued_at,
                        "external stage grant horizon invalid"
                    );
                    grant.part.validate(&context.intent)?;
                }
            }
            ExternalStageOperation::FreezeParts {
                upload_id,
                manifest,
                first_part,
                parts,
            } => {
                provider_id(upload_id)?;
                digest(&manifest.manifest_digest)?;
                ensure!(
                    manifest.placement == expected_placement,
                    "external manifest placement differs"
                );
                ensure!(
                    *first_part > 0
                        && !parts.is_empty()
                        && parts.len() <= MAX_EXTERNAL_STAGE_BATCH
                        && manifest.part_count == context.intent.part_count()?,
                    "external stage manifest chunk invalid"
                );
                for (offset, part) in parts.iter().enumerate() {
                    ensure!(
                        part.part.part_number as u64 == u64::from(*first_part) + offset as u64,
                        "external stage manifest chunk unordered"
                    );
                    part.part.validate(&context.intent)?;
                    ensure!(
                        crate::direct_upload::valid_direct_etag(&part.etag),
                        "external stage ETag invalid"
                    );
                }
            }
            ExternalStageOperation::CompleteStage {
                upload_id,
                manifest,
            }
            | ExternalStageOperation::CompleteDestination {
                upload_id,
                manifest,
                ..
            } => {
                provider_id(upload_id)?;
                digest(&manifest.manifest_digest)?;
                ensure!(
                    manifest.placement == expected_placement,
                    "external manifest placement differs"
                );
                ensure!(
                    manifest.part_count == context.intent.part_count()?,
                    "external stage manifest count differs"
                );
            }
            ExternalStageOperation::VerifyClosedStage {
                upload_id,
                close_receipt_digest,
            } => {
                if let Some(upload_id) = upload_id {
                    provider_id(upload_id)?;
                }
                ensure!(
                    upload_id.is_some() == (context.intent.byte_size.get() > 0),
                    "external stage closure kind differs"
                );
                digest(close_receipt_digest)?;
            }
            ExternalStageOperation::AbortStage { upload_id }
            | ExternalStageOperation::AbortDestination { upload_id, .. } => provider_id(upload_id)?,
            ExternalStageOperation::CreateDestination {
                verified_stage_receipt_digest,
            } => digest(verified_stage_receipt_digest)?,
            ExternalStageOperation::CopyDestinationPart {
                upload_id,
                verified_stage_receipt_digest,
                part,
            } => {
                provider_id(upload_id)?;
                digest(verified_stage_receipt_digest)?;
                part.validate(&context.intent)?;
            }
            ExternalStageOperation::CreateStage => {}
        }
        Ok(())
    }

    /// Identifies the one safe repeated observation of an immutable closed source.
    #[must_use]
    pub fn immutable_read(&self) -> bool {
        matches!(self, Self::VerifyClosedStage { .. })
    }
}

/// Selects fresh eligibility or the exact previously retained immutable read.
///
/// Recovery does not extend mutation, publication or logical commit eligibility.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalStageAdmissionMode {
    /// Requires the original logical owner to remain eligible.
    Fresh,
    /// Resumes only an exact pending read of a positively closed private stage.
    ResumeImmutableRead,
}

/// Authenticated short-lived control; historical receipt identity excludes leases/time.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalStageRequest {
    /// Protocol version, currently one.
    pub version: u8,
    /// Closed external-stage application domain.
    pub domain: String,
    /// Independently configured deployment identity.
    pub deployment_id: String,
    /// Stable retained business-effect identity.
    pub operation_id: String,
    /// Authentication issuance, separate from grant/settlement horizons.
    pub issued_at: WireInteger,
    /// Exclusive authentication expiry, at most30 seconds after issuance.
    pub expires_at: WireInteger,
    /// Complete original owner and selected immutable placement.
    pub context: ExternalStageContext,
    /// Fresh exact write lease for actual controls or delegated admission.
    pub write_lease: String,
    /// Fresh exact read lease for stage verification/copy source.
    pub read_lease: String,
    /// Required MAC-covered eligibility mode; never defaults on the wire.
    pub admission_mode: ExternalStageAdmissionMode,
    /// One closed retained effect or metadata operation.
    pub operation: ExternalStageOperation,
}

impl ExternalStageRequest {
    /// Constructs a domain-bound request without choosing provider coordinates.
    #[must_use]
    pub fn new(
        deployment_id: String,
        operation_id: String,
        issued_at: WireInteger,
        expires_at: WireInteger,
        context: ExternalStageContext,
        write_lease: String,
        read_lease: String,
        operation: ExternalStageOperation,
    ) -> Self {
        Self {
            version: 1,
            domain: DOMAIN.into(),
            deployment_id,
            operation_id,
            issued_at,
            expires_at,
            context,
            write_lease,
            read_lease,
            admission_mode: ExternalStageAdmissionMode::Fresh,
            operation,
        }
    }

    /// Signs only a closed bounded canonical control with a protected executor key.
    ///
    /// # Errors
    /// Returns an error for invalid scope/time, unsupported shape or size.
    pub fn sign(
        &self,
        key: &StorageWorkKey,
        deployment_id: &str,
        now: i64,
    ) -> Result<(Vec<u8>, String)> {
        self.validate(deployment_id, now)?;
        let body = serde_json::to_vec(self)?;
        ensure!(
            body.len() <= MAX_EXTERNAL_STAGE_REQUEST_BYTES,
            "external stage control oversized"
        );
        let protected = [AUTH_DOMAIN, body.as_slice()].concat();
        Ok((body, key.sign_body(&protected)?))
    }

    /// Authenticates before parsing and rejects noncanonical or unknown input.
    ///
    /// # Errors
    /// Returns an error for invalid signature, format, bounds, deployment or time.
    pub fn authenticate(
        key: &StorageWorkKey,
        signature: &str,
        bytes: &[u8],
        deployment_id: &str,
        now: i64,
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_EXTERNAL_STAGE_REQUEST_BYTES,
            "external stage control oversized"
        );
        key.verify_body(signature, &[AUTH_DOMAIN, bytes].concat())?;
        let value: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&value)? == bytes,
            "external stage control noncanonical"
        );
        value.validate(deployment_id, now)?;
        Ok(value)
    }

    /// Checks request time and immutable context without claiming current authority.
    ///
    /// # Errors
    /// Returns an error for malformed or stale authentication and request shape.
    pub fn validate(&self, deployment_id: &str, now: i64) -> Result<()> {
        ensure!(
            self.version == 1
                && self.domain == DOMAIN
                && self.deployment_id == deployment_id
                && self.context.deployment_id == deployment_id,
            "external stage domain differs"
        );
        identifier(&self.operation_id)?;
        let issued = i64::try_from(self.issued_at.get())?;
        let expires = i64::try_from(self.expires_at.get())?;
        ensure!(
            issued <= now.saturating_add(5)
                && now < expires
                && expires > issued
                && expires - issued <= 30,
            "external stage authentication expired"
        );
        ensure!(
            self.write_lease.len() <= super::super::lease::MAX_EPOCH_LEASE_BYTES
                && self.read_lease.len() <= super::super::lease::MAX_EPOCH_LEASE_BYTES,
            "external stage lease oversized"
        );
        self.context.validate()?;
        self.operation.validate(&self.context)?;
        ensure!(
            self.admission_mode == ExternalStageAdmissionMode::Fresh
                || self.operation.immutable_read(),
            "read recovery cannot authorize a mutation"
        );
        Ok(())
    }

    /// Rechecks scalar permission time after all cryptographic validation.
    ///
    /// The executor invokes this without an intervening await immediately before
    /// the provider Fetch. Recovery mode requires a separately admitted exact
    /// pending immutable read from the physical guard; this scalar check alone
    /// cannot establish that identity or extend logical commit eligibility.
    ///
    /// # Errors
    /// Returns an error for clock regression/uncertainty or expired lease,
    /// application authentication or binding publication.
    pub fn check_dispatch_time(
        &self,
        snapshot: &crate::storage_work::StorageBindingSnapshot,
        validated: &super::super::lease::ValidatedEpochLease,
        floor: &super::super::lease::EpochLeaseFloor,
        clock: super::super::lease::LeaseClock,
    ) -> Result<()> {
        ensure!(
            self.admission_mode == ExternalStageAdmissionMode::Fresh
                || self.operation.immutable_read(),
            "read recovery cannot authorize a mutation"
        );
        let payload = &validated.payload;
        ensure!(
            clock.observed_at >= floor.clock_floor.get()
                && clock.uncertainty >= 0
                && clock.uncertainty <= payload.timing_profile.maximum_clock_uncertainty.get(),
            "unqualified final stage dispatch clock"
        );
        let earliest = clock
            .observed_at
            .checked_sub(clock.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("stage clock underflow"))?;
        let latest = clock
            .observed_at
            .checked_add(clock.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("stage clock overflow"))?;
        ensure!(
            earliest >= 0 && payload.issued_at.get() <= latest && latest < payload.not_after.get(),
            "stage lease expired at provider dispatch"
        );
        let issued = i64::try_from(self.issued_at.get())?;
        let expires = i64::try_from(self.expires_at.get())?;
        ensure!(
            issued <= clock.observed_at.saturating_add(5)
                && clock.observed_at < expires
                && (self.admission_mode == ExternalStageAdmissionMode::ResumeImmutableRead
                    || clock.observed_at < i64::try_from(self.context.logical_expires_at.get())?)
                && snapshot.issued_at <= clock.observed_at.saturating_add(5)
                && clock.observed_at <= snapshot.expires_at,
            "stage application permission expired at provider dispatch"
        );
        Ok(())
    }
}

/// Positive retained outcome, never a guessed HEAD/expiry reconciliation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalStageOutcome {
    /// A real acknowledged empty-object PUT; no synthetic multipart identity.
    EmptyClosed {
        /// Strong provider acknowledgement ETag.
        etag: String,
        /// Guard-issued physical incarnation after acknowledgement.
        guard_stamp: StorageGuardStamp,
    },
    /// Exact provider session positively acknowledged by Create.
    Created {
        /// Nonsecret retained provider UploadId.
        upload_id: String,
    },
    /// Delegated part descriptors/horizons committed before capability exposure.
    Registered,
    /// Exact manifest chunk committed and new delegated grants closed.
    Frozen {
        /// Number of ordered parts durably frozen so far.
        part_count: u32,
    },
    /// Exact multipart completion positively closes this provider UploadId.
    Closed {
        /// Exact closed provider UploadId, distinct from guard incarnation.
        upload_id: String,
        /// Positive provider completion ETag.
        etag: String,
        /// Guard-issued physical incarnation after acknowledgement.
        guard_stamp: StorageGuardStamp,
    },
    /// Full stream hash and size of the immutable positively closed source.
    Verified {
        /// Exact independently computed full SHA-256.
        sha256: String,
        /// Exact independently counted bytes.
        byte_size: WireInteger,
        /// Original immutable close receipt.
        close_receipt_digest: String,
    },
    /// Exact provider Copy part positively acknowledged.
    Copied {
        /// Exact copied immutable part descriptor.
        part: DirectPart,
        /// Strong positive provider part ETag.
        etag: String,
    },
    /// Exact incomplete multipart Abort positively acknowledged.
    Aborted {
        /// Exact provider UploadId, not completed-object deletion.
        upload_id: String,
    },
}

/// Historical immutable effect receipt returned without repeating provider I/O.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalStageResult {
    /// Protocol version, currently one.
    pub version: u8,
    /// Exact original retained business effect identity.
    pub operation_id: String,
    /// Complete immutable context/effect commitment.
    pub intent_digest: String,
    /// Exact immutable terminal receipt commitment.
    pub receipt_digest: String,
    /// Positive historical acknowledgement; source verification requires closure.
    pub outcome: ExternalStageOutcome,
}

fn identifier(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'_' | b'.' | b':')),
        "invalid external stage identity"
    );
    Ok(())
}

fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid external stage commitment"
    );
    Ok(())
}

fn provider_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control),
        "invalid external stage provider session"
    );
    Ok(())
}
