//! Current SQL metadata permission for copy profile and retained-owner discovery.
//!
//! This query neither observes provider bytes nor authorizes a physical effect.
//! Native supplies both independently resolved placements and the actual claim;
//! Worker describes only its installed copy domain and genuine retained owner.
//!
//! ```text
//! request = {version, topology, source, destination, claim, plan, path}
//! reply = {request_digest, profile, retained: null | {original, progress}}
//! ```

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::{
    CopyPlacementPin, CopyTopologyOriginal, ExternalCopyOriginal,
    control::{CopyClaim, CopyProgress, MAX_EXTERNAL_COPY_CONTROL_BYTES},
    digest_string, identifier,
    original_lookup::CopyOriginalSelector,
};
use crate::{
    direct_upload::{MAX_DIRECT_PART_BYTES, MIN_DIRECT_PART_BYTES},
    storage_authority::{canonical_digest, lease::LeaseInteger},
    storage_work::{StorageWorkKey, StorageWorkOperation, StorageWorkPlan},
};

/// Authenticated internal metadata query with no provider dispatch capability.
pub const EXTERNAL_COPY_METADATA_PATH: &str = "/_internal/storage/external-copy-metadata/v1";
const DOMAIN: &str = "aos.external-copy-metadata.v1";
const REPLY_DOMAIN: &[u8] = b"aos.external-copy-metadata-reply.v1\0";

/// Selects the installed copy profile and existing owner under a live SQL claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyMetadataRequest {
    /// Closed metadata version.
    pub version: u8,
    /// Independent application domain.
    pub domain: String,
    /// Genuine immutable scheduled operation and target permissions.
    pub topology: CopyTopologyOriginal,
    /// Exact source row resolved from its sealed stable target.
    pub source: CopyPlacementPin,
    /// Exact destination row resolved from its sealed stable target.
    pub destination: CopyPlacementPin,
    /// Actual live SQL claim when present; absent for authorized failed-original diagnosis.
    /// Neither form permits provider dispatch through this read-only endpoint.
    pub claim: Option<CopyClaim>,
    /// Fresh destination HEAD-shaped metadata permission, never executed as HEAD.
    pub plan: StorageWorkPlan,
    /// Exact bounded inventory path.
    pub path: String,
    /// Requests only the installed profile, without owner or closure discovery.
    /// This read-only form still requires the exact current controller claim.
    #[serde(default, skip_serializing_if = "is_false")]
    pub profile_only: bool,
    /// Independent source Read plan for different bindings; old queries omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_plan: Option<StorageWorkPlan>,
}

impl CopyMetadataRequest {
    /// Creates a bounded read-only permission from actual SQL projections.
    ///
    /// # Errors
    /// Refuses malformed current pins, a foreign plan or an expired claim.
    pub fn new(
        topology: CopyTopologyOriginal,
        source: CopyPlacementPin,
        destination: CopyPlacementPin,
        claim: Option<CopyClaim>,
        plan: StorageWorkPlan,
        path: String,
        now: i64,
    ) -> Result<Self> {
        let value = Self {
            version: 1,
            domain: DOMAIN.into(),
            topology,
            source,
            destination,
            claim,
            plan,
            path,
            profile_only: false,
            source_plan: None,
        };
        value.validate(&value.plan.deployment_id, now)?;
        Ok(value)
    }

    /// Creates a paired query from independently resolved source/destination plans.
    ///
    /// # Errors
    /// Refuses a missing source Read scope, changed pins or expired permission.
    pub fn new_cross_binding(
        topology: CopyTopologyOriginal,
        source: CopyPlacementPin,
        destination: CopyPlacementPin,
        claim: Option<CopyClaim>,
        plan: StorageWorkPlan,
        source_plan: StorageWorkPlan,
        path: String,
        now: i64,
    ) -> Result<Self> {
        let value = Self {
            version: 1,
            domain: DOMAIN.into(),
            topology,
            source,
            destination,
            claim,
            plan,
            path,
            profile_only: false,
            source_plan: Some(source_plan),
        };
        value.validate(&value.plan.deployment_id, now)?;
        Ok(value)
    }

    /// Checks the exact current metadata selector without granting provider I/O.
    ///
    /// # Errors
    /// Refuses stale claims, different placements, cross-binding geometry or another operation.
    pub fn validate(&self, deployment: &str, now: i64) -> Result<()> {
        self.validate_checked(deployment, Some(now))
    }

    /// Checks a retained envelope's intrinsic shape without current permission.
    ///
    /// This observation neither authenticates a MAC nor reauthorizes the SQL
    /// claim. Its exact original window remains checked without inventing a
    /// historical validation clock.
    ///
    /// # Errors
    /// Returns an error for malformed pins, plan geometry, intrinsic deadlines,
    /// changed credential selectors or an excessive encoded envelope.
    pub fn validate_observation_shape(&self, deployment: &str) -> Result<()> {
        self.validate_checked(deployment, None)
    }

    fn validate_checked(&self, deployment: &str, now: Option<i64>) -> Result<()> {
        self.topology.validate()?;
        self.source.validate(&self.topology.source)?;
        self.destination.validate(&self.topology.destination)?;
        match now {
            Some(now) => self.plan.validate(deployment, now)?,
            None => self.plan.validate_observation_shape(deployment)?,
        }
        let binding_geometry = if let Some(source_plan) = &self.source_plan {
            match now {
                Some(now) => source_plan.validate(deployment, now)?,
                None => source_plan.validate_observation_shape(deployment)?,
            }
            ensure!(
                source_plan.binding_id == self.source.binding_id.get()
                    && source_plan.placement_id == self.source.placement_id.get()
                    && source_plan.placement_resource_version == self.source.resource_version.get()
                    && source_plan.placement_prefix == self.source.prefix
                    && matches!(&source_plan.operation, StorageWorkOperation::Head { path } if path == &self.path)
                    && matches!(source_plan.binding_kind.as_str(), "s3" | "r2")
                    && source_plan
                        .binding_snapshot_revision
                        .as_deref()
                        .is_some_and(digest_string)
                    && source_plan.credential_references.len() == 1
                    && source_plan.credential_references[0].purpose == "read"
                    && source_plan.issued_at == self.plan.issued_at
                    && source_plan.expires_at == self.plan.expires_at,
                "copy metadata source Read permission differs"
            );
            self.source.binding_id != self.destination.binding_id
        } else {
            self.source.binding_id == self.destination.binding_id
                && self.source.prefix != self.destination.prefix
        };
        ensure!(
            self.version == 1
                && self.domain == DOMAIN
                && (!self.profile_only || self.claim.is_some())
                && matches!(&self.plan.operation, StorageWorkOperation::Head { path } if path == &self.path)
                && self.plan.placement_id == self.destination.placement_id.get()
                && self.plan.placement_resource_version == self.destination.resource_version.get()
                && self.plan.placement_prefix == self.destination.prefix
                && self.plan.binding_id == self.destination.binding_id.get()
                && binding_geometry
                && self.source.placement_id != self.destination.placement_id
                && self.source.registry_id == self.destination.registry_id
                && self.source.cache_id == self.destination.cache_id
                && matches!(self.plan.binding_kind.as_str(), "s3" | "r2")
                && self
                    .plan
                    .binding_snapshot_revision
                    .as_deref()
                    .is_some_and(digest_string)
                && self.plan.credential_references.len() == 1
                && self.plan.credential_references[0].purpose == "read"
                && self
                    .claim
                    .as_ref()
                    .is_none_or(|claim| claim.operation_resource_version.get() > 0
                        && claim.claim_token.len() == 32
                        && claim
                            .claim_token
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        && self.plan.expires_at < claim.expires_at.get()
                        && now.is_none_or(|now| claim.expires_at.get() > now))
                && serde_json::to_vec(self)?.len() <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
            "copy metadata differs from current SQL permission"
        );
        Ok(())
    }

    /// Signs only the exact closed read-only query.
    ///
    /// # Errors
    /// Refuses invalid current permission, encoding or signing failure.
    pub fn sign(
        &self,
        key: &StorageWorkKey,
        deployment: &str,
        now: i64,
    ) -> Result<(Vec<u8>, String)> {
        self.validate(deployment, now)?;
        let body = serde_json::to_vec(self)?;
        Ok((body.clone(), key.sign_body(&body)?))
    }

    /// Authenticates canonical bounded bytes before interpreting query selectors.
    ///
    /// # Errors
    /// Refuses oversized, unauthenticated, noncanonical or expired queries.
    pub fn authenticate(
        key: &StorageWorkKey,
        signature: &str,
        body: &[u8],
        deployment: &str,
        now: i64,
    ) -> Result<Self> {
        ensure!(
            body.len() <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
            "copy metadata oversized"
        );
        key.verify_body(signature, body)?;
        let value: Self = serde_json::from_slice(body)?;
        ensure!(
            serde_json::to_vec(&value)? == body,
            "noncanonical copy metadata"
        );
        value.validate(deployment, now)?;
        Ok(value)
    }
}

/// Describes independently installed execution geometry without granting a lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyMetadataProfile {
    /// Exact association stable identity independently checked against SQL.
    pub binding_stable_id: String,
    /// Exact immutable SQL writer revision.
    pub binding_write_revision: LeaseInteger,
    /// Full independently installed copy domain commitment.
    pub profile_digest: String,
    /// Installed bounded multipart geometry.
    pub part_bytes: LeaseInteger,
    /// Installed purpose-local read generation.
    pub read_generation: LeaseInteger,
    /// Installed purpose-local write generation.
    pub write_generation: LeaseInteger,
    /// Selects only protected versionless originals; absent on version-one wire.
    #[serde(default, skip_serializing_if = "is_false")]
    pub protected_versionless: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

/// Returns the actual retained immutable owner and compact progress, without private receipts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedCopyOriginal {
    /// Full genuine original from guard storage; never reconstructed from HEAD.
    pub original: ExternalCopyOriginal,
    /// Compact validated durable phase and positive destination identity.
    pub progress: CopyProgress,
}

/// Binds installed metadata and optional retained original to the exact current query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyMetadataReply {
    /// Closed reply version.
    pub version: u8,
    /// Canonical current query commitment including deadline and claim.
    pub request_digest: String,
    /// Exact installed copy profile projection.
    pub profile: CopyMetadataProfile,
    /// Genuine existing owner; absence grants no physical effect.
    pub retained: Option<RetainedCopyOriginal>,
    /// Actual current source closure, required before new versionless admission.
    /// Absence never authorizes an unknown or discovered source object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_closure: Option<super::source::CopySourceClosure>,
    /// Independently installed source Read and destination mode projections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer: Option<super::transfer::CopyTransferPins>,
}

impl CopyMetadataReply {
    /// Reconstructs only the selector pins from this authenticated installed projection.
    ///
    /// # Errors
    /// Refuses changed query, association, generation, geometry or retained owner.
    pub fn selector(&self, request: &CopyMetadataRequest) -> Result<CopyOriginalSelector> {
        ensure!(
            !request.profile_only || (self.retained.is_none() && self.source_closure.is_none()),
            "profile-only metadata cannot contain physical owner evidence"
        );
        identifier(&self.profile.binding_stable_id)?;
        let source_protected = match (&self.transfer, &request.source_plan) {
            (Some(transfer), Some(plan)) => {
                transfer.validate(&request.source, &request.destination)?;
                ensure!(
                    transfer.source_binding.binding_resource_version.get()
                        == plan.binding_resource_version
                        && plan.binding_snapshot_revision.as_ref()
                            == Some(&transfer.source_binding.snapshot_revision)
                        && plan
                            .credential_references
                            .first()
                            .is_some_and(|credential| credential.purpose == "read"
                                && credential.generation
                                    == transfer.source_binding.read_generation.get())
                        && self.profile.part_bytes.get()
                            <= transfer.maximum_source_range_bytes.get()
                        && (transfer.destination_incarnation
                            == super::transfer::CopyIncarnationMode::GuardedClosure)
                            == self.profile.protected_versionless,
                    "copy installed source Read projection differs"
                );
                transfer.source_incarnation == super::transfer::CopyIncarnationMode::GuardedClosure
            }
            (None, None) => self.profile.protected_versionless,
            _ => anyhow::bail!("copy metadata paired source projection absent"),
        };
        ensure!(
            self.version == 1
                && self.request_digest == canonical_digest(request)?
                && self.profile.binding_write_revision.get() > 0
                && digest_string(&self.profile.profile_digest)
                && request
                    .plan
                    .credential_references
                    .first()
                    .is_some_and(|selector| selector.purpose == "read"
                        && selector.generation == self.profile.read_generation.get())
                && self.profile.write_generation.get() > 0
                && (MIN_DIRECT_PART_BYTES..=MAX_DIRECT_PART_BYTES)
                    .contains(&(self.profile.part_bytes.get() as u64)),
            "copy metadata profile differs"
        );
        if let Some(closure) = &self.source_closure {
            closure.validate()?;
            ensure!(
                source_protected,
                "versioned copy metadata cannot contain a protected closure"
            );
        }
        let selector = CopyOriginalSelector {
            deployment_id: request.plan.deployment_id.clone(),
            topology: request.topology.clone(),
            source: request.source.clone(),
            destination: request.destination.clone(),
            path: request.path.clone(),
            binding_stable_id: self.profile.binding_stable_id.clone(),
            binding_resource_version: LeaseInteger::new(request.plan.binding_resource_version)?,
            snapshot_revision: request
                .plan
                .binding_snapshot_revision
                .clone()
                .ok_or_else(|| anyhow::anyhow!("copy metadata snapshot absent"))?,
            profile_digest: self.profile.profile_digest.clone(),
            transfer: self.transfer.clone(),
        };
        selector.validate()?;
        if let Some(retained) = &self.retained {
            selector.validate_retained(&retained.original, &retained.progress)?;
            ensure!(
                (retained.original.destination_incarnation()?
                    == super::transfer::CopyIncarnationMode::GuardedClosure)
                    == self.profile.protected_versionless
                    && retained.original.binding_write_revision
                        == self.profile.binding_write_revision
                    && retained.original.read_generation
                        == self
                            .transfer
                            .as_ref()
                            .map_or(self.profile.read_generation, |transfer| transfer
                                .source_binding
                                .read_generation)
                    && retained.original.write_generation == self.profile.write_generation
                    && retained.original.part_bytes == self.profile.part_bytes,
                "retained copy installed purpose pins changed"
            );
        }
        Ok(selector)
    }

    /// Correlates bounded retained metadata without authenticating permission.
    ///
    /// # Errors
    /// Returns an error for malformed original shape, different installed
    /// profile or retained owner, impossible progress or excessive encoding.
    pub fn validate_observation_for(&self, request: &CopyMetadataRequest) -> Result<()> {
        request.validate_observation_shape(&request.plan.deployment_id)?;
        self.selector(request)?;
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
            "oversized copy metadata observation reply"
        );
        Ok(())
    }

    /// Signs a bounded read-only response with an independent reply domain.
    ///
    /// # Errors
    /// Refuses changed query/profile/original pins or oversized encoding.
    pub fn sign(
        &self,
        key: &StorageWorkKey,
        request: &CopyMetadataRequest,
    ) -> Result<(Vec<u8>, String)> {
        self.selector(request)?;
        let body = serde_json::to_vec(self)?;
        ensure!(
            body.len() <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
            "copy metadata reply oversized"
        );
        Ok((
            body.clone(),
            key.sign_body(&[REPLY_DOMAIN, &body].concat())?,
        ))
    }

    /// Authenticates exact bounded profile/owner metadata under current permission time.
    ///
    /// # Errors
    /// Refuses wrong key/domain/query, noncanonical bytes, invalid owner or expiry.
    pub fn authenticate(
        key: &StorageWorkKey,
        signature: &str,
        body: &[u8],
        request: &CopyMetadataRequest,
        deployment: &str,
        now: i64,
    ) -> Result<Self> {
        request.validate(deployment, now)?;
        ensure!(
            body.len() <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
            "copy metadata reply oversized"
        );
        key.verify_body(signature, &[REPLY_DOMAIN, body].concat())?;
        let value: Self = serde_json::from_slice(body)?;
        ensure!(
            serde_json::to_vec(&value)? == body,
            "noncanonical copy metadata reply"
        );
        value.selector(request)?;
        Ok(value)
    }
}
