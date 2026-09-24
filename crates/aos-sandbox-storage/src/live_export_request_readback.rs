//! Read-only Storage inspection of a signed LocalLive export request.
//!
//! This is an internal receipt precursor, not an export authority or socket
//! endpoint. It authenticates both request signers from Storage-owned trust,
//! checks current Storage publication, and reopens the physical workspace
//! origin. Provider's selected catalog row and protected attempt are not yet
//! independently proven current to Storage, so this type exposes no source FD
//! or lease-signing path. The ingress durably fences exact replay, but a future
//! issuer still needs that separate proof and the enforcing kernel grant.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedStorageLiveExportRequestV1, SourceResourceV1, StorageLiveExportSelectorV1,
    StorageLiveExportSourceV1, digest_signed_request,
};
use sha2::{Digest as _, Sha256};

use crate::live_export_catalog::{StorageLiveExportCatalogErrorV1, StorageLiveExportCatalogV1};
use crate::live_export_clone::{
    StorageLiveExportCloneErrorV1, StorageLiveExportCloneLedgerV1, StorageLiveExportCloneV1,
};
use crate::live_export_consumer_claim::AuthenticatedNamedConsumerClaimV1;
use crate::live_export_origin::StorageLiveExportOriginV1;
use crate::live_export_request_trust::{
    StorageLiveExportRequestTrustErrorV1, StorageLiveExportRequestTrustV1,
};
use crate::runtime::{StorageBrokerRuntime, StorageRuntimeError};

const READBACK_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-request-readback.v1\0";

/// Reports a failed non-authorizing request inspection.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageLiveExportReadbackErrorV1 {
    /// The canonical signed plan is malformed.
    #[error("Storage live-export request is noncanonical")]
    Request,
    /// Protected trust or either independent request signature failed.
    #[error("Storage live-export request trust failed: {0}")]
    Trust(#[from] StorageLiveExportRequestTrustErrorV1),
    /// The current export publication is unavailable or differs.
    #[error("Storage live-export publication failed: {0}")]
    Catalog(#[from] StorageLiveExportCatalogErrorV1),
    /// The current workspace origin could not be physically reobserved.
    #[error("Storage live-export origin failed: {0}")]
    Origin(#[from] StorageRuntimeError),
    /// The request interval or RootMount deadline is no longer current.
    #[error("Storage live-export request is not current")]
    Expired,
    /// The signed selector differs from the current protected export.
    #[error("Storage live-export selector differs from current publication")]
    Selector,
    /// The private detached clone or its durable custody could not be verified.
    #[error("Storage live-export clone failed: {0}")]
    Clone(#[from] StorageLiveExportCloneErrorV1),
}

/// Holds one verified but non-authorizing Storage request readback.
///
/// The private root FD keeps the checked physical object live only while this
/// value exists. No source descriptor, Storage signature, or grant can be
/// obtained through this type.
pub(crate) struct StorageLiveExportReadbackV1 {
    provider_authority_id: [u8; 16],
    provider_generation: u64,
    plan_id: [u8; 16],
    signed_request_digest: ObjectDigest,
    signed_root_request_digest: ObjectDigest,
    holder_authority_id: [u8; 16],
    holder_generation: u64,
    holder_authority_digest: ObjectDigest,
    expires_seconds: i64,
    named_consumer: AuthenticatedNamedConsumerClaimV1,
    claimed_resource: SourceResourceV1,
    source: StorageLiveExportSourceV1,
    _origin: StorageLiveExportOriginV1,
}

impl StorageLiveExportReadbackV1 {
    /// Returns the Provider-scoped replay identity established by both pins.
    #[must_use]
    pub(crate) const fn replay_identity(&self) -> ([u8; 16], u64, [u8; 16]) {
        (
            self.provider_authority_id,
            self.provider_generation,
            self.plan_id,
        )
    }

    /// Returns the complete signed request digest for future durable replay.
    #[must_use]
    pub(crate) const fn signed_request_digest(&self) -> ObjectDigest {
        self.signed_request_digest
    }

    /// Returns the embedded signed RootMount request digest.
    #[must_use]
    pub(crate) const fn signed_root_request_digest(&self) -> ObjectDigest {
        self.signed_root_request_digest
    }

    /// Returns the independently signed RootMount holder binding.
    #[must_use]
    pub(crate) const fn holder_binding(&self) -> ([u8; 16], u64, ObjectDigest) {
        (
            self.holder_authority_id,
            self.holder_generation,
            self.holder_authority_digest,
        )
    }

    /// Returns the signed Provider plan's exclusive expiry.
    #[must_use]
    pub(crate) const fn expires_seconds(&self) -> i64 {
        self.expires_seconds
    }

    /// Returns names extracted only from Storage's dual-authenticated request.
    #[must_use]
    pub(crate) const fn named_consumer(&self) -> AuthenticatedNamedConsumerClaimV1 {
        self.named_consumer
    }

    /// Returns the Provider-claimed row, not an independently current row.
    #[must_use]
    pub(crate) const fn claimed_resource(&self) -> &SourceResourceV1 {
        &self.claimed_resource
    }

    /// Returns Storage's current catalog and physical-origin observation.
    #[must_use]
    pub(crate) const fn source(&self) -> StorageLiveExportSourceV1 {
        self.source
    }

    /// Commits the request and Storage source observation without signing it.
    #[must_use]
    pub(crate) fn digest(&self) -> ObjectDigest {
        let source = self.source;
        let mut hasher = Sha256::new();
        hasher.update(READBACK_DIGEST_DOMAIN);
        hasher.update(self.signed_request_digest.as_bytes());
        hasher.update(self.signed_root_request_digest.as_bytes());
        hasher.update(self.claimed_resource.resource_namespace_digest().as_bytes());
        hasher.update(self.claimed_resource.resource_id());
        hasher.update(self.claimed_resource.resource_generation().to_be_bytes());
        hasher.update(self.claimed_resource.resource_digest().as_bytes());
        hasher.update(self.claimed_resource.catalog_generation().to_be_bytes());
        hasher.update(self.claimed_resource.catalog_digest().as_bytes());
        hasher.update(self.claimed_resource.selection_generation().to_be_bytes());
        hasher.update(self.claimed_resource.selection_digest().as_bytes());
        hasher.update(source.source_assignment_digest().as_bytes());
        hasher.update(source.owner_sandbox());
        hasher.update(source.source_incarnation());
        hasher.update(source.export_id());
        hasher.update(source.export_generation().to_be_bytes());
        hasher.update(source.export_revocation_digest().as_bytes());
        hasher.update(source.workspace_id());
        hasher.update(source.workspace_digest().as_bytes());
        hasher.update(source.origin_boot_id());
        hasher.update(source.origin_device().to_be_bytes());
        hasher.update(source.origin_inode().to_be_bytes());
        hasher.update(source.origin_mount_id().to_be_bytes());
        ObjectDigest::from_bytes(hasher.finalize().into())
    }
}

/// Owns protected signer pins and the current Storage export catalog.
pub(crate) struct StorageLiveExportRequestReadbackOwnerV1 {
    trust: StorageLiveExportRequestTrustV1,
    catalog: StorageLiveExportCatalogV1,
}

impl StorageLiveExportRequestReadbackOwnerV1 {
    /// Opens root-owned trust/catalog input and protected writable journal.
    ///
    /// # Errors
    ///
    /// Returns trust or catalog errors for missing, unsafe, stale, or
    /// noncanonical protected inputs.
    pub(crate) fn open_root_owned(
        authority_directory: &Path,
        state_directory: &Path,
    ) -> Result<Self, StorageLiveExportReadbackErrorV1> {
        let trust = StorageLiveExportRequestTrustV1::open_root_owned(authority_directory)?;
        let catalog =
            StorageLiveExportCatalogV1::open_root_owned(authority_directory, state_directory)?;
        Ok(Self { trust, catalog })
    }

    /// Inspects a signed plan against current Storage publication and origin.
    ///
    /// The signed Provider resource is retained only as a claim. The absent
    /// Provider selected-row/current-attempt proof prevents a lease, socket FD
    /// response, or backend feature advertisement from this result.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed or unauthenticated bytes, stale
    /// time, changed signer/catalog custody, selector mismatch, or missing or
    /// changed physical workspace origin.
    pub(crate) fn inspect(
        &self,
        runtime: &mut StorageBrokerRuntime,
        signed_request_bytes: &[u8],
        deadline_boottime_nanoseconds: u64,
    ) -> Result<StorageLiveExportReadbackV1, StorageLiveExportReadbackErrorV1> {
        self.trust.validate_current()?;
        self.catalog.validate_current()?;
        let signed_request =
            SignedStorageLiveExportRequestV1::from_canonical_bytes(signed_request_bytes)
                .map_err(|_| StorageLiveExportReadbackErrorV1::Request)?;
        self.trust.verify(&signed_request)?;
        validate_plan_identity(
            signed_request.request().plan_id(),
            signed_request.request().effect_id(),
        )?;
        validate_time(&signed_request)?;
        let root_request = signed_request
            .request()
            .root_acquire()
            .map_err(|_| StorageLiveExportReadbackErrorV1::Request)?;

        let selector = signed_request.request().selector();
        let before = runtime
            .observe_live_export_origin(selector.workspace_id(), deadline_boottime_nanoseconds)?;
        let source = self.catalog.select_current(selector.export_id(), &before)?;
        compare_selector(selector, source)?;

        // Reobserve after catalog selection so a changed pin or inventory
        // cannot be masked by a still-open descriptor from the first sample.
        let after = runtime
            .observe_live_export_origin(selector.workspace_id(), deadline_boottime_nanoseconds)?;
        let final_source = self.catalog.select_current(selector.export_id(), &after)?;
        if final_source != source {
            return Err(StorageLiveExportReadbackErrorV1::Selector);
        }
        self.trust.validate_current()?;
        validate_time(&signed_request)?;
        let named_consumer = AuthenticatedNamedConsumerClaimV1::from_verified_plan(
            &signed_request,
            &root_request,
            final_source,
        )?;

        Ok(StorageLiveExportReadbackV1 {
            provider_authority_id: signed_request.signer().authority_id(),
            provider_generation: signed_request.signer().authority_generation(),
            plan_id: signed_request.request().plan_id(),
            signed_request_digest: signed_request.digest(),
            signed_root_request_digest: digest_signed_request(
                signed_request.request().signed_root_request(),
            ),
            holder_authority_id: root_request.holder_authority_id(),
            holder_generation: root_request.holder_generation(),
            holder_authority_digest: root_request.holder_authority_digest(),
            expires_seconds: signed_request.request().expires_seconds(),
            named_consumer,
            claimed_resource: signed_request.request().resource().clone(),
            source: final_source,
            _origin: after,
        })
    }

    /// Prepares one private RO clone while keeping all Provider responses closed.
    ///
    /// The signed request is re-inspected after the privileged, quiescent
    /// worker returns. A changed catalog, origin, signer, or physical plan
    /// drops the FD without recording authority. This method is deliberately
    /// not called by the Provider ingress until an independent grant owner can
    /// stop, drain, and delete every holder reference.
    pub(crate) fn prepare_private_clone(
        &self,
        runtime: &mut StorageBrokerRuntime,
        signed_request_bytes: &[u8],
        deadline_boottime_nanoseconds: u64,
        ledger: &mut StorageLiveExportCloneLedgerV1,
    ) -> Result<StorageLiveExportCloneV1, StorageLiveExportReadbackErrorV1> {
        let before = self.inspect(runtime, signed_request_bytes, deadline_boottime_nanoseconds)?;
        let mount =
            runtime.clone_live_export_mount(before.source(), deadline_boottime_nanoseconds)?;
        let after = self.inspect(runtime, signed_request_bytes, deadline_boottime_nanoseconds)?;
        if before.digest() != after.digest() || before.replay_identity() != after.replay_identity()
        {
            return Err(StorageLiveExportReadbackErrorV1::Selector);
        }
        StorageLiveExportCloneV1::retain(mount, &after, ledger).map_err(Into::into)
    }
}

fn compare_selector(
    selector: StorageLiveExportSelectorV1,
    source: StorageLiveExportSourceV1,
) -> Result<(), StorageLiveExportReadbackErrorV1> {
    if source.export_id() != selector.export_id()
        || source.export_generation() != selector.export_generation()
        || source.workspace_id() != selector.workspace_id()
        || source.source_assignment_digest() != selector.source_assignment_digest()
    {
        return Err(StorageLiveExportReadbackErrorV1::Selector);
    }
    Ok(())
}

fn validate_plan_identity(
    plan_id: [u8; 16],
    effect_id: [u8; 16],
) -> Result<(), StorageLiveExportReadbackErrorV1> {
    // Provider's durable effect ID is the sole Storage replay identity.
    if plan_id != effect_id {
        return Err(StorageLiveExportReadbackErrorV1::Request);
    }
    Ok(())
}

fn validate_time(
    request: &SignedStorageLiveExportRequestV1,
) -> Result<(), StorageLiveExportReadbackErrorV1> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageLiveExportReadbackErrorV1::Expired)?
        .as_secs();
    let now = i64::try_from(seconds).map_err(|_| StorageLiveExportReadbackErrorV1::Expired)?;
    let root = request
        .request()
        .root_acquire()
        .map_err(|_| StorageLiveExportReadbackErrorV1::Request)?;
    if now < request.request().issued_seconds()
        || now >= request.request().expires_seconds()
        || now >= root.deadline_seconds()
    {
        return Err(StorageLiveExportReadbackErrorV1::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> StorageLiveExportSourceV1 {
        StorageLiveExportSourceV1::new(
            ObjectDigest::from_bytes([1; 32]),
            [2; 16],
            [3; 16],
            [4; 16],
            5,
            ObjectDigest::from_bytes([6; 32]),
            [7; 32],
            ObjectDigest::from_bytes([8; 32]),
            [9; 16],
            10,
            11,
            12,
        )
        .unwrap()
    }

    #[test]
    fn physical_source_and_selector_are_exactly_bound() {
        let source = source();
        let selector = StorageLiveExportSelectorV1::new(
            source.export_id(),
            source.export_generation(),
            source.workspace_id(),
            source.source_assignment_digest(),
        )
        .unwrap();
        assert!(compare_selector(selector, source).is_ok());

        let replacement = StorageLiveExportSelectorV1::new(
            source.export_id(),
            source.export_generation() + 1,
            source.workspace_id(),
            source.source_assignment_digest(),
        )
        .unwrap();
        assert!(matches!(
            compare_selector(replacement, source),
            Err(StorageLiveExportReadbackErrorV1::Selector)
        ));
    }

    #[test]
    fn storage_plan_identity_is_the_durable_effect_id() {
        assert!(validate_plan_identity([1; 16], [1; 16]).is_ok());
        assert!(matches!(
            validate_plan_identity([1; 16], [2; 16]),
            Err(StorageLiveExportReadbackErrorV1::Request)
        ));
    }
}
