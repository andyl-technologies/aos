//! Fixed-owner inspection of a protected native held-snapshot catalog row.
//!
//! The catalog publisher asserts a snapshot GUID and hold identity; only an
//! independently authenticated Storage receipt can establish that either is
//! physically current. This module returns a nonauthorizing claim for that
//! future comparison. It cannot produce an Acquire effect or SourceRoot.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{SourceResourceV1, ZfsHeldSnapshotProofV1};

use crate::{FixedProviderOwnerV1, ProviderLedgerError};

/// Records one catalog-asserted native snapshot at a protected publication head.
///
/// This is not a Storage receipt, active hold, backend attestation, or effect
/// permit. Its currentness was checked when it was read, not after return.
pub struct ProviderHeldSnapshotCatalogClaimV1 {
    resource: SourceResourceV1,
    snapshot: ZfsHeldSnapshotProofV1,
    publication_head_commitment: ObjectDigest,
}

impl core::fmt::Debug for ProviderHeldSnapshotCatalogClaimV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderHeldSnapshotCatalogClaimV1([nonauthorizing catalog claim])")
    }
}

impl ProviderHeldSnapshotCatalogClaimV1 {
    /// Returns the resource identity asserted by the current catalog row.
    #[must_use]
    pub const fn resource(&self) -> &SourceResourceV1 {
        &self.resource
    }

    /// Returns the snapshot identity asserted by the current catalog row.
    #[must_use]
    pub const fn snapshot(&self) -> &ZfsHeldSnapshotProofV1 {
        &self.snapshot
    }

    /// Returns the exact protected publication-head commitment observed.
    #[must_use]
    pub const fn publication_head_commitment(&self) -> ObjectDigest {
        self.publication_head_commitment
    }
}

impl FixedProviderOwnerV1 {
    /// Inspects a native row under the exact current protected catalog head.
    ///
    /// The fixed owner authenticates the signed publication against its live
    /// session and protected namespace-41 journal, then checks the canonical
    /// `AOSPCZ01` bytes and row against that head. The result carries no
    /// authority to Acquire: a fresh, independently authenticated Storage
    /// GUID-and-hold receipt is still required, and no such receipt consumer
    /// is available here.
    ///
    /// # Errors
    ///
    /// Rejects unavailable custody/session, an invalid or stale publication,
    /// a malformed or mismatched catalog, an absent binding, or changed journal.
    pub fn inspect_current_held_snapshot_catalog_claim(
        &mut self,
        canonical_catalog_publication: &[u8],
        canonical_held_snapshot_catalog: &[u8],
        binding_digest: ObjectDigest,
    ) -> Result<ProviderHeldSnapshotCatalogClaimV1, ProviderLedgerError> {
        self.with_ledger(|ledger| {
            let snapshot = ledger.journal.snapshot()?;
            let session = ledger.current_sessions.values_mut().next().ok_or(
                ProviderLedgerError::InvalidTransition("missing live Provider session"),
            )?;
            let configuration = session.session.revalidated_provider_configuration()?;
            let publication = aos_sandbox_source_provider_security::verify_catalog_publication(
                &configuration,
                canonical_catalog_publication,
            )?;
            let current_catalog = session
                .session
                .authorize_fixed_current_catalog_publication_v1(
                    &ledger.journal,
                    snapshot,
                    publication,
                )?;
            let selected = current_catalog.select_held_snapshot_row(
                &ledger.journal,
                canonical_held_snapshot_catalog,
                binding_digest,
            )?;
            if !selected.is_current(&ledger.journal) {
                return Err(ProviderLedgerError::ConfigurationMismatch);
            }

            let (resource, snapshot) = selected.selected();
            Ok(ProviderHeldSnapshotCatalogClaimV1 {
                resource: resource.clone(),
                snapshot: snapshot.clone(),
                publication_head_commitment: current_catalog.projection().head_commitment(),
            })
        })
    }
}
