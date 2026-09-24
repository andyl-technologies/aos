//! Authenticated, nonauthorizing provider catalog-publication projection.
//!
//! ```text
//! AOSPCP01 | version:u16be=2 | reserved[6] | provider-authority[56] |
//! namespace-digest[32] | catalog-generation:u64be | catalog-digest[32] |
//! publisher-authority-id[16] | publication-generation:u64be |
//! predecessor-generation:u64be | predecessor-digest[32] |
//! floor-generation:u64be | floor-digest[32] | publication-seconds:i64be |
//! trust-generation:u64be | trust-digest[32] | revocation-generation:u64be |
//! revocation-digest[32] | signer[120] | signature[64]
//! ```
//!
//! Verification resolves the exact signer through a freshly revalidated
//! protected trust projection. The result carries no key, signer handle,
//! journal mutation, backend effect, or activation authority.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    ProviderCatalogManifestV1, ProviderHeldSnapshotCatalogV1, SourceProviderAuthorityTrustStateV1,
    SourceProviderAuthorityV1, SourceProviderKeyTrustStateV1, SourceProviderKeyUsageV1,
    SourceProviderSigningKeyV1, SourceResourceV1, StorageLiveExportSelectorV1,
    ZfsHeldSnapshotProofV1,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{RevalidatedProviderConfigurationV1, SourceProviderSecurityError};

const MAGIC: &[u8; 8] = b"AOSPCP01";
const VERSION: u16 = 2;
const SIGNED_BYTES: usize = 520;
const SIGNATURE_OFFSET: usize = 456;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-provider.catalog-publication.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.source-provider.catalog-publication-receipt.v1\0";

/// Carries one exact catalog publication authenticated by protected trust.
pub struct VerifiedCatalogPublicationV1 {
    provider: SourceProviderAuthorityV1,
    resource_namespace_digest: ObjectDigest,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    publisher_authority_id: [u8; 16],
    publication_generation: u64,
    publication_receipt_digest: ObjectDigest,
    predecessor_catalog_generation: u64,
    predecessor_catalog_digest: ObjectDigest,
    catalog_floor_generation: u64,
    catalog_floor_digest: ObjectDigest,
    publication_seconds: i64,
    publication_trust_generation: u64,
    publication_trust_digest: ObjectDigest,
    publication_revocation_generation: u64,
    publication_revocation_digest: ObjectDigest,
    publisher_signer: SourceProviderSigningKeyV1,
    canonical_publication: Vec<u8>,
}

/// Projects the exact protected current catalog-publication head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentCatalogPublicationProjectionV1 {
    provider: SourceProviderAuthorityV1,
    resource_namespace_digest: ObjectDigest,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    publisher_signer: SourceProviderSigningKeyV1,
    publisher_authority_id: [u8; 16],
    publication_generation: u64,
    publication_receipt_digest: ObjectDigest,
    predecessor_catalog_generation: u64,
    predecessor_catalog_digest: ObjectDigest,
    catalog_floor_generation: u64,
    catalog_floor_digest: ObjectDigest,
    publication_seconds: i64,
    publication_trust_generation: u64,
    publication_trust_digest: ObjectDigest,
    publication_revocation_generation: u64,
    publication_revocation_digest: ObjectDigest,
    head_commitment: ObjectDigest,
}

/// Authorizes one use of the exact non-GCable current AOSSPL catalog head.
pub struct ProtectedCurrentCatalogPublicationV1 {
    pub(crate) projection: CurrentCatalogPublicationProjectionV1,
    pub(crate) publication: VerifiedCatalogPublicationV1,
    pub(crate) journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
    pub(crate) catalog_key: Vec<u8>,
    pub(crate) catalog_record: Vec<u8>,
}

/// Retains a selected row only while its manifest matches the protected head.
pub struct ProtectedProviderCatalogSelectionV1<'catalog> {
    resource: SourceResourceV1,
    storage_selector: StorageLiveExportSelectorV1,
    current_catalog: &'catalog ProtectedCurrentCatalogPublicationV1,
}

/// Retains a native snapshot row only while its catalog matches the protected head.
///
/// This is a catalog claim, not a physical Storage observation or an effect permit.
/// A separate authenticated GUID-and-hold receipt is required before any use
/// that could authorize a backend effect.
pub struct ProtectedProviderHeldSnapshotSelectionV1<'catalog> {
    resource: SourceResourceV1,
    snapshot: ZfsHeldSnapshotProofV1,
    current_catalog: &'catalog ProtectedCurrentCatalogPublicationV1,
}

impl core::fmt::Debug for ProtectedProviderHeldSnapshotSelectionV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedProviderHeldSnapshotSelectionV1([protected catalog claim])")
    }
}

impl core::fmt::Debug for ProtectedProviderCatalogSelectionV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedProviderCatalogSelectionV1([protected selection])")
    }
}

struct CatalogPublisherAuthorizationV1<'key> {
    trusted: &'key crate::HistoricalProviderVerificationKeyV1,
}

impl core::fmt::Debug for VerifiedCatalogPublicationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedCatalogPublicationV1([authenticated publication])")
    }
}

impl core::fmt::Debug for ProtectedCurrentCatalogPublicationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedCurrentCatalogPublicationV1([protected current head])")
    }
}

/// Authorizes the exact publication selected by the protected current AOSSPL head.
///
/// The namespace-41 journal must already be claimed through its protected
/// authority. A current whole-graph validation identifies the sole catalog
/// reachable from the authority head and rejects stale, alternate, or GCable
/// publication records.
///
/// # Errors
///
/// Returns [`SourceProviderSecurityError`] for a stale snapshot, malformed
/// AOSSPL graph, mismatched protected configuration, noncurrent publication,
/// or catalog lineage equivocation.
pub(crate) fn authorize_current_catalog_publication_v1(
    configuration: &RevalidatedProviderConfigurationV1,
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
    publication: VerifiedCatalogPublicationV1,
) -> Result<ProtectedCurrentCatalogPublicationV1, SourceProviderSecurityError> {
    use aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1;

    journal
        .validate_source_provider_authority_snapshot(&journal_snapshot)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let records = aos_sandbox_source_provider_ledger::collect_bounded_records(
        journal
            .records()
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    aos_sandbox_source_provider_ledger::validate_prospective_records(
        records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let authority = records.iter().find_map(|(key, value)| {
        match aos_sandbox_source_provider_ledger::ledger::format::decode_record(key, value).ok()? {
            DecodedRecordV1::Authority(value) => Some(value),
            _ => None,
        }
    });
    let authority = authority.ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let current = records.iter().find_map(|(key, value)| {
        match aos_sandbox_source_provider_ledger::ledger::format::decode_record(key, value).ok()? {
            DecodedRecordV1::Catalog(catalog)
                if catalog.catalog_generation == authority.catalog_generation
                    && catalog.catalog_digest == authority.catalog_digest =>
            {
                Some((key.clone(), value.clone(), catalog))
            }
            _ => None,
        }
    });
    let (catalog_key, catalog_record, catalog) =
        current.ok_or(SourceProviderSecurityError::SessionContinuity)?;
    if !configuration_matches_authority(configuration, &authority)
        || !publication_matches_catalog(&publication, &catalog)
        || journal
            .validate_source_provider_authority_snapshot(&journal_snapshot)
            .is_err()
        || journal.get(&catalog_key).ok().flatten() != Some(catalog_record.as_slice())
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let projection = current_catalog_projection(&catalog);
    Ok(ProtectedCurrentCatalogPublicationV1 {
        projection,
        publication,
        journal_snapshot,
        catalog_key,
        catalog_record,
    })
}

/// Authenticates exact canonical catalog-publication bytes against custody.
///
/// # Errors
///
/// Returns [`SourceProviderSecurityError`] for malformed bytes, a signer not
/// present in protected trust, revoked or mismatched signer identity, invalid
/// catalog lineage, or an invalid Ed25519 signature.
pub fn verify_catalog_publication(
    configuration: &RevalidatedProviderConfigurationV1,
    bytes: &[u8],
) -> Result<VerifiedCatalogPublicationV1, SourceProviderSecurityError> {
    if bytes.len() != SIGNED_BYTES
        || bytes.get(..8) != Some(MAGIC.as_slice())
        || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
        || bytes.get(10..16) != Some([0_u8; 6].as_slice())
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let provider = SourceProviderAuthorityV1::new(
        array(bytes, 16)?,
        u64_at(bytes, 32)?,
        ObjectDigest::from_bytes(array(bytes, 40)?),
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let resource_namespace_digest = ObjectDigest::from_bytes(array(bytes, 72)?);
    let catalog_generation = u64_at(bytes, 104)?;
    let catalog_digest = ObjectDigest::from_bytes(array(bytes, 112)?);
    let publisher_authority_id = array(bytes, 144)?;
    let publication_generation = u64_at(bytes, 160)?;
    let predecessor_catalog_generation = u64_at(bytes, 168)?;
    let predecessor_catalog_digest = ObjectDigest::from_bytes(array(bytes, 176)?);
    let catalog_floor_generation = u64_at(bytes, 208)?;
    let catalog_floor_digest = ObjectDigest::from_bytes(array(bytes, 216)?);
    let publication_seconds = i64_at(bytes, 248)?;
    let publication_trust_generation = u64_at(bytes, 256)?;
    let publication_trust_digest = ObjectDigest::from_bytes(array(bytes, 264)?);
    let publication_revocation_generation = u64_at(bytes, 296)?;
    let publication_revocation_digest = ObjectDigest::from_bytes(array(bytes, 304)?);
    let signer = decode_signer(
        bytes
            .get(336..SIGNATURE_OFFSET)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?,
    )?;
    let authorization = authorize_catalog_publisher(
        configuration,
        &signer,
        &provider,
        resource_namespace_digest,
        publication_seconds,
        publication_trust_generation,
        publication_trust_digest,
        publication_revocation_generation,
        publication_revocation_digest,
    )?;
    if provider != *configuration.provider()
        || resource_namespace_digest != configuration.resource_namespace_digest()
        || resource_namespace_digest.as_bytes() == &[0; 32]
        || catalog_generation == 0
        || catalog_digest.as_bytes() == &[0; 32]
        || publisher_authority_id == [0; 16]
        || publication_generation == 0
        || signer.authority_id() != publisher_authority_id
        || catalog_floor_generation == 0
        || catalog_floor_generation > catalog_generation
        || catalog_floor_digest.as_bytes() == &[0; 32]
        || (catalog_floor_generation == catalog_generation
            && catalog_floor_digest != catalog_digest)
        || (predecessor_catalog_generation == 0)
            != (predecessor_catalog_digest.as_bytes() == &[0; 32])
        || (catalog_generation > catalog_floor_generation
            && predecessor_catalog_generation < catalog_floor_generation)
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let publication_receipt_digest =
        verify_catalog_signature(bytes, authorization.trusted.public_key())?;
    Ok(VerifiedCatalogPublicationV1 {
        provider,
        resource_namespace_digest,
        catalog_generation,
        catalog_digest,
        publisher_authority_id,
        publication_generation,
        publication_receipt_digest,
        predecessor_catalog_generation,
        predecessor_catalog_digest,
        catalog_floor_generation,
        catalog_floor_digest,
        publication_seconds,
        publication_trust_generation,
        publication_trust_digest,
        publication_revocation_generation,
        publication_revocation_digest,
        publisher_signer: signer,
        canonical_publication: bytes.to_vec(),
    })
}

/// Verifies a retained publication against its exact protected key issuance.
///
/// This historical verifier is cryptographic and nonauthorizing. Superseded
/// keys remain valid at their recorded issuance floor; revoked keys fail.
///
/// # Errors
///
/// Returns [`SourceProviderSecurityError`] for malformed canonical bytes,
/// mismatched signer or issuance epochs, invalid lineage, or signature failure.
pub fn verify_retained_catalog_publication(
    trust_history: &[crate::ProtectedTrustHeadLinkV2],
    trusted: &crate::HistoricalProviderVerificationKeyV1,
    bytes: &[u8],
) -> Result<VerifiedCatalogPublicationV1, SourceProviderSecurityError> {
    verify_retained_catalog_publication_inner(trust_history, trusted, bytes, false)
        .map(|(publication, _)| publication)
}

fn verify_retained_catalog_publication_inner(
    trust_history: &[crate::ProtectedTrustHeadLinkV2],
    trusted: &crate::HistoricalProviderVerificationKeyV1,
    bytes: &[u8],
    allow_revoked_cleanup: bool,
) -> Result<(VerifiedCatalogPublicationV1, bool), SourceProviderSecurityError> {
    if bytes.len() != SIGNED_BYTES
        || bytes.get(..8) != Some(MAGIC.as_slice())
        || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
        || bytes.get(10..16) != Some([0_u8; 6].as_slice())
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let provider = SourceProviderAuthorityV1::new(
        array(bytes, 16)?,
        u64_at(bytes, 32)?,
        ObjectDigest::from_bytes(array(bytes, 40)?),
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let resource_namespace_digest = ObjectDigest::from_bytes(array(bytes, 72)?);
    let catalog_generation = u64_at(bytes, 104)?;
    let catalog_digest = ObjectDigest::from_bytes(array(bytes, 112)?);
    let publisher_authority_id = array(bytes, 144)?;
    let publication_generation = u64_at(bytes, 160)?;
    let predecessor_catalog_generation = u64_at(bytes, 168)?;
    let predecessor_catalog_digest = ObjectDigest::from_bytes(array(bytes, 176)?);
    let catalog_floor_generation = u64_at(bytes, 208)?;
    let catalog_floor_digest = ObjectDigest::from_bytes(array(bytes, 216)?);
    let publication_seconds = i64_at(bytes, 248)?;
    let publication_trust_generation = u64_at(bytes, 256)?;
    let publication_trust_digest = ObjectDigest::from_bytes(array(bytes, 264)?);
    let publication_revocation_generation = u64_at(bytes, 296)?;
    let publication_revocation_digest = ObjectDigest::from_bytes(array(bytes, 304)?);
    let signer = decode_signer(
        bytes
            .get(336..SIGNATURE_OFFSET)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?,
    )?;
    let (key_from, key_until) = trusted.validity();
    let (authority_from, authority_until, _) = trusted.authority_issuance();
    let historically_active = crate::configuration::historical_key_active_at(
        trust_history,
        trusted,
        publication_seconds,
        publication_trust_generation,
        publication_trust_digest,
        publication_revocation_generation,
        publication_revocation_digest,
    );
    let cleanup_only = !historically_active
        && allow_revoked_cleanup
        && crate::configuration::historical_cleanup_key_active_at(
            trust_history,
            trusted,
            publication_seconds,
            publication_trust_generation,
            publication_trust_digest,
            publication_revocation_generation,
            publication_revocation_digest,
        );
    if trusted.signer() != &signer
        || signer.usage() != SourceProviderKeyUsageV1::CatalogPublisher
        || signer.authority_id() != publisher_authority_id
        || resource_namespace_digest.as_bytes() == &[0; 32]
        || catalog_generation == 0
        || catalog_digest.as_bytes() == &[0; 32]
        || publication_generation == 0
        || publication_seconds < key_from.max(authority_from)
        || publication_seconds >= key_until.min(authority_until)
        || (!historically_active && !cleanup_only)
        || catalog_floor_generation == 0
        || catalog_floor_generation > catalog_generation
        || (catalog_floor_generation == catalog_generation
            && catalog_floor_digest != catalog_digest)
        || (predecessor_catalog_generation == 0)
            != (predecessor_catalog_digest.as_bytes() == &[0; 32])
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let publication_receipt_digest = verify_catalog_signature(bytes, trusted.public_key())?;
    Ok((
        VerifiedCatalogPublicationV1 {
            provider,
            resource_namespace_digest,
            catalog_generation,
            catalog_digest,
            publisher_authority_id,
            publication_generation,
            publication_receipt_digest,
            predecessor_catalog_generation,
            predecessor_catalog_digest,
            catalog_floor_generation,
            catalog_floor_digest,
            publication_seconds,
            publication_trust_generation,
            publication_trust_digest,
            publication_revocation_generation,
            publication_revocation_digest,
            publisher_signer: signer,
            canonical_publication: bytes.to_vec(),
        },
        cleanup_only,
    ))
}

// Both trust paths authenticate the same canonical bytes after their distinct
// authority and lineage checks.
fn verify_catalog_signature(
    bytes: &[u8],
    public_key: &[u8; 32],
) -> Result<ObjectDigest, SourceProviderSecurityError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    if verifying_key.is_weak() {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let signature = Signature::from_bytes(&array(bytes, SIGNATURE_OFFSET)?);
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + SIGNATURE_OFFSET);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&bytes[..SIGNATURE_OFFSET]);
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_DOMAIN);
    hasher.update(bytes);
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

impl VerifiedCatalogPublicationV1 {
    /// Returns the provider authority.
    #[must_use]
    pub const fn provider(&self) -> &SourceProviderAuthorityV1 {
        &self.provider
    }

    /// Returns the protected resource namespace.
    #[must_use]
    pub const fn resource_namespace_digest(&self) -> ObjectDigest {
        self.resource_namespace_digest
    }

    /// Returns the catalog head.
    #[must_use]
    pub const fn catalog_head(&self) -> (u64, ObjectDigest) {
        (self.catalog_generation, self.catalog_digest)
    }

    /// Returns the publisher identity, generation, and signed receipt digest.
    #[must_use]
    pub const fn publication(&self) -> ([u8; 16], u64, ObjectDigest) {
        (
            self.publisher_authority_id,
            self.publication_generation,
            self.publication_receipt_digest,
        )
    }

    /// Returns the exact predecessor catalog head.
    #[must_use]
    pub const fn predecessor(&self) -> (u64, ObjectDigest) {
        (
            self.predecessor_catalog_generation,
            self.predecessor_catalog_digest,
        )
    }

    /// Returns the retained catalog floor.
    #[must_use]
    pub const fn catalog_floor(&self) -> (u64, ObjectDigest) {
        (self.catalog_floor_generation, self.catalog_floor_digest)
    }

    /// Returns the authenticated publication time and protected trust floors.
    #[must_use]
    pub const fn issuance(&self) -> (i64, u64, ObjectDigest, u64, ObjectDigest) {
        (
            self.publication_seconds,
            self.publication_trust_generation,
            self.publication_trust_digest,
            self.publication_revocation_generation,
            self.publication_revocation_digest,
        )
    }

    /// Returns the dedicated catalog-publisher signer identity.
    #[must_use]
    pub const fn publisher_signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.publisher_signer
    }

    /// Returns the exact authenticated canonical publication artifact.
    #[must_use]
    pub fn canonical_publication(&self) -> &[u8] {
        &self.canonical_publication
    }
}

impl CurrentCatalogPublicationProjectionV1 {
    /// Returns the exact protected provider and resource namespace.
    #[must_use]
    pub const fn scope(&self) -> (&SourceProviderAuthorityV1, ObjectDigest) {
        (&self.provider, self.resource_namespace_digest)
    }

    /// Returns the exact current catalog head.
    #[must_use]
    pub const fn catalog_head(&self) -> (u64, ObjectDigest) {
        (self.catalog_generation, self.catalog_digest)
    }

    /// Returns the exact current publisher signer.
    #[must_use]
    pub const fn publisher_signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.publisher_signer
    }

    /// Returns the authenticated publication identity.
    #[must_use]
    pub const fn publication(&self) -> ([u8; 16], u64, ObjectDigest) {
        (
            self.publisher_authority_id,
            self.publication_generation,
            self.publication_receipt_digest,
        )
    }

    /// Returns the exact predecessor catalog head.
    #[must_use]
    pub const fn predecessor(&self) -> (u64, ObjectDigest) {
        (
            self.predecessor_catalog_generation,
            self.predecessor_catalog_digest,
        )
    }

    /// Returns the protected non-GCable catalog floor.
    #[must_use]
    pub const fn floor(&self) -> (u64, ObjectDigest) {
        (self.catalog_floor_generation, self.catalog_floor_digest)
    }

    /// Returns publication time and exact authenticated trust heads.
    #[must_use]
    pub const fn issuance(&self) -> (i64, u64, ObjectDigest, u64, ObjectDigest) {
        (
            self.publication_seconds,
            self.publication_trust_generation,
            self.publication_trust_digest,
            self.publication_revocation_generation,
            self.publication_revocation_digest,
        )
    }

    /// Returns the commitment to every current publication-head field.
    #[must_use]
    pub const fn head_commitment(&self) -> ObjectDigest {
        self.head_commitment
    }
}

impl ProtectedCurrentCatalogPublicationV1 {
    /// Borrows the nonauthorizing durable current-head projection.
    #[must_use]
    pub const fn projection(&self) -> &CurrentCatalogPublicationProjectionV1 {
        &self.projection
    }

    /// Selects one manifest row under this exact protected current publication.
    ///
    /// The manifest is untrusted input until its canonical digest equals the
    /// authenticated journal head. A changed journal invalidates the returned
    /// selection before it can be used for a Provider-signed export plan.
    ///
    /// # Errors
    ///
    /// Rejects a stale journal, malformed manifest, forked/downgraded catalog,
    /// namespace mismatch, or absent logical-binding row.
    pub fn select_manifest_row<'catalog>(
        &'catalog self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        canonical_manifest: &[u8],
        binding_digest: ObjectDigest,
    ) -> Result<ProtectedProviderCatalogSelectionV1<'catalog>, SourceProviderSecurityError> {
        if !self.validate_current(journal) {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let manifest = ProviderCatalogManifestV1::from_canonical_bytes(canonical_manifest)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let (generation, digest) = self.projection.catalog_head();
        let (_, namespace) = self.projection.scope();
        let (resource, storage_selector) = manifest
            .select_current(generation, digest, namespace, binding_digest)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;

        Ok(ProtectedProviderCatalogSelectionV1 {
            resource,
            storage_selector,
            current_catalog: self,
        })
    }

    /// Selects one native held-snapshot claim under this protected publication.
    ///
    /// The selected GUID and hold are asserted by the catalog publisher only.
    /// This does not authenticate their physical existence or currentness in
    /// Storage and cannot authorize a SourceRoot or backend effect.
    ///
    /// # Errors
    ///
    /// Rejects a stale journal, malformed catalog, mismatched publication
    /// head or namespace, or absent logical-binding row.
    pub fn select_held_snapshot_row<'catalog>(
        &'catalog self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        canonical_catalog: &[u8],
        binding_digest: ObjectDigest,
    ) -> Result<ProtectedProviderHeldSnapshotSelectionV1<'catalog>, SourceProviderSecurityError>
    {
        if !self.validate_current(journal) {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let (generation, digest) = self.projection.catalog_head();
        let (_, namespace) = self.projection.scope();
        let (resource, snapshot) = select_held_snapshot_under_head(
            canonical_catalog,
            generation,
            digest,
            namespace,
            binding_digest,
        )?;

        Ok(ProtectedProviderHeldSnapshotSelectionV1 {
            resource,
            snapshot,
            current_catalog: self,
        })
    }

    pub(crate) fn validate_current(
        &self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    ) -> bool {
        journal
            .validate_source_provider_authority_snapshot(&self.journal_snapshot)
            .is_ok()
            && journal.get(&self.catalog_key).ok().flatten() == Some(self.catalog_record.as_slice())
    }
}

impl ProtectedProviderCatalogSelectionV1<'_> {
    /// Returns the exact authenticated selected row and Storage export selector.
    #[must_use]
    pub const fn selected(&self) -> (&SourceResourceV1, StorageLiveExportSelectorV1) {
        (&self.resource, self.storage_selector)
    }

    /// Rechecks that the same protected catalog head remains current.
    #[must_use]
    pub fn is_current(&self, journal: &aos_sandbox::ProtectedJournalAuthority<'_>) -> bool {
        self.current_catalog.validate_current(journal)
    }
}

impl ProtectedProviderHeldSnapshotSelectionV1<'_> {
    /// Returns the catalog-asserted resource and held-snapshot identity.
    #[must_use]
    pub const fn selected(&self) -> (&SourceResourceV1, &ZfsHeldSnapshotProofV1) {
        (&self.resource, &self.snapshot)
    }

    /// Rechecks that the same protected catalog head remains current.
    #[must_use]
    pub fn is_current(&self, journal: &aos_sandbox::ProtectedJournalAuthority<'_>) -> bool {
        self.current_catalog.validate_current(journal)
    }
}

fn select_held_snapshot_under_head(
    canonical_catalog: &[u8],
    generation: u64,
    digest: ObjectDigest,
    namespace: ObjectDigest,
    binding_digest: ObjectDigest,
) -> Result<(SourceResourceV1, ZfsHeldSnapshotProofV1), SourceProviderSecurityError> {
    let catalog = ProviderHeldSnapshotCatalogV1::from_canonical_bytes(canonical_catalog)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    catalog
        .select_under_head(generation, digest, namespace, binding_digest)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

pub(crate) fn configuration_matches_authority(
    configuration: &RevalidatedProviderConfigurationV1,
    authority: &aos_sandbox_source_provider_ledger::ledger::model::AuthorityHeadRecordV1,
) -> bool {
    let (trust_generation, trust_digest) = configuration.trust_head();
    let (revocation_generation, revocation_digest) = configuration.revocation_head();
    let (route_id, route_generation, route_digest) = configuration.route_head();
    let (valid_from_seconds, valid_until_seconds) = configuration.validity();
    authority.provider == *configuration.provider()
        && authority.trust_generation == trust_generation
        && authority.trust_digest == trust_digest
        && authority.revocation_generation == revocation_generation
        && authority.revocation_digest == revocation_digest
        && authority.route_id == route_id
        && authority.route_generation == route_generation
        && authority.route_digest == route_digest
        && authority.resource_namespace_digest == configuration.resource_namespace_digest()
        && authority.valid_from_seconds == valid_from_seconds
        && authority.valid_until_seconds == valid_until_seconds
        && authority.proof_class_capabilities == configuration.proof_class_capabilities()
        && authority.supports_recursive == configuration.supports_recursive()
        && authority.supports_kernel_coupled == configuration.supports_kernel_coupled()
        && authority.provider_hello_signer == *configuration.provider_hello_signer()
        && authority.provider_outcome_signer == *configuration.provider_outcome_signer()
}

pub(crate) fn publication_matches_catalog(
    publication: &VerifiedCatalogPublicationV1,
    catalog: &aos_sandbox_source_provider_ledger::ledger::model::CatalogHeadRecordV1,
) -> bool {
    let (publisher_authority_id, publication_generation, publication_receipt_digest) =
        publication.publication();
    let (
        publication_seconds,
        publication_trust_generation,
        publication_trust_digest,
        publication_revocation_generation,
        publication_revocation_digest,
    ) = publication.issuance();
    publication.provider() == &catalog.provider
        && publication.resource_namespace_digest() == catalog.resource_namespace_digest
        && publication.catalog_head() == (catalog.catalog_generation, catalog.catalog_digest)
        && (
            publisher_authority_id,
            publication_generation,
            publication_receipt_digest,
        ) == (
            catalog.publisher_authority_id,
            catalog.publication_generation,
            catalog.publication_receipt_digest,
        )
        && publication.predecessor()
            == (
                catalog.predecessor_catalog_generation,
                catalog.predecessor_catalog_digest,
            )
        && publication.catalog_floor()
            == (
                catalog.catalog_floor_generation,
                catalog.catalog_floor_digest,
            )
        && (
            publication_seconds,
            publication_trust_generation,
            publication_trust_digest,
            publication_revocation_generation,
            publication_revocation_digest,
        ) == (
            catalog.publication_seconds,
            catalog.publication_trust_generation,
            catalog.publication_trust_digest,
            catalog.publication_revocation_generation,
            catalog.publication_revocation_digest,
        )
        && publication.publisher_signer() == &catalog.publisher_signer
        && publication.canonical_publication() == catalog.canonical_publication
}

pub(crate) fn current_catalog_projection(
    catalog: &aos_sandbox_source_provider_ledger::ledger::model::CatalogHeadRecordV1,
) -> CurrentCatalogPublicationProjectionV1 {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.current-catalog-publication-head.v1\0");
    hasher.update(aos_sandbox_source_provider_ledger::ledger::format::encode_catalog(catalog));
    CurrentCatalogPublicationProjectionV1 {
        provider: catalog.provider.clone(),
        resource_namespace_digest: catalog.resource_namespace_digest,
        catalog_generation: catalog.catalog_generation,
        catalog_digest: catalog.catalog_digest,
        publisher_signer: catalog.publisher_signer.clone(),
        publisher_authority_id: catalog.publisher_authority_id,
        publication_generation: catalog.publication_generation,
        publication_receipt_digest: catalog.publication_receipt_digest,
        predecessor_catalog_generation: catalog.predecessor_catalog_generation,
        predecessor_catalog_digest: catalog.predecessor_catalog_digest,
        catalog_floor_generation: catalog.catalog_floor_generation,
        catalog_floor_digest: catalog.catalog_floor_digest,
        publication_seconds: catalog.publication_seconds,
        publication_trust_generation: catalog.publication_trust_generation,
        publication_trust_digest: catalog.publication_trust_digest,
        publication_revocation_generation: catalog.publication_revocation_generation,
        publication_revocation_digest: catalog.publication_revocation_digest,
        head_commitment: ObjectDigest::from_bytes(hasher.finalize().into()),
    }
}

pub(crate) fn current_catalog_head_matches(
    configuration: &RevalidatedProviderConfigurationV1,
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    expected_commitment: ObjectDigest,
) -> bool {
    use aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1;

    let Some(records) = validated_catalog_records(journal) else {
        return false;
    };
    let authority = records.iter().find_map(|(key, value)| {
        match aos_sandbox_source_provider_ledger::ledger::format::decode_record(key, value).ok()? {
            DecodedRecordV1::Authority(value) => Some(value),
            _ => None,
        }
    });
    let Some(authority) =
        authority.filter(|value| configuration_matches_authority(configuration, value))
    else {
        return false;
    };
    records.iter().any(|(key, value)| {
        let Ok(DecodedRecordV1::Catalog(catalog)) =
            aos_sandbox_source_provider_ledger::ledger::format::decode_record(key, value)
        else {
            return false;
        };
        catalog.catalog_generation == authority.catalog_generation
            && catalog.catalog_digest == authority.catalog_digest
            && verify_catalog_publication(configuration, &catalog.canonical_publication)
                .is_ok_and(|publication| publication_matches_catalog(&publication, &catalog))
            && current_catalog_projection(&catalog).head_commitment == expected_commitment
    })
}

pub(crate) fn retained_catalog_head_cleanup_status(
    configuration: &RevalidatedProviderConfigurationV1,
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    expected_commitment: ObjectDigest,
    catalog_floor: &aos_sandbox_source_provider_protocol::ProviderCatalogFloorV1,
    verified_at_seconds: i64,
) -> Option<bool> {
    use aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1;

    let records = validated_catalog_records(journal)?;
    let authority = records.iter().find_map(|(key, value)| {
        match aos_sandbox_source_provider_ledger::ledger::format::decode_record(key, value).ok()? {
            DecodedRecordV1::Authority(value) => Some(value),
            _ => None,
        }
    });
    let Some(authority) =
        authority.filter(|value| configuration_matches_authority(configuration, value))
    else {
        return None;
    };
    let mut matches = records.iter().filter_map(|(key, value)| {
        let DecodedRecordV1::Catalog(catalog) =
            aos_sandbox_source_provider_ledger::ledger::format::decode_record(key, value).ok()?
        else {
            return None;
        };
        if current_catalog_projection(&catalog).head_commitment != expected_commitment {
            return None;
        }
        Some(catalog)
    });
    let Some(catalog) = matches.next() else {
        return None;
    };
    if matches.next().is_some()
        || catalog.provider != *configuration.provider()
        || catalog.resource_namespace_digest != configuration.resource_namespace_digest()
        || catalog.provider.authority_id() != catalog_floor.provider_authority_id()
        || catalog.resource_namespace_digest != catalog_floor.resource_namespace_digest()
        || catalog.catalog_generation < catalog_floor.minimum_catalog_generation()
        || (catalog.catalog_generation == catalog_floor.minimum_catalog_generation()
            && catalog.catalog_digest != catalog_floor.minimum_catalog_digest())
        || authority.catalog_generation < catalog.catalog_floor_generation
        || catalog.publication_seconds > verified_at_seconds
    {
        return None;
    }
    let Some(trusted) = configuration
        .historical_public_keys()
        .iter()
        .find(|entry| entry.signer() == &catalog.publisher_signer)
    else {
        return None;
    };
    verify_retained_catalog_publication_inner(
        configuration.trust_history(),
        trusted,
        &catalog.canonical_publication,
        true,
    )
    .ok()
    .and_then(|(publication, cleanup_only)| {
        publication_matches_catalog(&publication, &catalog).then_some(cleanup_only)
    })
}

fn validated_catalog_records(
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
) -> Option<std::collections::BTreeMap<Vec<u8>, Vec<u8>>> {
    journal.validate_source_provider_authority().ok()?;
    let records =
        aos_sandbox_source_provider_ledger::collect_bounded_records(journal.records().ok()?)
            .ok()?;
    aos_sandbox_source_provider_ledger::validate_prospective_records(
        records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .ok()?;
    Some(records)
}

#[allow(clippy::too_many_arguments)]
fn authorize_catalog_publisher<'key>(
    configuration: &'key RevalidatedProviderConfigurationV1,
    signer: &SourceProviderSigningKeyV1,
    provider: &SourceProviderAuthorityV1,
    namespace: ObjectDigest,
    publication_seconds: i64,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
) -> Result<CatalogPublisherAuthorizationV1<'key>, SourceProviderSecurityError> {
    let now = crate::handshake::current_unix_seconds()?;
    let trusted = configuration
        .historical_public_keys()
        .iter()
        .find(|entry| entry.signer() == signer)
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let (state, _) = trusted.state_and_successor();
    let (key_from, key_until) = trusted.validity();
    let (authority_from, authority_until, authority_state) = trusted.authority_issuance();
    if signer.usage() != SourceProviderKeyUsageV1::CatalogPublisher
        || provider != configuration.provider()
        || namespace != configuration.resource_namespace_digest()
        || (trust_generation, trust_digest) != configuration.trust_head()
        || (revocation_generation, revocation_digest) != configuration.revocation_head()
        || state != SourceProviderKeyTrustStateV1::Eligible
        || authority_state != SourceProviderAuthorityTrustStateV1::Trusted
        || publication_seconds < key_from.max(authority_from)
        || publication_seconds >= key_until.min(authority_until)
        || now < key_from.max(authority_from)
        || now >= key_until.min(authority_until)
        || publication_seconds > now
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(CatalogPublisherAuthorizationV1 { trusted })
}

fn decode_signer(bytes: &[u8]) -> Result<SourceProviderSigningKeyV1, SourceProviderSecurityError> {
    if bytes.len() != 120 || bytes.get(113..120) != Some([0_u8; 7].as_slice()) {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let usage = match bytes[112] {
        5 => SourceProviderKeyUsageV1::CatalogPublisher,
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    SourceProviderSigningKeyV1::new(
        array(bytes, 0)?,
        u64_at(bytes, 16)?,
        ObjectDigest::from_bytes(array(bytes, 24)?),
        array(bytes, 56)?,
        u64_at(bytes, 72)?,
        ObjectDigest::from_bytes(array(bytes, 80)?),
        usage,
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], SourceProviderSecurityError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(SourceProviderSecurityError::SessionContinuity)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, SourceProviderSecurityError> {
    Ok(u64::from_be_bytes(array(bytes, offset)?))
}

fn i64_at(bytes: &[u8], offset: usize) -> Result<i64, SourceProviderSecurityError> {
    Ok(i64::from_be_bytes(array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use aos_sandbox_source_provider_protocol::ProviderHeldSnapshotRowV1;

    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn held_snapshot_catalog() -> ProviderHeldSnapshotCatalogV1 {
        let snapshot = ZfsHeldSnapshotProofV1::new(
            [7; 32],
            8,
            9,
            10,
            11,
            [12; 16],
            13,
            digest(14),
            digest(15),
            digest(16),
        )
        .unwrap();
        let row = ProviderHeldSnapshotRowV1::new(
            digest(1),
            [2; 32],
            3,
            digest(4),
            5,
            digest(6),
            snapshot,
        )
        .unwrap();

        ProviderHeldSnapshotCatalogV1::new(17, digest(18), vec![row]).unwrap()
    }

    #[test]
    fn native_row_requires_exact_published_head_and_binding() {
        let catalog = held_snapshot_catalog();
        let bytes = catalog.to_canonical_bytes();

        let (resource, snapshot) =
            select_held_snapshot_under_head(&bytes, 17, catalog.digest(), digest(18), digest(1))
                .unwrap();
        assert_eq!(resource.resource_id(), [2; 32]);
        assert_eq!(snapshot.snapshot_guid(), 11);

        for (generation, digest, namespace, binding) in [
            (18, catalog.digest(), digest(18), digest(1)),
            (17, digest(19), digest(18), digest(1)),
            (17, catalog.digest(), digest(19), digest(1)),
            (17, catalog.digest(), digest(18), digest(19)),
        ] {
            assert!(
                select_held_snapshot_under_head(&bytes, generation, digest, namespace, binding,)
                    .is_err()
            );
        }
    }

    #[test]
    fn native_row_rejects_malformed_catalog_bytes() {
        let catalog = held_snapshot_catalog();
        let mut bytes = catalog.to_canonical_bytes();
        bytes[0..8].copy_from_slice(b"AOSPCM01");

        assert!(
            select_held_snapshot_under_head(&bytes, 17, catalog.digest(), digest(18), digest(1),)
                .is_err()
        );
    }
}
