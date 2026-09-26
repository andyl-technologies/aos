//! Fixed-owner inspection of a protected native held-snapshot catalog row.
//!
//! The catalog publisher asserts a snapshot GUID and hold identity; a signed
//! Storage receipt plus trusted current readback must independently establish
//! the physical state. This module returns only nonauthorizing checks. It
//! cannot produce an Acquire effect or SourceRoot.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V2, ProviderHeldSnapshotCatalogV1,
    SignedSourceProviderRequestV1, SignedStorageZfsHoldReceiptV1, SourceProviderAuthorityV1,
    SourceProviderMethod, SourceResourceV1, StorageZfsHoldReceiptV1,
    StorageZfsHoldTransportRequestV1, ZfsHeldSnapshotProofV1, decode_acquire_request,
    digest_acquire_request, digest_signed_request,
};

use crate::model::{ProviderAcquisitionStateV1, ProviderAttemptStateV1};
use crate::zfs_hold_challenge::{
    ChallengeRecordV1, CurrentZfsHoldChallengeContextV1, ProviderZfsHoldChallengeV1,
    current_seconds, expiry,
};
use crate::zfs_hold_verifier::ProtectedStorageZfsHoldVerifierV1;
use crate::{FixedProviderOwnerV1, ProviderLedgerError, ProviderLedgerV1};

/// Records one catalog-asserted native snapshot at a protected publication head.
///
/// This is not a Storage receipt, active hold, backend attestation, or effect
/// permit. Its currentness was checked when it was read, not after return.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderHeldSnapshotCatalogClaimV1 {
    provider: SourceProviderAuthorityV1,
    holder_authority_id: [u8; 16],
    session_binding: ObjectDigest,
    binding_digest: ObjectDigest,
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
    /// Issues one durable native challenge and packages its exact session claim.
    ///
    /// The packet is fit for a future authenticated Provider-to-Storage
    /// connection. It contains only assertions; no Storage hold receipt,
    /// SourceRoot, or native Acquire authority follows from its construction.
    /// The future authenticated carrier supplies and advances `sequence` for
    /// its live connection; this owner rejects zero but has no connection state.
    /// A changed catalog after issuance consumes the challenge without
    /// returning a packet, preserving the one-attempt replay fence.
    ///
    /// # Errors
    ///
    /// Rejects a zero sequence before challenge issuance, failed challenge
    /// issuance, changed protected selection, or malformed native catalog bytes.
    pub fn issue_current_zfs_hold_transport_request(
        &mut self,
        sequence: u64,
        canonical_catalog_publication: &[u8],
        canonical_held_snapshot_catalog: &[u8],
        holder_authority_id: [u8; 16],
        acquisition_id: ObjectDigest,
        binding_digest: ObjectDigest,
    ) -> Result<StorageZfsHoldTransportRequestV1, ProviderLedgerError> {
        if sequence == 0 {
            return Err(ProviderLedgerError::InvalidTransition(
                "native hold transport sequence is zero",
            ));
        }
        let challenge = self.issue_current_zfs_hold_challenge(
            canonical_catalog_publication,
            canonical_held_snapshot_catalog,
            holder_authority_id,
            acquisition_id,
            binding_digest,
        )?;
        self.with_ledger_and_hold_challenges(|ledger, challenges| {
            let journal_snapshot = ledger.journal.snapshot()?;
            let claim = select_current_held_snapshot_claim(
                ledger,
                canonical_catalog_publication,
                canonical_held_snapshot_catalog,
                holder_authority_id,
                binding_digest,
            )?;
            let (issued_seconds, valid_until_seconds) = challenge.validity();
            validate_current_native_attempt(
                ledger,
                &claim,
                acquisition_id,
                challenge.attempt_digest(),
                issued_seconds,
                valid_until_seconds,
            )?;
            let reserved = challenges.issued_for(challenge.nonce())?;
            let current = CurrentZfsHoldChallengeContextV1 {
                nonce: challenge.nonce(),
                provider_id: claim.provider.authority_id(),
                holder_id: holder_authority_id,
                session_binding: claim.session_binding,
                attempt_digest: challenge.attempt_digest(),
                acquisition_id,
                binding_digest,
                publication_head: claim.publication_head_commitment,
                validity: challenge.validity(),
            };
            if !reserved.matches_current(current) {
                return Err(ProviderLedgerError::Unavailable);
            }
            let catalog = ProviderHeldSnapshotCatalogV1::from_canonical_bytes(
                canonical_held_snapshot_catalog,
            )
            .map_err(|_| ProviderLedgerError::Unavailable)?;
            let selected = catalog
                .select_under_head(
                    claim.resource.catalog_generation(),
                    claim.resource.catalog_digest(),
                    claim.resource.resource_namespace_digest(),
                    binding_digest,
                )
                .map_err(|_| ProviderLedgerError::Unavailable)?;
            if selected != (claim.resource.clone(), claim.snapshot.clone()) {
                return Err(ProviderLedgerError::Unavailable);
            }
            ledger
                .journal
                .validate_source_provider_authority_snapshot(&journal_snapshot)?;

            StorageZfsHoldTransportRequestV1::new(
                sequence,
                challenge.nonce(),
                challenge.attempt_digest(),
                claim.provider.authority_id(),
                claim.holder_authority_id,
                claim.session_binding,
                acquisition_id,
                binding_digest,
                claim.publication_head_commitment,
                issued_seconds,
                valid_until_seconds,
                catalog,
            )
            .map_err(|_| ProviderLedgerError::Unavailable)
        })
    }

    /// Durably issues one fresh native hold challenge for a reserved Acquire.
    ///
    /// The challenge is committed beneath the fixed protected Provider state
    /// before it is returned. The owner verifies the current holder session,
    /// exact pending attempt, and protected native catalog selection. A
    /// retained challenge cannot be issued again for the same attempt, even
    /// after reboot or expiry. Issuance does not authorize a backend effect.
    ///
    /// # Errors
    ///
    /// Rejects unavailable custody, an invalid selection or attempt, a
    /// duplicate or exhausted challenge journal, or failed durable commit.
    pub fn issue_current_zfs_hold_challenge(
        &mut self,
        canonical_catalog_publication: &[u8],
        canonical_held_snapshot_catalog: &[u8],
        holder_authority_id: [u8; 16],
        acquisition_id: ObjectDigest,
        binding_digest: ObjectDigest,
    ) -> Result<ProviderZfsHoldChallengeV1, ProviderLedgerError> {
        self.with_ledger_and_hold_challenges(|ledger, challenges| {
            let journal_snapshot = ledger.journal.snapshot()?;
            let claim = select_current_held_snapshot_claim(
                ledger,
                canonical_catalog_publication,
                canonical_held_snapshot_catalog,
                holder_authority_id,
                binding_digest,
            )?;
            let (attempt_digest, attempt_deadline) =
                current_native_attempt_window(ledger, acquisition_id)?;
            let issued_seconds = current_seconds()?;
            let valid_until_seconds = expiry(issued_seconds)?.min(attempt_deadline);
            if valid_until_seconds <= issued_seconds {
                return Err(ProviderLedgerError::Unavailable);
            }
            validate_current_native_attempt(
                ledger,
                &claim,
                acquisition_id,
                attempt_digest,
                issued_seconds,
                valid_until_seconds,
            )?;
            ledger
                .journal
                .validate_source_provider_authority_snapshot(&journal_snapshot)?;

            let record = ChallengeRecordV1::new(
                claim.provider.authority_id(),
                holder_authority_id,
                claim.session_binding,
                attempt_digest,
                acquisition_id,
                binding_digest,
                claim.publication_head_commitment,
                issued_seconds,
                valid_until_seconds,
            );
            challenges.issue(record)
        })
    }

    /// Inspects a native row under the exact current protected catalog head.
    ///
    /// The fixed owner authenticates the signed publication against the exact
    /// holder's live session and protected namespace-41 journal, then checks
    /// the canonical `AOSPCZ01` bytes and row against that head. The result
    /// carries no authority to Acquire: a fresh, independently authenticated
    /// Storage GUID-and-hold receipt and durable replay exclusion are still
    /// required; the receipt inspection below grants neither authority.
    ///
    /// # Errors
    ///
    /// Rejects unavailable custody or the named holder's session, an invalid
    /// or stale publication, a malformed or mismatched catalog, an absent
    /// binding, or changed journal.
    pub fn inspect_current_held_snapshot_catalog_claim(
        &mut self,
        canonical_catalog_publication: &[u8],
        canonical_held_snapshot_catalog: &[u8],
        holder_authority_id: [u8; 16],
        binding_digest: ObjectDigest,
    ) -> Result<ProviderHeldSnapshotCatalogClaimV1, ProviderLedgerError> {
        self.with_ledger(|ledger| {
            select_current_held_snapshot_claim(
                ledger,
                canonical_catalog_publication,
                canonical_held_snapshot_catalog,
                holder_authority_id,
                binding_digest,
            )
        })
    }

    /// Checks a signed ZFS hold receipt without granting native Acquire authority.
    ///
    /// The signed Storage head still lacks an independently trusted current-head
    /// carrier, so this inspection neither spends the challenge nor authorizes
    /// native Acquire. Spending is reserved for a future successful currentness
    /// cut, before a positive backend effect or outcome can be exposed.
    ///
    /// # Errors
    ///
    /// Always returns an error. It rejects a missing protected verifier,
    /// invalid or spent receipt, stale publication or attempt, or the absent
    /// trusted-Storage-head completion gate.
    #[allow(clippy::too_many_arguments)]
    pub fn inspect_current_zfs_hold_receipt_closed(
        &mut self,
        canonical_catalog_publication: &[u8],
        canonical_held_snapshot_catalog: &[u8],
        holder_authority_id: [u8; 16],
        acquisition_id: ObjectDigest,
        canonical_signed_receipt: &[u8],
    ) -> Result<(), ProviderLedgerError> {
        let verifier = ProtectedStorageZfsHoldVerifierV1::load(self.backend_verifier())?;
        let signed = SignedStorageZfsHoldReceiptV1::decode(canonical_signed_receipt)
            .map_err(|_| ProviderLedgerError::Unavailable)?;

        self.with_ledger_and_hold_challenges(|ledger, challenges| {
            let receipt = signed.receipt();
            let (challenge_nonce, attempt_digest) = receipt.attempt();
            let (issued_seconds, valid_until_seconds) = receipt.validity();
            let journal_snapshot = ledger.journal.snapshot()?;
            let claim = select_current_held_snapshot_claim(
                ledger,
                canonical_catalog_publication,
                canonical_held_snapshot_catalog,
                holder_authority_id,
                receipt.binding_digest(),
            )?;
            if !claim_matches_receipt(&claim, receipt) {
                return Err(ProviderLedgerError::Unavailable);
            }
            validate_current_native_attempt(
                ledger,
                &claim,
                acquisition_id,
                attempt_digest,
                issued_seconds,
                valid_until_seconds,
            )?;
            let reserved = challenges.issued_for(challenge_nonce)?;
            let current = CurrentZfsHoldChallengeContextV1 {
                nonce: challenge_nonce,
                provider_id: claim.provider.authority_id(),
                holder_id: holder_authority_id,
                session_binding: claim.session_binding,
                attempt_digest,
                acquisition_id,
                binding_digest: claim.binding_digest,
                publication_head: claim.publication_head_commitment,
                validity: receipt.validity(),
            };
            if !reserved.matches_current(current) {
                return Err(ProviderLedgerError::Unavailable);
            }
            verifier.verify_for(&signed, receipt)?;
            ledger
                .journal
                .validate_source_provider_authority_snapshot(&journal_snapshot)?;
            let final_claim = select_current_held_snapshot_claim(
                ledger,
                canonical_catalog_publication,
                canonical_held_snapshot_catalog,
                holder_authority_id,
                receipt.binding_digest(),
            )?;
            if final_claim != claim {
                return Err(ProviderLedgerError::ConfigurationMismatch);
            }

            // The signed head is an assertion until Storage currentness is carried here.
            Err(ProviderLedgerError::Unavailable)
        })
    }
}

fn select_current_held_snapshot_claim(
    ledger: &mut ProviderLedgerV1<'_>,
    canonical_catalog_publication: &[u8],
    canonical_held_snapshot_catalog: &[u8],
    holder_authority_id: [u8; 16],
    binding_digest: ObjectDigest,
) -> Result<ProviderHeldSnapshotCatalogClaimV1, ProviderLedgerError> {
    let journal_snapshot = ledger.journal.snapshot()?;
    let session = ledger
        .current_sessions
        .get_mut(&holder_authority_id)
        .ok_or(ProviderLedgerError::InvalidTransition(
            "missing holder Provider session",
        ))?;
    let configuration = session.session.revalidated_provider_configuration()?;
    let publication = aos_sandbox_source_provider_security::verify_catalog_publication(
        &configuration,
        canonical_catalog_publication,
    )?;
    let current_catalog = session
        .session
        .authorize_fixed_current_catalog_publication_v1(
            &ledger.journal,
            journal_snapshot,
            publication,
        )?;
    let selected = current_catalog.select_held_snapshot_row(
        &ledger.journal,
        canonical_held_snapshot_catalog,
        binding_digest,
    )?;
    let session_binding = session.session.current_projection()?.session_binding();
    if !selected.is_current(&ledger.journal) {
        return Err(ProviderLedgerError::ConfigurationMismatch);
    }

    let (resource, snapshot) = selected.selected();
    let (provider, _) = current_catalog.projection().scope();
    Ok(ProviderHeldSnapshotCatalogClaimV1 {
        provider: provider.clone(),
        holder_authority_id,
        session_binding,
        binding_digest,
        resource: resource.clone(),
        snapshot: snapshot.clone(),
        publication_head_commitment: current_catalog.projection().head_commitment(),
    })
}

fn validate_current_native_attempt(
    ledger: &ProviderLedgerV1<'_>,
    claim: &ProviderHeldSnapshotCatalogClaimV1,
    acquisition_id: ObjectDigest,
    attempt_digest: ObjectDigest,
    issued_seconds: i64,
    valid_until_seconds: i64,
) -> Result<(), ProviderLedgerError> {
    let acquisition = unique_match(ledger.recovered.acquisitions.values(), |record| {
        record.acquisition_id == acquisition_id
    })?;
    if acquisition.state != ProviderAcquisitionStateV1::Applying
        || acquisition.provider != claim.provider
        || acquisition.holder.authority_id() != claim.holder_authority_id
        || acquisition.proof_class != 1
        || acquisition.normalized_intent.binding_digest() != claim.binding_digest
        || acquisition.current_attempt_digest != attempt_digest
        || acquisition.effect_attempt_digest != attempt_digest
        || acquisition.resource_namespace_digest != claim.resource.resource_namespace_digest()
        || acquisition.resource_id != claim.resource.resource_id()
        || acquisition.resource_generation != claim.resource.resource_generation()
        || acquisition.resource_digest != claim.resource.resource_digest()
        || acquisition.catalog_generation != claim.resource.catalog_generation()
        || acquisition.catalog_digest != claim.resource.catalog_digest()
        || acquisition.selection_generation != claim.resource.selection_generation()
        || acquisition.selection_digest != claim.resource.selection_digest()
        || acquisition.lease_id.is_some()
        || acquisition.backend_evidence.is_some()
        || acquisition.source_root.is_some()
    {
        return Err(ProviderLedgerError::Unavailable);
    }

    let attempt = unique_match(ledger.recovered.attempts.values(), |record| {
        record.attempt_digest == attempt_digest
    })?;
    let holder_head = ledger
        .recovered
        .sessions
        .get(&(
            acquisition.provider.authority_id(),
            claim.holder_authority_id,
        ))
        .ok_or(ProviderLedgerError::Unavailable)?;
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| ProviderLedgerError::Corrupt("retained signed Acquire request"))?;
    let request = decode_acquire_request(signed_request.subject())
        .map_err(|_| ProviderLedgerError::Corrupt("retained Acquire subject"))?;
    if attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.method != SourceProviderMethod::Acquire
        || attempt.status.is_some()
        || attempt.response_sequence.is_some()
        || attempt.provider != acquisition.provider
        || attempt.holder != acquisition.holder
        || attempt.session_binding != claim.session_binding
        || holder_head.session_binding != claim.session_binding
        || holder_head.pending_attempt_digest != Some(attempt_digest)
        || holder_head.next_request_sequence
            != attempt
                .request_sequence
                .checked_add(1)
                .ok_or(ProviderLedgerError::Unavailable)?
        || attempt.signed_request_digest != digest_signed_request(&signed_request)
        || attempt.signed_request_digest_again != attempt.signed_request_digest
        || attempt.typed_request_digest != digest_acquire_request(&request)
        || attempt.root_record_signer != *signed_request.signer()
        || attempt.operation_intent_digest != acquisition.normalized_intent.digest()
        || attempt.acquisition_sequence != acquisition.acquisition_sequence
        || request.session_binding() != claim.session_binding
        || request.sequence() != attempt.request_sequence
        || request.request_id() != attempt.request_id
        || request.acquisition_id() != acquisition_id
        || request.acquisition_version() != ACQUIRE_SOURCE_REQUEST_VERSION_V2
        || request.acquisition_sequence() != acquisition.acquisition_sequence
        || request.binding_digest() != claim.binding_digest
        || issued_seconds < attempt.verified_at_seconds
        || valid_until_seconds > attempt.current_valid_until_seconds
        || valid_until_seconds > request.deadline_seconds()
    {
        return Err(ProviderLedgerError::Unavailable);
    }
    Ok(())
}

fn current_native_attempt_window(
    ledger: &ProviderLedgerV1<'_>,
    acquisition_id: ObjectDigest,
) -> Result<(ObjectDigest, i64), ProviderLedgerError> {
    let acquisition = unique_match(ledger.recovered.acquisitions.values(), |record| {
        record.acquisition_id == acquisition_id
    })?;
    let attempt_digest = acquisition.current_attempt_digest;
    let attempt = unique_match(ledger.recovered.attempts.values(), |record| {
        record.attempt_digest == attempt_digest
    })?;
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| ProviderLedgerError::Corrupt("retained signed Acquire request"))?;
    let request = decode_acquire_request(signed_request.subject())
        .map_err(|_| ProviderLedgerError::Corrupt("retained Acquire subject"))?;
    Ok((
        attempt_digest,
        attempt
            .current_valid_until_seconds
            .min(request.deadline_seconds()),
    ))
}

fn unique_match<T>(
    records: impl Iterator<Item = T>,
    predicate: impl FnMut(&T) -> bool,
) -> Result<T, ProviderLedgerError> {
    let mut matches = records.filter(predicate);
    let record = matches.next().ok_or(ProviderLedgerError::Unavailable)?;
    if matches.next().is_some() {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(record)
}

fn claim_matches_receipt(
    claim: &ProviderHeldSnapshotCatalogClaimV1,
    expected: &StorageZfsHoldReceiptV1,
) -> bool {
    expected.binding_digest() == claim.binding_digest
        && expected.resource() == &claim.resource
        && expected.snapshot() == &claim.snapshot
}

#[cfg(test)]
mod tests {
    use aos_sandbox_source_provider_protocol::StorageZfsHoldHeadV1;

    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    #[test]
    fn unique_match_preserves_absence_and_equivocation() {
        assert!(matches!(
            unique_match(std::iter::empty::<u8>(), |_| true),
            Err(ProviderLedgerError::Unavailable)
        ));
        assert_eq!(unique_match(std::iter::once(7), |_| true).unwrap(), 7);
        assert!(matches!(
            unique_match([7, 8].into_iter(), |_| true),
            Err(ProviderLedgerError::Equivocation)
        ));
    }

    #[test]
    fn native_receipt_claim_requires_exact_resource_snapshot_and_binding() {
        let resource =
            SourceResourceV1::new(digest(1), [2; 32], 3, digest(4), 5, digest(6), 7, digest(8))
                .unwrap();
        let snapshot = ZfsHeldSnapshotProofV1::new(
            [9; 32],
            10,
            11,
            12,
            13,
            [14; 16],
            15,
            digest(16),
            digest(17),
            digest(18),
        )
        .unwrap();
        let head =
            StorageZfsHoldHeadV1::new(19, digest(20), 21, digest(22), 23, digest(24), digest(25))
                .unwrap();
        let claim = ProviderHeldSnapshotCatalogClaimV1 {
            provider: SourceProviderAuthorityV1::new([35; 16], 36, digest(37)).unwrap(),
            holder_authority_id: [26; 16],
            session_binding: digest(27),
            binding_digest: digest(28),
            resource: resource.clone(),
            snapshot: snapshot.clone(),
            publication_head_commitment: digest(29),
        };
        let receipt = |binding, resource, snapshot| {
            StorageZfsHoldReceiptV1::new(
                [30; 32],
                digest(31),
                binding,
                resource,
                snapshot,
                head,
                100,
                120,
            )
            .unwrap()
        };

        assert!(claim_matches_receipt(
            &claim,
            &receipt(digest(28), resource.clone(), snapshot.clone()),
        ));
        assert!(!claim_matches_receipt(
            &claim,
            &receipt(digest(32), resource.clone(), snapshot.clone()),
        ));
        let other_resource = SourceResourceV1::new(
            digest(1),
            [2; 32],
            3,
            digest(4),
            5,
            digest(33),
            7,
            digest(8),
        )
        .unwrap();
        assert!(!claim_matches_receipt(
            &claim,
            &receipt(digest(28), other_resource, snapshot.clone()),
        ));
        let other_snapshot = ZfsHeldSnapshotProofV1::new(
            [9; 32],
            10,
            11,
            12,
            34,
            [14; 16],
            15,
            digest(16),
            digest(17),
            digest(18),
        )
        .unwrap();
        assert!(!claim_matches_receipt(
            &claim,
            &receipt(digest(28), resource, other_snapshot),
        ));
    }
}
