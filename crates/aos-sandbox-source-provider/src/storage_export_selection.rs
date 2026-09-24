//! Protected Provider row and current-attempt selection for Storage export plans.
//!
//! This closed seam derives a plan basis only from the exact current journal,
//! signed catalog publication, canonical manifest, and retained RootMount
//! request. Repeated construction produces the same plan identity and interval
//! from the durable attempt; neither a new clock sample nor a caller-selected
//! lease can fork the Storage request. It does not permit a backend effect.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V2, SignedSourceProviderRequestV1, SourceProviderAuthorityV1,
    SourceProviderMethod, SourceResourceV1, StorageLiveExportRequestV1,
    StorageLiveExportSelectorV1, decode_acquire_request, digest_acquire_request,
    digest_signed_request,
};
use aos_sandbox_source_provider_security::ProtectedProviderCatalogSelectionV1;

use crate::backend::DurableAcquireEffectPermitV1;
use crate::model::{
    AcquisitionRecordV1, AttemptRecordV1, ProviderAcquisitionStateV1, ProviderAttemptStateV1,
};
use crate::{FixedProviderOwnerV1, ProviderLedgerError, ProviderLedgerV1};

/// Carries only the exact protected facts needed to form one Storage plan.
///
/// The value is nonauthorizing outside the fixed owner's callback. There is
/// no public constructor or signing method. LocalLive may reserve a selected
/// row for readback, but all descriptor-bearing effects remain closed until
/// independent Storage and kernel producers exist.
pub struct ProviderStorageExportPlanBasisV1 {
    resource: SourceResourceV1,
    storage_selector: StorageLiveExportSelectorV1,
    signed_root_request: SignedSourceProviderRequestV1,
    protected_attempt_digest: ObjectDigest,
    normalized_intent_digest: ObjectDigest,
    effect_id: [u8; 16],
    backend_id: ObjectDigest,
    verified_at_seconds: i64,
    current_valid_until_seconds: i64,
}

impl core::fmt::Debug for ProviderStorageExportPlanBasisV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderStorageExportPlanBasisV1([protected plan basis])")
    }
}

impl ProviderStorageExportPlanBasisV1 {
    /// Returns the exact selected Provider resource.
    #[must_use]
    pub const fn resource(&self) -> &SourceResourceV1 {
        &self.resource
    }

    /// Returns the matching Storage export selector.
    #[must_use]
    pub const fn storage_selector(&self) -> StorageLiveExportSelectorV1 {
        self.storage_selector
    }

    /// Returns the original RootMount-signed Acquire request.
    #[must_use]
    pub const fn signed_root_request(&self) -> &SignedSourceProviderRequestV1 {
        &self.signed_root_request
    }

    /// Returns the durable current attempt commitment.
    #[must_use]
    pub const fn protected_attempt_digest(&self) -> ObjectDigest {
        self.protected_attempt_digest
    }

    /// Returns the durable normalized intent commitment.
    #[must_use]
    pub const fn normalized_intent_digest(&self) -> ObjectDigest {
        self.normalized_intent_digest
    }

    /// Returns the exact Provider effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> [u8; 16] {
        self.effect_id
    }

    /// Returns the exact Provider backend assignment.
    #[must_use]
    pub const fn backend_id(&self) -> ObjectDigest {
        self.backend_id
    }

    /// Constructs the exact replay-stable, still-unsigned Storage request.
    ///
    /// The plan ID is the already durable Provider effect ID. Its interval is
    /// bounded by the admitted verification time, current trust horizon,
    /// RootMount deadline, and requested lease; retry cannot extend it.
    ///
    /// # Errors
    ///
    /// Rejects an expired or contradictory retained interval or request.
    pub fn to_storage_request(&self) -> Result<StorageLiveExportRequestV1, ProviderLedgerError> {
        let root_request = decode_acquire_request(self.signed_root_request.subject())
            .map_err(|_| ProviderLedgerError::Corrupt("retained Acquire subject"))?;
        let (issued_seconds, expires_seconds) = durable_storage_interval(
            self.verified_at_seconds,
            self.current_valid_until_seconds,
            root_request.deadline_seconds(),
            root_request.requested_lease_seconds(),
        )
        .ok_or(ProviderLedgerError::Unavailable)?;

        StorageLiveExportRequestV1::new(
            self.effect_id,
            self.protected_attempt_digest,
            self.normalized_intent_digest,
            self.effect_id,
            self.backend_id,
            self.resource.clone(),
            self.storage_selector,
            issued_seconds,
            expires_seconds,
            self.signed_root_request.clone(),
        )
        .map_err(|_| ProviderLedgerError::Unavailable)
    }
}

fn durable_storage_interval(
    verified_at_seconds: i64,
    current_valid_until_seconds: i64,
    request_deadline_seconds: i64,
    requested_lease_seconds: u64,
) -> Option<(i64, i64)> {
    if verified_at_seconds <= 0 || requested_lease_seconds == 0 {
        return None;
    }
    let lease_end = verified_at_seconds
        .saturating_add(i64::try_from(requested_lease_seconds).unwrap_or(i64::MAX));
    let expires_seconds = lease_end
        .min(current_valid_until_seconds)
        .min(request_deadline_seconds);
    (expires_seconds > verified_at_seconds).then_some((verified_at_seconds, expires_seconds))
}

impl FixedProviderOwnerV1 {
    /// Borrows an exact current selected row and reserved Acquire attempt.
    ///
    /// Both byte slices are nonauthorizing inputs. The method verifies the
    /// publication against protected trust/journal state, checks the manifest
    /// digest and binding selection, then proves the retained RootMount request
    /// is the sole current attempt with a nonzero durable selected row. The
    /// journal snapshot is rechecked before and after the callback.
    ///
    /// # Errors
    ///
    /// Rejects stale publication, forked manifest, missing/ambiguous attempt,
    /// replayed sequence, zero-sentinel row, changed journal, or callback error.
    pub fn with_current_storage_export_plan_basis<R>(
        &mut self,
        canonical_catalog_publication: &[u8],
        canonical_manifest: &[u8],
        acquisition_id: ObjectDigest,
        operation: impl FnOnce(&ProviderStorageExportPlanBasisV1) -> Result<R, ProviderLedgerError>,
    ) -> Result<R, ProviderLedgerError> {
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
            let mut acquisitions = ledger
                .recovered
                .acquisitions
                .values()
                .filter(|record| record.acquisition_id == acquisition_id);
            let acquisition = acquisitions
                .next()
                .ok_or(ProviderLedgerError::Unavailable)?;
            if acquisitions.next().is_some() {
                return Err(ProviderLedgerError::Equivocation);
            }
            let mut attempts = ledger
                .recovered
                .attempts
                .values()
                .filter(|record| record.attempt_digest == acquisition.current_attempt_digest);
            let attempt = attempts.next().ok_or(ProviderLedgerError::Unavailable)?;
            if attempts.next().is_some() {
                return Err(ProviderLedgerError::Equivocation);
            }
            let selected = current_catalog.select_manifest_row(
                &ledger.journal,
                canonical_manifest,
                acquisition.normalized_intent.binding_digest(),
            )?;
            let (current_provider, _) = current_catalog.projection().scope();
            let basis = validate_selected_attempt(
                acquisition,
                attempt,
                &selected,
                current_provider,
                session.session.current_projection()?.session_binding(),
                ledger
                    .recovered
                    .sessions
                    .get(&(
                        acquisition.provider.authority_id(),
                        acquisition.holder.authority_id(),
                    ))
                    .map(|record| record.next_request_sequence),
            )?;
            if !selected.is_current(&ledger.journal) {
                return Err(ProviderLedgerError::ConfigurationMismatch);
            }
            let result = operation(&basis)?;
            if !selected.is_current(&ledger.journal) {
                return Err(ProviderLedgerError::ConfigurationMismatch);
            }
            Ok(result)
        })
    }
}

impl ProviderLedgerV1<'_> {
    /// Signs one exact current LocalLive plan under a durable Acquire permit.
    ///
    /// The Provider outcome key is borrowed only through the live session's
    /// one-shot security facade. This method performs no Storage or kernel
    /// effect; the caller may submit the returned bytes only to the closed
    /// authenticated Storage inspection endpoint.
    ///
    /// # Errors
    ///
    /// Rejects a stale permit, publication, manifest, row, attempt, interval,
    /// or Provider signing custody.
    pub(crate) fn sign_current_storage_export_request(
        &mut self,
        permit: &DurableAcquireEffectPermitV1,
        canonical_catalog_publication: &[u8],
        canonical_manifest: &[u8],
    ) -> Result<
        aos_sandbox_source_provider_protocol::SignedStorageLiveExportRequestV1,
        ProviderLedgerError,
    > {
        if !permit.plan.kernel_coupled()
            || permit.plan.attempt_digest() != permit.completion_attempt_digest
            || permit.plan.session_binding() != permit.completion_session_binding
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        self.journal
            .validate_source_provider_authority_snapshot(&permit.journal_snapshot)?;
        let mut acquisitions = self
            .recovered
            .acquisitions
            .values()
            .filter(|record| record.acquisition_id == permit.plan.acquisition_id());
        let acquisition = acquisitions
            .next()
            .ok_or(ProviderLedgerError::Unavailable)?;
        if acquisitions.next().is_some() {
            return Err(ProviderLedgerError::Equivocation);
        }
        let mut attempts = self
            .recovered
            .attempts
            .values()
            .filter(|record| record.attempt_digest == permit.plan.attempt_digest());
        let attempt = attempts.next().ok_or(ProviderLedgerError::Unavailable)?;
        if attempts.next().is_some() {
            return Err(ProviderLedgerError::Equivocation);
        }
        let session = self
            .current_sessions
            .get_mut(&permit.plan.holder_id())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let configuration = session.session.revalidated_provider_configuration()?;
        let publication = aos_sandbox_source_provider_security::verify_catalog_publication(
            &configuration,
            canonical_catalog_publication,
        )?;
        let snapshot = self.journal.snapshot()?;
        let current_catalog = session
            .session
            .authorize_fixed_current_catalog_publication_v1(&self.journal, snapshot, publication)?;
        let selected = current_catalog.select_manifest_row(
            &self.journal,
            canonical_manifest,
            acquisition.normalized_intent.binding_digest(),
        )?;
        let (current_provider, _) = current_catalog.projection().scope();
        let basis = validate_selected_attempt(
            acquisition,
            attempt,
            &selected,
            current_provider,
            session.session.current_projection()?.session_binding(),
            self.recovered
                .sessions
                .get(&(
                    acquisition.provider.authority_id(),
                    acquisition.holder.authority_id(),
                ))
                .map(|record| record.next_request_sequence),
        )?;
        if basis.effect_id != permit.plan.effect_id()
            || basis.backend_id.as_bytes() != &permit.plan.backend_id()
            || basis.normalized_intent_digest != permit.plan.normalized_intent_digest()
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        let request = basis.to_storage_request()?;
        let signed = session
            .session
            .provider_outcome_facade(&self.journal, &permit.signing_authorization)?
            .sign_current_storage_export_request(&selected, request)?;
        if !selected.is_current(&self.journal) {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        Ok(signed)
    }
}

fn validate_selected_attempt(
    acquisition: &AcquisitionRecordV1,
    attempt: &AttemptRecordV1,
    selected: &ProtectedProviderCatalogSelectionV1<'_>,
    current_provider: &SourceProviderAuthorityV1,
    current_session_binding: ObjectDigest,
    next_request_sequence: Option<u64>,
) -> Result<ProviderStorageExportPlanBasisV1, ProviderLedgerError> {
    let (resource, storage_selector) = selected.selected();
    let signed_root_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| ProviderLedgerError::Corrupt("retained signed Acquire request"))?;
    let request = decode_acquire_request(signed_root_request.subject())
        .map_err(|_| ProviderLedgerError::Corrupt("retained Acquire subject"))?;
    let selected_matches_durable = acquisition.resource_namespace_digest
        == resource.resource_namespace_digest()
        && acquisition.resource_id == resource.resource_id()
        && acquisition.resource_generation == resource.resource_generation()
        && acquisition.resource_digest == resource.resource_digest()
        && acquisition.catalog_generation == resource.catalog_generation()
        && acquisition.catalog_digest == resource.catalog_digest()
        && acquisition.selection_generation == resource.selection_generation()
        && acquisition.selection_digest == resource.selection_digest();
    let attempt_is_current = acquisition.state == ProviderAcquisitionStateV1::Applying
        && acquisition.provider == *current_provider
        && acquisition.effect_id != [0; 16]
        && acquisition.backend_id != [0; 32]
        && attempt.state == ProviderAttemptStateV1::Reserved
        && acquisition.current_attempt_digest == attempt.attempt_digest
        && acquisition.effect_attempt_digest == attempt.attempt_digest
        && current_attempt_sequence_matches(
            current_session_binding,
            next_request_sequence,
            attempt.session_binding,
            attempt.request_sequence,
            request.session_binding(),
            request.sequence(),
        )
        && attempt.method == SourceProviderMethod::Acquire
        && attempt.status.is_none()
        && attempt.response_sequence.is_none()
        && attempt.signed_request_digest == digest_signed_request(&signed_root_request)
        && attempt.signed_request_digest_again == attempt.signed_request_digest
        && attempt.typed_request_digest == digest_acquire_request(&request)
        && attempt.root_record_signer == *signed_root_request.signer()
        && attempt.provider == acquisition.provider
        && attempt.holder == acquisition.holder
        && attempt.operation_intent_digest == acquisition.normalized_intent.digest()
        && request.request_id() == attempt.request_id
        && request.acquisition_id() == acquisition.acquisition_id
        && request.acquisition_version() == ACQUIRE_SOURCE_REQUEST_VERSION_V2
        && request.acquisition_sequence() == acquisition.acquisition_sequence
        && request.binding_digest() == acquisition.normalized_intent.binding_digest()
        && request.kernel_coupled()
        && acquisition.normalized_intent.kernel_coupled();
    if !selected_matches_durable || !attempt_is_current {
        return Err(ProviderLedgerError::Unavailable);
    }

    Ok(ProviderStorageExportPlanBasisV1 {
        resource: resource.clone(),
        storage_selector,
        signed_root_request,
        protected_attempt_digest: attempt.attempt_digest,
        normalized_intent_digest: acquisition.normalized_intent.digest(),
        effect_id: acquisition.effect_id,
        backend_id: ObjectDigest::from_bytes(acquisition.backend_id),
        verified_at_seconds: attempt.verified_at_seconds,
        current_valid_until_seconds: attempt.current_valid_until_seconds,
    })
}

fn current_attempt_sequence_matches(
    current_session_binding: ObjectDigest,
    next_request_sequence: Option<u64>,
    retained_session_binding: ObjectDigest,
    retained_request_sequence: u64,
    signed_session_binding: ObjectDigest,
    signed_request_sequence: u64,
) -> bool {
    retained_session_binding == current_session_binding
        && signed_session_binding == retained_session_binding
        && signed_request_sequence == retained_request_sequence
        && next_request_sequence.is_some_and(|next| next > retained_request_sequence)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use aos_sandbox_source_provider_protocol::{
        AcquireSourceRequestV1, SignedStorageLiveExportRequestV1, SourceProviderKeyUsageV1,
        SourceProviderSigningKeyV1, SourceUseV1, digest_logical_binding_bytes,
        encode_acquire_request, prospective_mount_apply_template_digest_v1, sign_request,
    };

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn replay_basis() -> ProviderStorageExportPlanBasisV1 {
        let root_key = SigningKey::from_bytes(&[41; 32]);
        let mut template = Vec::new();
        for tag in 1u8..=27 {
            let value = match tag {
                1 => b"AOSMSEM1".to_vec(),
                2 => 1u16.to_be_bytes().to_vec(),
                _ => vec![tag, tag.wrapping_add(1)],
            };
            template.push(tag);
            template.extend_from_slice(&(value.len() as u32).to_be_bytes());
            template.extend_from_slice(&value);
        }
        let template_digest = prospective_mount_apply_template_digest_v1(&template).unwrap();
        let binding = b"exact-root-mount-attachment".to_vec();
        let binding_digest = digest_logical_binding_bytes(&binding);
        let root_request = AcquireSourceRequestV1::new_v2(
            digest(1),
            2,
            [3; 16],
            4,
            template,
            template_digest,
            SourceUseV1::MountCreate,
            [5; 16],
            [6; 16],
            [7; 16],
            8,
            digest(9),
            binding,
            binding_digest,
            1000,
            60,
            digest(10),
            false,
            0,
            true,
        )
        .unwrap();
        let root_signer = SourceProviderSigningKeyV1::for_signing_key(
            [7; 16],
            8,
            digest(9),
            [11; 16],
            12,
            SourceProviderKeyUsageV1::RootMountRecord,
            &root_key,
        )
        .unwrap();
        let signed_root_request = sign_request(
            SourceProviderMethod::Acquire,
            encode_acquire_request(&root_request),
            root_signer,
            &root_key,
        )
        .unwrap();

        ProviderStorageExportPlanBasisV1 {
            resource: SourceResourceV1::new(
                digest(13),
                [14; 32],
                15,
                digest(16),
                17,
                digest(18),
                19,
                digest(20),
            )
            .unwrap(),
            storage_selector: StorageLiveExportSelectorV1::new([21; 16], 22, [23; 32], digest(24))
                .unwrap(),
            signed_root_request,
            protected_attempt_digest: digest(25),
            normalized_intent_digest: digest(26),
            effect_id: [27; 16],
            backend_id: digest(28),
            verified_at_seconds: 950,
            current_valid_until_seconds: 1010,
        }
    }

    #[test]
    fn selected_attempt_sequence_rejects_replay_and_superseded_session() {
        let current = ObjectDigest::from_bytes([1; 32]);
        let stale = ObjectDigest::from_bytes([2; 32]);
        assert!(current_attempt_sequence_matches(
            current,
            Some(9),
            current,
            8,
            current,
            8
        ));
        assert!(!current_attempt_sequence_matches(
            current,
            Some(8),
            current,
            8,
            current,
            8
        ));
        assert!(!current_attempt_sequence_matches(
            current,
            Some(9),
            current,
            8,
            current,
            7
        ));
        assert!(!current_attempt_sequence_matches(
            current,
            Some(9),
            stale,
            8,
            stale,
            8
        ));
        assert!(!current_attempt_sequence_matches(
            current, None, current, 8, current, 8
        ));
    }

    #[test]
    fn durable_storage_interval_never_extends_on_retry() {
        let first = durable_storage_interval(100, 200, 180, 60);
        assert_eq!(first, Some((100, 160)));
        assert_eq!(durable_storage_interval(100, 200, 180, 60), first);
        assert_eq!(
            durable_storage_interval(100, 130, 180, 60),
            Some((100, 130))
        );
        assert_eq!(
            durable_storage_interval(100, 200, 120, 60),
            Some((100, 120))
        );
        assert_eq!(durable_storage_interval(100, 100, 180, 60), None);
        assert_eq!(durable_storage_interval(100, 200, 100, 60), None);
    }

    #[test]
    fn same_durable_attempt_reproduces_exact_signed_plan_bytes() {
        let mut basis = replay_basis();
        let first = basis.to_storage_request().unwrap();
        let retry = basis.to_storage_request().unwrap();
        assert_eq!(first, retry);
        assert_eq!(first.plan_id(), basis.effect_id());
        assert_eq!(
            (first.issued_seconds(), first.expires_seconds()),
            (950, 1000)
        );

        let provider_key = SigningKey::from_bytes(&[42; 32]);
        let provider_signer = SourceProviderSigningKeyV1::for_signing_key(
            [30; 16],
            31,
            digest(32),
            [33; 16],
            34,
            SourceProviderKeyUsageV1::ProviderOutcome,
            &provider_key,
        )
        .unwrap();
        let signed_first =
            SignedStorageLiveExportRequestV1::sign(first, provider_signer.clone(), &provider_key)
                .unwrap();
        let signed_retry =
            SignedStorageLiveExportRequestV1::sign(retry, provider_signer.clone(), &provider_key)
                .unwrap();
        assert_eq!(
            signed_first.to_canonical_bytes(),
            signed_retry.to_canonical_bytes()
        );

        basis.effect_id = [35; 16];
        let fork = SignedStorageLiveExportRequestV1::sign(
            basis.to_storage_request().unwrap(),
            provider_signer,
            &provider_key,
        )
        .unwrap();
        assert_ne!(signed_first.to_canonical_bytes(), fork.to_canonical_bytes());
    }
}
