//! Protected Provider row and current-attempt selection for Storage export plans.
//!
//! This closed seam derives a plan basis only from the exact current journal,
//! signed catalog publication, canonical manifest, and retained RootMount
//! request. It does not sign or transmit a plan or permit a backend effect.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V2, SignedSourceProviderRequestV1, SourceProviderAuthorityV1,
    SourceProviderMethod, SourceResourceV1, StorageLiveExportSelectorV1, decode_acquire_request,
    digest_acquire_request, digest_signed_request,
};
use aos_sandbox_source_provider_security::ProtectedProviderCatalogSelectionV1;

use crate::model::{
    AcquisitionRecordV1, AttemptRecordV1, ProviderAcquisitionStateV1, ProviderAttemptStateV1,
};
use crate::{FixedProviderOwnerV1, ProviderLedgerError};

/// Carries only the exact protected facts needed to form one Storage plan.
///
/// The value is nonauthorizing outside the fixed owner's callback. There is
/// no public constructor or signing method, and LocalLive reservation remains
/// closed until independent Storage and kernel producers exist.
pub struct ProviderStorageExportPlanBasisV1 {
    resource: SourceResourceV1,
    storage_selector: StorageLiveExportSelectorV1,
    signed_root_request: SignedSourceProviderRequestV1,
    protected_attempt_digest: ObjectDigest,
    normalized_intent_digest: ObjectDigest,
    effect_id: [u8; 16],
    backend_id: ObjectDigest,
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
    use super::*;

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
}
