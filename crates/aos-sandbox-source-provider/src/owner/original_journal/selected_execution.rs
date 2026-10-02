//! Derive-once selected execution inputs at the actual original pre-Ready cut.
//!
//! The original pair, full Applying transaction, selected publication/catalog
//! and both protected enrollment owners remain resident. This child retains
//! Source-local comparison DATA only; it supplies no Root observation, live
//! effect grant. Immutable archive installation follows the resident frame;
//! every repeat compares against the first frame and same original file.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_ledger::ledger::native_completion::OriginalSourceOwnerDataV5;
use aos_sandbox_source_provider_protocol::{
    ProviderHeldSnapshotCatalogV1, SignedStorageNativeAcquireRequestV2, VerifiedProviderRequestV1,
    native_held_completion::{
        SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1, SourceSelectedNativeExecutionInputDataV1,
        SourceSelectedNativeExecutionInputFieldsV1, NativeHeldScopeV1, NativeHeldCompletionErrorV1,
        frame::SignedNativeHeldControlV1,
    },
};
use sha2::{Digest, Sha256};

use super::producer::OriginalProducerErrorV5;
use super::{FixedProviderOwnerStateV1, FixedProviderOwnerV1};
use crate::{ProviderLedgerError, backend::AcquirePlanV1};

impl FixedProviderOwnerV1 {
    /// Retains the first Source-local frame before the producer reports Ready.
    ///
    /// The sole caller holds the original producer closure guard and has just
    /// checked current custody and the actual ChallengeIssued readback.
    /// Enrollment bytes are parked before later crossings. The final bookend
    /// samples the same clock after the potentially slow protected-owner checks.
    pub(super) fn retain_selected_execution_input_v1(
        &mut self,
    ) -> Result<&[u8; SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1], OriginalProducerErrorV5> {
        self.retain_selected_enrollments_v1()?;

        let expected = self.derive_selected_execution_input_v1()?;
        retain_frame(
            &mut self.original_source_producer_mut_v5()?.selected_execution,
            expected,
        )?;

        self.require_selected_enrollments_v1()?;
        self.require_original_producer_current_v5()?;
        self.require_original_producer_readback_v5()?;
        let signed = self.original_source_producer_v5()?
            .signed
            .as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;
        self.original_ingress.borrowed_clock_v5()?.require_request(signed)?;

        self.retain_selected_input_archive_v1()?;

        let retained = self.original_source_producer_v5()?
            .selected_execution
            .as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;
        Ok(retained.as_canonical_bytes())
    }

    fn retain_selected_enrollments_v1(&mut self) -> Result<(), OriginalProducerErrorV5> {
        let backend: [u8; 928] = self.backend_verifier
            .original_enrollment_v1()?
            .try_into()
            .map_err(|_| ProviderLedgerError::Corrupt("original backend enrollment width"))?;
        retain_enrollment(
            &mut self.original_source_producer_mut_v5()?.selected_backend_enrollment,
            backend,
        )?;

        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_ref() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let storage = held.original.as_ref()
            .and_then(|original| original.history.storage.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let dedicated: [u8; 160] = storage.original_enrollment_v5()?
            .try_into()
            .map_err(|_| ProviderLedgerError::Corrupt("original dedicated enrollment width"))?;
        retain_enrollment(
            &mut self.original_source_producer_mut_v5()?.selected_dedicated_enrollment,
            dedicated,
        )?;
        Ok(())
    }

    pub(super) fn require_selected_enrollments_v1(&self) -> Result<(), OriginalProducerErrorV5> {
        let producer = self.original_source_producer_v5()?;
        let backend = producer.selected_backend_enrollment.as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;
        self.backend_verifier.require_original_enrollment_v1(backend)?;

        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_ref() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let storage = held.original.as_ref()
            .and_then(|original| original.history.storage.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let dedicated = producer.selected_dedicated_enrollment.as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;
        storage.require_original_enrollment_v5(dedicated)?;
        Ok(())
    }

    fn derive_selected_execution_input_v1(
        &mut self,
    ) -> Result<SourceSelectedNativeExecutionInputDataV1, OriginalProducerErrorV5> {
        let (root, acquire) = self.original_ingress.borrowed_pair_v5()?;
        let VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else {
            return Err(ProviderLedgerError::Equivocation.into());
        };
        let request = verified.request();
        let projection = verified.ingress_projection();
        let native = request.native_catalog().ok_or(ProviderLedgerError::Equivocation)?;
        let rows = self.original_ingress.borrowed_catalog_v1()?;
        let catalog = ProviderHeldSnapshotCatalogV1::from_canonical_bytes(rows)?;
        let selected = catalog.select_under_head(
            native.head().0,
            native.head().1,
            native.resource_namespace_digest(),
            request.binding_digest(),
        )?;

        let selection = self.original_ingress.borrowed_selection_v5()?;
        let (publication, publication_digest) = selection.original_publication_projection();
        let (resource, snapshot) = selection.original_selected_tuple();
        if publication.catalog_head() != native.head()
            || publication.floor() != native.floor()
            || publication_digest != native.canonical_publication_digest()
            || &selected.0 != resource
            || Some(&selected.1) != snapshot
        {
            return Err(ProviderLedgerError::ConfigurationMismatch.into());
        }

        // Borrow disjoint real owners. The replay origin is historical DATA
        // from this SAME current writer, never a restored Applying capability.
        let Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) = self.state.as_ref() else {
            return Err(ProviderLedgerError::Unavailable.into());
        };
        let producer = held.original.as_ref()
            .and_then(|original| original.producer.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)?;
        let signed = producer.signed.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let claims = signed.request().claims();
        let plan = producer.physical_plan.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let challenges = self.hold_challenges.original_history_v5()?;
        let journal = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let authority = journal.claim_source_original_native_v5(&challenges)?;
        let replay = authority.replayed_origins()?;
        let applying = producer.applying_transaction_v5()?;
        let origin = replay.origins().iter()
            .find(|origin| {
                origin.applying_transaction() == applying
                    && origin.admission_comparison().original().acquisition_id
                        == request.acquisition_id()
            })
            .ok_or(ProviderLedgerError::Unavailable)?;
        let original = origin.admission_comparison().original();
        require_plan_origin(plan, original)?;

        let normalized = crate::acquire::normalized_intent(verified)?;
        let backend = aos_sandbox_source_provider_ledger::identity::acquire_native_dispatch_id_v2(
            normalized.digest(),
            native.head().0,
            native.head().1,
            verified.attempt().attempt_digest(),
        );
        let effect = crate::acquire::derive_acquire_effect_id(
            request.acquisition_id(),
            verified.attempt().attempt_digest(),
        )?;

        // Compare every plan field, including the two omitted by its lineage
        // hash, with the genuine original request and existing identity engine.
        if plan.provider_id() != projection.provider_authority().authority_id()
            || plan.holder_id() != projection.root_mount_authority().authority_id()
            || plan.session_binding() != request.session_binding()
            || plan.attempt_digest() != verified.attempt().attempt_digest()
            || plan.acquisition_id() != request.acquisition_id()
            || plan.effect_id() != effect
            || plan.normalized_intent_digest() != normalized.digest()
            || plan.kernel_coupled()
            || normalized.kernel_coupled()
            || plan.backend_id() != backend
        {
            return Err(ProviderLedgerError::Equivocation.into());
        }

        // These remain the SAME signed originals and selected complete rowset;
        // neither a self-agreeing hash nor a decoded catalog is current custody.
        if original.root_request_digest != root.control().scope().original_root_request
            || original.root_prepared_digest != root.control().digest()
            || original.catalog_head != native.head()
            || original.resource_namespace_digest != native.resource_namespace_digest()
            || signed.request().signed_root_request().to_canonical_bytes()
                != verified.attempt().canonical_signed_request()
            || claims.provider_acquisition() != (plan.provider_id(), plan.acquisition_id())
            || claims.holder_session() != (plan.holder_id(), plan.session_binding())
            || claims.attempt().1 != plan.attempt_digest()
            || claims.selection() != (request.binding_digest(), native.current_head_commitment())
            || claims.catalog() != &catalog
            || raw_digest(&held.publication) != publication_digest
        {
            return Err(ProviderLedgerError::Equivocation.into());
        }

        let scope = selected_execution_scope_v1(original, root.control(), signed)?;
        let backend_enrollment = producer.selected_backend_enrollment.as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;
        let dedicated_enrollment = producer.selected_dedicated_enrollment.as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;

        Ok(assemble_selected_execution_input_v1(
            original, scope, root.control(), &catalog, publication_digest,
            request.binding_digest(), backend_enrollment, dedicated_enrollment,
        )?)
    }
}

// Both adapters use the same assembly. Their distinct live/historical checks
// stay outside: this helper constructs comparison DATA, never verified owners.
pub(super) fn selected_execution_scope_v1(
    original: &OriginalSourceOwnerDataV5,
    root: &SignedNativeHeldControlV1,
    signed: &SignedStorageNativeAcquireRequestV2,
) -> Result<NativeHeldScopeV1, NativeHeldCompletionErrorV1> {
    let mut scope = *root.scope();
    scope.provider_attempt = original.attempt_digest;
    scope.original_native_request = signed.digest();
    scope.require_root_prefix(root.scope())?;
    Ok(scope)
}

pub(super) fn assemble_selected_execution_input_v1(
    original: &OriginalSourceOwnerDataV5,
    scope: NativeHeldScopeV1,
    root: &SignedNativeHeldControlV1,
    catalog: &ProviderHeldSnapshotCatalogV1,
    publication: ObjectDigest,
    binding: ObjectDigest,
    backend_enrollment: &[u8],
    dedicated_enrollment: &[u8],
) -> Result<SourceSelectedNativeExecutionInputDataV1, NativeHeldCompletionErrorV1> {
    Ok(SourceSelectedNativeExecutionInputDataV1::new(
        SourceSelectedNativeExecutionInputFieldsV1 {
            scope,
            provider_id: original.provider.authority_id(),
            holder_id: original.holder.authority_id(),
            session_binding: original.session_binding,
            attempt_digest: original.attempt_digest,
            acquisition_id: original.acquisition_id,
            effect_id: original.operation_id,
            normalized_intent_digest: original.normalized_intent_digest,
            kernel_coupled: false,
            backend_id: original.backend_id,
            root_prepared: root.digest(),
            publication,
            catalog: catalog.digest(),
            binding,
            backend_enrollment: raw_digest(backend_enrollment),
            dedicated_enrollment: raw_digest(dedicated_enrollment),
        },
    )?)
}

fn require_plan_origin(
    plan: &AcquirePlanV1,
    original: &OriginalSourceOwnerDataV5,
) -> Result<(), ProviderLedgerError> {
    if plan.provider_id() != original.provider.authority_id()
        || plan.holder_id() != original.holder.authority_id()
        || plan.session_binding() != original.session_binding
        || plan.attempt_digest() != original.attempt_digest
        || plan.acquisition_id() != original.acquisition_id
        || plan.effect_id() != original.operation_id
        || plan.normalized_intent_digest() != original.normalized_intent_digest
        || plan.kernel_coupled()
        || plan.backend_id() != original.backend_id
        || plan.lineage_digest() != original.backend_lineage_digest
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(())
}

fn retain_enrollment<const N: usize>(
    retained: &mut Option<[u8; N]>,
    observed: [u8; N],
) -> Result<(), ProviderLedgerError> {
    if let Some(original) = retained.as_ref() {
        if original != &observed {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
    } else {
        *retained = Some(observed);
    }
    Ok(())
}

fn retain_frame(
    retained: &mut Option<SourceSelectedNativeExecutionInputDataV1>,
    observed: SourceSelectedNativeExecutionInputDataV1,
) -> Result<(), ProviderLedgerError> {
    if let Some(original) = retained.as_ref() {
        if original.as_canonical_bytes() != observed.as_canonical_bytes() {
            return Err(ProviderLedgerError::Equivocation);
        }
    } else {
        *retained = Some(observed);
    }
    Ok(())
}

fn raw_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    //! UNRUN pure comparison vectors, not genuine protected-owner admissions.

    use super::*;
    use aos_sandbox_source_provider_ledger::ledger::native_completion::OriginalSourceOwnerPrefixV5;
    use aos_sandbox_source_provider_protocol::{
        SourceProviderAuthorityV1,
        native_held_completion::{NativeHeldScopeV1, native_held_flight_digest_v1},
    };

    fn d(value: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([value; 32])
    }

    fn plan() -> AcquirePlanV1 {
        AcquirePlanV1 {
            provider_id: [1; 16],
            holder_id: [2; 16],
            session_binding: d(3),
            attempt_digest: d(4),
            acquisition_id: d(5),
            effect_id: [6; 16],
            normalized_intent_digest: d(7),
            kernel_coupled: false,
            backend_id: [8; 32],
        }
    }

    fn origin(plan: &AcquirePlanV1) -> OriginalSourceOwnerDataV5 {
        OriginalSourceOwnerDataV5 {
            prefix: OriginalSourceOwnerPrefixV5::Applying,
            provider: SourceProviderAuthorityV1::new(plan.provider_id(), 1, d(11)).unwrap(),
            holder: SourceProviderAuthorityV1::new(plan.holder_id(), 1, d(12)).unwrap(),
            acquisition_id: plan.acquisition_id(),
            operation_id: plan.effect_id(),
            reservation_acquisition_digest: d(13),
            attempt_digest: plan.attempt_digest(),
            root_request_digest: d(14),
            session_binding: plan.session_binding(),
            root_prepared_digest: d(15),
            configuration_digest: d(16),
            catalog_head: (1, d(17)),
            resource_namespace_digest: d(18),
            backend_id: plan.backend_id(),
            backend_lineage_digest: plan.lineage_digest(),
            normalized_intent_digest: plan.normalized_intent_digest(),
            native_request_digest: None,
        }
    }

    fn frame(plan: &AcquirePlanV1) -> SourceSelectedNativeExecutionInputDataV1 {
        let scope = NativeHeldScopeV1 {
            flight: native_held_flight_digest_v1(d(14), d(19), plan.session_binding()),
            original_source_session: plan.session_binding(),
            mount_attempt: d(19),
            provider_attempt: plan.attempt_digest(),
            provider_acquisition: plan.acquisition_id(),
            original_root_request: d(14),
            original_native_request: d(20),
        };
        SourceSelectedNativeExecutionInputDataV1::new(
            SourceSelectedNativeExecutionInputFieldsV1 {
                scope,
                provider_id: plan.provider_id(),
                holder_id: plan.holder_id(),
                session_binding: plan.session_binding(),
                attempt_digest: plan.attempt_digest(),
                acquisition_id: plan.acquisition_id(),
                effect_id: plan.effect_id(),
                normalized_intent_digest: plan.normalized_intent_digest(),
                kernel_coupled: plan.kernel_coupled(),
                backend_id: plan.backend_id(),
                root_prepared: d(15),
                publication: d(21),
                catalog: d(22),
                binding: d(23),
                backend_enrollment: raw_digest(&[24; 928]),
                dedicated_enrollment: raw_digest(&[25; 160]),
            },
        )
        .unwrap()
    }

    #[test]
    fn complete_plan_comparison_refuses_every_substitution() {
        let plan = plan();
        let original = origin(&plan);
        require_plan_origin(&plan, &original).unwrap();

        for field in 0..10 {
            let mut changed = plan.clone();
            match field {
                0 => changed.provider_id = [91; 16],
                1 => changed.holder_id = [91; 16],
                2 => changed.session_binding = d(91),
                3 => changed.attempt_digest = d(91),
                4 => changed.acquisition_id = d(91),
                5 => changed.effect_id = [91; 16],
                6 => changed.normalized_intent_digest = d(91),
                7 => changed.kernel_coupled = true,
                8 => changed.backend_id = [91; 32],
                _ => {
                    let mut wrong_lineage = original.clone();
                    wrong_lineage.backend_lineage_digest = d(91);
                    assert!(require_plan_origin(&changed, &wrong_lineage).is_err());
                    continue;
                }
            }
            assert!(require_plan_origin(&changed, &original).is_err());
        }

        // The old lineage intentionally omits these two fields. The full plan
        // comparison must still reject them rather than aliasing that hash.
        let mut changed = plan.clone();
        changed.normalized_intent_digest = d(91);
        assert_eq!(changed.lineage_digest(), plan.lineage_digest());
        assert!(require_plan_origin(&changed, &original).is_err());
    }

    #[test]
    fn both_enrollment_slots_compare_without_replacement() {
        let mut backend = None;
        let mut dedicated = None;
        retain_enrollment(&mut backend, [24; 928]).unwrap();
        retain_enrollment(&mut dedicated, [25; 160]).unwrap();

        retain_enrollment(&mut backend, [24; 928]).unwrap();
        retain_enrollment(&mut dedicated, [25; 160]).unwrap();
        assert!(retain_enrollment(&mut backend, [26; 928]).is_err());
        assert!(retain_enrollment(&mut dedicated, [27; 160]).is_err());
        assert_eq!(backend, Some([24; 928]));
        assert_eq!(dedicated, Some([25; 160]));
    }

    #[test]
    fn first_frame_survives_repeated_equal_and_changed_comparisons() {
        let original = frame(&plan());
        let mut retained = None;
        retain_frame(&mut retained, original.clone()).unwrap();
        retain_frame(&mut retained, original.clone()).unwrap();

        for field in 0..6 {
            let mut fields = *original.fields();
            match field {
                0 => fields.root_prepared = d(91),
                1 => fields.publication = d(91),
                2 => fields.catalog = d(91),
                3 => fields.binding = d(91),
                4 => fields.backend_enrollment = d(91),
                _ => fields.dedicated_enrollment = d(91),
            }
            let changed = SourceSelectedNativeExecutionInputDataV1::new(fields).unwrap();
            assert!(retain_frame(&mut retained, changed).is_err());
            assert_eq!(retained.as_ref(), Some(&original));
        }
    }

    #[test]
    fn raw_enrollment_commitments_cover_whole_distinct_images() {
        let mut backend = [24; 928];
        let mut dedicated = [25; 160];
        let backend_digest = raw_digest(&backend);
        let dedicated_digest = raw_digest(&dedicated);
        assert_ne!(backend_digest, dedicated_digest);

        backend[927] ^= 1;
        dedicated[159] ^= 1;
        assert_ne!(raw_digest(&backend), backend_digest);
        assert_ne!(raw_digest(&dedicated), dedicated_digest);
    }
}
