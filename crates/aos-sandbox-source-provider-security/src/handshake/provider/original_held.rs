//! Once-only ProviderHeld signing on the SAME genuine Source Session.
//!
//! The resident reservoir owns preparation, samples and the actual first cause.
//! The reservoir alone does not authorize send, Root acceptance or settlement.

use super::*;
use aos_sandbox::journal::{
    OriginalSourceProtectedReadbackV5, SourceOriginalNativeJournalAuthorityV5,
};
use aos_sandbox_core::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1 as Kind, NativeHeldSectionTagV1 as Tag,
    frame::{NativeHeldSignerV1, PreparedNativeHeldControlV1, SignedNativeHeldControlV1},
    witness::NativeHeldOwnerWitnessV1,
};
use ed25519_dalek::Signer as _;

mod delivery;

#[derive(Clone, Copy)]
enum OriginalHeldBindingPurposeV5<'control> {
    Preparation(&'control PreparedNativeHeldControlV1),
    Delivery(&'control SignedNativeHeldControlV1, &'control [u8]),
}

impl OriginalHeldBindingPurposeV5<'_> {
    fn prepared(&self) -> &PreparedNativeHeldControlV1 {
        match self {
            Self::Preparation(prepared) => prepared,
            Self::Delivery(signed, _) => signed.prepared(),
        }
    }
}

#[derive(thiserror::Error)]
enum OriginalHeldCauseV5 {
    #[error("original held custody failed")]
    Security(#[from] SourceProviderSecurityError),
    #[error("original held protected readback failed")]
    Journal(#[from] aos_sandbox::JournalError),
    #[error("original held clock failed")]
    Clock(#[from] aos_sandbox_core::OwnershipLeaseVerificationError),
    #[error("original held Storage custody failed")]
    Storage(#[from] crate::OriginalStorageOfferErrorV5),
}

impl core::fmt::Debug for OriginalHeldCauseV5 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("OriginalHeldCauseV5([retained cause])")
    }
}

/// Retains one original Held signing and delivery attempt without a send permit.
///
/// Only the genuine Session creates this empty reservoir. Repeat entry cannot
/// reset that Session's purpose, even if a different reservoir is supplied.
pub struct OriginalProviderHeldSignaturesV5 {
    usable: bool,
    attempted: bool,
    prepared: Option<PreparedNativeHeldControlV1>,
    message: Option<Vec<u8>>,
    detached: Option<[u8; 64]>,
    signed: Option<SignedNativeHeldControlV1>,
    samples: [Option<Result<RawPairedClockSample, SourceProviderSecurityError>>; 2],
    cause: Option<OriginalHeldCauseV5>,
    postcheck_debt: Option<OriginalHeldCauseV5>,
    delivery: delivery::OriginalHeldDeliveryV5,
}

impl OriginalProviderHeldSignaturesV5 {
    fn pending(usable: bool) -> Self {
        Self {
            usable,
            attempted: false,
            prepared: None,
            message: None,
            detached: None,
            signed: None,
            samples: std::array::from_fn(|_| None),
            cause: None,
            postcheck_debt: None,
            delivery: delivery::OriginalHeldDeliveryV5::pending(),
        }
    }

    /// Borrows the actual first cause, before any later postcheck debt.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|cause| cause as _)
            .or_else(|| self.samples.iter().find_map(|sample| {
                sample.as_ref()?.as_ref().err().map(|cause| cause as _)
            }))
            .or_else(|| self.postcheck_debt.as_ref().map(|cause| cause as _))
            .or_else(|| self.delivery.failure())
    }

    /// Borrows signed DATA only when this original attempt has no debt.
    #[must_use]
    pub fn signed(&self) -> Option<&SignedNativeHeldControlV1> {
        if self.failure().is_some() {
            None
        } else {
            self.signed.as_ref()
        }
    }

    fn sample(
        &mut self,
        index: usize,
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
    ) -> Result<(), OriginalHeldCauseV5> {
        self.samples[index] = Some(super::super::original_kernel_clock());
        let Some(Ok(later)) = &self.samples[index] else {
            // The actual native cause is still in this whole Result slot.
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        initial.validate_later_sample(*later)?;
        if later.wall_seconds() < validity.0
            || later.wall_seconds() >= validity.1
            || later.boottime_nanoseconds() >= deadline
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        Ok(())
    }
}

impl CurrentProviderIngressSessionV1 {
    /// Irreversibly arms original Held retention before the upper next gate.
    ///
    /// The returned empty DATA reservoir is not a signing or currentness permit.
    /// Repeated entry ends the SAME purpose; it never mints a new signing epoch.
    #[doc(hidden)]
    pub fn begin_original_held_v5(&mut self) -> OriginalProviderHeldSignaturesV5 {
        let usable = arm_original_held_once_v5(&mut self.failure_disposition);
        if !usable {
            self.close_original_held_after_failure_v5();
        }
        OriginalProviderHeldSignaturesV5::pending(usable)
    }

    /// Permanently ends selected progress without disposing original custody.
    #[doc(hidden)]
    pub fn close_original_held_after_failure_v5(&mut self) {
        self.custody.inner_mut().poison();
        self.failure_disposition = CurrentSessionFailureDispositionV5::OriginalHeldEnded;
        self.carrier.end_original_delivery_if_started_v5();
    }

    /// Observes the actual Source carrier cookie using the existing revalidator.
    ///
    /// # Errors
    ///
    /// Rejects stale genuine custody. No supplied cookie or replacement FD is used.
    #[doc(hidden)]
    pub fn original_held_socket_cookie_v5(
        &mut self,
    ) -> Result<std::num::NonZeroU64, SourceProviderSecurityError> {
        self.revalidate()?;
        let cookie = self.carrier.socket().peer().socket_cookie();
        self.revalidate()?;
        Ok(cookie)
    }

    /// Rechecks the resident original mount using the SAME private observer.
    ///
    /// # Errors
    ///
    /// Rejects stale Session or mount custody without exposing its descriptor.
    #[doc(hidden)]
    pub fn revalidate_original_held_mount_v5(
        &mut self,
        physical: &crate::ProviderSourceRootHandoffV1,
    ) -> Result<(), SourceProviderSecurityError> {
        self.revalidate()?;
        physical.revalidate()
            .map_err(|cause| self.fail_current_custody_v5(cause))?;
        self.revalidate()
    }

    fn require_original_held_bindings_v5(
        &mut self,
        journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5,
        root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1,
        physical: &crate::ProviderSourceRootHandoffV1,
        lease: &SignedSourceExportLeaseV1,
        archive: &crate::ProtectedOriginalConfigurationArchiveV5,
        selected: &crate::ProtectedOriginalSelectedInputV1,
        storage: &mut crate::OriginalStorageOfferTransportV5,
        purpose: OriginalHeldBindingPurposeV5<'_>,
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
    ) -> Result<(), OriginalHeldCauseV5> {
        let exact = purpose.prepared();
        self.revalidate_root_prepared_carrier_v1(root)?;
        self.revalidate()?;
        physical.revalidate()?;
        let aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(verified)
            = acquire.verified() else {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        let request = verified.request();
        let projection = verified.ingress_projection();
        let current = self.current_projection()?;
        let origin = match purpose {
            OriginalHeldBindingPurposeV5::Preparation(_) => journal.original_held_signing_basis_v5(
                readback, request.acquisition_id(), exact,
            )?,
            OriginalHeldBindingPurposeV5::Delivery(signed, _) => journal.original_held_delivery_basis_v5(
                readback, request.acquisition_id(), signed,
            )?,
        };
        let provenance = origin.initial_floor().original_provenance().claims();
        let acquisition_key = provenance.records[1].key();
        let acquisition_bytes = readback.rows().get(&(
            aos_sandbox::RecordNamespace::SourceProviderAuthority, acquisition_key.to_vec(),
        )).ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Acquisition(acquisition) =
            aos_sandbox_source_provider_ledger::ledger::format::decode_record(acquisition_key, acquisition_bytes)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)? else {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        let key = aos_sandbox_source_provider_ledger::ledger::native_completion::
            native_completion_key_v2(request.acquisition_id());
        let bytes = readback.rows().get(&(aos_sandbox::RecordNamespace::SourceProviderAuthority, key.clone()))
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let native = aos_sandbox_source_provider_ledger::ledger::native_held_completion::
            SourceNativeHeldCompletionRecordV1::from_canonical_bytes(&key, bytes)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let original = native.original();
        let signed = original.canonical_request.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let anchor = original.original_clock.ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let receipt = original.accepted_reply.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?.receipt();
        let acceptance = physical.native_acceptance().ok_or(SourceProviderSecurityError::DescriptorObservation)?;
        let observation = physical.observation();
        let witness = NativeHeldOwnerWitnessV1::from_canonical_bytes(
            aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldOwnerV1::Provider,
            exact.section(Tag::Witness).ok_or(SourceProviderSecurityError::SessionContinuity)?,
        ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let NativeHeldOwnerWitnessV1::Provider(witness) = witness else {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        self.revalidated_provider_configuration()?;
        let inner = self.custody.inner();
        let execution = inner.execution().baseline();
        if exact.kind() != Kind::ProviderHeld
            || exact.scope() != &selected.frame().fields().scope
            || exact.signer() != &NativeHeldSignerV1::SourceProvider(
                inner.provider_authority().traffic_signer().clone(),
            )
            || root.control() != &provenance.root_prepared
            || signed.request().claims() != &provenance.claims
            || signed.request().signed_root_request().to_canonical_bytes()
                != verified.attempt().canonical_signed_request()
            || current.provider() != projection.provider_authority()
            || current.holder() != projection.root_mount_authority()
            || current.session_binding() != projection.session_binding()
            || current.root_process_instance() != projection.root_mount_process_instance()
            || current.provider_process_instance() != projection.provider_process_instance()
            || acquire.provider_execution_identity() != (execution.pid, execution.start_time_ticks)
            || request.acquisition_version() != aos_sandbox_source_provider_protocol::ACQUIRE_SOURCE_REQUEST_VERSION_V3
            || request.kernel_coupled()
            || !matches!(verified.sequence(),
                aos_sandbox_source_provider_protocol::VerifiedProviderRequestSequenceV1::Fresh(_))
            || witness.root_local_cookie != self.carrier.socket().peer().socket_cookie().get()
            || witness.selected_manifest != selected.frame().digest()
            || witness.backend_manifest != selected.frame().fields().backend_enrollment
            || witness.verifier_manifest != selected.frame().fields().dedicated_enrollment
            || original.acceptance_payload_digest != acceptance.acceptance_payload_digest()
            || original.acceptance_digest != acceptance.signed_acceptance_digest()
            || (original.original_root.kernel_boot_id(), original.original_root.device(),
                original.original_root.inode(), original.original_root.unique_mount_id())
                != (observation.kernel_boot_id(), observation.device(),
                    observation.inode(), observation.unique_mount_id())
            || original.descriptor_commitment != aos_sandbox_source_provider_protocol::
                source_root_descriptor_commitment_v1(observation)
            || acquisition.signed_lease != lease.to_canonical_bytes()
            || initial != anchor.initial()
            || deadline > anchor.deadline()
            || deadline <= initial.boottime_nanoseconds()
            || validity.0 < provenance.claims.validity().0.max(receipt.receipt().validity().0)
            || validity.1 > provenance.claims.validity().1.min(receipt.receipt().validity().1)
            || validity.1 > projection.current_valid_until_seconds()
            || validity.1 > request.deadline_seconds()
            || validity.0 < lease.subject().validity().0
            || validity.1 > lease.subject().validity().1
            || validity.0 >= validity.1
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        inner.provider_authority().validate_at(current_unix_seconds()?)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        inner.root_authority().validate_at(current_unix_seconds()?)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        archive.validate_selected_input_v1(selected)?;
        if storage.original_socket_cookie_v5()?.get() != witness.storage_local_cookie {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        if let OriginalHeldBindingPurposeV5::Delivery(_, complete) = purpose {
            delivery::require_original_complete_delivery_v5(
                readback, provenance.records[0].key(), &acquisition, original,
                acquire, physical, complete,
            )?;
        }
        Ok(())
    }

    /// Signs exact phase5 once with the existing ProviderOutcome key and domain.
    ///
    /// Preparation and every native sample remain resident before postchecks.
    /// The boolean is progress only; the reservoir retains the actual cause.
    #[doc(hidden)]
    pub fn sign_original_held_v5(
        &mut self,
        journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5,
        root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1,
        physical: &crate::ProviderSourceRootHandoffV1,
        lease: &SignedSourceExportLeaseV1,
        archive: &crate::ProtectedOriginalConfigurationArchiveV5,
        selected: &crate::ProtectedOriginalSelectedInputV1,
        storage: &mut crate::OriginalStorageOfferTransportV5,
        prepared: PreparedNativeHeldControlV1,
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
        signatures: &mut OriginalProviderHeldSignaturesV5,
    ) -> bool {
        if signatures.attempted {
            self.close_original_held_after_failure_v5();
            if signatures.failure().is_none() {
                signatures.cause = Some(SourceProviderSecurityError::SessionContinuity.into());
            }
            return false;
        }
        let available = signatures.usable && !signatures.attempted
            && self.failure_disposition == CurrentSessionFailureDispositionV5::OriginalHeldRetention;
        signatures.attempted = true;
        self.failure_disposition = CurrentSessionFailureDispositionV5::OriginalHeldEnded;
        signatures.prepared = Some(prepared);
        let action = (|| {
            if !available {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            }
            let exact = signatures.prepared.as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(verified)
                = acquire.verified() else {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            };
            // Claim before any fallible basis check can permit a second crypto attempt.
            journal.claim_original_held_signing_v5(
                readback, verified.request().acquisition_id(), exact,
            )?;
            self.require_original_held_bindings_v5(
                journal, readback, root, acquire, physical, lease, archive, selected,
                storage, OriginalHeldBindingPurposeV5::Preparation(exact), initial, deadline, validity,
            )?;
            signatures.message = Some(exact.signature_message());
            signatures.sample(0, initial, deadline, validity)?;
            let message = signatures.message.as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            signatures.detached = Some(
                self.custody.inner().outcome_key().signing_key().sign(message).to_bytes(),
            );
            if let (Some(prepared), Some(raw)) = (signatures.prepared.take(), signatures.detached) {
                signatures.signed = Some(prepared.with_signature(raw));
            }
            Ok::<_, OriginalHeldCauseV5>(())
        })();
        if let Err(cause) = action {
            if signatures.failure().is_none() {
                signatures.cause = Some(cause);
            }
        }

        // Later debt is never substituted for the action's resident first cause.
        let postcheck = (|| {
            let exact = signatures.prepared.as_ref()
                .or_else(|| signatures.signed.as_ref().map(SignedNativeHeldControlV1::prepared))
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            self.require_original_held_bindings_v5(
                journal, readback, root, acquire, physical, lease, archive, selected,
                storage, OriginalHeldBindingPurposeV5::Preparation(exact), initial, deadline, validity,
            )?;
            signatures.sample(1, initial, deadline, validity)
        })();
        if let Err(cause) = postcheck {
            if signatures.postcheck_debt.is_none() {
                signatures.postcheck_debt = Some(cause);
            }
        }
        if signatures.failure().is_some() {
            self.close_original_held_after_failure_v5();
            false
        } else {
            signatures.signed.is_some()
        }
    }
}

// A pure private state transition, not a custody constructor or signing grant.
fn arm_original_held_once_v5(disposition: &mut CurrentSessionFailureDispositionV5) -> bool {
    if *disposition != CurrentSessionFailureDispositionV5::LegacyDisposal {
        return false;
    }
    *disposition = CurrentSessionFailureDispositionV5::OriginalHeldRetention;
    true
}

#[cfg(test)]
mod tests {
    //! UNRUN reservoir/state mechanics only; no synthetic live Session exists.

    use super::*;

    #[test]
    fn same_disposition_cannot_mint_another_epoch() {
        let mut disposition = CurrentSessionFailureDispositionV5::LegacyDisposal;

        assert!(arm_original_held_once_v5(&mut disposition));
        assert!(!arm_original_held_once_v5(&mut disposition));
        disposition = CurrentSessionFailureDispositionV5::OriginalHeldEnded;
        assert!(!arm_original_held_once_v5(&mut disposition));
    }

    #[test]
    fn empty_closed_reservoir_contains_no_signed_success() {
        let reservoir = OriginalProviderHeldSignaturesV5::pending(false);

        assert!(!reservoir.usable);
        assert!(!reservoir.attempted);
        assert!(reservoir.signed().is_none());
        assert!(reservoir.failure().is_none());
    }

    #[test]
    fn first_action_cause_survives_later_debt_without_extraction() {
        let mut reservoir = OriginalProviderHeldSignaturesV5::pending(false);
        reservoir.cause = Some(SourceProviderSecurityError::SessionContinuity.into());
        reservoir.postcheck_debt = Some(aos_sandbox::JournalError::InvalidTransaction.into());

        assert!(matches!(
            reservoir.failure().and_then(|cause| cause.downcast_ref::<OriginalHeldCauseV5>()),
            Some(OriginalHeldCauseV5::Security(_)),
        ));
        assert!(matches!(reservoir.cause, Some(OriginalHeldCauseV5::Security(_))));
        assert!(matches!(reservoir.postcheck_debt, Some(OriginalHeldCauseV5::Journal(_))));
    }
}
