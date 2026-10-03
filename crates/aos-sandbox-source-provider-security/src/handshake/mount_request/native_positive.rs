//! Resident original Held/Complete reception and local RootAccepted preparation.
//!
//! Only the original Session and actual protected Root readbacks drive these
//! stages. Received packets, SourceRoot FD, readonly archives, physical staging,
//! unsigned preparation and signature remain resident on failure. Phase5 is
//! local stored RootAccepted DATA, not an ACK, manager handoff or settled flight.

use aos_sandbox_protocol::mount_source_acquisition_state::{
    ProviderAttemptStateV2, ProviderStatusV2,
    native_held_completion::{RootNativeCutKindV1, RootNativeCutV1, original_root_remaining_v5},
};
use aos_sandbox_source_provider_protocol::{
    SourceRootObservationV1, StorageNativeAcquireReplyV3,
    native_held_completion::{
        MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1, NativeHeldOwnerV1,
        frame::{NativeHeldSignerV1, SignedNativeHeldControlV1},
        witness::ProviderNativeHeldWitnessV1,
    },
};
use ed25519_dalek::Signer as _;

use super::*;
use crate::{
    configuration::original_archive::FixedSourcePublicArchiveReadbackV1,
    descriptor::OriginalSourceRootObservationV5,
};

#[path = "native_positive/readback.rs"]
mod readback;

/// Stages no positive owner: only the actual original receiver initializes it.
pub(super) struct OriginalPositiveProgressV5 {
    held: Option<SignedNativeHeldControlV1>,
    storage: Option<SignedNativeHeldControlV1>,
    reply: Option<StorageNativeAcquireReplyV3>,
    witness: Option<ProviderNativeHeldWitnessV1>,
    archive: FixedSourcePublicArchiveReadbackV1,
    complete: Option<RetainedSourceProviderRecordV5>,
    checked: Option<VerifiedMountProviderOutcomeV2>,
    physical: OriginalSourceRootObservationV5,
    cut: Option<RootNativeCutV1>,
    disposition: Option<RootNativeDispositionAssertionV1>,
    unsigned: Option<PreparedNativeHeldControlV1>,
    signature_attempted: bool,
    signing_preparation: Option<PreparedNativeHeldControlV1>,
    signature: Option<[u8; 64]>,
    signed: Option<SignedNativeHeldControlV1>,
    first_failure: Option<SourceProviderSecurityError>,
    postcheck_failure: Option<SourceProviderSecurityError>,
}

impl OriginalPositiveProgressV5 {
    pub(super) fn new() -> Self {
        Self {
            held: None,
            storage: None,
            reply: None,
            witness: None,
            archive: FixedSourcePublicArchiveReadbackV1::new(),
            complete: None,
            checked: None,
            physical: OriginalSourceRootObservationV5::new(),
            cut: None,
            disposition: None,
            unsigned: None,
            signature_attempted: false,
            signing_preparation: None,
            signature: None,
            signed: None,
            first_failure: None,
            postcheck_failure: None,
        }
    }

    pub(super) fn held(&self) -> Option<&SignedNativeHeldControlV1> {
        self.held.as_ref()
    }

    fn preclaim_signature(&mut self) -> Result<(), SourceProviderSecurityError> {
        if self.signature_attempted || self.first_failure.is_some() {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.signature_attempted = true;
        Ok(())
    }

    fn retain_failure(&mut self, error: SourceProviderSecurityError) {
        if self.first_failure.is_none() {
            self.first_failure = Some(error);
        } else if self.postcheck_failure.is_none() {
            self.postcheck_failure = Some(error);
        }
    }
}

impl OriginalNativeReceivedOutcomeV5 {
    pub(in crate::handshake::mount_request) fn original_complete_record_v5(
        &self,
    ) -> Option<&crate::carrier::ReceivedSourceProviderRecordV1> {
        if self.failed.get() || self.positive.held.is_none() {
            return None;
        }
        self.positive
            .complete
            .as_ref()
            .and_then(RetainedSourceProviderRecordV5::bound)
    }

    pub(in crate::handshake::mount_request) fn require_checked_complete_basis_v5(
        &self,
        authorization: &AuthorizedMountProviderOutcomeV2,
        canonical: &[u8],
        observation: Option<SourceRootObservationV1>,
        status: SourceProviderStatus,
    ) -> Result<(), SourceProviderSecurityError> {
        let record = self
            .original_complete_record_v5()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let held = self
            .positive
            .held
            .as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if status != SourceProviderStatus::Complete
            || authorization.method != SourceProviderMethod::Acquire
            || authorization.native_outcome.as_ref()
                .is_none_or(|original| !Arc::ptr_eq(original, &self.original))
            || record.payload != canonical
            || record.descriptors.len() != 1
            || observation.is_none()
            || held.scope().original_source_session != authorization.session_binding
            || held.section(Tag::SourceArtifact)
                != Some(
                    aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                        SourceProviderMethod::Acquire,
                        canonical,
                    )
                    .as_bytes(),
                )
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(())
    }

    /// Borrows exact checked CAS DATA without releasing its original FD owner.
    ///
    /// Generic native completion/consumption still refuses these DATA. Only the
    /// closed original receiver can join them to the actual phase3 readback.
    #[doc(hidden)]
    #[must_use]
    pub fn checked_original_complete_v5(
        &self,
    ) -> Option<(&VerifiedMountProviderOutcomeV2, &SourceRootObservationV1)> {
        if self.failed.get() || self.original_complete_record_v5().is_none() {
            return None;
        }
        Some((
            self.positive.checked.as_ref()?,
            self.positive.physical.observation()?,
        ))
    }

    /// Borrows observed Held DATA; this does not prove remote currentness.
    #[doc(hidden)]
    #[must_use]
    pub fn original_held_v5(&self) -> Option<&SignedNativeHeldControlV1> {
        if self.failed.get() {
            None
        } else {
            self.positive.held.as_ref()
        }
    }

    /// Borrows the exact original unsigned local RootAccepted preparation.
    #[doc(hidden)]
    #[must_use]
    pub fn original_unsigned_accepted_v5(&self) -> Option<&PreparedNativeHeldControlV1> {
        self.positive.unsigned.as_ref()
    }

    /// Borrows retained signed DATA even after a failed post-sign observation.
    #[doc(hidden)]
    #[must_use]
    pub fn original_signed_accepted_v5(&self) -> Option<&SignedNativeHeldControlV1> {
        self.positive.signed.as_ref()
    }

    /// Borrows the exact first-R cut required by the existing native reducer.
    #[doc(hidden)]
    #[must_use]
    pub fn original_accepted_cut_v5(&self) -> Option<&RootNativeCutV1> {
        self.positive.cut.as_ref()
    }

    /// Borrows original first-cause and later observation debt separately.
    #[doc(hidden)]
    #[must_use]
    pub fn original_positive_failures_v5(
        &self,
    ) -> (Option<&SourceProviderSecurityError>, Option<&SourceProviderSecurityError>) {
        (
            self.positive.first_failure.as_ref(),
            self.positive.postcheck_failure.as_ref(),
        )
    }

    fn retain_positive_failure(&mut self, error: SourceProviderSecurityError) {
        self.failed.set(true);
        self.positive.retain_failure(error);
    }

    pub(super) fn retain_first_positive_failure_v5(&mut self, error: SourceProviderSecurityError) {
        self.failed.set(true);
        if self.positive.first_failure.is_none() {
            self.positive.first_failure = Some(error);
        }
    }
}

impl CurrentRootMountSourceProviderSessionV1 {
    pub(in crate::handshake::mount_request) fn capture_original_held_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase1: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        let result = (|| {
            let record = retained
                .record()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            if !record.descriptors.is_empty()
                || record.payload.len() > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1
                || retained.positive.held.is_some()
            {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            retained.positive.held = Some(
                SignedNativeHeldControlV1::from_canonical_bytes(&record.payload)
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
            );
            let held = retained.positive.held.as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            if held.kind() != Kind::ProviderHeld {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            retained.positive.storage = Some(
                SignedNativeHeldControlV1::from_canonical_bytes(
                    held.section(Tag::StorageHeld)
                        .ok_or(SourceProviderSecurityError::SessionContinuity)?,
                )
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
            );
            let storage = retained.positive.storage.as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            retained.positive.reply = Some(
                StorageNativeAcquireReplyV3::from_canonical_bytes(
                    storage.section(Tag::NativeReply)
                        .ok_or(SourceProviderSecurityError::SessionContinuity)?,
                )
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
            );
            let witness = NativeHeldOwnerWitnessV1::from_canonical_bytes(
                NativeHeldOwnerV1::Provider,
                held.section(Tag::Witness)
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?,
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            let NativeHeldOwnerWitnessV1::Provider(witness) = witness else {
                return Err(SourceProviderSecurityError::SessionContinuity);
            };
            retained.positive.witness = Some(witness);

            // Authenticate the Source assertion before using its fixed filename.
            self.require_original_held_signature_v5(authorization, retained)?;
            readback::capture(
                &mut retained.positive.archive,
                retained.positive.witness.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?,
            )?;
            self.require_original_positive_owner_v5(writer, phase1, authorization, retained)
        })();
        self.finish_original_positive_v5(retained, result)
    }

    fn require_original_held_signature_v5(
        &mut self,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        self.require_native_outcome_authorization_v3(authorization)?;
        if retained.failed.get()
            || authorization.native_outcome.as_ref()
                .is_none_or(|original| !Arc::ptr_eq(original, &retained.original))
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let record = retained
            .record()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        record.execution.revalidate(self.carrier.socket().peer())?;
        if !record.descriptors.is_empty()
            || !record.execution.has_same_execution(&self.provider_execution)
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let held = retained.positive.held.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if held.to_canonical_bytes() != record.payload {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        held.verify_signature_claim(
            &NativeHeldSignerV1::SourceProvider(authorization.provider_outcome_signer.clone()),
            &authorization.provider_outcome_public_key,
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)
    }

    fn require_original_positive_owner_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        writer.validate_readback(readback)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        self.require_original_held_signature_v5(authorization, retained)?;
        let sidecar = readback.graph().sidecars().get(&readback.attempt())
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let phase = sidecar.suffix().phase();
        let root1 = sidecar.suffix().control(Kind::RootPrepared)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let floor = readback.floor()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let held = retained.positive.held.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let storage = retained.positive.storage.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let reply = retained.positive.reply.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let witness = retained.positive.witness.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        held.scope().require_root_prefix(root1.scope())
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        if authorization.mount_attempt_id != Some(readback.attempt())
            || !(1..=5).contains(&phase)
            || floor.request().owner_id != readback.attempt()
            || floor.original_prepared() != root1.prepared()
            || floor.admission_cut() != sidecar.admission_cut()
            || storage.section(Tag::RootPrepared) != Some(root1.to_canonical_bytes().as_slice())
            || (phase >= 2 && sidecar.suffix().control(Kind::ProviderHeld) != Some(held))
            || (phase >= 2 && sidecar.original_scope() != held.scope())
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        readback::compare(
            &mut retained.positive.archive,
            authorization,
            &retained.original,
            held,
            storage,
            reply,
            root1,
            witness,
            self.custody.inner().trust(),
        )?;
        let (issued, expires) = reply.receipt().receipt().validity();
        let now = super::super::current_unix_seconds()?;
        if now < issued || now >= expires || expires > authorization.deadline_seconds {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.require_original_storage_validity_v5(authorization, expires)?;

        if phase >= 3 {
            require_original_complete_cut_v5(readback, authorization, retained)?;
        }
        if retained.positive.checked.is_some() {
            self.recheck_original_complete_physical_v5(authorization, retained)?;
        }
        if phase >= 4 {
            require_original_accepted_cut_v5(readback, retained)?;
        }
        self.require_native_outcome_authorization_v3(authorization)?;
        writer.validate_readback(readback)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;

        // Final paired time follows the slow original file/physical/full-graph
        // observations. The same lease may narrow, never renew, the old fence.
        if let Some(record) = retained.original_complete_record_v5() {
            self.require_original_positive_effect_clock_v5(
                &retained.original,
                &record.payload,
                expires,
            )
        } else {
            self.require_original_storage_validity_v5(authorization, expires)
        }
    }

    /// Rechecks the same original packets, readonly images and protected cut.
    ///
    /// # Errors
    ///
    /// Retains the typed first refusal and closes the same original Session on
    /// any replacement, clock, signature, physical FD or native-cut mismatch.
    #[doc(hidden)]
    pub fn revalidate_original_positive_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = owner.require_original_positive_owner_v5(writer, readback, authorization, retained);
            owner.finish_original_positive_v5(retained, result)
        })
    }

    /// Receives exactly one Complete after actual Held phase2 readback.
    ///
    /// # Errors
    ///
    /// Rejects duplicates, a foreign peer, another status/control or any FD set
    /// except the sole SourceRoot, retaining every returned owner and cause.
    #[doc(hidden)]
    pub fn receive_original_complete_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase2: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<bool, SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = (|| {
                owner.require_original_positive_owner_v5(writer, phase2, authorization, retained)?;
                if phase2.graph().sidecars().get(&phase2.attempt())
                    .is_none_or(|sidecar| sidecar.suffix().phase() != 2)
                    || retained.positive.complete.is_some() || retained.positive.checked.is_some()
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                match owner.carrier.receive_original_complete_retaining_v5(&mut retained.positive.complete) {
                    Ok(true) => {}
                    Ok(false) | Err(CarrierFailureV1::Retryable) => {
                        owner.require_original_positive_owner_v5(writer, phase2, authorization, retained)?;
                        owner.carrier.finish_original_receive_backpressure_v5();
                        return Ok(false);
                    }
                    Err(CarrierFailureV1::Fatal(error)) => return Err(error),
                }
                owner.capture_original_complete_v5(authorization, retained)?;
                owner.require_original_positive_owner_v5(writer, phase2, authorization, retained)?;
                Ok(true)
            })();
            match result {
                Ok(ready) => Ok(ready),
                Err(error) => {
                    retained.retain_positive_failure(error);
                    Err(owner.poison(SourceProviderSecurityError::SessionContinuity))
                }
            }
        })
    }

    fn capture_original_complete_v5(
        &mut self,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        let record = retained.original_complete_record_v5()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        record.execution.revalidate(self.carrier.socket().peer())?;
        if record.descriptors.len() != 1
            || !record.execution.has_same_execution(&self.provider_execution)
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let response = decode_acquire_response(&record.payload)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        if response.status() != SourceProviderStatus::Complete {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let receipt = response.signed_receipt()
            .and_then(|bytes| SignedSourceProviderReceiptV1::from_canonical_bytes(bytes).ok())
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let lease = SignedSourceExportLeaseV1::from_canonical_bytes(
            receipt.subject().signed_export_lease(),
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let expected = SourceRootObservationV1::new(
            receipt.subject().kernel_boot_id(),
            receipt.subject().device(),
            receipt.subject().inode(),
            receipt.subject().unique_mount_id(),
            true,
            true,
            true,
        )
        .map_err(|_| SourceProviderSecurityError::DescriptorObservation)?;

        // The actual descriptor remains in its received packet throughout all
        // observations. Only checked DATA, never positive FD custody, is shared.
        let record = retained.positive.complete.as_ref()
            .and_then(RetainedSourceProviderRecordV5::bound)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let descriptor = record.descriptors.first()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let cookie = self.carrier.socket().peer().socket_cookie();
        self.require_complete_acquire_association(authorization.session_binding, cookie, &record.execution)?;
        let physical = retained.positive.physical.capture_preliminary(descriptor)?;
        self.require_complete_acquire_association(authorization.session_binding, cookie, &record.execution)?;
        retained.positive.checked = Some(
            self.check_original_complete_bytes_v5(authorization, retained, physical)?,
        );

        let checked = retained.positive.checked.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let profile = outcome::verified_source_root_profile(checked)?;
        let commitment = checked.descriptor_commitment;
        let record = retained.positive.complete.as_ref()
            .and_then(RetainedSourceProviderRecordV5::bound)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let descriptor = record.descriptors.first()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        retained.positive.physical.capture_authenticated(
            descriptor,
            &record.execution,
            profile,
            expected,
            commitment,
            self,
            authorization.session_binding,
            cookie,
        )?;
        self.recheck_original_complete_physical_v5(authorization, retained)?;

        // The existing freshness finisher anchors the completed physical work;
        // later rechecks compare this exact anchor rather than renewing it.
        let checked = retained.positive.checked.as_mut()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        outcome::finish_source_root_verification(
            checked,
            authorization,
            lease.subject().expires_seconds(),
        )?;
        let record = retained.original_complete_record_v5()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        self.require_native_outcome_response_v3(authorization, &record.payload, true)
    }

    fn recheck_original_complete_physical_v5(
        &mut self,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        let record = retained.positive.complete.as_ref()
            .and_then(RetainedSourceProviderRecordV5::bound)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let descriptor = record.descriptors.first()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let cookie = self.carrier.socket().peer().socket_cookie();
        retained.positive.physical.revalidate(
            descriptor,
            &record.execution,
            self,
            authorization.session_binding,
            cookie,
        )?;
        self.require_native_outcome_response_v3(authorization, &record.payload, true)
    }

    /// Derives first-R and unsigned Root4 only from the actual Complete phase3.
    ///
    /// # Errors
    ///
    /// Rejects stale currentness, another phase, occupied preparation or a wrong
    /// first-R transaction/physical successor. No bytes are regenerated on error.
    #[doc(hidden)]
    pub fn prepare_original_root_accepted_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase3: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        transaction: [u8; 16],
        successor_sequence: u64,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = (|| {
                owner.require_original_positive_owner_v5(writer, phase3, authorization, retained)?;
                let sidecar = phase3.graph().sidecars().get(&phase3.attempt())
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                if sidecar.suffix().phase() != 3
                    || retained.positive.cut.is_some()
                    || retained.positive.unsigned.is_some()
                    || phase3.sequence().checked_add(5) != Some(successor_sequence)
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                retained.positive.cut = Some(
                    RootNativeCutV1::capture(
                        RootNativeCutKindV1::Disposition,
                        transaction,
                        phase3.graph().legacy(),
                        phase3.attempt(),
                    )
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
                );
                let captured = retained.positive.cut.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?
                    .reconstruct(phase3.graph().legacy(), phase3.attempt())
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
                let held = retained.positive.held.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let checked = retained.positive.checked.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let artifact = aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                    SourceProviderMethod::Acquire,
                    &checked.canonical_response,
                );
                retained.positive.disposition = Some(RootNativeDispositionAssertionV1 {
                    disposition: NativeHeldDispositionV1::Accepted,
                    observation: RootNativeObservationV1::ProviderHeldObserved,
                    scope: *held.scope(),
                    source_artifact: artifact,
                    descriptor_commitment: checked.descriptor_commitment,
                    records: captured.witnesses().clone(),
                });
                let witness = NativeHeldOwnerWitnessV1::Root(
                    retained.original.original_root_witness(
                        captured.witnesses().clone(),
                        successor_sequence,
                    )?,
                )
                .to_canonical_bytes()
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
                let root1 = sidecar.suffix().control(Kind::RootPrepared)
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let assertion = retained.positive.disposition.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let sections = vec![
                        NativeHeldSectionV1::new(Tag::Witness, witness),
                        NativeHeldSectionV1::new(Tag::SourceArtifact, artifact.as_bytes().to_vec()),
                        NativeHeldSectionV1::new(
                            Tag::RootDispositionAssertion,
                            assertion.to_canonical_bytes()
                                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
                                .to_vec(),
                        ),
                    ]
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
                retained.positive.unsigned = Some(
                    PreparedNativeHeldControlV1::new(
                        Kind::RootAccepted,
                        *held.scope(),
                        held.digest(),
                        sections,
                        root1.prepared().signer().clone(),
                    )
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
                );
                owner.require_original_positive_owner_v5(writer, phase3, authorization, retained)
            })();
            owner.finish_original_positive_v5(retained, result)
        })
    }

    /// Signs the same physically stored phase4 preparation once.
    ///
    /// # Errors
    ///
    /// Preclaims before role/currentness checks. Any refusal, unwind or late
    /// failure permanently prevents another signature and retains its output.
    #[doc(hidden)]
    pub fn sign_original_root_accepted_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase4: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = (|| {
                if retained.failed.get() {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                retained.positive.preclaim_signature()?;
                owner.require_original_positive_owner_v5(writer, phase4, authorization, retained)?;
                if phase4.graph().sidecars().get(&phase4.attempt())
                    .is_none_or(|sidecar| sidecar.suffix().phase() != 4)
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                let unsigned = retained.positive.unsigned.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                owner.require_current_root_mount_record_role_v5(unsigned.signer())?;
                retained.positive.signing_preparation = Some(unsigned.clone());
                owner.require_original_positive_owner_v5(writer, phase4, authorization, retained)?;

                // Sample the SAME original pair after slow physical/file/role
                // bookends, immediately before crypto. No deadline is renewed.
                let unsigned = retained.positive.signing_preparation.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let record = retained.original_complete_record_v5()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let (_, expires) = retained.positive.reply.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?
                    .receipt().receipt().validity();
                owner.require_original_positive_effect_clock_v5(
                    &retained.original,
                    &record.payload,
                    expires,
                )?;
                let signature = owner.custody.inner().outcome_key().signing_key()
                    .sign(&unsigned.signature_message())
                    .to_bytes();
                retained.positive.signature = Some(signature);

                // The prepared copy was parked before crypto. Moving it into
                // the signed DATA is infallible and precedes all postchecks.
                if let Some(unsigned) = retained.positive.signing_preparation.take() {
                    retained.positive.signed = Some(unsigned.with_signature(signature));
                }
                owner.require_original_positive_owner_v5(writer, phase4, authorization, retained)
            })();
            owner.finish_original_positive_v5(retained, result)
        })
    }

    fn finish_original_positive_v5(
        &mut self,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        result: Result<(), SourceProviderSecurityError>,
    ) -> Result<(), SourceProviderSecurityError> {
        if let Err(error) = result {
            retained.retain_positive_failure(error);
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        Ok(())
    }
}

fn require_original_complete_cut_v5(
    readback: &OriginalRootProtectedReadbackV5,
    authorization: &AuthorizedMountProviderOutcomeV2,
    retained: &OriginalNativeReceivedOutcomeV5,
) -> Result<(), SourceProviderSecurityError> {
    let checked = retained.positive.checked.as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let record = retained.original_complete_record_v5()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    retained.require_checked_complete_basis_v5(
        authorization,
        &checked.canonical_response,
        retained.positive.physical.observation().cloned(),
        checked.status,
    )?;
    let attempt = readback.graph().legacy().provider_attempts.get(&readback.attempt())
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let ProviderAttemptStateV2::DispositionConsumed {
        response_sequence,
        verification_anchor,
        status,
        signed_status,
        signed_result,
        ..
    } = &attempt.state else {
        return Err(SourceProviderSecurityError::SessionContinuity);
    };
    let response = decode_acquire_response(&record.payload)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    if attempt.revision != 2
        || *status != ProviderStatusV2::Complete
        || attempt.signed_request != authorization.signed_request.to_canonical_bytes()
        || *response_sequence != checked.response_sequence
        || *verification_anchor != checked.verification_anchor
        || *signed_status != response.signed_status().to_canonical_bytes()
        || response.signed_receipt() != Some(signed_result.as_slice())
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

fn require_original_accepted_cut_v5(
    readback: &OriginalRootProtectedReadbackV5,
    retained: &OriginalNativeReceivedOutcomeV5,
) -> Result<(), SourceProviderSecurityError> {
    let sidecar = readback.graph().sidecars().get(&readback.attempt())
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let cut = retained.positive.cut.as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let assertion = retained.positive.disposition.as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let unsigned = retained.positive.unsigned.as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let floor = readback.floor()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let remaining = original_root_remaining_v5(readback.graph(), readback.attempt())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    if sidecar.disposition_cut() != Some(cut)
        || sidecar.disposition() != Some(assertion)
        || floor.request().future_transactions != remaining
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let captured = cut.reconstruct(readback.graph().legacy(), readback.attempt())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    if captured.witnesses() != &assertion.records {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    let NativeHeldOwnerWitnessV1::Root(witness) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
        NativeHeldOwnerV1::Root,
        unsigned.section(Tag::Witness)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?,
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)? else {
        return Err(SourceProviderSecurityError::SessionContinuity);
    };
    let expected = NativeHeldOwnerWitnessV1::Root(
        retained.original.original_root_witness(
            captured.witnesses().clone(),
            witness.journal_sequence,
        )?,
    )
    .to_canonical_bytes()
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let exact = match sidecar.suffix().phase() {
        4 => {
            sidecar.suffix().prepared() == Some(unsigned)
                && readback.sequence() == witness.journal_sequence
        }
        5 => retained.positive.signed.as_ref().is_some_and(|signed| {
            signed.prepared() == unsigned
                && sidecar.suffix().prepared().is_none()
                && sidecar.suffix().control(Kind::RootAccepted) == Some(signed)
        }),
        _ => false,
    };
    if !exact || unsigned.section(Tag::Witness) != Some(expected.as_slice()) {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_signature_preclaim_is_irreversible_without_an_owner_or_output() {
        let mut progress = OriginalPositiveProgressV5::new();

        progress.preclaim_signature().unwrap();
        assert!(progress.preclaim_signature().is_err());
        assert!(progress.held.is_none());
        assert!(progress.signature.is_none());
        assert!(progress.signed.is_none());
        assert!(progress.checked.is_none());
    }

    #[test]
    fn first_cause_and_postcheck_debt_are_separate_and_bounded() {
        let mut progress = OriginalPositiveProgressV5::new();
        progress.retain_failure(SourceProviderSecurityError::DirectoryPath);
        let first = progress.first_failure.as_ref().unwrap() as *const _;

        progress.retain_failure(SourceProviderSecurityError::DescriptorObservation);
        let debt = progress.postcheck_failure.as_ref().unwrap() as *const _;
        progress.retain_failure(SourceProviderSecurityError::SessionContinuity);

        assert_eq!(progress.first_failure.as_ref().unwrap() as *const _, first);
        assert_eq!(progress.postcheck_failure.as_ref().unwrap() as *const _, debt);
        assert!(progress.preclaim_signature().is_err());
    }

    #[test]
    fn empty_progress_exposes_no_received_or_current_authority() {
        let progress = OriginalPositiveProgressV5::new();

        assert!(progress.held().is_none());
        assert!(progress.complete.is_none());
        assert!(progress.physical.observation().is_none());
        assert!(progress.archive.selected_frame().is_none());
        assert!(progress.archive.deployment_data().is_none());
        assert!(progress.cut.is_none());
        assert!(progress.unsigned.is_none());
    }

    #[test]
    fn empty_staging_does_not_open_the_ordinary_native_complete_barrier() {
        let progress = OriginalPositiveProgressV5::new();

        assert!(progress.checked.is_none());
        assert!(native_catalog::require_native_completion_barrier(true).is_err());
        assert!(native_catalog::require_native_completion_barrier(false).is_ok());
    }
}
