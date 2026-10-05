//! Resident original Held/Complete reception and local RootAccepted preparation.
//!
//! Only the original Session and actual protected Root readbacks drive these
//! stages. Received packets, SourceRoot FD, readonly archives, physical staging,
//! unsigned preparation and signature remain resident on failure. Phase5 is
//! local stored RootAccepted DATA, not an ACK, manager handoff or settled flight.
//! Its named one-shot sender retains native output and never infers receipt.

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

#[path = "native_positive/terminal.rs"]
mod terminal;

#[derive(Clone, Copy)]
enum OriginalPositivePurposeV5<'release> {
    Positive,
    Terminal,
    Release(&'release PreparedMountProviderRequestV2),
}

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
    send_attempted: bool,
    send_payload: Option<Vec<u8>>,
    send_result: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    first_failure: Option<SourceProviderSecurityError>,
    postcheck_failure: Option<SourceProviderSecurityError>,
    terminal: terminal::OriginalTerminalProgressV5,
    release_send_attempted: bool,
    release_send_result: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    release_status: Option<RetainedSourceProviderRecordV5>,
    release_receive_failure: Option<crate::carrier::OriginalRootAcceptedCarrierFailureV5>,
    release_checked: Option<VerifiedMountProviderOutcomeV2>,
    release_status_failure: Option<SourceProviderSecurityError>,
    release_receive_loaned: bool,
    release_receive_result: Option<Result<bool, CarrierFailureV1>>,
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
            send_attempted: false,
            send_payload: None,
            send_result: None,
            first_failure: None,
            postcheck_failure: None,
            terminal: terminal::OriginalTerminalProgressV5::new(),
            release_send_attempted: false,
            release_send_result: None,
            release_status: None,
            release_receive_failure: None,
            release_checked: None,
            release_status_failure: None,
            release_receive_loaned: false,
            release_receive_result: None,
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

    // Pure purpose state only: the caller still checks the real phase5 owner.
    fn preclaim_send(&mut self) -> Result<bool, SourceProviderSecurityError> {
        if self.send_attempted && !matches!(self.send_result, Some(Ok(()))) {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let already_sent = self.send_attempted;
        self.send_attempted = true;
        Ok(already_sent)
    }

    fn retain_failure(&mut self, error: SourceProviderSecurityError) {
        if self.first_failure.is_none() {
            self.first_failure = Some(error);
        } else if self.postcheck_failure.is_none() {
            self.postcheck_failure = Some(error);
        }
    }
}

/// Borrows the actual original queue for one already checked Release send.
///
/// Construction is available only through the genuine Session and phase7
/// receiver. Its private fields expose neither a socket nor a signing key.
/// The caller keeps a separate reopened Release-effect owner and clock alive.
pub struct OriginalReleaseSendLoanV1<'owner, 'payload> {
    carrier: &'owner mut crate::carrier::InertSourceProviderCarrierV1,
    progress: &'owner mut OriginalPositiveProgressV5,
    payload: &'payload [u8],
}

impl OriginalReleaseSendLoanV1<'_, '_> {
    /// Sends once and immediately parks the whole returned native result.
    ///
    /// All application preparation and checks preceded this consuming entry.
    /// Retryable native errors are terminal for this selected purpose. Local
    /// success proves neither Source admission, receipt, cleanup nor Drain.
    pub fn send(self) {
        self.progress.release_send_result = Some(
            self.carrier.send_original_held_retaining_v5(self.payload),
        );
    }
}

/// Borrows the original queue after all Release/custody observations finish.
///
/// This concrete, move-only loan exposes no queue or authority. The caller
/// samples its disjoint genuine Release clock last before consuming it.
pub struct OriginalReleaseStatusReceiveLoanV1<'owner> {
    carrier: &'owner mut crate::carrier::InertSourceProviderCarrierV1,
    progress: &'owner mut OriginalPositiveProgressV5,
}

impl OriginalReleaseStatusReceiveLoanV1<'_> {
    /// Receives once and immediately parks the whole raw result and packet.
    pub fn receive(self) {
        self.progress.release_receive_result = Some(
            self.carrier.receive_original_root_accepted_retaining_v5(
                &mut self.progress.release_status, &mut self.progress.release_receive_failure,
            ),
        );
    }
}

impl OriginalNativeReceivedOutcomeV5 {
    pub(in crate::handshake::mount_request) fn original_release_status_record_v1(
        &self,
    ) -> Option<&crate::carrier::ReceivedSourceProviderRecordV1> {
        self.positive.release_status.as_ref().and_then(RetainedSourceProviderRecordV5::bound)
    }

    pub(in crate::handshake::mount_request) fn require_checked_release_status_basis_v1(
        &self,
        original: &AuthorizedMountProviderOutcomeV2,
        canonical: &[u8],
        status: SourceProviderStatus,
    ) -> Result<(), SourceProviderSecurityError> {
        use aos_sandbox_source_provider_protocol::ReleaseSourceResponseProfileV2;

        let record = self.original_release_status_record_v1()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let response = ReleaseSourceResponseProfileV2::from_canonical_bytes(canonical)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let fence = response.native_fence().ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let reply = self.positive.reply.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let held = self.positive.held.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if status != SourceProviderStatus::Pending || !record.descriptors.is_empty()
            || record.payload != canonical || self.failed.get()
            || original.native_outcome.as_ref().is_none_or(|actual| !Arc::ptr_eq(actual, &self.original))
            || fence.subject().acceptance() != reply.acceptance().acceptance()
            || fence.subject().native_request_digest() != reply.acceptance().acceptance().request_digest()
            || fence.subject().signed_acceptance_digest() != reply.acceptance().digest()
            || fence.subject().acquire().root_request_digest != original.signed_request_digest
            || fence.subject().acquire().session_binding != held.scope().original_source_session
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(())
    }

    /// Borrows the checked zero-FD Pending DATA while retaining its whole packet.
    #[doc(hidden)]
    #[must_use]
    pub fn checked_original_release_status_v1(&self) -> Option<&VerifiedMountProviderOutcomeV2> {
        if self.failed.get() || self.positive.release_status_failure.is_some()
            || self.positive.release_receive_failure.is_some()
        { return None; }
        self.positive.release_checked.as_ref()
    }

    /// Borrows the actual receive/verification cause; never extracts its owners.
    #[doc(hidden)]
    #[must_use]
    pub fn original_release_status_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.positive.release_receive_failure.as_ref().map(|cause| cause as _)
            .or_else(|| self.positive.release_status_failure.as_ref().map(|cause| cause as _))
    }

    /// Borrows the actual selected Release send result without observing I/O.
    #[doc(hidden)]
    #[must_use]
    pub fn original_release_send_result_v1(
        &self,
    ) -> Option<&Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>> {
        self.positive.release_send_result.as_ref()
    }

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

    /// Borrows the actual one-shot Root4 native failure without observing I/O.
    ///
    /// A later currentness refusal stays in the separate positive postcheck
    /// slot; it does not replace this error or turn transmission into Drain.
    #[doc(hidden)]
    #[must_use]
    pub fn original_accepted_send_failure_v5(
        &self,
    ) -> Option<&aos_sandbox_linux::seqpacket::SeqpacketError> {
        self.positive.send_result.as_ref().and_then(|result| result.as_ref().err())
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
    /// Prearms one receive after checking the same actual Release originals.
    ///
    /// # Errors
    /// Rejects any consumed/abandoned loan, failed owner or changed current cut.
    #[doc(hidden)]
    pub fn borrow_original_release_status_receive_v1<'owner>(
        &'owner mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        current: &OriginalRootProtectedReadbackV5,
        original: &AuthorizedMountProviderOutcomeV2,
        retained: &'owner mut OriginalNativeReceivedOutcomeV5,
        release: &PreparedMountProviderRequestV2,
    ) -> Result<OriginalReleaseStatusReceiveLoanV1<'owner>, SourceProviderSecurityError> {
        if retained.positive.release_receive_loaned || retained.positive.release_status.is_some()
            || retained.positive.release_receive_result.is_some()
            || retained.positive.release_receive_failure.is_some()
            || retained.positive.release_status_failure.is_some()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        retained.positive.release_receive_loaned = true;
        self.revalidate_original_release_custody_v1(writer, current, original, retained, release)?;
        if !matches!(retained.positive.release_send_result, Some(Ok(()))) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        Ok(OriginalReleaseStatusReceiveLoanV1 { carrier: &mut self.carrier, progress: &mut retained.positive })
    }

    /// Seals the resident Pending only after exact consumed native readback.
    ///
    /// # Errors
    ///
    /// Refuses a changed original, stale consumed owner, another signed response
    /// or any failed custody. Acceptance denotes no future exports, not Drain.
    #[doc(hidden)]
    pub fn seal_original_release_status_v1(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        current: &OriginalRootProtectedReadbackV5,
        original: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        release: &PreparedMountProviderRequestV2,
        release_attempt: [u8; 32],
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = (|| {
                owner.revalidate_original_release_custody_v1(writer, current, original, retained, release)?;
                if current.graph().legacy().provider_attempts.get(&release_attempt)
                    .is_none_or(|attempt| attempt.signed_request != release.signed_request)
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                let checked = retained.positive.release_checked.as_mut()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                owner.seal_original_native_export_fence_v1(writer, current, release_attempt, checked)?;
                owner.revalidate_original_release_custody_v1(writer, current, original, retained, release)
            })();
            owner.finish_original_positive_v5(retained, result)
        })
    }

    /// Verifies the Pending already parked by the original receive loan.
    ///
    /// # Errors
    ///
    /// Retains the whole packet, unexpected descriptors and native/verification
    /// cause on any consumed refusal. Only a nonconsuming empty receive may wait
    /// under the same original clock; it never resends or renews the request.
    #[doc(hidden)]
    pub fn advance_original_release_status_v1(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        current: &OriginalRootProtectedReadbackV5,
        original: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        release: &PreparedMountProviderRequestV2,
    ) -> Result<bool, SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = (|| {
                owner.revalidate_original_release_custody_v1(writer, current, original, retained, release)?;
                if !matches!(retained.positive.release_send_result, Some(Ok(())))
                    || retained.positive.release_checked.is_some()
                    || retained.positive.release_status_failure.is_some()
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                match retained.positive.release_receive_result.as_ref() {
                    Some(Ok(true)) => {}
                    Some(Ok(false)) | Some(Err(CarrierFailureV1::Retryable)) => {
                        owner.revalidate_original_release_custody_v1(writer, current, original, retained, release)?;
                        owner.carrier.finish_original_receive_backpressure_v5();
                        // Only a proven nonconsuming wait is reusable. Every
                        // consumed packet or abandoned loan remains irreversible.
                        retained.positive.release_receive_result = None;
                        retained.positive.release_receive_loaned = false;
                        return Ok(false);
                    }
                    _ => return Err(SourceProviderSecurityError::SessionContinuity),
                }
                owner.check_original_release_packet_execution_v1(retained)?;
                // The actual result moves into the resident reservoir before
                // independent physical/Session observations can fail or unwind.
                match owner.check_original_release_status_bytes_v1(current, release, original, retained) {
                    Ok(checked) => retained.positive.release_checked = Some(checked),
                    Err(cause) => {
                        retained.positive.release_status_failure = Some(cause);
                        return Err(SourceProviderSecurityError::SessionContinuity);
                    }
                }
                owner.revalidate_original_release_custody_v1(writer, current, original, retained, release)?;
                Ok(true)
            })();
            match result {
                Ok(ready) => Ok(ready),
                Err(cause) => {
                    if retained.positive.release_receive_failure.is_none()
                        && retained.positive.release_status_failure.is_none()
                    {
                        retained.positive.release_status_failure = Some(cause);
                    }
                    retained.retain_positive_failure(SourceProviderSecurityError::SessionContinuity);
                    Err(owner.poison(SourceProviderSecurityError::SessionContinuity))
                }
            }
        })
    }

    /// Lends one prearmed native send over the same independently admitted Release.
    ///
    /// All whole-Session, canonical and physical readback checks finish before
    /// return. While the short loan lives, the caller checks its disjoint effect
    /// owner and original paired clock last, then consumes the loan into send.
    ///
    /// # Errors
    ///
    /// Refuses a previous attempt, missing genuine phase7 custody, stale or
    /// mismatched reservation, a changed current role, or unavailable originals.
    #[doc(hidden)]
    pub fn borrow_original_release_send_v1<'owner, 'payload>(
        &'owner mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        current: &OriginalRootProtectedReadbackV5,
        original: &AuthorizedMountProviderOutcomeV2,
        retained: &'owner mut OriginalNativeReceivedOutcomeV5,
        release: &'payload PreparedMountProviderRequestV2,
    ) -> Result<OriginalReleaseSendLoanV1<'owner, 'payload>, SourceProviderSecurityError> {
        self.revalidate_original_release_custody_v1(writer, current, original, retained, release)?;
        if retained.positive.release_send_attempted
            || retained.positive.release_send_result.is_some()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let mut matching = current.graph().legacy().provider_attempts.values().filter(|attempt| {
            attempt.method == aos_sandbox_protocol::mount_source_acquisition_state::ProviderMethodV2::Release
                && attempt.signed_request == release.canonical_signed_request()
                && attempt.signed_request_digest == *release.projection().request_digests().2.as_bytes()
                && attempt.request_id == release.projection().request_identity().0
                && attempt.request_sequence == release.projection().request_identity().1
                && attempt.state == ProviderAttemptStateV2::Reserved
        });
        let attempt = matching.next().ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if matching.next().is_some()
            || current.graph().legacy().provider_heads.values().all(|head| {
                head.pending_attempt.is_none_or(|pending| pending.id != attempt.attempt_id
                    || pending.revision != attempt.revision
                    || pending.record_digest != attempt.record_digest)
            })
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        // The same resident receiver owns this irreversible latch and result.
        // Dropping a loan before send never creates a retry opportunity.
        retained.positive.release_send_attempted = true;
        Ok(OriginalReleaseSendLoanV1 {
            carrier: &mut self.carrier,
            progress: &mut retained.positive,
            payload: release.canonical_signed_request(),
        })
    }

    pub(in crate::handshake::mount_request) fn require_original_release_request_current_v1(
        &mut self,
        release: &PreparedMountProviderRequestV2,
        original: &AuthorizedMountProviderOutcomeV2,
        retained: &OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        self.revalidate()?;
        let now = super::super::current_unix_seconds()?;
        let authorization = &release.outcome;
        let projection = &release.projection;
        let request = aos_sandbox_source_provider_protocol::decode_release_request(
            authorization.signed_request.subject(),
        ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let complete = retained.original_complete_record_v5()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let response = decode_acquire_response(&complete.payload)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(
            response.signed_receipt().ok_or(SourceProviderSecurityError::SessionContinuity)?,
        ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let lease = SignedSourceExportLeaseV1::from_canonical_bytes(
            receipt.subject().signed_export_lease(),
        ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let (lease_issued, lease_expires) = lease.subject().validity();
        let inner = self.custody.inner();
        let provider_key = inner.trust().keys().iter().find(|entry| {
            entry.signer() == inner.provider_authority().traffic_signer()
                && entry.state() == SourceProviderKeyTrustStateV1::Eligible
        }).ok_or(SourceProviderSecurityError::SessionContinuity)?;

        // This preparation is already signed by the genuine current Session.
        // Its current role and exact bytes remain bound to the old physical
        // acquisition; the historical Acquire deadline is not extended.
        if retained.failed.get()
            || original.native_outcome.as_ref()
                .is_none_or(|owner| !Arc::ptr_eq(owner, &retained.original))
            || authorization.native_outcome.is_some()
            || authorization.method != SourceProviderMethod::Release
            || authorization.signed_request.method() != SourceProviderMethod::Release
            || projection.method != SourceProviderMethod::Release
            || release.signed_request != authorization.signed_request.to_canonical_bytes()
            || projection.signed_request_digest != digest_signed_request(&authorization.signed_request)
            || authorization.signed_request_digest != projection.signed_request_digest
            || authorization.typed_request_digest != digest_release_request(&request)
            || projection.typed_request_digest != authorization.typed_request_digest
            || authorization.provider != *inner.provider_authority().authority()
            || authorization.holder != *inner.root_authority().authority()
            || authorization.provider != original.provider
            || authorization.holder != original.holder
            || authorization.signed_request.signer() != inner.root_authority().traffic_signer()
            || authorization.provider_outcome_signer != *provider_key.signer()
            || authorization.provider_outcome_public_key != *provider_key.public_key()
            || original.provider_outcome_signer != authorization.provider_outcome_signer
            || original.provider_outcome_public_key != authorization.provider_outcome_public_key
            || authorization.session_binding != self.session.binding()
            || authorization.session_binding != original.session_binding
            || projection.session_binding != authorization.session_binding
            || request.session_binding() != authorization.session_binding
            || authorization.provider_process_instance != self.session.provider_hello().process_instance()
            || authorization.request_id != request.request_id()
            || projection.request_id != request.request_id()
            || authorization.request_sequence != request.sequence()
            || projection.request_sequence != request.sequence()
            || authorization.expected_response_sequence != projection.expected_response_sequence
            || authorization.acquisition_id != original.acquisition_id
            || authorization.acquisition_sequence != original.acquisition_sequence
            || authorization.acquisition_id != Some(request.acquisition_id())
            || authorization.lease_id != Some(request.lease_id())
            || authorization.lease_digest != Some(request.lease_digest())
            || lease.subject().lease_id() != request.lease_id()
            || digest_signed_export_lease(&lease) != request.lease_digest()
            || projection.session.trust_generation != inner.trust().trust_generation()
            || projection.session.trust_digest != inner.trust().trust_digest()
            || projection.session.revocation_generation != inner.trust().revocation_generation()
            || projection.session.revocation_digest != inner.trust().revocation_digest()
            || authorization.deadline_seconds != request.deadline_seconds()
            || now < projection.session.authenticated_at_seconds
            || now >= projection.session.current_valid_until_seconds
            || now < lease_issued
            || now >= lease_expires
            || now >= request.deadline_seconds()
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        // The original preparation supplies immutable catalog provenance only.
        // Current kernel/peer/custody observations above belong to this Session.
        retained.original.original_selection_v5()?;
        Ok(())
    }

    /// Rechecks the same terminal original custody for an independently signed Release.
    /// Attempts actual Session custody independently after a Release action.
    ///
    /// A missing or refused readback is not a reason to skip the kernel/peer
    /// observation. This lends no authority and never renews an Acquire clock.
    ///
    /// # Errors
    /// Returns the actual currentness refusal or rejects an unavailable cut.
    #[doc(hidden)]
    pub fn observe_original_release_post_v1(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        current: Option<&OriginalRootProtectedReadbackV5>,
        original: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        release: Option<&PreparedMountProviderRequestV2>,
    ) -> Result<(), SourceProviderSecurityError> {
        self.revalidate()?;
        let current = current.ok_or(SourceProviderSecurityError::SessionContinuity)?;
        match release {
            Some(release) => self.revalidate_original_release_custody_v1(
                writer, current, original, retained, release,
            ),
            None => self.original_release_projection_v1(writer, current, original, retained)
                .map(|_| ()),
        }
    }

    /// Rechecks the same terminal original custody for an independently signed Release.
    ///
    /// This borrows the resident preparation and original image/descriptor
    /// owners. It neither recreates their baseline nor supplies a Release-effect
    /// permit; the caller separately checks its genuine paired Release clock.
    ///
    /// # Errors
    ///
    /// Retains the first refusal and ends the original Session on a changed
    /// current role, Release, terminal cut, archive, physical owner or lease.
    #[doc(hidden)]
    pub fn revalidate_original_release_custody_v1(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        current: &OriginalRootProtectedReadbackV5,
        original: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        release: &PreparedMountProviderRequestV2,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = (|| {
                if !retained.positive.send_attempted
                    || !matches!(retained.positive.send_result, Some(Ok(())))
                    || retained.positive.first_failure.is_some()
                    || retained.positive.postcheck_failure.is_some()
                    || retained.original_terminal_failure_v5().is_some()
                    || retained.original_terminal_postcheck_debt_v5().is_some()
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                owner.require_original_positive_owner_for_v5(
                    writer, current, original, retained, OriginalPositivePurposeV5::Release(release),
                )?;
                let sidecar = current.graph().sidecars().get(&current.attempt())
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let provider = retained.original_provider_settled_v5()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let unsigned = retained.original_unsigned_terminal_v5()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let signed = retained.original_signed_terminal_v5()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                if sidecar.suffix().phase() != 7 || current.floor().is_some()
                    || sidecar.suffix().control(Kind::ProviderSettled) != Some(provider)
                    || sidecar.suffix().control(Kind::RootTerminalRecorded) != Some(signed)
                    || signed.prepared() != unsigned || unsigned.predecessor() != provider.digest()
                    || provider.scope() != signed.scope()
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                provider.verify_signature_claim(
                    &NativeHeldSignerV1::SourceProvider(original.provider_outcome_signer.clone()),
                    &original.provider_outcome_public_key,
                ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
                owner.require_current_root_mount_record_role_v5(unsigned.signer())?;
                owner.require_original_release_request_current_v1(release, original, retained)
            })();
            owner.finish_original_positive_v5(retained, result)
        })
    }

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
        self.require_original_held_signature_for_v1(
            authorization, retained, OriginalPositivePurposeV5::Positive,
        )
    }

    fn require_original_held_signature_for_v1(
        &mut self,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &OriginalNativeReceivedOutcomeV5,
        purpose: OriginalPositivePurposeV5<'_>,
    ) -> Result<(), SourceProviderSecurityError> {
        match purpose {
            OriginalPositivePurposeV5::Release(release) => {
                self.require_original_release_request_current_v1(release, authorization, retained)?;
            }
            _ => self.require_native_outcome_authorization_v3(authorization)?,
        }
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
        self.require_original_positive_owner_for_v5(
            writer, readback, authorization, retained, OriginalPositivePurposeV5::Positive,
        )
    }

    // One recipe owns the archive, Complete physical, role and paired-clock
    // observations. Terminal selection comes only from the locally sent Root4.
    fn require_original_positive_owner_for_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        purpose: OriginalPositivePurposeV5<'_>,
    ) -> Result<(), SourceProviderSecurityError> {
        writer.validate_readback(readback)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        self.require_original_held_signature_for_v1(authorization, retained, purpose)?;
        let sidecar = readback.graph().sidecars().get(&readback.attempt())
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let phase = sidecar.suffix().phase();
        let root1 = sidecar.suffix().control(Kind::RootPrepared)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let floor = match purpose {
            OriginalPositivePurposeV5::Positive => Some(readback.floor()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?),
            OriginalPositivePurposeV5::Terminal | OriginalPositivePurposeV5::Release(_) => readback.floor(),
        };
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
            || match purpose {
                OriginalPositivePurposeV5::Positive => !(1..=5).contains(&phase),
                OriginalPositivePurposeV5::Terminal => !matches!(phase, 6 | 7),
                OriginalPositivePurposeV5::Release(_) => phase != 7,
            }
            || match floor {
                Some(floor) => floor.request().owner_id != readback.attempt()
                    || floor.original_prepared() != root1.prepared()
                    || floor.admission_cut() != sidecar.admission_cut(),
                None => !matches!(purpose, OriginalPositivePurposeV5::Terminal | OriginalPositivePurposeV5::Release(_)) || phase != 7
                    || original_root_remaining_v5(readback.graph(), readback.attempt())
                        .map_err(|_| SourceProviderSecurityError::SessionContinuity)? != 0,
            }
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
        match purpose {
            OriginalPositivePurposeV5::Release(release) => {
                // Storage's old signed validity is historical provenance, not
                // the current Release clock or a renewed Acquire deadline.
                if issued >= expires || expires > authorization.deadline_seconds {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                self.require_original_release_request_current_v1(release, authorization, retained)?;
            }
            _ => {
                let now = super::super::current_unix_seconds()?;
                if now < issued || now >= expires || expires > authorization.deadline_seconds {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                self.require_original_storage_validity_v5(authorization, expires)?;
            }
        }

        if phase >= 3 {
            require_original_complete_cut_v5(readback, authorization, retained)?;
        }
        if retained.positive.checked.is_some() {
            self.recheck_original_complete_physical_for_v1(authorization, retained, purpose)?;
        }
        if phase >= 4 {
            match purpose {
                OriginalPositivePurposeV5::Positive => require_original_accepted_cut_v5(readback, retained)?,
                OriginalPositivePurposeV5::Terminal | OriginalPositivePurposeV5::Release(_) => {
                    require_original_accepted_cut_for_v5(readback, retained, purpose)?;
                }
            }
        }
        match purpose {
            OriginalPositivePurposeV5::Release(release) => {
                self.require_original_release_request_current_v1(release, authorization, retained)?;
            }
            _ => self.require_native_outcome_authorization_v3(authorization)?,
        }
        writer.validate_readback(readback)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;

        // Final paired time follows the slow original file/physical/full-graph
        // observations. The same lease may narrow, never renew, the old fence.
        if let OriginalPositivePurposeV5::Release(release) = purpose {
            self.require_original_release_request_current_v1(release, authorization, retained)
        } else if let Some(record) = retained.original_complete_record_v5() {
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
        self.recheck_original_complete_physical_for_v1(
            authorization, retained, OriginalPositivePurposeV5::Positive,
        )
    }

    fn recheck_original_complete_physical_for_v1(
        &mut self,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        purpose: OriginalPositivePurposeV5<'_>,
    ) -> Result<(), SourceProviderSecurityError> {
        self.recheck_original_complete_baseline_v1(authorization, retained)?;
        let record = retained.positive.complete.as_ref()
            .and_then(RetainedSourceProviderRecordV5::bound)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        match purpose {
            OriginalPositivePurposeV5::Release(release) => {
                self.require_original_release_request_current_v1(release, authorization, retained)
            }
            _ => self.require_native_outcome_response_v3(authorization, &record.payload, true),
        }
    }

    fn recheck_original_complete_baseline_v1(
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
        )
    }

    /// Projects the same physical original into Release reservation DATA.
    ///
    /// No descriptor or manager-presence capability is transferred. The real
    /// caller retains this original and separately admits a new live Release.
    ///
    /// # Errors
    ///
    /// Rejects an uncompleted terminal cut, failed original, changed physical
    /// descriptor, current Root signer or acquisition association.
    #[doc(hidden)]
    pub fn original_release_projection_v1(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        current: &OriginalRootProtectedReadbackV5,
        original: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<crate::descriptor::MountSourceRootCustodyProjectionV2, SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = (|| {
                writer.validate_readback(current)
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
                owner.revalidate()?;
                if retained.failed.get() || retained.original_terminal_failure_v5().is_some()
                    || retained.original_terminal_postcheck_debt_v5().is_some()
                    || original.native_outcome.as_ref()
                        .is_none_or(|actual| !Arc::ptr_eq(actual, &retained.original))
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                let sidecar = current.graph().sidecars().get(&current.attempt())
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let signed = retained.original_signed_terminal_v5()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                if sidecar.suffix().phase() != 7 || current.floor().is_some()
                    || sidecar.suffix().control(Kind::RootTerminalRecorded) != Some(signed)
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                owner.require_current_root_mount_record_role_v5(signed.signer())?;
                require_original_complete_cut_v5(current, original, retained)?;
                owner.recheck_original_complete_baseline_v1(original, retained)?;
                let checked = retained.positive.checked.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let observation = retained.positive.physical.observation()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let acquisition = current.graph().legacy().acquisitions.get(
                    &current.graph().legacy().provider_attempts.get(&current.attempt())
                        .ok_or(SourceProviderSecurityError::SessionContinuity)?.owner.owner_id(),
                ).ok_or(SourceProviderSecurityError::SessionContinuity)?;
                crate::descriptor::original_release_projection_v1(acquisition, checked, observation)
            })();
            match result {
                Ok(projection) => Ok(projection),
                Err(cause) => {
                    retained.retain_positive_failure(cause);
                    Err(owner.poison(SourceProviderSecurityError::SessionContinuity))
                }
            }
        })
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

    /// Sends the physically stored RootAccepted4 once on the original carrier.
    ///
    /// Every native result stays in the original received owner before the
    /// later physical/current-role/clock checks. Successful re-entry only
    /// rechecks that same phase5 cut; it never sends again or implies receipt.
    ///
    /// # Errors
    ///
    /// Ends the same Session on missing/stale custody, send refusal (including
    /// EAGAIN/EINTR), or later debt. The actual native cause remains borrowable.
    #[doc(hidden)]
    pub fn send_original_root_accepted_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase5: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<bool, SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            if retained.failed.get()
                || retained.positive.first_failure.is_some()
                || retained.positive.postcheck_failure.is_some()
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }

            // End the possible-send purpose before preparation or observations.
            let already_sent = match retained.positive.preclaim_send() {
                Ok(already_sent) => already_sent,
                Err(cause) => return Err(owner.poison(cause)),
            };
            let before = (|| {
                if !already_sent {
                    let signed = retained.positive.signed.as_ref()
                        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                    retained.positive.send_payload = Some(signed.to_canonical_bytes());
                }
                owner.require_stored_original_accepted_v5(
                    writer, phase5, authorization, retained,
                )
            })();
            if let Err(cause) = before {
                return owner.finish_original_positive_v5(retained, Err(cause)).map(|()| false);
            }
            if already_sent {
                return Ok(true);
            }

            let Some(payload) = retained.positive.send_payload.as_ref() else {
                return owner.finish_original_positive_v5(
                    retained, Err(SourceProviderSecurityError::SessionContinuity),
                ).map(|()| false);
            };
            retained.positive.send_result = Some(
                owner.carrier.send_original_root_accepted_retaining_v5(payload),
            );

            // Native output is resident even if this slower observation fails.
            let after = owner.require_stored_original_accepted_v5(
                writer, phase5, authorization, retained,
            );
            if let Err(cause) = after {
                if retained.positive.postcheck_failure.is_none() {
                    retained.positive.postcheck_failure = Some(cause);
                }
            }
            if !matches!(retained.positive.send_result, Some(Ok(())))
                || retained.positive.postcheck_failure.is_some()
            {
                retained.failed.set(true);
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            Ok(true)
        })
    }

    fn require_stored_original_accepted_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase5: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        let sidecar = phase5.graph().sidecars().get(&phase5.attempt())
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let signed = retained.positive.signed.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let payload = retained.positive.send_payload.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if sidecar.suffix().phase() != 5
            || sidecar.suffix().prepared().is_some()
            || sidecar.suffix().control(Kind::RootAccepted) != Some(signed)
            || payload.len() > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1
            || *payload != signed.to_canonical_bytes()
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.require_current_root_mount_record_role_v5(signed.prepared().signer())?;
        // The shared original checks include actual conserved floor, Complete
        // descriptor, archived Source files and paired time LAST.
        self.require_original_positive_owner_v5(writer, phase5, authorization, retained)
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
    require_original_accepted_cut_for_v5(readback, retained, OriginalPositivePurposeV5::Positive)
}

fn require_original_accepted_cut_for_v5(
    readback: &OriginalRootProtectedReadbackV5,
    retained: &OriginalNativeReceivedOutcomeV5,
    purpose: OriginalPositivePurposeV5<'_>,
) -> Result<(), SourceProviderSecurityError> {
    let sidecar = readback.graph().sidecars().get(&readback.attempt())
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let cut = retained.positive.cut.as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let assertion = retained.positive.disposition.as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let unsigned = retained.positive.unsigned.as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let floor = match purpose {
        OriginalPositivePurposeV5::Positive => Some(readback.floor()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?),
        OriginalPositivePurposeV5::Terminal | OriginalPositivePurposeV5::Release(_) => readback.floor(),
    };
    let remaining = original_root_remaining_v5(readback.graph(), readback.attempt())
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    if sidecar.disposition_cut() != Some(cut)
        || sidecar.disposition() != Some(assertion)
        || match floor {
            Some(floor) => floor.request().future_transactions != remaining,
            None => !matches!(purpose, OriginalPositivePurposeV5::Terminal | OriginalPositivePurposeV5::Release(_))
                || sidecar.suffix().phase() != 7 || remaining != 0,
        }
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
        6 | 7 if matches!(purpose, OriginalPositivePurposeV5::Terminal | OriginalPositivePurposeV5::Release(_)) => {
            retained.positive.signed.as_ref().is_some_and(|signed| {
                signed.prepared() == unsigned
                    && sidecar.suffix().control(Kind::RootAccepted) == Some(signed)
            })
        }
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
    fn attempted_send_without_native_success_never_rearms() {
        let mut progress = OriginalPositiveProgressV5::new();

        assert!(!progress.preclaim_send().unwrap());
        assert!(progress.preclaim_send().is_err());
        progress.send_result = Some(Err(aos_sandbox_linux::seqpacket::SeqpacketError::WouldBlock));

        assert!(progress.preclaim_send().is_err());
        assert!(matches!(progress.send_result, Some(Err(aos_sandbox_linux::seqpacket::SeqpacketError::WouldBlock))));
    }

    #[test]
    fn successful_native_state_is_observation_not_another_send_claim() {
        let mut progress = OriginalPositiveProgressV5::new();
        assert!(!progress.preclaim_send().unwrap());
        progress.send_result = Some(Ok(()));

        assert!(progress.preclaim_send().unwrap());
        assert!(progress.send_payload.is_none());
        assert!(progress.signed.is_none());
    }

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
