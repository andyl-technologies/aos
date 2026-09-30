//! Retained actual original Pending receipt and unsigned Closed preparation.
//!
//! No constructor accepts recovered rows or caller bytes. The typed carrier
//! packet, sender subject, transferred FDs and original guard remain owned on
//! every post-receive error. Positive packets stay unsupported and parked.

use std::{cell::Cell, sync::Arc};

use aos_sandbox::{MountOriginalNativeJournalAuthorityV5, OriginalRootProtectedReadbackV5};
use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::RootNativeCutV1;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1 as Kind, NativeHeldSectionTagV1 as Tag,
    assertion::{NativeHeldDispositionV1, RootNativeDispositionAssertionV1, RootNativeObservationV1},
    frame::{NativeHeldSectionV1, PreparedNativeHeldControlV1},
    witness::NativeHeldOwnerWitnessV1,
};

use super::*;
use crate::carrier::RetainedSourceProviderRecordV5;

mod root_closed;

/// Owns one actual original packet through its Pending-only continuation.
///
/// This move-only value has no public constructor or descriptor extractor.
/// Verification borrows the original packet and shares only the same private
/// original guard already retained by the actual sent authorization.
pub struct OriginalNativeReceivedOutcomeV5 {
    received: Option<RetainedSourceProviderRecordV5>,
    original: Arc<native_catalog::NativeAcquireOutcomeCustodyV3>,
    verified: Option<VerifiedMountProviderOutcomeV2>,
    pending_cut: Option<RootNativeCutV1>,
    disposition: Option<RootNativeDispositionAssertionV1>,
    unsigned8: Option<PreparedNativeHeldControlV1>,
    closed: root_closed::RootClosedProgressV5,
    failed: Cell<bool>,
}

impl OriginalNativeReceivedOutcomeV5 {
    pub(in crate::handshake::mount_request) fn fail_original_custody_v5(&self) {
        self.failed.set(true);
    }

    fn record(&self) -> Option<&crate::carrier::ReceivedSourceProviderRecordV1> {
        self.received
            .as_ref()
            .and_then(RetainedSourceProviderRecordV5::bound)
    }

    /// Borrows verified Pending DATA without releasing original packet custody.
    #[must_use]
    pub fn verified_pending(&self) -> Option<&VerifiedMountProviderOutcomeV2> {
        if self.failed.get() || self.record().is_none() {
            None
        } else {
            self.verified.as_ref()
        }
    }

    /// Borrows retained unsigned Closed DATA even after a post-check failure.
    #[must_use]
    pub const fn unsigned_closed(&self) -> Option<&PreparedNativeHeldControlV1> {
        self.unsigned8.as_ref()
    }
}

impl CurrentRootMountSourceProviderSessionV1 {
    /// Revokes original continuation effects without asserting currentness.
    #[doc(hidden)]
    pub fn invalidate_original_inventory_continuation_v6(
        &mut self,
        retained: Option<&OriginalNativeReceivedOutcomeV5>,
    ) {
        if let Some(retained) = retained {
            retained.failed.set(true);
        }
        self.poison(SourceProviderSecurityError::SessionContinuity);
    }

    /// Receives once under the exact original phase1 sent authorization.
    ///
    /// `false` means transport backpressure without any typed packet. The
    /// same healthy empty shell may retry after all original checks. A parked
    /// packet or failed shell forbids another receive, including an unsupported
    /// Held/Complete first packet.
    ///
    /// # Errors
    ///
    /// Retains every successfully typed packet on origin, execution, framing,
    /// currentness or signature failure and poisons effect authority.
    #[doc(hidden)]
    pub fn advance_original_native_outcome_receive_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase1: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        slot: &mut Option<OriginalNativeReceivedOutcomeV5>,
    ) -> Result<bool, SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, slot).run(|owner, slot| {
            if slot.as_ref().is_some_and(|retained| {
                retained.failed.get()
                    || retained.received.is_some()
                    || retained.verified.is_some()
            }) {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            writer
                .validate_readback(phase1)
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            let sidecar = phase1
                .graph()
                .sidecars()
                .get(&phase1.attempt())
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let original_attempt = phase1
                .graph()
                .legacy()
                .provider_attempts
                .get(&phase1.attempt())
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            if sidecar.suffix().phase() != 1
                || authorization.method != SourceProviderMethod::Acquire
                || authorization.mount_attempt_id != Some(phase1.attempt())
                || original_attempt.signed_request != authorization.signed_request.to_canonical_bytes()
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }

            owner.require_native_outcome_authorization_v3(authorization)?;

            let original = authorization.native_outcome.as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            if slot.as_ref().is_some_and(|retained| {
                !Arc::ptr_eq(original, &retained.original)
            }) {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            if slot.is_none() {
                **slot = Some(OriginalNativeReceivedOutcomeV5 {
                    received: None,
                    original: Arc::clone(original),
                    verified: None,
                    pending_cut: None,
                    disposition: None,
                    unsigned8: None,
                    closed: root_closed::RootClosedProgressV5::new(),
                    failed: Cell::new(false),
                });
            }
            let retained = slot.as_mut()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            match owner.carrier.receive_original_retaining_v5(&mut retained.received) {
                Ok(true) => {}
                Ok(false) | Err(CarrierFailureV1::Retryable) => return Ok(false),
                Err(CarrierFailureV1::Fatal(error)) => return Err(owner.poison(error)),
            }

            let retained = slot
                .as_mut()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let result = (|| {
                let record = retained
                    .record()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                record.execution.revalidate(owner.carrier.socket().peer())?;
                if !record.execution.has_same_execution(&owner.provider_execution) {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }

                // Native control packets do not pass this ordinary response parser;
                // Complete remains parked with its sole descriptor, never accepted.
                let response = decode_acquire_response(&record.payload)
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
                if response.status() != SourceProviderStatus::Pending
                    || response.signed_receipt().is_some()
                    || !record.descriptors.is_empty()
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }

                owner.require_native_outcome_authorization_v3(authorization)?;
                retained.verified = Some(owner.verify_provider_outcome_bytes_v2(
                    None,
                    authorization,
                    record.payload.clone(),
                    None,
                )?);
                owner.revalidate_original_pending_receipt_v5(writer, phase1, authorization, retained)?;
                Ok(true)
            })();

            result
        })
    }

    /// Rechecks the same received token against the exact current protected cut.
    ///
    /// # Errors
    ///
    /// Rejects lost physical readback, original guard, peer, cookie, catalog,
    /// trust, clock, request or signed Pending identity.
    #[doc(hidden)]
    pub fn revalidate_original_pending_receipt_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &**retained;
            let result = owner.revalidate_original_pending_receipt_inner_v5(
                writer,
                readback,
                authorization,
                retained,
            );
            if result.is_err() {
                retained.failed.set(true);
                owner.poison(SourceProviderSecurityError::SessionContinuity);
            }
            result
        })
    }

    fn revalidate_original_pending_receipt_inner_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        writer
            .validate_readback(readback)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        self.require_original_pending_receipt_owner_v5(
            authorization,
            retained,
            readback.graph(),
            readback.attempt(),
        )?;
        writer
            .validate_readback(readback)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))
    }

    // Receipt custody is shared without relaxing either named physical view.
    fn require_original_pending_receipt_owner_v5(
        &mut self,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &OriginalNativeReceivedOutcomeV5,
        checked: &aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::RootNativeHeldGraphV2,
        original_attempt: [u8; 32],
    ) -> Result<(), SourceProviderSecurityError> {
        self.require_native_outcome_authorization_v3(authorization)?;
        let outcome = retained
            .verified_pending()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let record = retained
            .record()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if authorization
            .native_outcome
            .as_ref()
            .is_none_or(|original| !Arc::ptr_eq(original, &retained.original))
            || outcome
                .native_outcome
                .as_ref()
                .is_none_or(|original| !Arc::ptr_eq(original, &retained.original))
            || authorization.mount_attempt_id != Some(original_attempt)
            || outcome.status != SourceProviderStatus::Pending
            || outcome.canonical_response != record.payload
            || !record.descriptors.is_empty()
            || !record.execution.has_same_execution(&self.provider_execution)
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }

        record.execution.revalidate(self.carrier.socket().peer())?;
        let attempt = checked
            .legacy()
            .provider_attempts
            .get(&original_attempt)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        require_received_pending_attempt_v5(authorization, outcome, attempt, true)?;
        if attempt.revision == 2 {
            let sidecar = checked
                .sidecars()
                .get(&original_attempt)
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            if retained.pending_cut.as_ref() != sidecar.disposition_cut()
                || retained.disposition.as_ref() != sidecar.disposition()
            {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
        }
        self.require_verified_native_outcome_v3(
            outcome,
            &authorization.signed_request.to_canonical_bytes(),
        )?;

        Ok(())
    }

    /// Derives unsigned original8 under the same received guard and first-R cut.
    ///
    /// This retains DATA only and performs no signature, append or send.
    ///
    /// # Errors
    ///
    /// Rejects stale original custody, another phase or changed prospective
    /// companions, signer or physical successor sequence.
    #[doc(hidden)]
    pub fn prepare_original_pending_closed_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase1: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        owners: &aos_sandbox::JournalTransaction,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = owner.prepare_original_pending_closed_inner_v5(
                writer,
                phase1,
                authorization,
                retained,
                owners,
            );
            if result.is_err() {
                retained.failed.set(true);
                owner.poison(SourceProviderSecurityError::SessionContinuity);
            }
            result
        })
    }

    fn prepare_original_pending_closed_inner_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase1: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        owners: &aos_sandbox::JournalTransaction,
    ) -> Result<(), SourceProviderSecurityError> {
        if retained.pending_cut.is_some() || retained.unsigned8.is_some() {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }

        self.revalidate_original_pending_receipt_v5(writer, phase1, authorization, retained)?;
        let (cut, captured, sequence) = writer
            .prospective_original_pending_cut_v5(phase1, owners)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        // Preserve the exact proposed cut even if a later equality or frame
        // check fails. This token can never rederive it under a refreshed guard.
        retained.pending_cut = Some(cut);

        let attempt_key =
            aos_sandbox_protocol::mount_source_acquisition_state::provider_attempt_key(phase1.attempt());
        let attempt_bytes = captured
            .canonical_records()
            .get(&attempt_key)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderQueryAttempt {
            value: captured_attempt,
        } = aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(
            &attempt_key,
            attempt_bytes,
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        else {
            return Err(SourceProviderSecurityError::SessionContinuity);
        };
        require_received_pending_attempt_v5(
            authorization,
            retained
                .verified_pending()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?,
            &captured_attempt,
            false,
        )?;

        let sidecar = phase1
            .graph()
            .sidecars()
            .get(&phase1.attempt())
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let root1 = sidecar
            .suffix()
            .control(Kind::RootPrepared)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let r = RootNativeDispositionAssertionV1 {
            disposition: NativeHeldDispositionV1::Closed,
            observation: RootNativeObservationV1::PreparedOnly,
            scope: *sidecar.original_scope(),
            source_artifact: ObjectDigest::from_bytes([0; 32]),
            descriptor_commitment: ObjectDigest::from_bytes([0; 32]),
            records: captured.witnesses().clone(),
        };
        retained.disposition = Some(r);
        let r = retained.disposition.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let witness = NativeHeldOwnerWitnessV1::Root(
            retained
                .original
                .original_root_witness(captured.witnesses().clone(), sequence)?,
        )
        .to_canonical_bytes()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;

        let unsigned = PreparedNativeHeldControlV1::new(
            Kind::RootClosed,
            r.scope,
            root1.digest(),
            vec![
                NativeHeldSectionV1::new(Tag::Witness, witness),
                NativeHeldSectionV1::new(Tag::RootPrepared, root1.to_canonical_bytes()),
                NativeHeldSectionV1::new(
                    Tag::RootDispositionAssertion,
                    r.to_canonical_bytes()
                        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
                        .to_vec(),
                ),
            ]
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
            root1.prepared().signer().clone(),
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;

        // Retain first-R DATA before any post-preparation failure. It is never
        // rederived with a different cut or a refreshed original clock.
        retained.unsigned8 = Some(unsigned);
        self.revalidate_original_pending_receipt_v5(writer, phase1, authorization, retained)?;
        Ok(())
    }
}

/// Binds prospective and committed Pending2 to the actual verifier's output.
fn require_received_pending_attempt_v5(
    authorization: &AuthorizedMountProviderOutcomeV2,
    outcome: &VerifiedMountProviderOutcomeV2,
    attempt: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderQueryAttemptV2,
    allow_reserved: bool,
) -> Result<(), SourceProviderSecurityError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        ProviderAttemptStateV2, ProviderStatusV2,
    };

    if authorization.mount_attempt_id != Some(attempt.attempt_id)
        || authorization.mount_session_id != Some(attempt.session_id)
        || attempt.signed_request != authorization.signed_request.to_canonical_bytes()
        || attempt.signed_request_digest != *authorization.signed_request_digest.as_bytes()
        || attempt.request_sequence != outcome.response_sequence
        || outcome.session_binding != authorization.session_binding
        || attempt
            .provider_acquisition
            .map(|value| ObjectDigest::from_bytes(value.acquisition_id))
            != outcome.acquisition_id
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    if allow_reserved
        && attempt.revision == 1
        && matches!(attempt.state, ProviderAttemptStateV2::Reserved)
    {
        return Ok(());
    }
    let ProviderAttemptStateV2::DispositionConsumed {
        response_sequence,
        verification_anchor,
        status,
        signed_status,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Err(SourceProviderSecurityError::SessionContinuity);
    };
    let response = decode_acquire_response(&outcome.canonical_response)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    if attempt.revision != 2
        || *status != ProviderStatusV2::Pending
        || *response_sequence != outcome.response_sequence
        || *verification_anchor != outcome.verification_anchor
        || *signed_status != response.signed_status().to_canonical_bytes()
        || !signed_result.is_empty()
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }

    Ok(())
}
