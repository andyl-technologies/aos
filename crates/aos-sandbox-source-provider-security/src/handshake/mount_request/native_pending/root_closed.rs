//! Original Pending RootClosed signing and same-carrier zero-FD sending.
//!
//! The real received token owns both effect latches. Historical archive DATA
//! never recreates that token, its original guard or a signing/send permission.

use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::{
    RootNativeHeldGraphV2, RootNativeReconstructedCutV1, has_original_pending_closed_cut_v5,
};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldOwnerV1, frame::SignedNativeHeldControlV1,
};
use ed25519_dalek::Signer as _;

use super::*;

enum SignatureState {
    Unattempted,
    Attempted,
    Signed(SignedNativeHeldControlV1),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SendState {
    Unattempted,
    Attempted,
    Retryable,
    Sent,
}

/// Retains signature and possible-send progress on the actual received owner.
pub(super) struct RootClosedProgressV5 {
    signature: SignatureState,
    send: SendState,
}

impl RootClosedProgressV5 {
    /// Initializes unattempted progress within an actual receive construction.
    pub(super) const fn new() -> Self {
        Self {
            signature: SignatureState::Unattempted,
            send: SendState::Unattempted,
        }
    }

    fn signed(&self) -> Option<&SignedNativeHeldControlV1> {
        match &self.signature {
            SignatureState::Signed(signed) => Some(signed),
            _ => None,
        }
    }

    fn arm_signature(&mut self) -> Result<(), SourceProviderSecurityError> {
        if !matches!(self.signature, SignatureState::Unattempted) {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.signature = SignatureState::Attempted;
        Ok(())
    }

    fn arm_send(&mut self) -> Result<(), SourceProviderSecurityError> {
        if !matches!(self.send, SendState::Unattempted | SendState::Retryable) {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.send = SendState::Attempted;
        Ok(())
    }
}

impl OriginalNativeReceivedOutcomeV5 {
    /// Borrows exact signed Closed DATA, including after a post-sign failure.
    #[must_use]
    pub fn signed_closed(&self) -> Option<&SignedNativeHeldControlV1> {
        self.closed.signed()
    }
}

impl CurrentRootMountSourceProviderSessionV1 {
    /// Rechecks the actual original Pending cut, role and retained Closed bytes.
    ///
    /// Phase10 binds the unsigned Witness to the actual first-R sequence;
    /// phase11 preserves that sequence while requiring the exact stored signature.
    ///
    /// # Errors
    ///
    /// Latches the received token and Session closed on any physical, current
    /// companion, packet, original guard, role or exact archive mismatch.
    #[doc(hidden)]
    pub fn revalidate_original_root_closed_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        let result = self.require_original_root_closed_v5(writer, readback, authorization, retained);
        if let Err(error) = result {
            retained.failed.set(true);
            return Err(self.poison(error));
        }

        Ok(())
    }

    fn require_original_root_closed_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        self.revalidate_original_pending_receipt_v5(writer, readback, authorization, retained)?;
        let graph = readback.graph();
        let sidecar = graph
            .sidecars()
            .get(&readback.attempt())
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let phase = sidecar.suffix().phase();
        if !matches!(phase, 10 | 11)
            || !has_original_pending_closed_cut_v5(graph, sidecar)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
            || sidecar.settlement().is_some()
            || sidecar.terminal_verifier().is_some()
            || matches!(retained.closed.signature, SignatureState::Attempted)
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }

        let outcome = retained
            .verified_pending()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let attempt = graph
            .legacy()
            .provider_attempts
            .get(&readback.attempt())
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        require_received_pending_attempt_v5(authorization, outcome, attempt, false)?;
        let cut = retained
            .pending_cut
            .as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let captured = cut
            .reconstruct(graph.legacy(), readback.attempt())
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        require_current_companions(graph, &captured)?;

        let root1 = sidecar
            .suffix()
            .control(Kind::RootPrepared)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let floor = readback
            .floor()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let unsigned = retained
            .unsigned_closed()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let r = retained
            .disposition
            .as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if floor.request().owner_id != readback.attempt()
            || floor.request().future_transactions != if phase == 10 { 3 } else { 2 }
            || floor.original_prepared() != root1.prepared()
            || floor.admission_cut() != sidecar.admission_cut()
            || unsigned.kind() != Kind::RootClosed
            || unsigned.scope() != sidecar.original_scope()
            || unsigned.scope().original_source_session != self.session.binding()
            || unsigned.predecessor() != root1.digest()
            || unsigned.signer() != root1.prepared().signer()
            || unsigned.sections().len() != 3
            || unsigned.section(Tag::RootPrepared) != Some(root1.to_canonical_bytes().as_slice())
            || unsigned.section(Tag::RootDispositionAssertion)
                != Some(
                    r.to_canonical_bytes()
                        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
                        .as_slice(),
                )
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }

        let NativeHeldOwnerWitnessV1::Root(witness) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
            NativeHeldOwnerV1::Root,
            unsigned
                .section(Tag::Witness)
                .ok_or(SourceProviderSecurityError::SessionContinuity)?,
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        else {
            return Err(SourceProviderSecurityError::SessionContinuity);
        };
        let sequence = if phase == 10 {
            readback.sequence()
        } else {
            witness.journal_sequence
        };
        let expected = NativeHeldOwnerWitnessV1::Root(
            retained
                .original
                .original_root_witness(captured.witnesses().clone(), sequence),
        )
        .to_canonical_bytes()
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        if unsigned.section(Tag::Witness) != Some(expected.as_slice()) {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }

        let exact_suffix = match phase {
            10 => {
                sidecar.suffix().prepared() == Some(unsigned)
                    && sidecar.suffix().controls().len() == 1
            }
            11 => {
                sidecar.suffix().prepared().is_none()
                    && sidecar.suffix().controls().len() == 2
                    && retained.signed_closed().is_some_and(|signed| {
                        signed.prepared() == unsigned
                            && sidecar.suffix().control(Kind::RootClosed) == Some(signed)
                    })
            }
            _ => false,
        };
        if !exact_suffix {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }

        self.require_current_root_mount_record_role_v5(unsigned.signer())?;
        self.revalidate_original_pending_receipt_v5(writer, readback, authorization, retained)
    }

    /// Signs the retained first-R unsigned8 once and parks it before postchecks.
    ///
    /// # Errors
    ///
    /// Rejects another signature attempt or anything except the current actual
    /// Pending phase10 endpoint. Any produced signature stays on the token even
    /// when the post-sign checks fail or the caller loses the return value.
    #[doc(hidden)]
    pub fn sign_original_root_closed_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase10: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        let result = (|| {
            self.revalidate_original_root_closed_v5(writer, phase10, authorization, retained)?;
            if phase10
                .graph()
                .sidecars()
                .get(&phase10.attempt())
                .is_none_or(|sidecar| sidecar.suffix().phase() != 10)
            {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            let unsigned = retained
                .unsigned_closed()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?
                .clone();

            // A lost return cannot restore Unattempted or lose signed custody.
            retained.closed.arm_signature()?;
            let signature = self
                .custody
                .inner()
                .outcome_key()
                .signing_key()
                .sign(&unsigned.signature_message())
                .to_bytes();
            retained.closed.signature = SignatureState::Signed(unsigned.with_signature(signature));

            self.revalidate_original_root_closed_v5(writer, phase10, authorization, retained)
        })();

        if let Err(error) = result {
            retained.failed.set(true);
            return Err(self.poison(error));
        }

        Ok(())
    }

    /// Sends exact stored original8 with zero FDs on the same original carrier.
    ///
    /// Returns false only for bounded transport retry. Repeating a completed
    /// local send rechecks custody without retransmitting the frame.
    ///
    /// # Errors
    ///
    /// Latches hot effects closed on currentness or fatal I/O failure. Attempted
    /// send debt and exact signed bytes remain on the actual received token,
    /// including after successful I/O followed by a failing postcheck.
    #[doc(hidden)]
    pub fn send_original_root_closed_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase11: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<bool, SourceProviderSecurityError> {
        let result = (|| {
            self.revalidate_original_root_closed_v5(writer, phase11, authorization, retained)?;
            if phase11
                .graph()
                .sidecars()
                .get(&phase11.attempt())
                .is_none_or(|sidecar| sidecar.suffix().phase() != 11)
            {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            if retained.closed.send == SendState::Sent {
                return Ok(true);
            }

            let bytes = retained
                .signed_closed()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?
                .to_canonical_bytes();

            retained.closed.arm_send()?;
            let sent = match self.carrier.send(&bytes) {
                Ok(()) => true,
                Err(CarrierFailureV1::Retryable) => {
                    retained.closed.send = SendState::Retryable;
                    false
                }
                Err(CarrierFailureV1::Fatal(error)) => return Err(error),
            };
            self.revalidate_original_root_closed_v5(writer, phase11, authorization, retained)?;
            if sent {
                retained.closed.send = SendState::Sent;
            }
            Ok(sent)
        })();

        if let Err(error) = result {
            retained.failed.set(true);
            return Err(self.poison(error));
        }

        result
    }
}

fn require_current_companions(
    graph: &RootNativeHeldGraphV2,
    captured: &RootNativeReconstructedCutV1,
) -> Result<(), SourceProviderSecurityError> {
    if captured.canonical_records().len() != 4
        || captured
            .canonical_records()
            .iter()
            .any(|(key, bytes)| graph.canonical_records().get(key) != Some(bytes))
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }

    Ok(())
}

#[cfg(test)]
mod tests;
