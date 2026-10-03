//! Once-only local transmission from the original hot Held reservoir.
//!
//! Whole native results and paired samples remain owned through every bookend.
//! A local send is not Root receipt, acceptance, settlement or drain.

use super::*;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_source_provider_protocol::native_held_completion::MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1;
use aos_sandbox_source_provider_ledger::ledger::{
    format::decode_record,
    model::{AcquisitionRecordV1, DecodedRecordV1, ProviderAttemptStateV1},
    native_completion::{NativeAcquireCompletionRecordV2, validate_native_complete_export_v1},
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum DeliveryStageV5 {
    Unstarted,
    SendHeld,
    AttemptingHeld,
    SendComplete,
    AttemptingComplete,
    CompleteSent,
    Closed,
}

#[derive(Clone, Copy)]
enum FirstDeliveryFailureV5 {
    Validation,
    Native(usize),
    Sample(usize),
}

pub(super) struct OriginalHeldDeliveryV5 {
    stage: DeliveryStageV5,
    packet: Option<Vec<u8>>,
    sends: [Option<Result<(), SeqpacketError>>; 2],
    samples: [Option<Result<RawPairedClockSample, SourceProviderSecurityError>>; 4],
    first: Option<FirstDeliveryFailureV5>,
    cause: Option<OriginalHeldCauseV5>,
    postcheck_debt: Option<OriginalHeldCauseV5>,
}

impl OriginalHeldDeliveryV5 {
    pub(super) fn pending() -> Self {
        Self {
            stage: DeliveryStageV5::Unstarted,
            packet: None,
            sends: std::array::from_fn(|_| None),
            samples: std::array::from_fn(|_| None),
            first: None,
            cause: None,
            postcheck_debt: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let original: Option<&(dyn std::error::Error + 'static)> = match self.first {
            Some(FirstDeliveryFailureV5::Validation) => self.cause.as_ref().map(|cause| cause as _),
            Some(FirstDeliveryFailureV5::Native(index)) => self.sends[index].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(FirstDeliveryFailureV5::Sample(index)) => self.samples[index].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            None => None,
        };
        original.or_else(|| self.postcheck_debt.as_ref().map(|cause| cause as _))
    }

    fn retain_action_failure(&mut self, cause: OriginalHeldCauseV5) {
        if self.first.is_none() {
            self.cause = Some(cause);
            self.first = Some(FirstDeliveryFailureV5::Validation);
        }
    }

    fn begin_packet(&mut self) -> Option<usize> {
        let (index, attempted) = match self.stage {
            DeliveryStageV5::SendHeld => (0, DeliveryStageV5::AttemptingHeld),
            DeliveryStageV5::SendComplete => (1, DeliveryStageV5::AttemptingComplete),
            _ => return None,
        };
        self.stage = attempted;
        Some(index)
    }

    fn sample(
        &mut self,
        index: usize,
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
    ) -> Result<(), OriginalHeldCauseV5> {
        self.samples[index] = Some(super::super::super::original_kernel_clock());
        let Some(Ok(later)) = &self.samples[index] else {
            if self.first.is_none() {
                self.first = Some(FirstDeliveryFailureV5::Sample(index));
            }
            // Only this marker returns; the native cause stays in its fixed slot.
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

impl OriginalProviderHeldSignaturesV5 {
    /// Observes whether the original negative-retention delivery epoch began.
    #[must_use]
    pub fn delivery_started(&self) -> bool {
        self.delivery.stage != DeliveryStageV5::Unstarted
    }

    /// Observes local ProviderHeld transmission, not remote receipt or acceptance.
    #[must_use]
    pub fn provider_held_sent(&self) -> bool {
        matches!(self.delivery.sends[0], Some(Ok(())))
            && matches!(
                self.delivery.stage,
                DeliveryStageV5::SendComplete | DeliveryStageV5::CompleteSent,
            )
            && self.failure().is_none()
    }

    /// Observes local Complete-plus-SourceRoot transmission after bookends.
    #[must_use]
    pub fn delivery_complete(&self) -> bool {
        self.delivery.stage == DeliveryStageV5::CompleteSent && self.failure().is_none()
    }
}

impl CurrentProviderIngressSessionV1 {
    /// Arms the SAME original carrier before the next delivery gate.
    ///
    /// Reentry closes this epoch. Neither signed DATA nor another reservoir
    /// can recreate a consumed Session's signing or delivery purpose.
    #[doc(hidden)]
    pub fn begin_original_held_delivery_v5(
        &mut self,
        signatures: &mut OriginalProviderHeldSignaturesV5,
    ) {
        self.carrier.begin_original_delivery_retention_v5();
        if signatures.delivery.stage == DeliveryStageV5::Unstarted
            && signatures.usable
            && signatures.attempted
            && signatures.signed.is_some()
            && signatures.failure().is_none()
            && self.failure_disposition == CurrentSessionFailureDispositionV5::OriginalHeldEnded
        {
            signatures.delivery.stage = DeliveryStageV5::SendHeld;
        } else {
            signatures.delivery.retain_action_failure(
                SourceProviderSecurityError::SessionContinuity.into(),
            );
            signatures.delivery.stage = DeliveryStageV5::Closed;
            self.close_original_held_after_failure_v5();
        }
    }

    /// Advances one exact packet from genuine phase6 readback and original custody.
    ///
    /// The two whole send results are parked before postchecks. Every error,
    /// including Interrupted or WouldBlock, permanently ends this epoch. This
    /// reports local transmission only and never authenticates a Root ACK.
    #[doc(hidden)]
    pub fn advance_original_held_delivery_v5(
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
        complete: &[u8],
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
        signatures: &mut OriginalProviderHeldSignaturesV5,
    ) -> bool {
        if signatures.delivery.stage == DeliveryStageV5::CompleteSent
            && signatures.failure().is_none()
        {
            return true;
        }
        // Prearm before any basis, codec, clock or descriptor observation.
        let Some(index) = signatures.delivery.begin_packet() else {
            signatures.delivery.retain_action_failure(
                SourceProviderSecurityError::SessionContinuity.into(),
            );
            signatures.delivery.stage = DeliveryStageV5::Closed;
            self.close_original_held_after_failure_v5();
            return false;
        };
        let signed = signatures.signed.as_ref();
        let delivery = &mut signatures.delivery;
        let action = (|| {
            let signed = signed.ok_or(SourceProviderSecurityError::SessionContinuity)?;
            self.require_original_held_bindings_v5(
                journal, readback, root, acquire, physical, lease, archive, selected,
                storage, OriginalHeldBindingPurposeV5::Delivery(signed, complete), initial, deadline, validity,
            )?;
            if index == 0 {
                delivery.packet = Some(signed.to_canonical_bytes());
                if delivery.packet.as_ref().is_none_or(|packet| {
                    packet.len() > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1
                })
                {
                    return Err(SourceProviderSecurityError::SessionContinuity.into());
                }
            }
            // The original paired sample is last, after all potentially slow checks.
            delivery.sample(index * 2, initial, deadline, validity)?;
            let result = if index == 0 {
                self.carrier.send_original_held_retaining_v5(
                    delivery.packet.as_deref().ok_or(SourceProviderSecurityError::SessionContinuity)?,
                )
            } else {
                self.carrier.send_original_complete_retaining_v5(complete, physical.descriptor())
            };
            delivery.sends[index] = Some(result);
            if delivery.sends[index].as_ref().is_some_and(Result::is_err)
                && delivery.first.is_none()
            {
                delivery.first = Some(FirstDeliveryFailureV5::Native(index));
            }
            Ok::<_, OriginalHeldCauseV5>(())
        })();
        if let Err(cause) = action {
            delivery.retain_action_failure(cause);
        }

        // Even native failure is followed by bookends; it is never replaced by them.
        let postcheck = (|| {
            let signed = signed.ok_or(SourceProviderSecurityError::SessionContinuity)?;
            self.require_original_held_bindings_v5(
                journal, readback, root, acquire, physical, lease, archive, selected,
                storage, OriginalHeldBindingPurposeV5::Delivery(signed, complete), initial, deadline, validity,
            )?;
            delivery.sample(index * 2 + 1, initial, deadline, validity)
        })();
        if let Err(cause) = postcheck {
            if delivery.postcheck_debt.is_none() {
                delivery.postcheck_debt = Some(cause);
            }
        }
        if delivery.failure().is_some() || !matches!(delivery.sends[index], Some(Ok(()))) {
            delivery.stage = DeliveryStageV5::Closed;
            self.close_original_held_after_failure_v5();
            false
        } else {
            delivery.stage = if index == 0 {
                DeliveryStageV5::SendComplete
            } else {
                DeliveryStageV5::CompleteSent
            };
            true
        }
    }
}

// This is a comparison over the genuine protected current cut, not a cold
// artifact exporter or a new CommittedProviderOutcome constructor.
pub(super) fn require_original_complete_delivery_v5(
    readback: &OriginalSourceProtectedReadbackV5,
    attempt_key: &[u8],
    acquisition: &AcquisitionRecordV1,
    native: &NativeAcquireCompletionRecordV2,
    acquire: &CurrentProviderRequestV1,
    physical: &crate::ProviderSourceRootHandoffV1,
    complete: &[u8],
) -> Result<(), OriginalHeldCauseV5> {
    let aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(verified)
        = acquire.verified() else {
        return Err(SourceProviderSecurityError::SessionContinuity.into());
    };
    let bytes = readback.rows().get(&(
        aos_sandbox::RecordNamespace::SourceProviderAuthority, attempt_key.to_vec(),
    ))
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let DecodedRecordV1::Attempt(attempt) = decode_record(attempt_key, bytes)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)? else {
        return Err(SourceProviderSecurityError::SessionContinuity.into());
    };
    validate_native_complete_export_v1(acquisition, Some(native), &attempt)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    let identity = validate_send_response_with_source_root(
        SourceProviderMethod::Acquire, complete, Some(physical),
    )?;
    if complete.len() > MAXIMUM_FRAME_BYTES
        || attempt.state != ProviderAttemptStateV1::Completed
        || attempt.method != SourceProviderMethod::Acquire
        || attempt.status != Some(SourceProviderStatus::Complete)
        || attempt.completed_response != complete
        || attempt.response_digest != Some(aos_sandbox_source_provider_protocol::
            provider_response_artifact_digest_v1(SourceProviderMethod::Acquire, complete))
        || identity.0 != attempt.session_binding
        || identity.0 != verified.ingress_projection().session_binding()
        || Some(identity.1) != attempt.response_sequence
        || attempt.signed_request_digest != verified.attempt().signed_request_digest()
        || attempt.request_id != verified.request().request_id()
    {
        return Err(SourceProviderSecurityError::SessionContinuity.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! UNRUN pure retention mechanics, not synthetic Session/send positives.

    use super::*;

    #[test]
    fn empty_delivery_has_no_packet_result_or_success() {
        let delivery = OriginalHeldDeliveryV5::pending();

        assert!(delivery.stage == DeliveryStageV5::Unstarted);
        assert!(delivery.packet.is_none());
        assert!(delivery.sends.iter().all(Option::is_none));
        assert!(delivery.failure().is_none());
    }

    #[test]
    fn native_first_cause_is_borrowed_from_the_original_slot() {
        let mut delivery = OriginalHeldDeliveryV5::pending();
        delivery.sends[0] = Some(Err(SeqpacketError::Interrupted));
        delivery.first = Some(FirstDeliveryFailureV5::Native(0));
        delivery.postcheck_debt = Some(SourceProviderSecurityError::SessionContinuity.into());

        assert!(matches!(
            delivery.failure().and_then(|cause| cause.downcast_ref::<SeqpacketError>()),
            Some(SeqpacketError::Interrupted),
        ));
        assert!(delivery.postcheck_debt.is_some());
    }

    #[test]
    fn each_packet_prearms_once_before_any_fallible_work() {
        let mut delivery = OriginalHeldDeliveryV5::pending();

        assert_eq!(delivery.begin_packet(), None);
        delivery.stage = DeliveryStageV5::SendHeld;
        assert_eq!(delivery.begin_packet(), Some(0));
        assert!(delivery.stage == DeliveryStageV5::AttemptingHeld);
        assert_eq!(delivery.begin_packet(), None);

        delivery.stage = DeliveryStageV5::SendComplete;
        assert_eq!(delivery.begin_packet(), Some(1));
        assert!(delivery.stage == DeliveryStageV5::AttemptingComplete);
        assert_eq!(delivery.begin_packet(), None);
    }
}
