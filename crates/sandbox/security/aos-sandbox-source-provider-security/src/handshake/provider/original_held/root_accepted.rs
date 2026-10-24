//! Retained Root4 receipt on the same successful Held/Complete Session.
//!
//! One resident child owns raw record, execution, typed native/codec causes and
//! paired samples. Receipt is DATA only; no signing epoch, ACK or release opens.

use super::*;
use crate::carrier::{
    CarrierFailureV1, OriginalRootAcceptedCarrierFailureV5, RetainedSourceProviderRecordV5,
};
use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldCompletionErrorV1;

#[derive(Clone, Copy, Eq, PartialEq)]
enum RootReceiptStageV5 {
    Unstarted,
    Receiving,
    Attempting,
    Received,
    Closed,
}

#[derive(Clone, Copy)]
enum FirstRootReceiptFailureV5 {
    Validation,
    Carrier,
    Decode,
    Sample(usize),
}

pub(super) struct OriginalRootAcceptedV5 {
    stage: RootReceiptStageV5,
    record: Option<RetainedSourceProviderRecordV5>,
    carrier_failure: Option<OriginalRootAcceptedCarrierFailureV5>,
    decoded: Option<Result<SignedNativeHeldControlV1, NativeHeldCompletionErrorV1>>,
    samples: [Option<Result<RawPairedClockSample, SourceProviderSecurityError>>; 2],
    first: Option<FirstRootReceiptFailureV5>,
    cause: Option<OriginalHeldCauseV5>,
    postcheck_debt: Option<OriginalHeldCauseV5>,
}

impl OriginalRootAcceptedV5 {
    pub(super) fn pending() -> Self {
        Self {
            stage: RootReceiptStageV5::Unstarted,
            record: None,
            carrier_failure: None,
            decoded: None,
            samples: std::array::from_fn(|_| None),
            first: None,
            cause: None,
            postcheck_debt: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let first: Option<&(dyn std::error::Error + 'static)> = match self.first {
            Some(FirstRootReceiptFailureV5::Validation) => self.cause.as_ref().map(|cause| cause as _),
            Some(FirstRootReceiptFailureV5::Carrier) => self.carrier_failure.as_ref().map(|cause| cause as _),
            Some(FirstRootReceiptFailureV5::Decode) => self.decoded.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(FirstRootReceiptFailureV5::Sample(index)) => self.samples[index].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            None => None,
        };
        first.or_else(|| self.postcheck_debt.as_ref().map(|cause| cause as _))
    }

    fn retain_failure(&mut self, cause: OriginalHeldCauseV5) {
        if self.first.is_none() {
            self.cause = Some(cause);
            self.first = Some(FirstRootReceiptFailureV5::Validation);
        }
    }

    pub(super) fn control(&self) -> Option<&SignedNativeHeldControlV1> {
        self.decoded.as_ref().and_then(|result| result.as_ref().ok())
    }

    /// Rechecks the original authenticated Root4 record without opening a cut.
    ///
    /// # Errors
    ///
    /// Refuses missing, failed or unreceived custody and stale record execution.
    pub(super) fn revalidate_execution(
        &self,
        peer: &aos_sandbox_linux::seqpacket::ConnectionPeerIdentity,
    ) -> Result<(), SourceProviderSecurityError> {
        if self.failure().is_some() || self.stage != RootReceiptStageV5::Received {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let record = self.record.as_ref().and_then(RetainedSourceProviderRecordV5::bound)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        record.execution.revalidate(peer)
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
                self.first = Some(FirstRootReceiptFailureV5::Sample(index));
            }
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        validate_original_held_clock_sample_v5(initial, *later, deadline, validity)
    }
}

// A caught unwind cannot revive the receive purpose. This guard closes the same
// endpoint before the original packet, FD, execution or cause can be destroyed.
struct RootReceiptBoundaryV5<'owner> {
    session: &'owner mut CurrentProviderIngressSessionV1,
    signatures: &'owner mut OriginalProviderHeldSignaturesV5,
    completed: bool,
}

impl Drop for RootReceiptBoundaryV5<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.signatures.root_accepted.stage = RootReceiptStageV5::Closed;
            self.session.close_original_held_after_failure_v5();
        }
    }
}

impl OriginalProviderHeldSignaturesV5 {
    /// Borrows authenticated Root4 DATA while its original child has no debt.
    ///
    /// This borrow grants no append, relay signing, acknowledgement or release.
    #[must_use]
    pub fn root_accepted(&self) -> Option<&SignedNativeHeldControlV1> {
        if self.failure().is_some() || self.root_accepted.stage != RootReceiptStageV5::Received {
            None
        } else {
            self.root_accepted.control()
        }
    }
}

impl CurrentProviderIngressSessionV1 {
    /// Arms one Root4 child only after this same reservoir sent Complete.
    ///
    /// OriginalHeldEnded remains the consumed signing disposition. This does
    /// not reset it or turn a negative endpoint end into a fresh receive epoch.
    #[doc(hidden)]
    pub fn begin_original_root_disposition_v5(
        &mut self,
        signatures: &mut OriginalProviderHeldSignaturesV5,
    ) -> bool {
        if signatures.root_accepted.stage == RootReceiptStageV5::Unstarted
            && signatures.delivery_complete()
            && self.failure_disposition == CurrentSessionFailureDispositionV5::OriginalHeldEnded
        {
            signatures.root_accepted.stage = RootReceiptStageV5::Receiving;
            true
        } else {
            signatures.root_accepted.retain_failure(SourceProviderSecurityError::SessionContinuity.into());
            signatures.root_accepted.stage = RootReceiptStageV5::Closed;
            self.close_original_held_after_failure_v5();
            false
        }
    }

    /// Receives and authenticates Root4 with the actual phase6 and original cut.
    ///
    /// Native errors and unexpected descriptors remain resident before every
    /// upper check. Proven nonconsuming backpressure alone may await a later turn.
    #[doc(hidden)]
    pub fn receive_original_root_accepted_v5(
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
        if signatures.failure().is_some()
            || !matches!(signatures.root_accepted.stage, RootReceiptStageV5::Receiving | RootReceiptStageV5::Received)
        {
            signatures.root_accepted.retain_failure(SourceProviderSecurityError::SessionContinuity.into());
            signatures.root_accepted.stage = RootReceiptStageV5::Closed;
            self.close_original_held_after_failure_v5();
            return false;
        }
        let received_before = signatures.root_accepted.stage == RootReceiptStageV5::Received;
        signatures.root_accepted.stage = RootReceiptStageV5::Attempting;
        let mut boundary = RootReceiptBoundaryV5 { session: self, signatures, completed: false };
        let signed = boundary.signatures.signed.as_ref();
        let child = &mut boundary.signatures.root_accepted;

        let action = (|| {
            let signed = signed.ok_or(SourceProviderSecurityError::SessionContinuity)?;
            boundary.session.require_original_held_bindings_v5(
                journal, readback, root, acquire, physical, lease, archive, selected,
                storage, OriginalHeldBindingPurposeV5::Delivery(signed, complete), initial, deadline, validity,
            )?;
            child.sample(0, initial, deadline, validity)?;
            if !received_before {
                let received = boundary.session.carrier.receive_original_root_accepted_retaining_v5(
                    &mut child.record, &mut child.carrier_failure,
                );
                if child.carrier_failure.is_some() && child.first.is_none() {
                    child.first = Some(FirstRootReceiptFailureV5::Carrier);
                }
                match received {
                    Ok(false) | Err(CarrierFailureV1::Retryable) => return Ok(false),
                    Err(CarrierFailureV1::Fatal(cause)) => return Err(cause.into()),
                    Ok(true) => {}
                }
                let record = child.record.as_ref().and_then(RetainedSourceProviderRecordV5::bound)
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                record.execution.revalidate(boundary.session.carrier.socket().peer())?;
                if !record.descriptors.is_empty()
                    || !record.execution.has_same_execution(&boundary.session.root_mount_execution)
                {
                    return Err(SourceProviderSecurityError::SessionContinuity.into());
                }
                child.decoded = Some(SignedNativeHeldControlV1::from_canonical_bytes(&record.payload));
                if child.decoded.as_ref().is_some_and(Result::is_err) {
                    if child.first.is_none() {
                        child.first = Some(FirstRootReceiptFailureV5::Decode);
                    }
                    return Err(SourceProviderSecurityError::SessionContinuity.into());
                }
            }
            let root4 = child.control().ok_or(SourceProviderSecurityError::SessionContinuity)?;
            boundary.session.require_original_held_bindings_v5(
                journal, readback, root, acquire, physical, lease, archive, selected,
                storage, OriginalHeldBindingPurposeV5::RootReceived(signed, complete, root4), initial, deadline, validity,
            )?;
            Ok::<_, OriginalHeldCauseV5>(true)
        })();
        let received = match action {
            Ok(received) => received,
            Err(cause) => {
                child.retain_failure(cause);
                false
            }
        };

        let postcheck = (|| {
            let signed = signed.ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let purpose = match child.control() {
                Some(root4) => OriginalHeldBindingPurposeV5::RootReceived(signed, complete, root4),
                None => OriginalHeldBindingPurposeV5::Delivery(signed, complete),
            };
            boundary.session.require_original_held_bindings_v5(
                journal, readback, root, acquire, physical, lease, archive, selected,
                storage, purpose, initial, deadline, validity,
            )?;
            if let Some(record) = child.record.as_ref().and_then(RetainedSourceProviderRecordV5::bound) {
                record.execution.revalidate(boundary.session.carrier.socket().peer())?;
            }
            child.sample(1, initial, deadline, validity)
        })();
        if let Err(cause) = postcheck {
            if child.postcheck_debt.is_none() {
                child.postcheck_debt = Some(cause);
            }
        }
        if child.failure().is_some() {
            return false;
        }
        if received {
            child.stage = RootReceiptStageV5::Received;
        } else {
            // Only the engine's nonterminal nonconsuming outcome reaches here.
            boundary.session.carrier.finish_original_receive_backpressure_v5();
            child.stage = RootReceiptStageV5::Receiving;
        }
        boundary.completed = true;
        received
    }

    /// Rechecks the actual retained receipt against the same-writer phase7 cut.
    ///
    /// This performs no receive, signing or relay send and never changes D.
    #[doc(hidden)]
    pub fn revalidate_original_root_disposition_v5(
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
        relay: &PreparedNativeHeldControlV1,
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
        signatures: &mut OriginalProviderHeldSignaturesV5,
    ) -> bool {
        if signatures.failure().is_some() || signatures.root_accepted.stage != RootReceiptStageV5::Received {
            signatures.root_accepted.retain_failure(SourceProviderSecurityError::SessionContinuity.into());
            signatures.root_accepted.stage = RootReceiptStageV5::Closed;
            self.close_original_held_after_failure_v5();
            return false;
        }
        signatures.root_accepted.stage = RootReceiptStageV5::Attempting;
        let mut boundary = RootReceiptBoundaryV5 { session: self, signatures, completed: false };
        let signed = boundary.signatures.signed.as_ref();
        let child = &mut boundary.signatures.root_accepted;
        let action = (|| {
            let signed = signed.ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let root4 = child.control().ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let record = child.record.as_ref().and_then(RetainedSourceProviderRecordV5::bound)
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            record.execution.revalidate(boundary.session.carrier.socket().peer())?;
            boundary.session.require_original_held_bindings_v5(
                journal, readback, root, acquire, physical, lease, archive, selected,
                storage, OriginalHeldBindingPurposeV5::RootDisposition(signed, complete, root4, relay), initial, deadline, validity,
            )?;
            child.sample(0, initial, deadline, validity)
        })();
        if let Err(cause) = action {
            child.retain_failure(cause);
        }
        let postcheck = (|| {
            let signed = signed.ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let root4 = child.control().ok_or(SourceProviderSecurityError::SessionContinuity)?;
            boundary.session.require_original_held_bindings_v5(
                journal, readback, root, acquire, physical, lease, archive, selected,
                storage, OriginalHeldBindingPurposeV5::RootDisposition(signed, complete, root4, relay), initial, deadline, validity,
            )?;
            let record = child.record.as_ref().and_then(RetainedSourceProviderRecordV5::bound)
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            record.execution.revalidate(boundary.session.carrier.socket().peer())?;
            child.sample(1, initial, deadline, validity)
        })();
        if let Err(cause) = postcheck {
            if child.postcheck_debt.is_none() {
                child.postcheck_debt = Some(cause);
            }
        }
        if child.failure().is_some() {
            false
        } else {
            child.stage = RootReceiptStageV5::Received;
            boundary.completed = true;
            true
        }
    }
}
