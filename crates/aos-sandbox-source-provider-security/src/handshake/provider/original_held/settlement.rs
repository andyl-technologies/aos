//! Storage6 admission and once-only ProviderSettled7 on the original Session.
//!
//! Raw receive, canonical DATA, signature, send and postcheck debt are distinct
//! resident slots. Neither receipt nor local dispatch proves retirement/drain.

use super::*;
use aos_sandbox_source_provider_ledger::ledger::native_held_completion::SourceNativeHeldStepV1;
use aos_sandbox_linux::seqpacket::SeqpacketError;

#[derive(Clone, Copy, Eq, PartialEq)]
enum SettlementStageV5 {
    Unstarted,
    Ready,
    Checking,
    Received,
    Signed,
    Sent,
    Closed,
}

#[derive(Clone, Copy)]
enum SettlementFailureV5 {
    Validation,
    Control,
    Sample(usize),
    Storage,
    Send,
    Postcheck(usize),
}

pub(super) struct OriginalProviderSettlementV5 {
    stage: SettlementStageV5,
    attempted: bool,
    control: Option<Result<SignedNativeHeldControlV1, aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldCompletionErrorV1>>,
    prepared: Option<PreparedNativeHeldControlV1>,
    message: Option<Vec<u8>>,
    detached: Option<[u8; 64]>,
    signed: Option<SignedNativeHeldControlV1>,
    packet: Option<Vec<u8>>,
    send: Option<Result<(), SeqpacketError>>,
    samples: [Option<Result<RawPairedClockSample, SourceProviderSecurityError>>; 2],
    first: Option<SettlementFailureV5>,
    cause: Option<OriginalHeldCauseV5>,
    postchecks: [Option<Result<(), OriginalHeldCauseV5>>; 3],
}

impl OriginalProviderSettlementV5 {
    pub(super) fn pending() -> Self {
        Self {
            stage: SettlementStageV5::Unstarted,
            attempted: false,
            control: None,
            prepared: None,
            message: None,
            detached: None,
            signed: None,
            packet: None,
            send: None,
            samples: std::array::from_fn(|_| None),
            first: None,
            cause: None,
            postchecks: std::array::from_fn(|_| None),
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first {
            Some(SettlementFailureV5::Validation) => self.cause.as_ref().map(|cause| cause as _),
            Some(SettlementFailureV5::Control) => self.control.as_ref()?.as_ref().err().map(|cause| cause as _),
            Some(SettlementFailureV5::Sample(index)) => self.samples[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            // Resolved by the containing owner through the SAME Storage child.
            Some(SettlementFailureV5::Storage) => None,
            Some(SettlementFailureV5::Send) => self.send.as_ref()?.as_ref().err().map(|cause| cause as _),
            Some(SettlementFailureV5::Postcheck(index)) => self.postchecks[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            None => None,
        }
    }

    fn failed(&self) -> bool { self.first.is_some() }

    fn retain(&mut self, cause: OriginalHeldCauseV5) {
        if self.first.is_none() {
            self.cause = Some(cause);
            self.first = Some(SettlementFailureV5::Validation);
        }
    }

    fn postcheck(&mut self, index: usize, result: Result<(), OriginalHeldCauseV5>) {
        self.postchecks[index] = Some(result);
        if self.first.is_none() && self.postchecks[index].as_ref().is_some_and(Result::is_err) {
            self.first = Some(SettlementFailureV5::Postcheck(index));
        }
    }

    fn sample(&mut self, index: usize, initial: RawPairedClockSample, deadline: u64, validity: (i64, i64)) -> Result<(), OriginalHeldCauseV5> {
        self.samples[index] = Some(super::super::super::original_kernel_clock());
        let Some(Ok(later)) = &self.samples[index] else {
            if self.first.is_none() { self.first = Some(SettlementFailureV5::Sample(index)); }
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        validate_original_held_clock_sample_v5(initial, *later, deadline, validity)
    }

    /// Lends only the two actual prior controls to the distinct terminal child.
    ///
    /// This fixed disjoint loan cannot reset settlement or extract its owners.
    pub(super) fn root_terminal_controls_v5(
        &self,
    ) -> Option<(&SignedNativeHeldControlV1, &SignedNativeHeldControlV1)> {
        if self.failed() || self.stage != SettlementStageV5::Sent {
            return None;
        }
        Some((self.control.as_ref()?.as_ref().ok()?, self.signed.as_ref()?))
    }

    fn storage6(&self) -> Result<&SignedNativeHeldControlV1, OriginalHeldCauseV5> {
        self.control.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| SourceProviderSecurityError::SessionContinuity.into())
    }

    fn purpose<'a>(&'a self, crossing: SettlementCrossingV5<'a>, held3: &'a SignedNativeHeldControlV1,
        root4: &'a SignedNativeHeldControlV1, relay5: &'a SignedNativeHeldControlV1, complete: &'a [u8],
    ) -> Result<OriginalHeldBindingPurposeV5<'a>, OriginalHeldCauseV5> {
        Ok(match crossing {
            SettlementCrossingV5::Receive | SettlementCrossingV5::Receiving => OriginalHeldBindingPurposeV5::RelayDelivery(held3, complete, root4, relay5),
            SettlementCrossingV5::Received => OriginalHeldBindingPurposeV5::SettlementReceived(held3, complete, root4, relay5, self.storage6()?),
            SettlementCrossingV5::Sign(prepared) => OriginalHeldBindingPurposeV5::SettlementPreparation(held3, complete, root4, relay5, self.storage6()?, prepared),
            SettlementCrossingV5::Preparation(prepared) => OriginalHeldBindingPurposeV5::SettlementPreparation(held3, complete, root4, relay5, self.storage6()?, prepared),
            SettlementCrossingV5::Delivery | SettlementCrossingV5::Send => OriginalHeldBindingPurposeV5::SettlementDelivery(held3, complete, root4, relay5, self.storage6()?,
                self.signed.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?),
        })
    }

    fn verify_storage6(&self, selected: &crate::ProtectedOriginalSelectedInputV1, relay5: &SignedNativeHeldControlV1) -> Result<(), OriginalHeldCauseV5> {
        use aos_sandbox_source_provider_protocol::storage_zfs_hold_receipt::{
            STORAGE_ZFS_HOLD_ENROLLMENT_BYTES_V1, decode_storage_zfs_hold_enrollment_v1,
        };
        let exact = self.storage6()?;
        let bytes: &[u8; STORAGE_ZFS_HOLD_ENROLLMENT_BYTES_V1] = selected.dedicated_enrollment().try_into()
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let verifier = decode_storage_zfs_hold_enrollment_v1(bytes)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let (signer, key) = verifier.projection();
        exact.verify_signature_claim(&NativeHeldSignerV1::Storage(signer), &key)?;
        if exact.kind() != Kind::StorageSettled || exact.scope() != relay5.scope()
            || exact.prepared().predecessor() != relay5.digest() {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        // The sole native proposer additionally compares the actual acceptance
        // and Root4 settlement tuple before any protected append.
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum SettlementCrossingV5<'a> {
    Receive,
    Receiving,
    Received,
    Sign(&'a PreparedNativeHeldControlV1),
    Preparation(&'a PreparedNativeHeldControlV1),
    Delivery,
    Send,
}

struct SettlementBoundaryV5<'a> {
    session: &'a mut CurrentProviderIngressSessionV1,
    signatures: &'a mut OriginalProviderHeldSignaturesV5,
    completed: bool,
}

impl Drop for SettlementBoundaryV5<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.signatures.settlement.stage = SettlementStageV5::Closed;
            self.session.close_original_held_after_failure_v5();
        }
    }
}

impl OriginalProviderHeldSignaturesV5 {
    /// Borrows authenticated Storage6 DATA after the original receive bookends.
    #[must_use]
    pub fn original_storage_settlement_v5(&self) -> Option<&SignedNativeHeldControlV1> {
        if self.settlement.failed() { return None; }
        self.settlement.control.as_ref()?.as_ref().ok()
    }

    /// Borrows signed7 DATA without turning it into a currentness permit.
    #[must_use]
    pub fn original_provider_settlement_v5(&self) -> Option<&SignedNativeHeldControlV1> {
        if self.settlement.failed() { return None; }
        self.settlement.signed.as_ref()
    }

    /// Observes local dispatch only, not Root receipt or physical drain.
    #[must_use]
    pub fn original_settlement_sent_v5(&self) -> bool {
        !self.settlement.failed() && self.settlement.stage == SettlementStageV5::Sent
    }

    /// Identifies a first cause that must be borrowed from the original Storage.
    #[must_use]
    #[doc(hidden)]
    pub fn original_settlement_storage_failed_v5(&self) -> bool {
        matches!(self.settlement.first, Some(SettlementFailureV5::Storage))
    }

    /// Borrows the chronological Session cause, leaving Storage resolution to its owner.
    #[must_use]
    #[doc(hidden)]
    pub fn original_settlement_failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.settlement.failure()
    }
}

impl CurrentProviderIngressSessionV1 {
    /// Arms one settlement purpose on the same successfully dispatched relay.
    #[doc(hidden)]
    pub fn begin_original_settlement_v5(&mut self, signatures: &mut OriginalProviderHeldSignaturesV5) -> bool {
        let eligible = signatures.original_relay_sent() && signatures.original_relay().is_some()
            && signatures.root_accepted().is_some() && signatures.delivery_complete()
            && self.failure_disposition == CurrentSessionFailureDispositionV5::OriginalHeldEnded
            && signatures.settlement.stage == SettlementStageV5::Unstarted;
        if !eligible {
            signatures.settlement.retain(SourceProviderSecurityError::SessionContinuity.into());
            signatures.settlement.stage = SettlementStageV5::Closed;
            self.close_original_held_after_failure_v5();
            return false;
        }
        signatures.settlement.stage = SettlementStageV5::Ready;
        true
    }

    /// Receives only Storage6 on the same retained original child.
    ///
    /// Actual action Results are retained before independent execution,
    /// binding and original-clock postchecks, including on action failure.
    #[doc(hidden)]
    pub fn receive_original_settlement_v5(
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
        self.observe_original_settlement_v5(journal, readback, root, acquire, physical, lease, archive, selected,
            storage, complete, initial, deadline, validity, signatures, SettlementCrossingV5::Receive)
    }

    /// Signs Kind7 once after the actual unsigned phase8 readback.
    ///
    /// Actual action Results are retained before independent execution,
    /// binding and original-clock postchecks, including on action failure.
    #[doc(hidden)]
    pub fn sign_original_settlement_v5(
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
        prepared: &PreparedNativeHeldControlV1,
    ) -> bool {
        self.observe_original_settlement_v5(journal, readback, root, acquire, physical, lease, archive, selected,
            storage, complete, initial, deadline, validity, signatures, SettlementCrossingV5::Sign(prepared))
    }

    /// Dispatches Kind7 once after the actual signed phase9 readback.
    ///
    /// Actual action Results are retained before independent execution,
    /// binding and original-clock postchecks, including on action failure.
    #[doc(hidden)]
    pub fn send_original_settlement_v5(
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
        self.observe_original_settlement_v5(journal, readback, root, acquire, physical, lease, archive, selected,
            storage, complete, initial, deadline, validity, signatures, SettlementCrossingV5::Send)
    }

    /// Rechecks only the named actual received, unsigned or signed cut.
    #[doc(hidden)]
    pub fn revalidate_original_settlement_v5(
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
        step: SourceNativeHeldStepV1,
        prepared: Option<&PreparedNativeHeldControlV1>,
    ) -> bool {
        let crossing = match step {
            SourceNativeHeldStepV1::RelayStored => SettlementCrossingV5::Receiving,
            SourceNativeHeldStepV1::StorageSettlementRecorded => SettlementCrossingV5::Received,
            SourceNativeHeldStepV1::ProviderSettledPrepared if prepared.is_some() => {
                let Some(prepared) = prepared else { return false; };
                SettlementCrossingV5::Preparation(prepared)
            }
            SourceNativeHeldStepV1::ProviderSettledStored => SettlementCrossingV5::Delivery,
            _ => {
                signatures.settlement.retain(SourceProviderSecurityError::SessionContinuity.into());
                signatures.settlement.stage = SettlementStageV5::Closed;
                self.close_original_held_after_failure_v5();
                return false;
            }
        };
        self.observe_original_settlement_v5(journal, readback, root, acquire, physical, lease, archive, selected,
            storage, complete, initial, deadline, validity, signatures, crossing)
    }

    fn observe_original_settlement_v5(
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
        crossing: SettlementCrossingV5<'_>,
    ) -> bool {
        let previous = signatures.settlement.stage;
        let signing = matches!(crossing, SettlementCrossingV5::Sign(_));
        let receiving = matches!(crossing, SettlementCrossingV5::Receive | SettlementCrossingV5::Receiving);
        // End the whole-owner eligibility loan before splitting the three
        // immutable prior controls from the new mutable purpose reservoir.
        let available = self.failure_disposition == CurrentSessionFailureDispositionV5::OriginalHeldEnded
            && signatures.root_accepted().is_some() && signatures.delivery_complete()
            && signatures.relay.control().is_some()
            && !signatures.settlement.failed()
            && if signing {
                previous == SettlementStageV5::Received && !signatures.settlement.attempted
            } else if receiving {
                matches!(previous, SettlementStageV5::Ready | SettlementStageV5::Received)
            } else {
                matches!(previous, SettlementStageV5::Received | SettlementStageV5::Signed | SettlementStageV5::Sent)
            };
        if !available {
            signatures.settlement.retain(SourceProviderSecurityError::SessionContinuity.into());
            signatures.settlement.stage = SettlementStageV5::Closed;
            self.close_original_held_after_failure_v5();
            return false;
        }
        if signing { signatures.settlement.attempted = true; }
        signatures.settlement.stage = SettlementStageV5::Checking;
        let mut boundary = SettlementBoundaryV5 { session: self, signatures, completed: false };
        let held3 = boundary.signatures.signed.as_ref();
        let root4 = &boundary.signatures.root_accepted;
        let relay5 = boundary.signatures.relay.control();
        let child = &mut boundary.signatures.settlement;
        let action = (|| -> Result<bool, OriginalHeldCauseV5> {
            if let SettlementCrossingV5::Sign(prepared) = crossing {
                let aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(verified)
                    = acquire.verified() else { return Err(SourceProviderSecurityError::SessionContinuity.into()); };
                journal.claim_original_settlement_signing_v5(readback, verified.request().acquisition_id(),
                    held3.ok_or(SourceProviderSecurityError::SessionContinuity)?,
                    root4.control().ok_or(SourceProviderSecurityError::SessionContinuity)?,
                    relay5.ok_or(SourceProviderSecurityError::SessionContinuity)?, child.storage6()?, prepared)?;
                child.prepared = Some(prepared.clone());
            }
            root4.revalidate_execution(boundary.session.carrier.socket().peer())?;
            boundary.session.require_original_held_bindings_v5(journal, readback, root, acquire, physical, lease, archive, selected,
                storage, child.purpose(crossing, held3.ok_or(SourceProviderSecurityError::SessionContinuity)?,
                    root4.control().ok_or(SourceProviderSecurityError::SessionContinuity)?,
                    relay5.ok_or(SourceProviderSecurityError::SessionContinuity)?, complete)?,
                initial, deadline, validity)?;
            if child.control.is_some() {
                child.verify_storage6(selected, relay5.ok_or(SourceProviderSecurityError::SessionContinuity)?)?;
            }
            if signing {
                child.message = Some(child.prepared.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?.signature_message());
            }
            if matches!(crossing, SettlementCrossingV5::Send) && child.packet.is_none() {
                child.packet = Some(child.signed.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?.to_canonical_bytes());
            }
            child.sample(0, initial, deadline, validity)?;
            match crossing {
                SettlementCrossingV5::Receive => {
                    if child.control.is_some() { return Ok(true); }
                    let received = storage.advance_original_settlement_receive_v5();
                    if storage.failure().is_some() {
                        child.first = Some(SettlementFailureV5::Storage);
                        return Ok(false);
                    }
                    if !received { return Ok(false); }
                    child.control = Some(SignedNativeHeldControlV1::from_canonical_bytes(
                        storage.original_settlement_packet_v5().ok_or(SourceProviderSecurityError::SessionContinuity)?));
                    if child.control.as_ref().is_some_and(Result::is_err) {
                        child.first = Some(SettlementFailureV5::Control);
                        return Ok(false);
                    }
                    child.verify_storage6(selected, relay5.ok_or(SourceProviderSecurityError::SessionContinuity)?)?;
                    Ok(true)
                }
                SettlementCrossingV5::Sign(_) => {
                    child.detached = Some(boundary.session.custody.inner().outcome_key().signing_key()
                        .sign(child.message.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?).to_bytes());
                    if let (Some(prepared), Some(raw)) = (child.prepared.take(), child.detached) {
                        child.signed = Some(prepared.with_signature(raw));
                    }
                    Ok(true)
                }
                SettlementCrossingV5::Send => {
                    if previous == SettlementStageV5::Sent { return Ok(true); }
                    child.send = Some(boundary.session.carrier.send_original_held_retaining_v5(
                        child.packet.as_deref().ok_or(SourceProviderSecurityError::SessionContinuity)?));
                    if child.send.as_ref().is_some_and(Result::is_err) {
                        child.first = Some(SettlementFailureV5::Send);
                        return Ok(false);
                    }
                    Ok(true)
                }
                _ => Ok(true),
            }
        })();
        let progressed = match action {
            Ok(progressed) => progressed,
            Err(cause) => { child.retain(cause); false }
        };

        // Independent postchecks run even after a native receive/sign/send Err.
        // A lower owning cause stays earlier than any later currentness debt.
        child.postcheck(0, root4.revalidate_execution(boundary.session.carrier.socket().peer()).map_err(OriginalHeldCauseV5::from));
        let bindings = (|| {
            boundary.session.require_original_held_bindings_v5(journal, readback, root, acquire, physical, lease, archive, selected,
                storage, child.purpose(crossing, held3.ok_or(SourceProviderSecurityError::SessionContinuity)?,
                    root4.control().ok_or(SourceProviderSecurityError::SessionContinuity)?,
                    relay5.ok_or(SourceProviderSecurityError::SessionContinuity)?, complete)?,
                initial, deadline, validity)?;
            if child.control.is_some() {
                child.verify_storage6(selected, relay5.ok_or(SourceProviderSecurityError::SessionContinuity)?)?;
            }
            Ok(())
        })();
        child.postcheck(1, bindings);
        let clock = child.sample(1, initial, deadline, validity);
        child.postcheck(2, clock);
        if child.failed() { return false; }
        child.stage = match crossing {
            SettlementCrossingV5::Receive if progressed => SettlementStageV5::Received,
            SettlementCrossingV5::Sign(_) => SettlementStageV5::Signed,
            SettlementCrossingV5::Send if progressed => SettlementStageV5::Sent,
            _ => previous,
        };
        boundary.completed = true;
        progressed
    }
}

#[cfg(test)]
mod tests {
    //! UNRUN first-cause DATA only; no genuine Session can be constructed here.

    use super::*;

    #[test]
    fn original_validation_cause_precedes_later_postcheck_debt() {
        let mut child = OriginalProviderSettlementV5::pending();
        child.retain(aos_sandbox::JournalError::InvalidTransaction.into());
        child.postcheck(0, Err(SourceProviderSecurityError::SessionContinuity.into()));

        assert!(matches!(child.failure().and_then(|cause| cause.downcast_ref::<OriginalHeldCauseV5>()),
            Some(OriginalHeldCauseV5::Journal(aos_sandbox::JournalError::InvalidTransaction))));
    }
}
