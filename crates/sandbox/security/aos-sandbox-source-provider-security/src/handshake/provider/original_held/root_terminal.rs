//! Once-only Root13 receipt on the original successfully dispatched Session.
//!
//! The raw record, unexpected rights, execution evidence, canonical Result and
//! paired samples remain resident. Receipt never discharges original custody.

use super::*;
use crate::carrier::{
    CarrierFailureV1, OriginalRootAcceptedCarrierFailureV5, RetainedSourceProviderRecordV5,
};
use aos_sandbox_source_provider_ledger::ledger::native_held_completion::SourceNativeHeldStepV1;
use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldCompletionErrorV1;

#[derive(Clone, Copy, Eq, PartialEq)]
enum TerminalStageV5 {
    Unstarted,
    Ready,
    Checking,
    Received,
    Closed,
}

#[derive(Clone, Copy)]
enum TerminalFailureV5 {
    Native,
    Decode,
    Action,
    NegativeAction,
    Sample(usize),
    Postcheck(usize),
}

pub(super) struct OriginalRootTerminalV5 {
    stage: TerminalStageV5,
    record: Option<RetainedSourceProviderRecordV5>,
    carrier_failure: Option<OriginalRootAcceptedCarrierFailureV5>,
    native: Option<Result<bool, CarrierFailureV1>>,
    negative_observed: bool,
    decoded: Option<Result<SignedNativeHeldControlV1, NativeHeldCompletionErrorV1>>,
    action: Option<Result<bool, OriginalHeldCauseV5>>,
    negative_action: Option<Result<bool, OriginalHeldCauseV5>>,
    samples: [Option<Result<RawPairedClockSample, SourceProviderSecurityError>>; 4],
    postchecks: [Option<Result<(), OriginalHeldCauseV5>>; 8],
    first: Option<TerminalFailureV5>,
    boundary: Option<OriginalHeldCauseV5>,
}

impl OriginalRootTerminalV5 {
    pub(super) fn pending() -> Self {
        Self {
            stage: TerminalStageV5::Unstarted,
            record: None,
            carrier_failure: None,
            native: None,
            negative_observed: false,
            decoded: None,
            action: None,
            negative_action: None,
            samples: std::array::from_fn(|_| None),
            postchecks: std::array::from_fn(|_| None),
            first: None,
            boundary: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first {
            Some(TerminalFailureV5::Native) => self.carrier_failure.as_ref().map(|cause| cause as _),
            Some(TerminalFailureV5::Decode) => self.decoded.as_ref()?.as_ref().err().map(|cause| cause as _),
            Some(TerminalFailureV5::Action) => self.boundary.as_ref().map(|cause| cause as _)
                .or_else(|| self.action.as_ref()?.as_ref().err().map(|cause| cause as _)),
            Some(TerminalFailureV5::NegativeAction) => self.negative_action.as_ref()?.as_ref().err().map(|cause| cause as _),
            Some(TerminalFailureV5::Sample(index)) => self.samples[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            Some(TerminalFailureV5::Postcheck(index)) => self.postchecks[index].as_ref()?.as_ref().err().map(|cause| cause as _),
            None => None,
        }
    }

    fn control(&self) -> Option<&SignedNativeHeldControlV1> {
        self.decoded.as_ref()?.as_ref().ok()
    }

    fn retain_boundary(&mut self, cause: OriginalHeldCauseV5) {
        if self.first.is_none() {
            self.boundary = Some(cause);
            self.first = Some(TerminalFailureV5::Action);
        }
        self.stage = TerminalStageV5::Closed;
    }

    fn postcheck(&mut self, index: usize, result: Result<(), OriginalHeldCauseV5>) {
        if result.is_err() && self.first.is_none() {
            self.first = Some(TerminalFailureV5::Postcheck(index));
        }
        self.postchecks[index] = Some(result);
    }

    fn sample(&mut self, index: usize, initial: RawPairedClockSample,
        deadline: u64, validity: (i64, i64),
    ) -> Result<(), OriginalHeldCauseV5> {
        self.samples[index] = Some(super::super::super::original_kernel_clock());
        let Some(Ok(later)) = &self.samples[index] else {
            if self.first.is_none() {
                self.first = Some(TerminalFailureV5::Sample(index));
            }
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        validate_original_held_clock_sample_v5(initial, *later, deadline, validity)
    }

    fn revalidate_record(&self, session: &CurrentProviderIngressSessionV1)
        -> Result<(), OriginalHeldCauseV5>
    {
        if let Some(record) = self.record.as_ref() {
            let record = record.bound().ok_or(SourceProviderSecurityError::SessionContinuity)?;
            record.execution.revalidate(session.carrier.socket().peer())?;
            if !record.descriptors.is_empty()
                || !record.execution.has_same_execution(&session.root_mount_execution)
            {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            }
        }
        Ok(())
    }

    fn verify_control(&self, session: &CurrentProviderIngressSessionV1,
        root: &CurrentRootPreparedCarrierV1, signed7: &SignedNativeHeldControlV1,
    ) -> Result<(), OriginalHeldCauseV5> {
        let exact = self.control().ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let inner = session.custody.inner();
        let now = current_unix_seconds()?;
        // The existing public verifier resolves eligibility using the actual
        // current Root1, Session and owned trust at this same observation time.
        aos_sandbox_source_provider_protocol::verify_current_root_prepared_v1(
            root.control(), &session.session, inner.trust(), inner.root_authority(), now,
        )?;
        let signer = inner.root_authority().traffic_signer();
        let key = inner.trust().keys().iter().find(|entry| entry.signer() == signer)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        exact.verify_signature_claim(&NativeHeldSignerV1::SourceProvider(signer.clone()), key.public_key())?;
        if exact.kind() != Kind::RootTerminalRecorded
            || exact.scope() != signed7.scope()
            || exact.prepared().predecessor() != signed7.digest()
            || exact.section(Tag::Settlement) != signed7.section(Tag::Settlement)
            || exact.section(Tag::Settlement).is_none()
        {
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        }
        Ok(())
    }
}

struct TerminalBoundaryV5<'a> {
    session: &'a mut CurrentProviderIngressSessionV1,
    signatures: &'a mut OriginalProviderHeldSignaturesV5,
    completed: bool,
}

impl Drop for TerminalBoundaryV5<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.signatures.root_terminal.stage = TerminalStageV5::Closed;
            self.session.close_original_held_after_failure_v5();
        }
    }
}

impl OriginalProviderHeldSignaturesV5 {
    /// Borrows authenticated Root13 DATA without authorizing cleanup.
    #[must_use]
    pub fn original_root_terminal_v5(&self) -> Option<&SignedNativeHeldControlV1> {
        if self.root_terminal.failure().is_some()
            || self.root_terminal.stage != TerminalStageV5::Received
        {
            return None;
        }
        self.root_terminal.control()
    }

    /// Borrows the original chronological terminal cause from its actual slot.
    #[must_use]
    #[doc(hidden)]
    pub fn original_root_terminal_failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.root_terminal.failure()
    }
}

impl CurrentProviderIngressSessionV1 {
    /// Observes retained originals only after the containing terminal failure.
    ///
    /// This irreversibly closes the purpose and returns no positive predicate,
    /// even if every available execution/mount observation succeeds. It needs
    /// no failed-writer authority and cannot reopen the endpoint or receive.
    #[doc(hidden)]
    pub fn observe_original_root_terminal_negative_v5(
        &mut self, physical: Option<&crate::ProviderSourceRootHandoffV1>,
        signatures: &mut OriginalProviderHeldSignaturesV5,
    ) {
        if signatures.root_terminal.negative_observed { return; }
        signatures.root_terminal.negative_observed = true;
        signatures.root_terminal.stage = TerminalStageV5::Closed;
        self.close_original_held_after_failure_v5();

        let root4 = &signatures.root_accepted;
        let child = &mut signatures.root_terminal;
        let old_root = root4.revalidate_execution(self.carrier.socket().peer()).map_err(Into::into);
        child.postcheck(4, old_root);
        let received = child.revalidate_record(self);
        child.postcheck(5, received);
        let mount = physical.ok_or(SourceProviderSecurityError::DescriptorObservation)
            .and_then(crate::ProviderSourceRootHandoffV1::revalidate).map_err(Into::into);
        child.postcheck(6, mount);
    }

    /// Arms one Root13 purpose after actual local Kind7 dispatch.
    #[doc(hidden)]
    pub fn begin_original_root_terminal_v5(&mut self, signatures: &mut OriginalProviderHeldSignaturesV5) -> bool {
        let eligible = signatures.original_settlement_sent_v5()
            && signatures.root_accepted().is_some() && signatures.failure().is_none()
            && self.failure_disposition == CurrentSessionFailureDispositionV5::OriginalHeldEnded
            && signatures.root_terminal.stage == TerminalStageV5::Unstarted;
        if !eligible {
            signatures.root_terminal.retain_boundary(SourceProviderSecurityError::SessionContinuity.into());
            self.close_original_held_after_failure_v5();
            return false;
        }
        signatures.root_terminal.stage = TerminalStageV5::Ready;
        true
    }

    /// Settles only nonconsuming backpressure after the containing owner posts.
    ///
    /// This performs no I/O and cannot rearm a consumed or negative receipt.
    #[doc(hidden)]
    pub fn finish_original_root_terminal_pending_v5(
        &mut self, signatures: &mut OriginalProviderHeldSignaturesV5,
    ) -> bool {
        let child = &mut signatures.root_terminal;
        if child.stage != TerminalStageV5::Ready || child.first.is_some()
            || child.record.is_some()
            || !matches!(child.native.as_ref(),
                Some(Ok(false) | Err(CarrierFailureV1::Retryable)))
        {
            child.retain_boundary(SourceProviderSecurityError::SessionContinuity.into());
            self.close_original_held_after_failure_v5();
            return false;
        }
        self.carrier.finish_original_receive_backpressure_v5();
        true
    }

    /// Receives once through the existing original optional-rights engine.
    ///
    /// Only proven nonconsuming backpressure remains pending after all posts.
    #[doc(hidden)]
    pub fn receive_original_root_terminal_v5(
        &mut self, journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5, root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1, physical: &crate::ProviderSourceRootHandoffV1,
        lease: &SignedSourceExportLeaseV1, archive: &crate::ProtectedOriginalConfigurationArchiveV5,
        selected: &crate::ProtectedOriginalSelectedInputV1, storage: &mut crate::OriginalStorageOfferTransportV5,
        complete: &[u8], initial: RawPairedClockSample, deadline: u64, validity: (i64, i64),
        signatures: &mut OriginalProviderHeldSignaturesV5,
    ) -> bool {
        self.observe_original_root_terminal_v5(journal, readback, root, acquire, physical, lease,
            archive, selected, storage, complete, initial, deadline, validity, signatures, true, false)
    }

    /// Rechecks original receipt custody against the actual phase9 or phase10 cut.
    ///
    /// Failure never creates another receive attempt or renews the original D.
    #[doc(hidden)]
    pub fn revalidate_original_root_terminal_v5(
        &mut self, journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5, root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1, physical: &crate::ProviderSourceRootHandoffV1,
        lease: &SignedSourceExportLeaseV1, archive: &crate::ProtectedOriginalConfigurationArchiveV5,
        selected: &crate::ProtectedOriginalSelectedInputV1, storage: &mut crate::OriginalStorageOfferTransportV5,
        complete: &[u8], initial: RawPairedClockSample, deadline: u64, validity: (i64, i64),
        signatures: &mut OriginalProviderHeldSignaturesV5, step: SourceNativeHeldStepV1,
    ) -> bool {
        let terminal = match step {
            SourceNativeHeldStepV1::ProviderSettledStored => false,
            SourceNativeHeldStepV1::RootTerminalRecorded => true,
            _ => {
                signatures.root_terminal.retain_boundary(SourceProviderSecurityError::SessionContinuity.into());
                self.close_original_held_after_failure_v5();
                return false;
            }
        };
        self.observe_original_root_terminal_v5(journal, readback, root, acquire, physical, lease,
            archive, selected, storage, complete, initial, deadline, validity, signatures, false, terminal)
    }

    fn observe_original_root_terminal_v5(
        &mut self, journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5, root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1, physical: &crate::ProviderSourceRootHandoffV1,
        lease: &SignedSourceExportLeaseV1, archive: &crate::ProtectedOriginalConfigurationArchiveV5,
        selected: &crate::ProtectedOriginalSelectedInputV1, storage: &mut crate::OriginalStorageOfferTransportV5,
        complete: &[u8], initial: RawPairedClockSample, deadline: u64, validity: (i64, i64),
        signatures: &mut OriginalProviderHeldSignaturesV5, receiving: bool, terminal: bool,
    ) -> bool {
        let previous = signatures.root_terminal.stage;
        if previous == TerminalStageV5::Closed && signatures.root_terminal.negative_observed {
            // No further effect or observation loop can overwrite ended cause
            // custody. The containing owner retains its own final clock debt.
            return false;
        }
        if previous == TerminalStageV5::Unstarted
            || (receiving && previous != TerminalStageV5::Ready)
        {
            signatures.root_terminal.retain_boundary(SourceProviderSecurityError::SessionContinuity.into());
            self.close_original_held_after_failure_v5();
            return false;
        }
        signatures.root_terminal.stage = TerminalStageV5::Checking;
        // One final negative observation uses separate slots so it cannot
        // overwrite the original action, sample or chronological first debt.
        let sample_offset = if previous == TerminalStageV5::Closed { 2 } else { 0 };
        let post_offset = if previous == TerminalStageV5::Closed { 4 } else { 0 };
        if previous == TerminalStageV5::Closed {
            signatures.root_terminal.negative_observed = true;
        }
        let mut boundary = TerminalBoundaryV5 { session: self, signatures, completed: false };
        let held3 = boundary.signatures.signed.as_ref();
        let root4 = &boundary.signatures.root_accepted;
        let relay5 = boundary.signatures.relay.control();
        let prior = boundary.signatures.settlement.root_terminal_controls_v5();
        let child = &mut boundary.signatures.root_terminal;

        let mut bindings = |session: &mut CurrentProviderIngressSessionV1,
            child: &OriginalRootTerminalV5| -> Result<(), OriginalHeldCauseV5> {
            let (storage6, signed7) = prior
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let held3 = held3.ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let root4 = root4.control().ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let relay5 = relay5.ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let purpose = if terminal {
                OriginalHeldBindingPurposeV5::RootTerminal(held3, complete, root4, relay5, storage6, signed7,
                    child.control().ok_or(SourceProviderSecurityError::SessionContinuity)?)
            } else {
                OriginalHeldBindingPurposeV5::SettlementDelivery(held3, complete, root4, relay5, storage6, signed7)
            };
            session.require_original_held_bindings_v5(journal, readback, root, acquire, physical, lease,
                archive, selected, storage, purpose, initial, deadline, validity)
        };
        let action = (|| -> Result<bool, OriginalHeldCauseV5> {
            if previous == TerminalStageV5::Closed {
                return Err(SourceProviderSecurityError::SessionContinuity.into());
            }
            bindings(boundary.session, child)?;
            root4.revalidate_execution(boundary.session.carrier.socket().peer())?;
            child.sample(sample_offset, initial, deadline, validity)?;
            if receiving {
                child.native = Some(boundary.session.carrier.receive_original_root_terminal_retaining_v5(
                    &mut child.record, &mut child.carrier_failure));
                match child.native.as_ref() {
                    Some(Ok(true)) => {}
                    Some(Ok(false) | Err(CarrierFailureV1::Retryable)) => return Ok(false),
                    _ => {
                        if child.first.is_none() { child.first = Some(TerminalFailureV5::Native); }
                        return Err(SourceProviderSecurityError::SessionContinuity.into());
                    }
                }
                child.revalidate_record(boundary.session)?;
                let record = child.record.as_ref().and_then(RetainedSourceProviderRecordV5::bound)
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                child.decoded = Some(SignedNativeHeldControlV1::from_canonical_bytes(&record.payload));
                if child.decoded.as_ref().is_some_and(Result::is_err) {
                    if child.first.is_none() { child.first = Some(TerminalFailureV5::Decode); }
                    return Err(SourceProviderSecurityError::SessionContinuity.into());
                }
            }
            if child.control().is_some() {
                let (_, signed7) = prior.ok_or(SourceProviderSecurityError::SessionContinuity)?;
                child.verify_control(boundary.session, root, signed7)?;
            }
            Ok(receiving || previous == TerminalStageV5::Received)
        })();
        let progressed = action.as_ref().is_ok_and(|received| *received);
        if action.is_err() && child.first.is_none() {
            child.first = Some(if previous == TerminalStageV5::Closed {
                TerminalFailureV5::NegativeAction
            } else { TerminalFailureV5::Action });
        }
        if previous == TerminalStageV5::Closed {
            child.negative_action = Some(action);
        } else {
            child.action = Some(action);
        }

        // No failing owner check skips either actual execution observation or
        // the independent original-clock observation after a receive effect.
        let owner = bindings(boundary.session, child);
        child.postcheck(post_offset, owner);
        let old_root = root4.revalidate_execution(boundary.session.carrier.socket().peer()).map_err(Into::into);
        child.postcheck(post_offset + 1, old_root);
        let record = child.revalidate_record(boundary.session).and_then(|()| {
            if child.control().is_some() {
                let (_, signed7) = prior.ok_or(SourceProviderSecurityError::SessionContinuity)?;
                child.verify_control(boundary.session, root, signed7)
            } else { Ok(()) }
        });
        child.postcheck(post_offset + 2, record);
        let clock = child.sample(sample_offset + 1, initial, deadline, validity);
        child.postcheck(post_offset + 3, clock);
        if child.first.is_some() { return false; }

        if receiving && !progressed {
            // The containing owner still owes its independent writer, Session
            // and original-clock posts before lower backpressure is settled.
            child.stage = TerminalStageV5::Ready;
        } else {
            child.stage = if child.control().is_some() { TerminalStageV5::Received } else { previous };
        }
        boundary.completed = true;
        progressed || !receiving
    }
}
