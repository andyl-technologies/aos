//! Selected Provider opening and the same parent HELLO recipes in resident custody.
//!
//! This owner parks returned role/custody, raw packet and signed prefixes before
//! each fallible parent recipe. It does not introduce a transcript parser,
//! signer, session engine or effect authority. Its same original queue is ended
//! before negative field destruction; shutdown observations never prove drain.

use std::os::fd::OwnedFd;

use super::{
    AwaitingRootMountHelloV1, CurrentProviderIngressSessionV1, HandshakeReceiveModeV1,
    InertSourceProviderCarrierV1, ProviderHelloPreparedV1,
    ProviderSourceProviderHandshakeStatusV1, ProviderSourceProviderOwnerStateV1,
    RetainedSourceProviderRecordV5, SignedSourceProviderHelloV1,
    SourceProviderIngressSessionV1, SourceProviderSecurityError, VerifiedRootMountHelloV1,
};
use crate::handshake::{SelectedHandshakeOpeningV1, SelectedSourceProviderFailureRefV1};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;

#[derive(Default)]
pub(super) struct SelectedCurrentReceiveV1 {
    pub(super) record: Option<RetainedSourceProviderRecordV5>,
    pub(super) completed: bool,
}

/// Retains one selected Provider opening, handshake and returned transcript prefix.
///
/// Construction occurs only through the fixed Provider entry. The same opaque
/// self custody precedes protected opens, and the same raw record is retained
/// through the shared parent validators. No completed Session can be extracted
/// without the existing genuine fixed-ledger journal handoff.
#[must_use = "retain the selected original and its first failure"]
pub struct SelectedProviderSourceProviderOwnerV1 {
    opening: SelectedHandshakeOpeningV1,
    state: Option<ProviderSourceProviderOwnerStateV1>,
    received: Option<RetainedSourceProviderRecordV5>,
    root_hello: Option<SignedSourceProviderHelloV1>,
    received_payload: Option<Vec<u8>>,
    received_descriptors: Option<Vec<OwnedFd>>,
    provider_hello: Option<SignedSourceProviderHelloV1>,
    session: Option<SourceProviderIngressSessionV1>,
    packet: Option<Vec<u8>>,
    first_failure: Option<SourceProviderSecurityError>,
    journal_failure: Option<aos_sandbox::JournalError>,
    attempted: bool,
    handed_off: bool,
    ended: bool,
}

struct SelectedProviderBoundaryV1<'owner> {
    owner: &'owner mut SelectedProviderSourceProviderOwnerV1,
    completed: bool,
}

impl Drop for SelectedProviderBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.end_original();
        }
    }
}

impl core::fmt::Debug for SelectedProviderSourceProviderOwnerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SelectedProviderSourceProviderOwnerV1([original custody])")
    }
}

impl SelectedProviderSourceProviderOwnerV1 {
    pub(super) fn new(socket: DescriptorSubjectSocket) -> Self {
        Self {
            opening: SelectedHandshakeOpeningV1::provider(socket),
            state: None,
            received: None,
            root_hello: None,
            received_payload: None,
            received_descriptors: None,
            provider_hello: None,
            session: None,
            packet: None,
            first_failure: None,
            journal_failure: None,
            attempted: false,
            handed_off: false,
            ended: false,
        }
    }

    /// Opens the fixed selected role once with every returned prefix resident.
    ///
    /// # Errors
    ///
    /// Lends the actual first custody/carrier failure. Reentry is refused
    /// without reopening protected files, renewing a nonce or replacing a peer.
    pub fn open_once(&mut self) -> Result<(), SelectedSourceProviderFailureRefV1<'_>> {
        if self.failure().is_some() || self.ended {
            self.end_original();
            return Err(self.failure_or_poison());
        }
        if self.attempted {
            self.first_failure = Some(SourceProviderSecurityError::Poisoned);
        } else {
            self.attempted = true;
            let mut boundary = SelectedProviderBoundaryV1 { owner: self, completed: false };
            if boundary.owner.opening.open_once().is_ok() {
                if let Err(error) = boundary.owner.open_inner() {
                    boundary.owner.first_failure = Some(error);
                }
            }
            boundary.completed = boundary.owner.failure().is_none();
        }
        if self.failure().is_some() || self.ended {
            self.end_original();
            return Err(self.failure_or_poison());
        }
        Ok(())
    }

    fn open_inner(&mut self) -> Result<(), SourceProviderSecurityError> {
        let (custody, carrier) = self
            .opening
            .take_provider_parts()
            .ok_or(SourceProviderSecurityError::Poisoned)?;
        self.state = Some(ProviderSourceProviderOwnerStateV1::Awaiting(
            AwaitingRootMountHelloV1 { custody, carrier },
        ));

        match self.state.as_mut() {
            Some(ProviderSourceProviderOwnerStateV1::Awaiting(awaiting)) => {
                awaiting.revalidate_before_action()
            }
            _ => Err(SourceProviderSecurityError::Poisoned),
        }
    }

    /// Advances the same parent recipes without taking a state across effects.
    ///
    /// # Errors
    ///
    /// Ends the original queue and lends the actual first receive, binding,
    /// execution, signing or custody failure. No later observation revives it.
    pub fn advance_handshake(
        &mut self,
    ) -> Result<ProviderSourceProviderHandshakeStatusV1, SelectedSourceProviderFailureRefV1<'_>> {
        if self.failure().is_none() && !self.handed_off && !self.ended {
            let progress = {
                let mut boundary = SelectedProviderBoundaryV1 { owner: self, completed: false };
                match boundary.owner.advance_inner() {
                    Ok(progress) => {
                        boundary.completed = true;
                        Some(progress)
                    }
                    Err(error) => {
                        boundary.owner.first_failure = Some(error);
                        None
                    }
                }
            };
            if let Some(progress) = progress {
                return Ok(progress);
            }
        }
        self.end_original();
        Err(self.failure_or_poison())
    }

    fn advance_inner(
        &mut self,
    ) -> Result<ProviderSourceProviderHandshakeStatusV1, SourceProviderSecurityError> {
        match self.state.as_mut() {
            Some(ProviderSourceProviderOwnerStateV1::Awaiting(awaiting)) => {
                if !awaiting.receive_step(
                    &mut self.received,
                    &mut self.root_hello,
                    HandshakeReceiveModeV1::Selected,
                )? {
                    return Ok(ProviderSourceProviderHandshakeStatusV1::Pending);
                }
                self.complete_received()?;
            }
            Some(ProviderSourceProviderOwnerStateV1::Verified(verified)) => {
                verified.prepare_step(
                    &mut self.provider_hello,
                    &mut self.session,
                    &mut self.packet,
                    HandshakeReceiveModeV1::Selected,
                )?;
                self.complete_prepared()?;
            }
            Some(ProviderSourceProviderOwnerStateV1::Prepared(prepared)) => {
                if !prepared.send_step()? {
                    return Ok(ProviderSourceProviderHandshakeStatusV1::Pending);
                }
                self.complete_sent()?;
                return Ok(ProviderSourceProviderHandshakeStatusV1::Current);
            }
            Some(ProviderSourceProviderOwnerStateV1::Current(current)) => {
                current.revalidate()?;
                return Ok(ProviderSourceProviderHandshakeStatusV1::Current);
            }
            None => return Err(SourceProviderSecurityError::Poisoned),
        }
        Ok(ProviderSourceProviderHandshakeStatusV1::Pending)
    }

    fn complete_received(&mut self) -> Result<(), SourceProviderSecurityError> {
        if !matches!(self.state, Some(ProviderSourceProviderOwnerStateV1::Awaiting(_)))
            || !matches!(self.received, Some(RetainedSourceProviderRecordV5::Bound(_)))
            || self.root_hello.is_none()
            || self.received_payload.is_some()
            || self.received_descriptors.is_some()
        {
            return Err(SourceProviderSecurityError::Poisoned);
        }
        match (self.state.take(), self.received.take(), self.root_hello.take()) {
            (
                Some(ProviderSourceProviderOwnerStateV1::Awaiting(awaiting)),
                Some(RetainedSourceProviderRecordV5::Bound(received)),
                Some(root_hello),
            ) => {
                self.received_payload = Some(received.payload);
                self.received_descriptors = Some(received.descriptors);
                self.state = Some(ProviderSourceProviderOwnerStateV1::Verified(
                    VerifiedRootMountHelloV1 {
                        custody: awaiting.custody,
                        carrier: awaiting.carrier,
                        root_mount_hello: Some(root_hello),
                        root_mount_execution: received.execution,
                    },
                ));
                Ok(())
            }
            (state, received, hello) => {
                self.state = state;
                self.received = received;
                self.root_hello = hello;
                Err(SourceProviderSecurityError::Poisoned)
            }
        }
    }

    fn complete_prepared(&mut self) -> Result<(), SourceProviderSecurityError> {
        let has_root_hello = matches!(
            self.state.as_ref(),
            Some(ProviderSourceProviderOwnerStateV1::Verified(verified))
                if verified.root_mount_hello.is_some()
        );
        if !has_root_hello
            || self.root_hello.is_some()
            || self.session.is_none()
            || self.packet.is_none()
        {
            return Err(SourceProviderSecurityError::Poisoned);
        }
        match (self.state.take(), self.session.take(), self.packet.take()) {
            (
                Some(ProviderSourceProviderOwnerStateV1::Verified(verified)),
                Some(session),
                Some(packet),
            ) => {
                self.root_hello = verified.root_mount_hello;
                self.state = Some(ProviderSourceProviderOwnerStateV1::Prepared(
                    ProviderHelloPreparedV1 {
                        custody: verified.custody,
                        carrier: verified.carrier,
                        session,
                        root_mount_execution: verified.root_mount_execution,
                        packet,
                    },
                ));
                Ok(())
            }
            (state, session, packet) => {
                self.state = state;
                self.session = session;
                self.packet = packet;
                Err(SourceProviderSecurityError::Poisoned)
            }
        }
    }

    fn complete_sent(&mut self) -> Result<(), SourceProviderSecurityError> {
        if !matches!(self.state, Some(ProviderSourceProviderOwnerStateV1::Prepared(_)))
            || self.packet.is_some()
        {
            return Err(SourceProviderSecurityError::Poisoned);
        }
        match self.state.take() {
            Some(ProviderSourceProviderOwnerStateV1::Prepared(prepared)) => {
                self.packet = Some(prepared.packet);
                self.state = Some(ProviderSourceProviderOwnerStateV1::Current(
                    CurrentProviderIngressSessionV1 {
                        custody: prepared.custody,
                        carrier: prepared.carrier,
                        session: prepared.session,
                        root_mount_execution: prepared.root_mount_execution,
                        failure_disposition: super::CurrentSessionFailureDispositionV5::LegacyDisposal,
                        selected_receive: Some(SelectedCurrentReceiveV1::default()),
                    },
                ));
                Ok(())
            }
            state => {
                self.state = state;
                Err(SourceProviderSecurityError::Poisoned)
            }
        }
    }

    /// Moves the completed Session once under the existing genuine journal loan.
    ///
    /// The caller must immediately park a successful original in its fixed
    /// owner before another fallible crossing, and retain this prefix owner.
    /// The handoff does not prove ledger replay, catalog, backend or effect
    /// authorization. The same alias remains shared by the transferred carrier.
    ///
    /// # Errors
    ///
    /// Refuses incomplete/repeated handoff, stale journal or currentness; the
    /// complete original stays resident and the first failure is lent.
    #[doc(hidden)]
    pub fn take_current_for_fixed_ledger(
        &mut self,
        journal: aos_sandbox::FixedSourceProviderJournalHandoffV1<'_, '_>,
    ) -> Result<CurrentProviderIngressSessionV1, SelectedSourceProviderFailureRefV1<'_>> {
        let current = {
            let mut boundary = SelectedProviderBoundaryV1 { owner: self, completed: false };
            if boundary.owner.validate_fixed_ledger_handoff(journal) {
                // Validation left the whole Current state resident. No
                // observation or allocation follows this final field move.
                match boundary.owner.state.take() {
                    Some(ProviderSourceProviderOwnerStateV1::Current(current)) => {
                        boundary.owner.handed_off = true;
                        boundary.completed = true;
                        Some(current)
                    }
                    state => {
                        boundary.owner.state = state;
                        boundary.owner.first_failure = Some(SourceProviderSecurityError::Poisoned);
                        None
                    }
                }
            } else {
                None
            }
        };
        match current {
            Some(current) => Ok(current),
            None => Err(self.failure_or_poison()),
        }
    }

    fn validate_fixed_ledger_handoff(
        &mut self,
        journal: aos_sandbox::FixedSourceProviderJournalHandoffV1<'_, '_>,
    ) -> bool {
        if self.handed_off || self.ended || self.failure().is_some() {
            if self.failure().is_none() {
                self.first_failure = Some(SourceProviderSecurityError::Poisoned);
            }
            return false;
        }
        if let Err(error) = journal.validate_current() {
            self.journal_failure = Some(error);
            return false;
        }
        let checked = match self.state.as_mut() {
            Some(ProviderSourceProviderOwnerStateV1::Current(current)) => current.revalidate(),
            _ => Err(SourceProviderSecurityError::SessionContinuity),
        };
        if let Err(error) = checked {
            if self.failure().is_none() {
                self.first_failure = Some(error);
            }
            return false;
        }
        true
    }

    /// Lends the actual first cause without observation, retry or replacement.
    pub fn failure(&self) -> Option<SelectedSourceProviderFailureRefV1<'_>> {
        if let Some(error) = &self.journal_failure {
            return Some(SelectedSourceProviderFailureRefV1::Journal(error));
        }
        let carrier = self.state.as_ref().map(state_carrier);
        if let Some(error) = carrier.and_then(InertSourceProviderCarrierV1::socket_failure) {
            return Some(SelectedSourceProviderFailureRefV1::Socket(error));
        }
        if let Some(error) = carrier.and_then(InertSourceProviderCarrierV1::binding_failure) {
            return Some(SelectedSourceProviderFailureRefV1::Binding(error));
        }
        self.first_failure
            .as_ref()
            .map(SelectedSourceProviderFailureRefV1::Source)
            .or_else(|| self.opening.failure())
    }

    fn failure_or_poison(&mut self) -> SelectedSourceProviderFailureRefV1<'_> {
        if let Some(error) = &self.journal_failure {
            return SelectedSourceProviderFailureRefV1::Journal(error);
        }
        let carrier = self.state.as_ref().map(state_carrier);
        if let Some(error) = carrier.and_then(InertSourceProviderCarrierV1::socket_failure) {
            return SelectedSourceProviderFailureRefV1::Socket(error);
        }
        if let Some(error) = carrier.and_then(InertSourceProviderCarrierV1::binding_failure) {
            return SelectedSourceProviderFailureRefV1::Binding(error);
        }
        match &mut self.first_failure {
            Some(error) => SelectedSourceProviderFailureRefV1::Source(error),
            slot => match self.opening.failure() {
                Some(error) => error,
                None => SelectedSourceProviderFailureRefV1::Source(
                    slot.insert(SourceProviderSecurityError::Poisoned),
                ),
            },
        }
    }

    /// Reports the irreversible shared endpoint end without observation.
    ///
    /// The same latch remains meaningful after the current Session moves into
    /// its genuine fixed ledger owner. This is negative DATA, not drain proof.
    #[must_use]
    pub fn has_ended(&self) -> bool {
        self.ended || self.opening.endpoint.as_ref().is_some_and(|endpoint| endpoint.has_ended())
    }

    /// Irreversibly ends the same original queue before retaining its debt.
    ///
    /// This is negative closure, not peer/process/descriptor-drain proof.
    pub fn end_original(&mut self) {
        self.ended = true;
        self.opening.close();
        match self.state.as_mut() {
            Some(ProviderSourceProviderOwnerStateV1::Awaiting(state)) => {
                state.carrier.close();
                state.custody.inner_mut().poison();
            }
            Some(ProviderSourceProviderOwnerStateV1::Verified(state)) => {
                state.carrier.close();
                state.custody.inner_mut().poison();
            }
            Some(ProviderSourceProviderOwnerStateV1::Prepared(state)) => {
                state.carrier.close();
                state.custody.inner_mut().poison();
            }
            Some(ProviderSourceProviderOwnerStateV1::Current(state)) => {
                state.carrier.close();
                state.custody.inner_mut().poison();
            }
            None => {}
        }
    }
}

fn state_carrier(state: &ProviderSourceProviderOwnerStateV1) -> &InertSourceProviderCarrierV1 {
    match state {
        ProviderSourceProviderOwnerStateV1::Awaiting(state) => &state.carrier,
        ProviderSourceProviderOwnerStateV1::Verified(state) => &state.carrier,
        ProviderSourceProviderOwnerStateV1::Prepared(state) => &state.carrier,
        ProviderSourceProviderOwnerStateV1::Current(state) => &state.carrier,
    }
}

impl Drop for SelectedProviderSourceProviderOwnerV1 {
    fn drop(&mut self) {
        // Handoff moves the live Session, not negative endpoint ownership.
        // The fixed parent retains this prefix before its other owned fields.
        self.end_original();
    }
}

impl CurrentProviderIngressSessionV1 {
    /// Lends the same selected carrier's owning lower receive/binding cause.
    ///
    /// This negative-only view neither observes nor retries the original.
    #[doc(hidden)]
    pub fn selected_original_carrier_failure(&self) -> Option<SelectedSourceProviderFailureRefV1<'_>> {
        if self.selected_receive.is_none() {
            return None;
        }
        self.carrier.socket_failure().map(SelectedSourceProviderFailureRefV1::Socket)
            .or_else(|| self.carrier.binding_failure().map(SelectedSourceProviderFailureRefV1::Binding))
    }
}
