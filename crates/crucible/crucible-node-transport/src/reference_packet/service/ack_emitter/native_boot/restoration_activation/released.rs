//! Authenticates the same physically released World without issuing method rights.
//!
//! The private witness names actual retained owners and an original sent prefix.
//! It is not a runtime execution, input, Capture, resource or adoption grant.
//! Every request reauthenticates the same connection and current Control world.

use super::*;
use crate::connection::ExchangeRecord;
use crate::reference_packet::control::ReleasedWorldControlInputsData;

pub(crate) enum OriginalRestorationReleaseState {
    /// Keeps the once-only restoration dispatcher closed to ordinary traffic.
    Pending,
    /// Carries the positively authenticated published World and physical release.
    Released(OriginalRestorationReleased),
}

/// Retains actual release provenance without cloning a phase or creating rights.
pub(crate) struct OriginalRestorationReleased {
    pub(super) boot: Rc<RefCell<NativeAckBoot>>,
    pub(super) world: Rc<RefCell<NativeRestorationActivationAttempt>>,
    pub(super) commit: Rc<RefCell<NativeCompleteRestoreAttempt>>,
    pub(super) hold: Rc<PacketCompleteRestorePhysicalHold>,
    pub(super) policy: Rc<crate::reference_packet::Native5Policy>,
    pub(super) record: usize,
}

impl NativeAckBoot {
    /// Authenticates a published World against its actual complete sent prefix.
    ///
    /// A missing World attempt remains Pending. Only a positive witness can
    /// enter the separately admitted ordinary request path; Pending never
    /// clears the sticky restore attempt or grants a generic fallback.
    ///
    /// # Errors
    /// Refuses stale, partial, foreign or conflicting release owners/literals.
    pub(crate) fn original_restoration_release_data<S: ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<OriginalRestorationReleaseState, ProviderError> {
        // Before a World attempt exists, this hook supplies no released
        // witness. Baseline Admit and the old sticky restoration path retain
        // their own original guards; missing state is never a legacy grant.
        {
            let owner = boot.try_borrow().map_err(|_| borrowed())?;
            owner.ensure_origin()?;
            if owner.restoration_activation[1].is_none() {
                return Ok(OriginalRestorationReleaseState::Pending);
            }
        }
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        // Mechanism4 never enters the new post-World receive. These complete
        // borrowed roster checks precede all new release/Observe construction;
        // their matching data supplies no claim or dispatch permission.
        crate::reference_packet::service::complete_restore::restoration_observe::authenticate_restoration_observe_selection_data(
            admission.policy.original_restoration_activation_selection_data(), &admission.authority,
        )?;
        if !Rc::ptr_eq(boot, &admission.boot) {
            return Err(refused());
        }
        let owner = boot.try_borrow().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        if !owner.requires_restoration_activation_data()? {
            return Err(refused());
        }
        let world = owner.restoration_activation[1]
            .as_ref()
            .ok_or_else(refused)?;
        let flight = world.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !flight.verified || !flight.dispatched || !flight.published {
            return Err(refused());
        }
        let terminal = flight.terminal.as_ref().ok_or_else(refused)?;
        let mut matched = None;
        for (index, record) in records.iter().enumerate() {
            if record.originals().contains(terminal) && matched.replace(index).is_some() {
                return Err(refused());
            }
        }
        let record = matched.ok_or_else(refused)?;
        let commit = Rc::clone(owner.restoration.as_ref().ok_or_else(refused)?);
        let hold = Rc::clone(
            commit
                .try_borrow()
                .map_err(|_| borrowed())?
                .physical_hold
                .as_ref()
                .ok_or_else(refused)?,
        );
        let witness = OriginalRestorationReleased {
            boot: Rc::clone(boot),
            world: Rc::clone(world),
            commit,
            hold,
            policy: Rc::clone(&admission.policy),
            record,
        };
        drop(flight);
        drop(owner);
        witness.authenticate_current_data(connection, control, records)?;
        Ok(OriginalRestorationReleaseState::Released(witness))
    }
}

impl OriginalRestorationReleased {
    /// Reauthenticates lifecycle release, preserving each method's own guards.
    ///
    /// # Errors
    /// Refuses another actor, changed owner/phase/cached response, unsent literal,
    /// expired authority or physical hold/current world disagreement.
    pub(crate) fn authenticate_current_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        if !Rc::ptr_eq(&admission.boot, &self.boot) || !Rc::ptr_eq(&admission.policy, &self.policy)
        {
            return Err(refused());
        }
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let flight = self.world.try_borrow().map_err(|_| borrowed())?;
        let commit = self.commit.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        commit.ensure_origin()?;
        if owner.restoration_activation[1]
            .as_ref()
            .is_none_or(|slot| !Rc::ptr_eq(slot, &self.world))
            || owner
                .restoration
                .as_ref()
                .is_none_or(|slot| !Rc::ptr_eq(slot, &self.commit))
            || commit
                .physical_hold
                .as_ref()
                .is_none_or(|hold| !Rc::ptr_eq(hold, &self.hold))
            || !commit.verified
            || !commit.installation_started
            || !commit.receipt_started
            || !flight.verified
            || !flight.dispatched
            || !flight.published
            || flight.phase != PacketRestorationActivationPhase::WorldActivate
            || self.hold.physical_gate_data()?
        {
            return Err(refused());
        }
        connection.authenticate_installed_complete_restoration(&commit.mapping)?;
        let original = flight.original.as_ref().ok_or_else(refused)?;
        let terminal = flight.terminal.as_ref().ok_or_else(refused)?;
        let incoming = connection.original_restoration_incoming_literal_data(
            original,
            flight.incoming_slot.ok_or_else(refused)?,
        )?;
        drop(incoming);
        let artifact = flight.artifact.as_ref().ok_or_else(refused)?;
        let context = flight.context.as_ref().ok_or_else(refused)?;
        if context.request != artifact.request {
            return Err(refused());
        }
        authenticate_completed_commit(&owner, &commit, &artifact.request.scope)?;
        let purpose = owner.authenticate_original_invocation_birth_data()?;
        purpose.authenticate_restoration_source_data(
            &artifact.request.scope.source_runtime,
            &artifact.request.scope.restoration.captured_owner_state,
            &artifact.request.scope.target.owner,
        )?;
        owner
            .authenticate_restoration_activation_uploads_data(&artifact.request.scope, original)?;
        let arm = owner.restoration_activation[0]
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        arm.ensure_origin()?;
        if !arm.verified
            || !arm.dispatched
            || !arm.published
            || arm.artifact.as_ref().ok_or_else(refused)?.request.scope != artifact.request.scope
        {
            return Err(refused());
        }
        control.authenticate_original_restoration_released_control_data(
            ReleasedWorldControlInputsData {
                original,
                terminal,
                scope: &artifact.request.scope,
                boot: &self.boot,
                mapping: &commit.mapping,
                hold: &self.hold,
                policy: &self.policy,
            },
        )?;
        let record = records.get(self.record).ok_or_else(refused)?;
        if record.sent() != record.originals().len()
            || crate::connection::original_restored_response_data(original, record.originals())?.1
                != terminal
        {
            return Err(refused());
        }
        // Physical original headers/bodies, actor and same frame bank are
        // checked independently of the terminal label or stored published bit.
        for index in 0..record.originals().len() {
            let sent = record.original_sent_frame(connection, index)?;
            if sent.original() != &record.originals()[index] {
                return Err(refused());
            }
        }
        Ok(())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    crate::connection::original_restored_response_counter_scratch_data()
        + size_of::<OriginalRestorationReleased>()
        + size_of::<OriginalRestorationReleaseState>()
        + size_of::<Result<OriginalRestorationReleaseState, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<&[ExchangeRecord]>()
        + size_of::<Option<usize>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, ExchangeRecord>>>()
        + size_of::<std::slice::Iter<'static, ExchangeRecord>>()
        + size_of::<(usize, &'static ExchangeRecord)>()
        + size_of::<Option<(usize, &'static ExchangeRecord)>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<crate::connection::OriginalSentFrameView<'static>>()
        + size_of::<Result<crate::connection::OriginalSentFrameView<'static>, ProviderError>>()
        + size_of::<std::cell::Ref<'static, NativeAckBoot>>()
        + size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, std::cell::BorrowError>>()
        + size_of::<Result<std::cell::Ref<'static, NativeRestorationActivationAttempt>, std::cell::BorrowError>>() * 2
        + size_of::<Result<std::cell::Ref<'static, NativeCompleteRestoreAttempt>, std::cell::BorrowError>>()
        + size_of::<Option<&'static crate::connection::ExchangeRecord>>()
        + size_of::<Option<&'static Envelope>>()
        + size_of::<Result<&'static Envelope, ProviderError>>()
        + size_of::<(&'static Envelope, &'static PacketRestorationActivationArtifact, &'static PacketRestorationActivationContext)>()
        + size_of::<ContentRef>()
        + size_of::<Result<ContentRef, ContractError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + crate::reference_packet::service::native_startup::original_native_invocation_counter_scratch_data()
        + crate::reference_packet::service::complete_restore::restoration_observe::restoration_observe_protocol_counter_scratch_data()
        + crate::connection::original_restoration_release_literal_counter_scratch_data()
        + crate::reference_packet::control::original_restoration_released_counter_scratch_data()
}

impl OriginalRestorationReleased {
    pub(super) fn authenticate_observation_request_data<S: ProviderStream>(
        &self,
        request: &crate::reference_packet::service::complete_restore::restoration_observe::PacketRestorationObservationRequest,
        connection: &Connection<S>,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        let flight = self.world.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !flight.verified
            || !flight.dispatched
            || !flight.published
            || flight.artifact.as_ref().ok_or_else(refused)?.request.scope != request.scope
        {
            return Err(refused());
        }
        let original = flight.original.as_ref().ok_or_else(refused)?;
        let incoming = connection.original_restoration_incoming_literal_data(
            original,
            flight.incoming_slot.ok_or_else(refused)?,
        )?;
        request.world_original.verify(&incoming)?;
        let record = records.get(self.record).ok_or_else(refused)?;
        let index = record
            .originals()
            .len()
            .checked_sub(1)
            .ok_or_else(refused)?;
        let sent = record.original_sent_frame(connection, index)?;
        if Some(sent.original()) != flight.terminal.as_ref() {
            return Err(refused());
        }
        request.world_terminal.verify(sent.canonical_body())?;
        Ok(())
    }
}
