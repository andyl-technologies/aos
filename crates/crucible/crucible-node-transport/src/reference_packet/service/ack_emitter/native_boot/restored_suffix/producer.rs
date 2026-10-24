//! Spends independent native axes for a closed current Producer original.
//!
//! The actual initial witness authenticates immutable boot/Commit/release
//! ancestry. Every dispatch additionally checks the live Producer model and
//! method-specific actual geometry; no historical held cursor is reused.

use super::*;

/// Borrows a spent receive slot under the actual published-first witness.
///
/// Dropping an unfinished scope poisons the owner and budget. Only complete
/// current native result, terminal and sent ACK publication reopen the ledger; raw or
/// typed receive success alone cannot do so.
pub(crate) struct OriginalRestoredProducerRead<'a> {
    witness: &'a OriginalRestoredSuffixPostObservation,
    boot: Rc<RefCell<NativeAckBoot>>,
    index: usize,
    frame: usize,
    attempt: Rc<RefCell<NativeRestoredProducerAttempt>>,
    receive_started: std::cell::Cell<bool>,
    incoming_slot: std::cell::Cell<Option<usize>>,
    action_started: std::cell::Cell<bool>,
    completed: std::cell::Cell<bool>,
}

impl<'a> OriginalRestoredProducerRead<'a> {
    /// Retains one irrevocably spent original under the actual received owner.
    ///
    /// # Errors
    /// Refuses stale custody, a depleted axis/count or failed slot allocation.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn retain_data(
        witness: &'a OriginalRestoredSuffixPostObservation,
        boot: &Rc<RefCell<NativeAckBoot>>,
        frame: usize,
    ) -> Result<Self, ProviderError> {
        let ingress = original_restored_producer_ingress_row_data(frame)?;
        let mut owner = boot.try_borrow_mut().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let state = owner
            .startup
            .as_mut()
            .and_then(|startup| startup.restored_suffix.as_mut())
            .ok_or_else(refused)?;
        state.ensure_current()?;
        state.reservation_data()?;
        // Spend first. A short row, failed allocation or later read cannot
        // obtain another slot or refund this native original's debit.
        state.failed = true;
        let ordinal = state.ledger.begin_ingress_data(ingress)?;
        state
            .producer_attempts
            .try_reserve_exact(1)
            .map_err(|_| exhausted())?;
        let index = state.producer_attempts.len();
        let attempt = Rc::new(RefCell::new(NativeRestoredProducerAttempt::new_data(
            ordinal,
        )));
        state.producer_attempts.push(Rc::clone(&attempt));
        state.failed = false;
        drop(owner);
        Ok(Self {
            witness,
            boot: Rc::clone(boot),
            index,
            frame,
            attempt,
            receive_started: std::cell::Cell::new(false),
            incoming_slot: std::cell::Cell::new(None),
            action_started: std::cell::Cell::new(false),
            completed: std::cell::Cell::new(false),
        })
    }

    /// Starts one receive on the same actual admitted native connection.
    ///
    /// # Errors
    /// Refuses repeated, completed, foreign or conflicting native custody.
    pub(crate) fn begin_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        if self.receive_started.replace(true) || self.completed.get() {
            return Err(refused());
        }
        self.authenticate_receive_data(connection)
    }

    /// Checks the same retained attempt, boot and current negotiated authority.
    ///
    /// # Errors
    /// Refuses missing, failed, foreign, completed or conflicting custody.
    pub(crate) fn authenticate_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        if !Rc::ptr_eq(&self.boot, &admission.boot) {
            return Err(refused());
        }
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let state = owner
            .startup
            .as_ref()
            .and_then(|startup| startup.restored_suffix.as_ref())
            .ok_or_else(refused)?;
        state.ensure_current()?;
        if !self.receive_started.get()
            || self.completed.get()
            || state
                .producer_attempts
                .get(self.index)
                .is_none_or(|attempt| !Rc::ptr_eq(attempt, &self.attempt))
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Borrows the exact original retained before policy and typed checks.
    ///
    /// # Errors
    /// Refuses missing, failed or conflicting attempt custody.
    pub(crate) fn original_data(&self) -> Result<std::cell::Ref<'_, Envelope>, ProviderError> {
        let attempt = self.attempt.try_borrow().map_err(|_| borrowed())?;
        attempt.original_data()?;
        std::cell::Ref::filter_map(attempt, |attempt| attempt.original_data().ok())
            .map_err(|_| refused())
    }

    /// Completes receive only for the actual fully retained incoming literal.
    ///
    /// # Errors
    /// Refuses repeated completion, stale custody or canonical frame mismatch.
    pub(crate) fn complete_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_receive_data(connection)?;
        if self.incoming_slot.get().is_some() {
            return Err(refused());
        }
        let original = self.original_data()?;
        let slot = connection.original_restored_producer_literal_slot_data(&original)?;
        self.incoming_slot.set(Some(slot));
        Ok(())
    }

    /// Debits complete native proof and publication demand before dispatch.
    ///
    /// # Errors
    /// Refuses another dispatch, changed current model/owners or any short axis.
    pub(crate) fn begin_dispatch_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        self.authenticate_receive_data(connection)?;
        if self.action_started.replace(true) {
            return Err(refused());
        }
        self.witness
            .authenticate_current_data(connection, control, records)?;
        {
            let original = self.original_data()?;
            connection.authenticate_original_restored_producer_literal_data(
                &original,
                self.incoming_slot.get().ok_or_else(refused)?,
            )?;
        }
        let required = {
            let attempt = self.attempt.try_borrow().map_err(|_| borrowed())?;
            self.witness
                .producer_row_data(connection, control, attempt.original_data()?)?
        };
        {
            let mut owner = self.boot.try_borrow_mut().map_err(|_| borrowed())?;
            let state = owner
                .startup
                .as_mut()
                .and_then(|startup| startup.restored_suffix.as_mut())
                .ok_or_else(refused)?;
            state.ensure_current()?;
            state.failed = true;
            state.ledger.begin_action_data(required)?;
            self.attempt
                .try_borrow_mut()
                .map_err(|_| borrowed())?
                .begin_dispatch_data()?;
            state.failed = false;
        }
        self.witness
            .authenticate_current_data(connection, control, records)
    }

    /// Authenticates the actual dispatched original under the same live Control.
    ///
    /// # Errors
    /// Refuses changed original identity, physical release, scope or live owners.
    pub(crate) fn authenticate_control_request_data(
        &self,
        original: &Envelope,
        selection: &crate::reference_packet::control::PacketControlSelection,
        control: &PacketControl,
    ) -> Result<(), ProviderError> {
        if !self.action_started.get() || self.completed.get() {
            return Err(refused());
        }
        let attempt = self.attempt.try_borrow().map_err(|_| borrowed())?;
        if !std::ptr::eq(attempt.original_data()?, original) {
            return Err(refused());
        }
        attempt.authenticate_dispatched_data()?;
        self.witness
            .authenticate_producer_control_data(original, selection, control)
    }

    pub(crate) fn activation_boundary_data(
        &self,
    ) -> Result<crucible_node_format::Position, ProviderError> {
        if !self.action_started.get() || self.completed.get() {
            return Err(refused());
        }
        self.attempt
            .try_borrow()
            .map_err(|_| borrowed())?
            .authenticate_dispatched_data()?;
        self.witness.producer_activation_boundary_data()
    }

    pub(crate) fn retain_prepared_reply_data(
        &self,
        reply: &crate::reference_packet::control::PacketControlReply,
    ) -> Result<(), ProviderError> {
        if !self.action_started.get() || self.completed.get() {
            return Err(refused());
        }
        self.attempt
            .try_borrow_mut()
            .map_err(|_| borrowed())?
            .retain_prepared_reply_data(reply)
    }

    /// Retains the real terminal before checking complete literal ACK publication.
    ///
    /// # Errors
    /// Refuses another completion, changed terminal/proof/currency, unsent frames
    /// or incomplete ACK publication. Every partial remains owned and spent.
    pub(crate) fn complete_publication_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        if !self.action_started.get() || self.completed.get() {
            return Err(refused());
        }
        let record = records.last().ok_or_else(refused)?;
        let (terminal_index, terminal) = {
            let original = self.original_data()?;
            crate::connection::original_restored_response_data(&original, record.originals())?
        };
        self.attempt
            .try_borrow_mut()
            .map_err(|_| borrowed())?
            .retain_terminal_data(terminal)?;
        {
            let attempt = self.attempt.try_borrow().map_err(|_| borrowed())?;
            let original = attempt.original_data()?;
            if !matches!(
                original.method,
                crate::envelope::Method::BlobBegin
                    | crate::envelope::Method::BlobChunk
                    | crate::envelope::Method::BlobFinish
            ) {
                control
                    .authenticate_original_restored_producer_terminal_data(original, terminal)?;
            }
            connection.authenticate_original_restored_producer_literal_data(
                attempt.original_data()?,
                self.incoming_slot.get().ok_or_else(refused)?,
            )?;
        }
        if record.sent() != record.originals().len() {
            return Err(refused());
        }
        if record
            .original_sent_frame(connection, terminal_index)?
            .original()
            != terminal
        {
            return Err(refused());
        }
        for index in 0..record.originals().len() {
            record.original_sent_frame(connection, index)?;
        }
        self.witness
            .authenticate_current_data(connection, control, records)?;
        self.authenticate_receive_data(connection)?;
        let mut owner = self.boot.try_borrow_mut().map_err(|_| borrowed())?;
        let state = owner
            .startup
            .as_mut()
            .and_then(|startup| startup.restored_suffix.as_mut())
            .ok_or_else(refused)?;
        state.failed = true;
        self.attempt
            .try_borrow_mut()
            .map_err(|_| borrowed())?
            .complete_publication_data()?;
        state.ledger.complete_publication_data()?;
        state.failed = false;
        self.completed.set(true);
        Ok(())
    }

    /// Retains the actual raw original before route or typed decoding can fail.
    ///
    /// This stage performs no model callback, native proof encoding or send.
    /// The same actual first-observation witness is rechecked around decoding;
    /// future advanced inventory must use a distinct current-proof validator.
    ///
    /// # Errors
    /// Refuses another route/frontier, raw or typed rejection, conflicting loans
    /// and any actual first-witness/current Control failure.
    pub(crate) fn retain_original_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
        original: Envelope,
    ) -> Result<(), ProviderError> {
        {
            let mut owner = self.boot.try_borrow_mut().map_err(|_| borrowed())?;
            let state = owner
                .startup
                .as_mut()
                .and_then(|startup| startup.restored_suffix.as_mut())
                .ok_or_else(refused)?;
            state.ensure_current()?;
            state
                .producer_attempts
                .get(self.index)
                .filter(|attempt| Rc::ptr_eq(attempt, &self.attempt))
                .ok_or_else(refused)?
                .try_borrow_mut()
                .map_err(|_| borrowed())?
                .retain_original_data(original)?;
        }
        // No boot RefMut crosses the witness's actual same-owner recheck.
        self.witness
            .authenticate_current_data(connection, control, records)?;
        {
            let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
            let state = owner
                .startup
                .as_ref()
                .and_then(|startup| startup.restored_suffix.as_ref())
                .ok_or_else(refused)?;
            let original = state
                .producer_attempts
                .get(self.index)
                .filter(|attempt| Rc::ptr_eq(attempt, &self.attempt))
                .ok_or_else(refused)?
                .try_borrow()
                .map_err(|_| borrowed())?;
            let original = original.original_data()?;
            self.witness
                .authenticate_producer_original_identity_data(original)?;
        }
        {
            let mut owner = self.boot.try_borrow_mut().map_err(|_| borrowed())?;
            let state = owner
                .startup
                .as_mut()
                .and_then(|startup| startup.restored_suffix.as_mut())
                .ok_or_else(refused)?;
            state
                .producer_attempts
                .get(self.index)
                .filter(|attempt| Rc::ptr_eq(attempt, &self.attempt))
                .ok_or_else(refused)?
                .try_borrow_mut()
                .map_err(|_| borrowed())?
                .decode_body_data(self.frame)?;
            state.failed = false;
        }
        self.witness
            .authenticate_current_data(connection, control, records)
    }
}

impl Drop for OriginalRestoredProducerRead<'_> {
    fn drop(&mut self) {
        if self.completed.get() {
            return;
        }

        if let Ok(mut owner) = self.boot.try_borrow_mut()
            && let Some(state) = owner
                .startup
                .as_mut()
                .and_then(|startup| startup.restored_suffix.as_mut())
        {
            state.failed = true;
            state.ledger.interrupt_data();
            if let Ok(mut attempt) = self.attempt.try_borrow_mut() {
                attempt.interrupt_data();
            }
        }
    }
}

pub(super) fn counter_scratch_data() -> usize {
    crate::reference_packet::control::original_released_world_inputs_counter_scratch_data()
        + size_of::<OriginalRestoredProducerRead<'static>>()
        + size_of::<Result<OriginalRestoredProducerRead<'static>, ProviderError>>()
        + size_of::<&OriginalRestoredProducerRead<'static>>()
        + size_of::<NativeRestoredProducerAttempt>()
        + size_of::<Rc<RefCell<NativeRestoredProducerAttempt>>>()
        + size_of::<Vec<Rc<RefCell<NativeRestoredProducerAttempt>>>>()
        + size_of::<std::slice::Iter<'static, Rc<RefCell<NativeRestoredProducerAttempt>>>>()
        + size_of::<std::cell::Ref<'static, NativeRestoredProducerAttempt>>()
        + size_of::<std::cell::RefMut<'static, NativeRestoredProducerAttempt>>()
        + size_of::<Result<std::cell::Ref<'static, NativeRestoredProducerAttempt>, std::cell::BorrowError>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeRestoredProducerAttempt>, std::cell::BorrowMutError>>()
        + size_of::<Result<std::cell::Ref<'static, NativeRestoredProducerAttempt>, ProviderError>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeRestoredProducerAttempt>, ProviderError>>()
        + size_of::<Option<&Rc<RefCell<NativeRestoredProducerAttempt>>>>()
        + size_of::<Result<&Rc<RefCell<NativeRestoredProducerAttempt>>, ProviderError>>()
        + size_of::<std::cell::Ref<'static, Envelope>>()
        + size_of::<Result<std::cell::Ref<'static, Envelope>, ProviderError>>()
        + size_of::<Result<std::cell::Ref<'static, Envelope>, std::cell::Ref<'static, NativeRestoredProducerAttempt>>>()
        + size_of::<std::cell::Cell<bool>>() * 3 + size_of::<std::cell::Cell<Option<usize>>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<crucible_node_format::Position, ProviderError>>()
        + size_of::<Option<usize>>() + size_of::<Result<Option<usize>, ProviderError>>()
        + crate::reference_packet::service::native_startup::native_closed_producer_action_counter_scratch_data()
        + crate::connection::original_restored_producer_receive_counter_scratch_data()
        + crate::reference_packet::control::original_restored_producer_control_counter_scratch_data()
        + crate::reference_packet::endpoint::original_restored_producer_endpoint_counter_scratch_data()
}
