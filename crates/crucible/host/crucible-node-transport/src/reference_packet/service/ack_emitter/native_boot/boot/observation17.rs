//! Drives one Source-authenticated Observe17 in its actual spent receive slot.
//!
//! The first/latest native lender, full literal prefix, Source MAC, independent
//! prospective debit and stopped-model comparison are separate conjuncts. Only
//! their private consuming path constructs the spent Control action. Every
//! unfinished scope poisons both actual retained owners without refunding them.

use super::NativeAckBoot;
use crate::connection::OriginalPacketPrefixProjectionStorageDataExt;
use crate::connection::{
    Connection, ExchangeRecord, OriginalContinuationContentExtent,
    OriginalPacketPrefixProjectionInput, OriginalPacketPrefixProjectionStorageData, ProviderStream,
};
use crate::reference_packet::control::{
    NativeObservation17ProducerStorageData, PacketControl, PacketControlReply,
};
use crate::reference_packet::service::native_startup::{
    NativeRestoredSettledActionAttempt, NativeRestoredSettledActionFamily17,
    PacketNativeStartupAllocationRow,
};
use crate::reference_packet::service::restored_input_reactive17::RESTORED_INPUT_REACTIVE17_FEATURE;
use crate::{ProviderError, envelope::Envelope};
use crucible_node_format::U64;
use std::{
    cell::{Cell, Ref, RefCell},
    mem::size_of,
    rc::Rc,
};

/// Owns one real receive occurrence; no historical DATA constructs this scope.
pub(crate) struct OriginalNativeObservation17Read {
    boot: Rc<RefCell<NativeAckBoot>>,
    index: usize,
    attempt: Rc<RefCell<NativeRestoredSettledActionAttempt>>,
    frame: usize,
    receiving: Cell<bool>,
    raw: Cell<bool>,
    incoming_slot: Cell<Option<usize>>,
    source_verified: Cell<bool>,
    action_started: Cell<bool>,
    producing: Cell<bool>,
    preparing: Cell<bool>,
    finishing: Cell<bool>,
    complete: Cell<bool>,
}

/// Lends a privately spent same-occurrence producer action exactly once.
///
/// This is never serialized, cloned, deserialized or constructed by a row,
/// public callback, signature DTO or historical completed-owner reader.
pub(crate) struct NativeObservation17SpentAction<'scope, 'original> {
    scope: &'scope OriginalNativeObservation17Read,
    storage: &'scope NativeObservation17ProducerStorageData<'original>,
    control_started: Cell<bool>,
}

impl NativeAckBoot {
    /// Retains an irreversible ingress before walking current ancestry or IO.
    ///
    /// # Errors
    /// Refuses unsealed/foreign/failed owners, exhausted actual ingress, missing
    /// genuine first ancestry or unsupported cold17 installation. No failure
    /// refunds its actual original slot or accumulated retained reservation.
    pub(crate) fn retain_original_observation17_read_data<S: ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<OriginalNativeObservation17Read, ProviderError> {
        let (frame, index, attempt) = {
            let mut owner = boot.try_borrow_mut().map_err(|_| refused())?;
            owner.ensure_origin()?;
            let state = owner.restored_settled.as_mut().ok_or_else(refused)?;
            let frame = state.sealed_storage_data(boot)?.maximum_frame_bytes_data();
            let index = state.begin_receive_data(boot)?;
            let attempt = match state.retained_attempt_data(boot, index) {
                Ok(attempt) => attempt,
                Err(error) => {
                    state.interrupt();
                    return Err(error);
                }
            };
            (frame, index, attempt)
        };
        let scope = OriginalNativeObservation17Read {
            boot: Rc::clone(boot),
            index,
            attempt,
            frame,
            receiving: Cell::new(false),
            raw: Cell::new(false),
            incoming_slot: Cell::new(None),
            source_verified: Cell::new(false),
            action_started: Cell::new(false),
            producing: Cell::new(false),
            preparing: Cell::new(false),
            finishing: Cell::new(false),
            complete: Cell::new(false),
        };
        Self::authenticate_original_observation17_ancestry_data(
            boot, connection, control, records,
        )?;
        scope.authenticate_slot_data(connection)?;
        Ok(scope)
    }
}

impl OriginalNativeObservation17Read {
    fn authenticate_slot_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        if self.complete.get() {
            return Err(refused());
        }
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        // The genuine ancestry constructor/lender proves verified Initial15
        // Commit and installed mapping. The old selected-class getter is an
        // installation-time Prepare cut and is deliberately not reused here.
        if !Rc::ptr_eq(&self.boot, &admission.boot) {
            return Err(refused());
        }
        self.authenticate_private_slot_data()
    }

    fn authenticate_private_slot_data(&self) -> Result<(), ProviderError> {
        if self.complete.get() {
            return Err(refused());
        }
        let owner = self.boot.try_borrow().map_err(|_| refused())?;
        owner.ensure_origin()?;
        owner
            .restored_settled
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_retained_attempt_data(&self.boot, self.index, &self.attempt)
    }

    /// Starts the single actual read beneath its prepaid private ingress.
    ///
    /// # Errors
    /// Refuses repeated receives or changed real native admission/occurrence.
    pub(crate) fn begin_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        if self.receiving.replace(true) {
            return Err(refused());
        }
        self.authenticate_slot_data(connection)
    }

    /// Retains the whole raw original before closed shape, policy or MAC checks.
    ///
    /// # Errors
    /// Refuses repeated raw input, another family/method or typed partial failure.
    /// Raw and every initialized child remain in this same actual native bank.
    pub(crate) fn retain_original_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: Envelope,
    ) -> Result<(), ProviderError> {
        if !self.receiving.get() || self.raw.replace(true) {
            return Err(refused());
        }
        self.attempt
            .try_borrow_mut()
            .map_err(|_| refused())?
            .retain_original_data(original)?;
        self.authenticate_slot_data(connection)?;
        let mut attempt = self.attempt.try_borrow_mut().map_err(|_| refused())?;
        attempt.decode_body_data(self.frame)?;
        if attempt.family_data()? != NativeRestoredSettledActionFamily17::InputReactive
            || attempt.original_data()?.method != crate::envelope::Method::Observe
            || !attempt
                .original_data()?
                .extensions
                .contains_key(RESTORED_INPUT_REACTIVE17_FEATURE)
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Borrows the actual retained raw original without granting dispatch.
    ///
    /// # Errors
    /// Refuses missing or conflicting actual retained custody.
    pub(crate) fn original_data(&self) -> Result<Ref<'_, Envelope>, ProviderError> {
        let attempt = self.attempt.try_borrow().map_err(|_| refused())?;
        Ref::filter_map(attempt, |attempt| attempt.original_data().ok()).map_err(|_| refused())
    }

    /// Retains the actual incoming literal slot after successful guard receive.
    ///
    /// # Errors
    /// Refuses a second completion, incomplete raw input or changed same literal.
    pub(crate) fn complete_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_slot_data(connection)?;
        if !self.raw.get() || self.incoming_slot.get().is_some() {
            return Err(refused());
        }
        let original = self.original_data()?;
        let slot = connection.original_restored_suffix_observation_literal_slot_data(&original)?;
        self.incoming_slot.set(Some(slot));
        Ok(())
    }

    fn authenticate_received_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_slot_data(connection)?;
        if !self.receiving.get() || !self.raw.get() {
            return Err(refused());
        }
        let original = self.original_data()?;
        connection.authenticate_original_restored_suffix_observation_literal_data(
            &original,
            self.incoming_slot.get().ok_or_else(refused)?,
        )
    }

    /// Authenticates actual Source custody before any action field walk.
    ///
    /// # Errors
    /// Refuses another receive/MAC/context, stale native slot or repeated proof.
    pub(crate) fn authenticate_source_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_received_data(connection)?;
        if self.source_verified.get() || self.action_started.get() {
            return Err(refused());
        }
        let owner = self.boot.try_borrow().map_err(|_| refused())?;
        owner.ensure_origin()?;
        let key: &[u8; 32] = owner
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        self.attempt
            .try_borrow_mut()
            .map_err(|_| refused())?
            .input_reactive_data_mut()?
            .authenticate_source_proof_data(key, self.frame)?;
        drop(owner);
        self.authenticate_received_data(connection)?;
        self.source_verified.set(true);
        Ok(())
    }

    /// Produces the actual signed proof under its genuine current owner and row.
    ///
    /// The returned transport geometry owns no original/model permission. The
    /// Endpoint separately prepares and publishes its same actual cached reply;
    /// only complete terminal/all-ACK custody can close this scope.
    ///
    /// # Errors
    /// Refuses another Source/current checkpoint/scope/cut, fixed or prospective
    /// short row, stopped-model mismatch, reentry or partial native production.
    pub(crate) fn produce_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &mut PacketControl,
        records: &Vec<ExchangeRecord>,
        first_outgoing: u64,
    ) -> Result<OriginalPacketPrefixProjectionStorageData<2>, ProviderError> {
        if self.producing.replace(true) {
            return Err(refused());
        }
        self.authenticate_received_data(connection)?;
        if !self.source_verified.get() || self.action_started.get() {
            return Err(refused());
        }
        let fixed = native_observation17_scope_counter_scratch_data();
        {
            let owner = self.boot.try_borrow().map_err(|_| refused())?;
            owner
                .restored_settled
                .as_ref()
                .ok_or_else(refused)?
                .authenticate_action_counter_scratch_data(
                    &self.boot,
                    self.index,
                    &self.attempt,
                    fixed,
                )?;
            let attempt = self.attempt.try_borrow().map_err(|_| refused())?;
            if attempt
                .input_reactive_data()?
                .request_data()?
                .native_allocation
                .declared_counter_scratch_bytes
                .get()
                < u64::try_from(fixed).map_err(|_| exhausted())?
            {
                return Err(exhausted());
            }
        }
        NativeAckBoot::with_original_observation17_checkpoint_data(
            &self.boot,
            self.index,
            &self.attempt,
            connection,
            control,
            records,
            |checkpoint, control| {
                let mut attempt = self.attempt.try_borrow_mut().map_err(|_| refused())?;
                let child = attempt.input_reactive_data_mut()?;
                let (original, observe, request) = child.observation17_quote_parts_data()?;
                if request.scope != *checkpoint.scope_data() {
                    return Err(refused());
                }
                control.authenticate_observation17_ancestry_data(
                    checkpoint.first_original_data(),
                    checkpoint.first_terminal_data(),
                    request,
                )?;
                let maximum = usize::try_from(request.native_allocation.requested_peak_data()?)
                    .map_err(|_| exhausted())?;
                connection.authenticate_native_observation17_literal_prefix_data(
                    original,
                    self.incoming_slot.get().ok_or_else(refused)?,
                    request.history_next_sequence,
                    &request.history_prefix,
                    usize::try_from(request.history_prefix.length.get())
                        .map_err(|_| exhausted())?,
                )?;
                let current = control.quote_observation17_checkpoint_data(
                    checkpoint.original_data(),
                    request,
                    maximum,
                )?;
                let production = control.quote_observation17_producer_data(
                    original, observe, request, self.frame, maximum,
                )?;
                let prefix = production.prefix_storage_data(
                    connection,
                    first_outgoing,
                    original,
                    maximum,
                )?;
                let mut transport = prefix.observation17_transport_storage_data()?;
                if records.len() == records.capacity() {
                    let target = records.len().checked_add(1).ok_or_else(exhausted)?;
                    let new_bank = target
                        .checked_mul(size_of::<ExchangeRecord>())
                        .ok_or_else(exhausted)?;
                    transport.retained_requested_bytes = transport
                        .retained_requested_bytes
                        .checked_add(U64::new(u64::try_from(new_bank).map_err(|_| exhausted())?))?;
                }
                let row =
                    combined_row(current.row_data(), production.row_data(), transport, fixed)?;
                request.native_allocation.authenticate_actual_data(&row)?;
                {
                    let mut owner = self.boot.try_borrow_mut().map_err(|_| refused())?;
                    owner
                        .restored_settled
                        .as_mut()
                        .ok_or_else(refused)?
                        .begin_action_data(&self.boot, self.index, row)?;
                }
                self.action_started.set(true);
                // Quotes borrow the immutable current child. End that borrow
                // before the real Stage transition, then reborrow its exact
                // unchanged original and retained destinations below.
                drop(production);
                child.begin_dispatch_data()?;
                let (original, observe, request, destination) = child.observation17_parts_data()?;
                control.authenticate_observation17_checkpoint_into_data(
                    checkpoint.original_data(),
                    request,
                    &current,
                    destination.checkpoint_destination_data(),
                )?;
                destination.authenticate_validated_checkpoint_data()?;
                // Reconstructing the pure projection allocates nothing; it is
                // now within the independently spent same-occurrence action.
                let production = control.quote_observation17_producer_data(
                    original, observe, request, self.frame, maximum,
                )?;
                let action = NativeObservation17SpentAction {
                    scope: self,
                    storage: &production,
                    control_started: Cell::new(false),
                };
                let reply = control.produce_observation17_into_data(
                    &action,
                    original,
                    observe,
                    request,
                    destination.production_destination_data(),
                )?;
                drop(action);
                drop(production);
                child.retain_prepared_reply_data(reply)?;
                Ok(prefix)
            },
        )
    }

    /// Borrows the actual completed producer and matching Control cache reply.
    ///
    /// # Errors
    /// Refuses partial production, another current occurrence or changed cache.
    pub(crate) fn with_prepared_reply_data<R>(
        &self,
        control: &PacketControl,
        inspect: impl FnOnce(&Envelope, &PacketControlReply) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if self.preparing.replace(true) {
            return Err(refused());
        }
        if !self.action_started.get() || !self.source_verified.get() {
            return Err(refused());
        }
        self.authenticate_private_slot_data()?;
        let attempt = self.attempt.try_borrow().map_err(|_| refused())?;
        let (original, production) = attempt
            .input_reactive_data()?
            .observation17_produced_parts_data()?;
        let reply = control.borrow_observation17_produced_reply_data(original, &production)?;
        let result = inspect(original, reply);
        self.authenticate_private_slot_data()?;
        result
    }

    /// Retains the actual prepared terminal before any publication IO.
    ///
    /// # Errors
    /// Refuses absent/multiple terminal, changed prepared body or same occurrence.
    pub(crate) fn retain_prepared_terminal_data(
        &self,
        record: &ExchangeRecord,
    ) -> Result<(), ProviderError> {
        self.authenticate_private_slot_data()?;
        if !self.action_started.get() {
            return Err(refused());
        }
        let mut terminals = record
            .originals()
            .iter()
            .filter(|value| value.message == crate::envelope::MessageKind::Response);
        let terminal = terminals.next().ok_or_else(refused)?;
        if terminals.next().is_some() {
            return Err(refused());
        }
        self.attempt
            .try_borrow_mut()
            .map_err(|_| refused())?
            .input_reactive_data_mut()?
            .retain_terminal_data(terminal)
    }

    /// Closes only the same complete actual terminal and every literal proof ACK.
    ///
    /// # Errors
    /// Refuses incomplete/foreign publication, changed cached proof banks or
    /// any lost first ancestry/current slot. Failed state remains retained.
    pub(crate) fn complete_publication_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        if self.finishing.replace(true) {
            return Err(refused());
        }
        self.authenticate_received_data(connection)?;
        if !self.action_started.get() || !self.source_verified.get() {
            return Err(refused());
        }
        NativeAckBoot::authenticate_original_observation17_ancestry_data(
            &self.boot, connection, control, records,
        )?;
        let index = records.len().checked_sub(1).ok_or_else(refused)?;
        let record = records.get(index).ok_or_else(refused)?;
        {
            let attempt = self.attempt.try_borrow().map_err(|_| refused())?;
            let child = attempt.input_reactive_data()?;
            let (original, production) = child.observation17_produced_parts_data()?;
            control.borrow_observation17_produced_reply_data(original, &production)?;
            let mut terminals = record
                .originals()
                .iter()
                .filter(|value| value.message == crate::envelope::MessageKind::Response);
            let terminal = terminals.next().ok_or_else(refused)?;
            if terminals.next().is_some() || terminal.body != *production.body_data() {
                return Err(refused());
            }
            record.authenticate_observation17_publication_data(connection, original, terminal)?;
        }
        self.attempt
            .try_borrow_mut()
            .map_err(|_| refused())?
            .input_reactive_data_mut()?
            .complete_publication_observation17_data(index)?;
        let mut owner = self.boot.try_borrow_mut().map_err(|_| refused())?;
        let state = owner.restored_settled.as_mut().ok_or_else(refused)?;
        state.authenticate_retained_attempt_data(&self.boot, self.index, &self.attempt)?;
        state.complete_publication_data(&self.boot, self.index)?;
        self.complete.set(true);
        Ok(())
    }
}

impl NativeObservation17SpentAction<'_, '_> {
    pub(crate) fn storage_data(&self) -> &NativeObservation17ProducerStorageData<'_> {
        self.storage
    }

    pub(crate) fn authenticate_control_data(
        &self,
        control: &PacketControl,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        if !self.scope.source_verified.get() || !self.scope.action_started.get() {
            return Err(refused());
        }
        self.scope.authenticate_private_slot_data()?;
        self.storage.authenticate_data(control, original)
    }

    pub(crate) fn begin_control_data(
        &self,
        control: &PacketControl,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_control_data(control, original)?;
        if self.control_started.replace(true) {
            return Err(refused());
        }
        Ok(())
    }
}

impl Drop for OriginalNativeObservation17Read {
    fn drop(&mut self) {
        if self.complete.get() {
            return;
        }
        if let Ok(mut attempt) = self.attempt.try_borrow_mut() {
            attempt.interrupt_data();
        }
        if let Ok(mut owner) = self.boot.try_borrow_mut() {
            if let Some(state) = &mut owner.restored_settled {
                state.interrupt();
            }
        }
    }
}

fn combined_row(
    current: PacketNativeStartupAllocationRow,
    production: PacketNativeStartupAllocationRow,
    transport: PacketNativeStartupAllocationRow,
    scratch: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    let sum = |values: [u64; 3]| {
        values.into_iter().try_fold(0u64, |total, next| {
            total.checked_add(next).ok_or_else(exhausted)
        })
    };
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(sum([
            current.retained_requested_bytes.get(),
            production.retained_requested_bytes.get(),
            transport.retained_requested_bytes.get(),
        ])?),
        maximum_simultaneous_transient_bytes: U64::new(sum([
            current.maximum_simultaneous_transient_bytes.get(),
            production.maximum_simultaneous_transient_bytes.get(),
            transport.maximum_simultaneous_transient_bytes.get(),
        ])?),
        declared_counter_scratch_bytes: U64::new(
            sum([
                current.declared_counter_scratch_bytes.get(),
                production.declared_counter_scratch_bytes.get(),
                transport.declared_counter_scratch_bytes.get(),
            ])?
            .checked_add(u64::try_from(scratch).map_err(|_| exhausted())?)
            .ok_or_else(exhausted)?,
        ),
    })
}

/// Names the actual scope, lender, literals and independent fixed Control work.
pub(crate) fn native_observation17_scope_counter_scratch_data() -> usize {
    size_of::<OriginalNativeObservation17Read>() + size_of::<NativeObservation17SpentAction<'static, 'static>>()
        + size_of::<Ref<'static, NativeRestoredSettledActionAttempt>>()
        + size_of::<std::cell::RefMut<'static, NativeRestoredSettledActionAttempt>>()
        + size_of::<Ref<'static, NativeAckBoot>>() + size_of::<std::cell::RefMut<'static, NativeAckBoot>>()
        + size_of::<OriginalPacketPrefixProjectionStorageData<2>>() + size_of::<OriginalPacketPrefixProjectionInput<'static>>()
        + size_of::<[OriginalContinuationContentExtent<'static>; 2]>() + 4 * size_of::<PacketNativeStartupAllocationRow>()
        + size_of::<Result<(), ProviderError>>() + size_of::<Result<OriginalPacketPrefixProjectionStorageData<2>, ProviderError>>()
        + crate::reference_packet::service::ack_emitter::original_observation17_checkpoint_owner_counter_scratch_data()
        + crate::reference_packet::control::observation17_producer_counter_scratch_data()
        + crate::connection::OriginalRestoredInput17LiteralPrefixIdentityData::counter_scratch_data()
        + crate::connection::native_observation17_receive_counter_scratch_data()
        + crate::reference_packet::endpoint::native_observation17_endpoint_counter_scratch_data()
        + Connection::<crate::client::DeadlineStream>::native_observation17_prefix_counter_scratch_data()
        + crate::reference_packet::service::restored_input_reactive17::restored_input_reactive17_contract_counter_scratch_data()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("signed Observe17 requires its actual spent native occurrence")
}
fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("signed Observe17 prospective native action")
}

// crucible-lint: allow panic-shortcut -- These controls compare row DATA; they create no native permission.
#[cfg(test)]
mod row_tests {
    use super::*;

    fn row(retained: u64, transient: u64, scratch: u64) -> PacketNativeStartupAllocationRow {
        PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(retained),
            maximum_simultaneous_transient_bytes: U64::new(transient),
            declared_counter_scratch_bytes: U64::new(scratch),
        }
    }

    #[test]
    fn prospective_current_producer_transport_and_counter_rows_stay_independent() {
        let actual = combined_row(row(1, 2, 3), row(4, 5, 6), row(7, 8, 9), 10).unwrap();
        assert_eq!(actual, row(12, 15, 28));
        actual.authenticate_actual_data(&actual).unwrap();
        for short in [row(11, 15, 28), row(12, 14, 28), row(12, 15, 27)] {
            assert!(short.authenticate_actual_data(&actual).is_err());
        }
    }

    #[test]
    fn no_axis_or_fixed_counter_can_wrap_into_a_smaller_action_quote() {
        for overflow in [
            row(u64::MAX, 0, 0),
            row(0, u64::MAX, 0),
            row(0, 0, u64::MAX),
        ] {
            assert!(combined_row(overflow, row(1, 1, 1), row(0, 0, 0), 0).is_err());
        }
        assert!(combined_row(row(0, 0, u64::MAX), row(0, 0, 0), row(0, 0, 0), 1).is_err());
    }
}
