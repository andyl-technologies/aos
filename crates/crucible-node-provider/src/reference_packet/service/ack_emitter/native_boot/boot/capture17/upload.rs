//! Spends one complete prospective upload phase under its real receive scope.
//!
//! The actual Source-assigned original, same Boot/index/Rc, independently
//! admitted receiver and complete prospective Blob/terminal/transport demand
//! precede every effect. The private action cannot be reconstructed from the
//! retained quote or a historical successful reply. Upload completion gives no
//! model, scheduling, consuming-schema or current-checkpoint permission.

use super::*;
use crate::blob::{
    BlobReceiver, NativeCapture17UploadInput, NativeCapture17UploadStorageData,
    capture17_upload_counter_scratch_data,
};
use crate::client::DeadlineStream;
use crate::connection::{
    OriginalPacketPrefixProjectionInput, OriginalPacketPrefixProjectionStorageData,
};
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::reference_packet::service::restored_input_reactive17::observation_geometry::{
    Observation17OriginalData, prospective_counter_scratch_data,
};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
};
use crucible_node_contract::U64;

/// Borrows an actually debited same-occurrence upload effect exactly once.
pub(crate) struct NativeCapture17UploadSpentAction<'a> {
    scope: &'a OriginalNativeCapture17Read,
    storage: &'a NativeCapture17UploadStorageData,
    effect_started: Cell<bool>,
    reply_started: Cell<bool>,
}

impl OriginalNativeCapture17Read {
    fn authenticate_private_upload_slot_data(&self) -> Result<(), ProviderError> {
        if self.complete.get() || !self.source_verified.get() {
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

    /// Quotes and spends Blob, owning reply and real transport before mutation.
    ///
    /// The installed live Connection binds its actual receiver ledger. The
    /// independently derived complete future phase row must
    /// fit both this Source-signed phase and the genuine native reservation.
    /// This first assigned branch accepts BlobBegin only. Later Chunk/Finish
    /// require the separate actual completed seed/custody chronology.
    ///
    /// # Errors
    /// Refuses repeated preparation, changed parents/literal, another assigned
    /// phase, unsupported chronology, short scratch/row or a failed once owner.
    pub(crate) fn prepare_assigned_upload17_data(
        &self,
        connection: &Connection<DeadlineStream>,
        receiver: &BlobReceiver,
        control: &PacketControl,
        records: &Vec<ExchangeRecord>,
        first_outgoing: u64,
    ) -> Result<OriginalPacketPrefixProjectionStorageData<0>, ProviderError> {
        if self.upload_preparing.replace(true) || self.upload_action_started.get() {
            return Err(refused());
        }
        self.authenticate_slot_data(connection)?;
        self.authenticate_private_upload_slot_data()?;
        // The prospective quote itself runs beneath its defining fixed scratch
        // bound. In particular no generic Bytes serializer is invoked here.
        let fixed = native_capture17_upload_scope_counter_scratch_data();
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
        }
        connection.authenticate_native_capture17_upload_receiver_data(receiver)?;
        NativeAckBoot::authenticate_original_observation17_ancestry_data(
            &self.boot, connection, control, records,
        )?;
        let mut attempt = self.attempt.try_borrow_mut().map_err(|_| refused())?;
        let child = attempt.capture_upload17_data_mut()?;
        let (original, input, signed) = child.assigned_upload17_quote_parts_data()?;
        if signed.declared_counter_scratch_bytes.get() < quantity(fixed)?.get() {
            return Err(exhausted());
        }
        connection.authenticate_original_native_capture17_literal_data(
            original,
            self.incoming_slot.get().ok_or_else(refused)?,
        )?;
        connection.authenticate_native_capture17_incoming_data(original)?;
        let maximum = usize::try_from(signed.requested_peak_data()?).map_err(|_| exhausted())?;
        let storage = receiver.quote_capture17_upload_storage_data(input, maximum)?;
        let original_shape = project_original_data(original, maximum)?;
        let terminal_shape = project_terminal_data(receiver, &storage, input, original, maximum)?;
        let prefix = connection.quote_original_capture17_upload_prefix_projection_storage_data(
            first_outgoing,
            original,
            OriginalPacketPrefixProjectionInput {
                terminal: &terminal_shape,
                original: &original_shape,
                objects: &[],
                maximum_requested_bytes: maximum,
            },
        )?;
        let mut transport = prefix.capture17_upload_transport_storage_data()?;
        if records.len() == records.capacity() {
            // The Endpoint's actual replacement bank coexists with its old one.
            // Length is not credited as if it were already spare capacity.
            let target = records.len().checked_add(1).ok_or_else(exhausted)?;
            let replacement = target
                .checked_mul(size_of::<ExchangeRecord>())
                .ok_or_else(exhausted)?;
            transport.retained_requested_bytes = transport
                .retained_requested_bytes
                .checked_add(quantity(replacement)?)?;
        }
        let row = combined_row(
            storage.row_data(),
            transport,
            terminal_shape.retained_value_backing_bytes,
            storage.reply_storage_data().retained_value_backing_bytes,
            fixed,
        )?;
        signed.authenticate_actual_data(&row)?;
        // The same actual receiver and original remain immutable throughout
        // quotation. No modeled graph census supplies allocation credit.
        {
            let mut owner = self.boot.try_borrow_mut().map_err(|_| refused())?;
            owner
                .restored_settled
                .as_mut()
                .ok_or_else(refused)?
                .begin_action_data(&self.boot, self.index, row)?;
        }
        self.upload_action_started.set(true);
        *self
            .upload_storage
            .try_borrow_mut()
            .map_err(|_| refused())? = Some(storage.duplicate_correspondence_data());
        child.install_upload17_action_data(storage, row)?;
        Ok(prefix)
    }

    /// Executes the admitted real receiver and retains its completed reply.
    ///
    /// # Errors
    /// Refuses absent/reused preparation, another actual receiver/input or a
    /// primitive/reply/fence failure; all existing partials remain in this slot.
    pub(crate) fn execute_assigned_upload17_data(
        &self,
        receiver: &mut BlobReceiver,
    ) -> Result<(), ProviderError> {
        self.authenticate_private_upload_slot_data()?;
        if !self.upload_action_started.get() {
            return Err(refused());
        }
        self.attempt
            .try_borrow_mut()
            .map_err(|_| refused())?
            .capture_upload17_data_mut()?
            .execute_assigned_upload17_data(receiver, self)?;
        self.authenticate_private_upload_slot_data()
    }

    /// Borrows the real successful reply for one independently priced builder.
    ///
    /// The temporary PacketControlReply owns one extra body copy for the
    /// existing ordinary builder API. That distinct transient is prepaid in
    /// the complete phase row; its empty evidence Vec allocates no bank.
    ///
    /// # Errors
    /// Refuses absent/failed production, repeated publication, changed native
    /// custody or callback/after-fence failure. No model currency is returned.
    pub(crate) fn with_prepared_upload17_reply_data<R>(
        &self,
        inspect: impl FnOnce(
            &Envelope,
            &crate::reference_packet::control::PacketControlReply,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if self.upload_publishing.replace(true) {
            return Err(refused());
        }
        self.authenticate_private_upload_slot_data()?;
        let mut attempt = self.attempt.try_borrow_mut().map_err(|_| refused())?;
        let child = attempt.capture_upload17_data_mut()?;
        child.begin_upload17_publication_data()?;
        drop(attempt);
        let attempt = self.attempt.try_borrow().map_err(|_| refused())?;
        let child = attempt.capture_upload17_data()?;
        let (original, body) = child.prepared_upload17_reply_parts_data()?;
        let reply = crate::reference_packet::control::PacketControlReply {
            body: body.clone(),
            evidence: Vec::new(),
        };
        let result = inspect(original, &reply);
        self.authenticate_private_upload_slot_data()?;
        result
    }

    /// Keeps the actual sole prepared response before ordinary publication IO.
    ///
    /// # Errors
    /// Refuses another record shape, missing normal reply or changed terminal.
    pub(crate) fn retain_upload17_terminal_data(
        &self,
        record: &ExchangeRecord,
    ) -> Result<(), ProviderError> {
        self.authenticate_private_upload_slot_data()?;
        let [terminal] = record.originals() else {
            return Err(refused());
        };
        if !self.upload_publishing.get() {
            return Err(refused());
        }
        self.attempt
            .try_borrow_mut()
            .map_err(|_| refused())?
            .capture_upload17_data_mut()?
            .retain_upload17_terminal_data(terminal)
    }

    /// Closes only one actually sent zero-evidence ordinary upload exchange.
    ///
    /// This proves transport/custody completion, never a newest model proof.
    /// Current checkpoint selection must independently validate the actual
    /// signed upload prefix bridge before skipping this grant-free occurrence.
    ///
    /// # Errors
    /// Refuses repeated/partial publication, changed source/first ancestry,
    /// another terminal/literal/record or unresolved ordinary correlation.
    pub(crate) fn complete_upload17_publication_data(
        &self,
        connection: &Connection<DeadlineStream>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        if self.upload_finishing.replace(true) || !self.upload_publishing.get() {
            return Err(refused());
        }
        self.authenticate_slot_data(connection)?;
        self.authenticate_private_upload_slot_data()?;
        NativeAckBoot::authenticate_original_observation17_ancestry_data(
            &self.boot, connection, control, records,
        )?;
        let index = records.len().checked_sub(1).ok_or_else(refused)?;
        let record = records.get(index).ok_or_else(refused)?;
        let [terminal] = record.originals() else {
            return Err(refused());
        };
        {
            let attempt = self.attempt.try_borrow().map_err(|_| refused())?;
            let child = attempt.capture_upload17_data()?;
            let (original, body) = child.prepared_upload17_reply_parts_data()?;
            if &terminal.body != body {
                return Err(refused());
            }
            connection.authenticate_original_native_capture17_literal_data(
                original,
                self.incoming_slot.get().ok_or_else(refused)?,
            )?;
            record
                .authenticate_capture17_upload_publication_data(connection, original, terminal)?;
        }
        self.attempt
            .try_borrow_mut()
            .map_err(|_| refused())?
            .capture_upload17_data_mut()?
            .complete_upload17_publication_data(terminal, index)?;
        let mut owner = self.boot.try_borrow_mut().map_err(|_| refused())?;
        let state = owner.restored_settled.as_mut().ok_or_else(refused)?;
        state.authenticate_retained_attempt_data(&self.boot, self.index, &self.attempt)?;
        state.complete_publication_data(&self.boot, self.index)?;
        self.complete.set(true);
        Ok(())
    }

    /// Runs one private action callback under its actual predebited quote.
    ///
    /// The real transaction owns all initialized receiver/result/reply fields.
    /// The retained quotation is independently compared before and after even
    /// when the callback fails; it never substitutes for the Source or once
    /// checks held by this unconstructible native receive scope.
    ///
    /// # Errors
    /// Refuses repeated execution, replaced quotes, changed native custody or
    /// any callback/after-fence failure. No spent state is reopened or refunded.
    pub(crate) fn with_spent_upload_action17_data<R>(
        &self,
        storage: &NativeCapture17UploadStorageData,
        inspect: impl FnOnce(&NativeCapture17UploadSpentAction<'_>) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        if self.upload_executing.replace(true) || !self.upload_action_started.get() {
            return Err(refused());
        }
        self.authenticate_private_upload_slot_data()?;
        let quoted = self.upload_storage.try_borrow().map_err(|_| refused())?;
        let quoted = quoted.as_ref().ok_or_else(refused)?;
        quoted.authenticate_same_quotation_data(storage)?;
        let action = NativeCapture17UploadSpentAction {
            scope: self,
            storage,
            effect_started: Cell::new(false),
            reply_started: Cell::new(false),
        };
        let result = inspect(&action);
        self.authenticate_private_upload_slot_data()?;
        quoted.authenticate_same_quotation_data(storage)?;
        result
    }
}

impl NativeCapture17UploadSpentAction<'_> {
    fn authenticate_data(
        &self,
        storage: &NativeCapture17UploadStorageData,
    ) -> Result<(), ProviderError> {
        if !std::ptr::eq(self.storage, storage) || !self.scope.upload_action_started.get() {
            return Err(refused());
        }
        self.scope.authenticate_private_upload_slot_data()
    }

    /// Starts the actual primitive after its exact unchanged prestate check.
    ///
    /// # Errors
    /// Refuses another quote/receiver/input, changed native ownership or retry.
    pub(crate) fn begin_upload_effect_data(
        &self,
        receiver: &BlobReceiver,
        storage: &NativeCapture17UploadStorageData,
        input: NativeCapture17UploadInput<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_data(storage)?;
        if self.effect_started.replace(true) {
            return Err(refused());
        }
        storage.authenticate_data(receiver, input)
    }

    /// Starts reply work after the real transaction has checked its result.
    ///
    /// The Blob producer independently proves actual successful result and
    /// full poststate before entering this method. This fence authenticates
    /// static owner/input and once state; it never reapplies stale prestate.
    ///
    /// # Errors
    /// Refuses another quote/receiver/input or absent/repeated effect/reply.
    pub(crate) fn begin_upload_reply_data(
        &self,
        receiver: &BlobReceiver,
        storage: &NativeCapture17UploadStorageData,
        input: NativeCapture17UploadInput<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_data(storage)?;
        if !self.effect_started.get() || self.reply_started.replace(true) {
            return Err(refused());
        }
        storage.authenticate_owner_input_data(receiver, input)
    }
}

fn project_original_data(
    original: &Envelope,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut out = OriginalSerializationStorageProjection::new(maximum)?;
    Observation17OriginalData::Actual(original).project(&mut out)?;
    out.finish(maximum)
}

fn project_terminal_data(
    receiver: &BlobReceiver,
    storage: &NativeCapture17UploadStorageData,
    input: NativeCapture17UploadInput<'_>,
    original: &Envelope,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut out = OriginalSerializationStorageProjection::new(maximum)?;
    out.add_object()?;
    for key in [
        "protocol",
        "message",
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
        "sequence",
        "method",
        "body",
        "extensions",
    ] {
        out.add_field(key)?;
    }
    out.add_string("CNP/1")?;
    out.add_value(&crate::envelope::MessageKind::Response)?;
    out.add_value(&original.session_id)?;
    out.add_value(&original.incarnation_id)?;
    out.add_value(&original.node_id)?;
    out.add_value(&original.execution_owner_id)?;
    out.add_value(&original.capture_owner_id)?;
    out.add_value(&original.request_id)?;
    out.add_value(&original.operation_id)?;
    out.add_unescaped_ascii_extent(20)?;
    out.add_value(&original.method)?;
    receiver.project_capture17_upload_reply_data(storage, input, &mut out)?;
    out.add_object()?;
    out.finish(maximum)
}

fn combined_row(
    blob: PacketNativeStartupAllocationRow,
    transport: PacketNativeStartupAllocationRow,
    terminal_retained: usize,
    reply_temporary: usize,
    fixed: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: blob
            .retained_requested_bytes
            .checked_add(transport.retained_requested_bytes)?
            // The retained ingress terminal owns its full Envelope separately
            // from outgoing plans/guard/containment. Its body is conservatively
            // counted again here; those transport banks cannot fund its header.
            .checked_add(quantity(terminal_retained)?)?,
        maximum_simultaneous_transient_bytes: blob
            .maximum_simultaneous_transient_bytes
            .checked_add(transport.maximum_simultaneous_transient_bytes)?
            .checked_add(quantity(reply_temporary)?)?,
        declared_counter_scratch_bytes: blob
            .declared_counter_scratch_bytes
            .checked_add(transport.declared_counter_scratch_bytes)?
            .checked_add(quantity(fixed)?)?,
    })
}

fn quantity(value: usize) -> Result<U64, ProviderError> {
    u64::try_from(value).map(U64::new).map_err(|_| exhausted())
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("Capture17 complete upload phase storage")
}

/// Names actual scope, Blob, projection and same-occurrence fixed headers.
pub(crate) fn native_capture17_upload_scope_counter_scratch_data() -> usize {
    size_of::<NativeCapture17UploadSpentAction<'static>>()
        + size_of::<&OriginalNativeCapture17Read>()
        + size_of::<Ref<'static, Option<NativeCapture17UploadStorageData>>>()
        + size_of::<OriginalPacketPrefixProjectionStorageData<0>>()
        + size_of::<OriginalPacketPrefixProjectionInput<'static>>()
        + size_of::<OriginalSerializationStorageData>() * 2
        + size_of::<OriginalSerializationStorageProjection>()
        + size_of::<crate::reference_packet::control::PacketControlReply>()
        + size_of::<Result<crate::reference_packet::control::PacketControlReply, ProviderError>>()
        + size_of::<&Connection<DeadlineStream>>()
        + size_of::<&BlobReceiver>()
        + size_of::<&mut BlobReceiver>()
        + size_of::<&Vec<ExchangeRecord>>()
        + size_of::<&[ExchangeRecord]>()
        + size_of::<&PacketControl>()
        + size_of::<Ref<'static, NativeAckBoot>>()
        + size_of::<std::cell::RefMut<'static, NativeAckBoot>>()
        + size_of::<Ref<'static, NativeRestoredSettledActionAttempt>>()
        + size_of::<std::cell::RefMut<'static, NativeRestoredSettledActionAttempt>>()
        + size_of::<&crate::reference_packet::service::native_startup::NativeRestoredSettledCaptureUploadAttempt>()
        + size_of::<&Envelope>()
        + size_of::<Result<(), crucible_node_contract::ContractError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<PacketNativeStartupAllocationRow>() * 4
        + size_of::<NativeCapture17UploadInput<'static>>()
        + size_of::<[&str; 13]>()
        + size_of::<std::array::IntoIter<&'static str, 13>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<OriginalPacketPrefixProjectionStorageData<0>, ProviderError>>()
        + crate::reference_packet::endpoint::native_capture17_upload_endpoint_counter_scratch_data()
        + crate::connection::original_native17_publication_literal_counter_scratch_data()
        + crate::reference_packet::service::native_startup::native_capture17_upload_action_counter_scratch_data()
        + capture17_upload_counter_scratch_data()
        + crate::reference_packet::service::native_startup::original_restored_settled_capture_upload_ingress_counter_scratch_data()
        + prospective_counter_scratch_data()
        + Connection::<DeadlineStream>::capture17_upload_prefix_counter_scratch_data()
        + crate::reference_packet::service::ack_emitter::original_observation17_checkpoint_owner_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::MessageKind;
    use serde_json::json;

    #[test]
    fn retained_terminal_is_independent_of_blob_body_and_transport_owners() {
        // This is actual Envelope allocation geometry, without Source/native
        // grants. The real ingress keeps this entire terminal after publishing.
        let mut terminal = crate::envelope::tests::request();
        terminal.message = MessageKind::Response;
        terminal.method = Method::BlobBegin;
        terminal.body = json!({
            "status":"completed", "operation_state":"completed",
            "result":{"transfer_id":"upload", "next_offset":"0", "maximum_chunk_bytes":"4096"},
            "extensions":{},
        })
        .as_object()
        .unwrap()
        .clone();
        let terminal = project_original_data(&terminal, 2 * 1024 * 1024).unwrap();
        assert!(terminal.retained_value_backing_bytes > 0);
        let blob = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(101),
            maximum_simultaneous_transient_bytes: U64::new(103),
            declared_counter_scratch_bytes: U64::new(107),
        };
        let transport = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(109),
            maximum_simultaneous_transient_bytes: U64::new(113),
            declared_counter_scratch_bytes: U64::new(127),
        };

        let actual = combined_row(
            blob,
            transport,
            terminal.retained_value_backing_bytes,
            131,
            137,
        )
        .unwrap();

        assert_eq!(
            actual.retained_requested_bytes.get(),
            210 + u64::try_from(terminal.retained_value_backing_bytes).unwrap()
        );
        assert_eq!(actual.maximum_simultaneous_transient_bytes.get(), 347);
        assert_eq!(actual.declared_counter_scratch_bytes.get(), 371);
        actual.authenticate_actual_data(&actual).unwrap();
        let mut short = actual;
        short.retained_requested_bytes = U64::new(actual.retained_requested_bytes.get() - 1);
        assert!(short.authenticate_actual_data(&actual).is_err());
        let overflowing = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(u64::MAX),
            ..blob
        };
        assert!(
            combined_row(
                overflowing,
                transport,
                terminal.retained_value_backing_bytes,
                131,
                137
            )
            .is_err()
        );
    }
}
