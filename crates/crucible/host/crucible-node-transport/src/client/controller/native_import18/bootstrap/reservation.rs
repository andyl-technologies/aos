//! Reserves the assigned bootstrap literal beneath unchanged original custody.
//!
//! The Source admits the complete holder and concrete supervisor callback before
//! entry. This bridge preserves an initialized slot after either outcome and
//! supplies no proof, publication, Source completion or native readiness.

use super::*;
use crate::client::{ClientSession, DeadlineStream};
use crate::connection::Connection;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapReservationRowData,
    native_import18_bootstrap_envelope_projection_data,
};

impl CnpController {
    /// Quotes the original literal slot and its definition/incident windows.
    ///
    /// The caller retains this row, ends all loans and independently admits the
    /// whole Source/Controller/Hello holder and actual supervisor callback. This
    /// quote allocates nothing and reserves neither bytes nor a descriptor.
    ///
    /// # Errors
    /// Refuses a spent or failed owner, changed original inputs/frontier/cut,
    /// insufficient already allocated literal capacity or short restriction.
    pub fn quote_original_native_import18_bootstrap_reservation_data(
        &self,
        hello: &OriginalHelloJournal,
        owner: &OriginalNativeImport18Bootstrap,
        maximum: usize,
    ) -> Result<PacketNativeImport18BootstrapReservationRowData, ProviderError> {
        if owner.failed
            || !owner.retained
            || owner.reservation_started
            || owner.literal_slot.is_some()
        {
            return Err(invalid());
        }
        let result = quote_after_assignment(self, hello, owner, maximum);
        let terminal = authenticate_cut(self, owner);
        let row = result?;
        terminal?;
        Ok(row)
    }

    /// Reserves the actual retained SDK's sole original Bootstrap literal slot.
    ///
    /// The attempt and its admitted component row are saved before fallible
    /// authentication. Every initialized slot stays in the same owner, including
    /// when request-ID retention or a terminal original-cut check refuses. No
    /// retry path resets the attempt, Session sequence, bank or original clock.
    ///
    /// # Errors
    /// Refuses repeated entry, failed typed custody, changed Hello/Controller/
    /// frontier, changed component row, expired cut or exhausted literal bank.
    pub fn reserve_original_native_import18_bootstrap_data(
        &mut self,
        hello: &OriginalHelloJournal,
        owner: &mut OriginalNativeImport18Bootstrap,
        row: &PacketNativeImport18BootstrapReservationRowData,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        if owner.failed
            || !owner.retained
            || owner.reservation_started
            || owner.literal_slot.is_some()
        {
            return Err(invalid());
        }
        owner.reservation_started = true;
        owner.failed = true;
        owner.reservation_row = Some(*row);

        let result = (|| {
            if quote_after_assignment(self, hello, owner, maximum)? != *row {
                return Err(invalid());
            }
            let original = owner
                .assignment
                .as_ref()
                .ok_or_else(invalid)?
                .borrowed_history_data()
                .original
                .ok_or_else(invalid)?;
            self.session.reserve_original_bootstrap_data(
                original,
                owner.request.as_ref().ok_or_else(invalid)?,
                owner.cut.ok_or_else(invalid)?,
                row.maximum_payload_bytes_data(),
                &mut owner.literal_slot,
            )
        })();
        let terminal = authenticate_cut(self, owner);
        result?;
        terminal?;
        owner.reserved = true;
        owner.failed = false;
        Ok(())
    }

    /// Names original custody, quote, SDK, cut and saved-slot control layouts.
    pub fn original_native_import18_bootstrap_reservation_counter_scratch_data() -> usize {
        Self::original_native_import18_bootstrap_assignment_counter_scratch_data()
            + ClientSession::original_bootstrap_effect_cut_counter_scratch_data()
            + Connection::<DeadlineStream>::original_bootstrap_reservation_counter_scratch_data()
            + size_of::<&mut Self>()
            + size_of::<&mut OriginalNativeImport18Bootstrap>()
            + size_of::<&PacketNativeImport18BootstrapReservationRowData>()
            + size_of::<PacketNativeImport18BootstrapReservationRowData>() * 2
            + size_of::<Result<PacketNativeImport18BootstrapReservationRowData, ProviderError>>()
            + size_of::<OriginalProtocolStorageFacts>()
            + size_of::<OperationalDeadline>()
            + size_of::<Option<usize>>()
            + size_of::<&mut Option<usize>>()
            + size_of::<&Envelope>()
            + size_of::<[usize; 3]>() * 2
            + size_of::<[Result<(), ProviderError>; 2]>()
    }
}

fn authenticate_cut(
    controller: &CnpController,
    owner: &OriginalNativeImport18Bootstrap,
) -> Result<(), ProviderError> {
    controller
        .session
        .authenticate_original_bootstrap_effect_cut_data(owner.cut.ok_or_else(invalid)?, 2)
}

fn quote_after_assignment(
    controller: &CnpController,
    hello: &OriginalHelloJournal,
    owner: &OriginalNativeImport18Bootstrap,
    maximum: usize,
) -> Result<PacketNativeImport18BootstrapReservationRowData, ProviderError> {
    let history = owner
        .assignment
        .as_ref()
        .ok_or_else(invalid)?
        .borrowed_history_data();
    if !history.assigned || history.failed || history.original.is_none() {
        return Err(invalid());
    }
    owner.row.authenticate_data(
        controller,
        hello,
        &owner.row.recipe,
        &owner.row.initial,
        owner.request_id.as_ref().ok_or_else(invalid)?,
        owner.request.as_ref().ok_or_else(invalid)?,
        storage::checked_sum_data(&owner.row.axes)?,
    )?;
    authenticate_cut(controller, owner)?;

    let projection = native_import18_bootstrap_envelope_projection_data(maximum)?;
    let payload = projection.maximum_encoded_bytes_data()[0];
    let framed = payload.checked_add(4).ok_or_else(credit)?;
    let bank = controller.original_native5_storage_facts()?;
    let descriptors = bank
        .incoming_frames
        .checked_add(bank.outgoing_frames)
        .ok_or_else(credit)?;
    if !bank.all_io_complete
        || payload > bank.maximum_frame_bytes
        || bank.outgoing_frames >= bank.maximum_frames_per_direction
        || descriptors >= bank.descriptor_capacity
        || bank
            .retained_bytes
            .checked_add(framed)
            .is_none_or(|bytes| bytes > bank.maximum_history_bytes)
    {
        return Err(credit());
    }
    let mut axes =
        Connection::<DeadlineStream>::original_bootstrap_reservation_construction_data(maximum)?;
    axes[0] = axes[0]
        .checked_add(size_of::<PacketNativeImport18BootstrapReservationRowData>())
        .ok_or_else(credit)?;
    axes[2] = axes[2]
        .checked_add(
            CnpController::original_native_import18_bootstrap_reservation_counter_scratch_data(),
        )
        .ok_or_else(credit)?;
    if storage::checked_sum_data(&axes)? > maximum {
        return Err(credit());
    }
    Ok(PacketNativeImport18BootstrapReservationRowData {
        axes,
        maximum_payload_bytes: payload,
    })
}
