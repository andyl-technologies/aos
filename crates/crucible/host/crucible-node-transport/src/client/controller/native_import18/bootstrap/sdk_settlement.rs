//! Retains typed Bootstrap decoding and the actual SDK original before return.
//!
//! The same Source separately verifies its private context and receipt MAC.
//! Transport settlement grants no Source completion, native phase or Ready.

use super::*;
use crate::client::{ClientSession, DeadlineStream};
use crate::connection::Connection;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    native_import18_bootstrap_envelope_projection_data,
    native_import18_bootstrap_response_decode_counter_scratch_data,
    native_import18_bootstrap_response_decode_quote_data,
};
use std::mem::align_of;

impl CnpController {
    /// Quotes typed decoding beside the same retained raw response and SDK.
    ///
    /// The caller first funds this fixed counter, retains the complete returned
    /// row, ends all loans and independently admits the whole Source holder.
    /// Existing raw, materialized and journal banks stay separately retained.
    ///
    /// # Errors
    /// Refuses spent custody, changed original/Hello/raw/SDK guards, checked
    /// overflow or independently derived demand exceeding the restriction.
    pub fn quote_original_native_import18_bootstrap_sdk_settlement_data(
        &self,
        hello: &OriginalHelloJournal,
        owner: &OriginalNativeImport18Bootstrap,
        maximum: usize,
    ) -> Result<PacketNativeImport18BootstrapSdkSettlementRowData, ProviderError> {
        require_entry(owner)?;
        receive::authenticate_terminal(self, hello, owner)?;
        quote(maximum)
    }

    /// Retains typed decoding and moves the actual SDK pending request once.
    ///
    /// The attempt and row survive before fallible guards. The decoder borrows
    /// the same saved raw frame; no read, raw parse or request clone repeats.
    /// Every initialized decoder prefix and moved SDK original stays in this
    /// owner after failure. Source receipt MAC verification remains separate.
    ///
    /// # Errors
    /// Refuses repeated entry, changed original/raw/row, malformed typed response,
    /// failed SDK settlement, expired original cut or retained-byte excess.
    pub fn settle_original_native_import18_bootstrap_sdk_data(
        &mut self,
        hello: &OriginalHelloJournal,
        owner: &mut OriginalNativeImport18Bootstrap,
        row: &PacketNativeImport18BootstrapSdkSettlementRowData,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        require_entry(owner)?;
        owner.settlement_started = true;
        owner.settlement_row = Some(*row);
        owner.failed = true;

        let result = (|| {
            receive::authenticate_terminal(self, hello, owner)?;
            if quote(maximum)? != *row {
                return Err(invalid());
            }
            let history = owner
                .sealing
                .as_ref()
                .ok_or_else(invalid)?
                .borrowed_history_data();
            let original = history
                .assignment
                .ok_or_else(invalid)?
                .original
                .ok_or_else(invalid)?;
            let raw = owner.raw_response.as_ref().ok_or_else(invalid)?;
            self.session.decode_original_bootstrap_raw_into_data(
                original,
                owner.cut.ok_or_else(invalid)?,
                raw.frame.as_ref().ok_or_else(invalid)?,
                &row.component,
                maximum,
                (&mut owner.decoded_response, &mut owner.settled_request),
            )
        })();
        let census = check_retained(owner, row);
        let terminal = authenticate_terminal(self, hello, owner);
        result?;
        census?;
        terminal?;
        owner.sdk_settled = true;
        owner.failed = false;
        Ok(())
    }

    /// Names actual typed decoders, SDK move, original guards and complete census.
    pub fn original_native_import18_bootstrap_sdk_settlement_counter_scratch_data() -> usize {
        Self::original_native_import18_bootstrap_receive_counter_scratch_data()
            + native_import18_bootstrap_response_decode_counter_scratch_data()
            + crate::session::CorrelationGuard::original_bootstrap_receive_counter_scratch_data()
            + ClientSession::original_bootstrap_effect_cut_counter_scratch_data()
            + size_of::<PacketNativeImport18BootstrapSdkSettlementRowData>() * 2
            + size_of::<Result<PacketNativeImport18BootstrapSdkSettlementRowData, ProviderError>>()
            + size_of::<&mut Self>()
            + size_of::<&OriginalHelloJournal>()
            + size_of::<&mut OriginalNativeImport18Bootstrap>()
            + size_of::<&mut Option<PacketNativeImport18BootstrapResponseDecodeData>>()
            + size_of::<&mut Option<Envelope>>()
            + size_of::<[usize; 6]>()
            + size_of::<[Result<(), ProviderError>; 3]>()
    }
}

fn require_entry(owner: &OriginalNativeImport18Bootstrap) -> Result<(), ProviderError> {
    if owner.failed
        || !owner.retained
        || !owner.received
        || !owner.published
        || owner.settlement_started
        || owner.decoded_response.is_some()
        || owner.settled_request.is_some()
        || owner.sdk_settled
    {
        return Err(invalid());
    }
    Ok(())
}

fn quote(
    maximum: usize,
) -> Result<PacketNativeImport18BootstrapSdkSettlementRowData, ProviderError> {
    let component = native_import18_bootstrap_response_decode_quote_data(maximum)?;
    let mut axes = component.requested_storage_under_tree_layout_data(
        size_of::<Id>() + size_of::<Envelope>(),
        align_of::<Id>().max(align_of::<Envelope>()),
    )?;
    let projection = native_import18_bootstrap_envelope_projection_data(maximum)?;
    let moved = projection.request_native_backing_storage_data(
        size_of::<Id>() + size_of::<Envelope>(),
        align_of::<Id>().max(align_of::<Envelope>()),
    )?;
    // Containment before the SDK move can retain a separate real incident clone.
    // After the move, the Controller keeps the original in its own output slot.
    let sdk = Connection::<DeadlineStream>::original_bootstrap_sealing_construction_data(maximum)?;
    axes[0] = sum(&[
        axes[0],
        moved,
        sdk[0],
        size_of::<PacketNativeImport18BootstrapSdkSettlementRowData>(),
    ])?;
    axes[1] = sum(&[
        axes[1],
        sdk[1],
        size_of::<Envelope>(),
        size_of::<PacketNativeImport18BootstrapSdkSettlementRowData>() * 2,
    ])?;
    axes[2] = sum(&[
        axes[2],
        sdk[2],
        CnpController::original_native_import18_bootstrap_sdk_settlement_counter_scratch_data(),
    ])?;
    if sum(&axes)? > maximum {
        return Err(credit());
    }
    Ok(PacketNativeImport18BootstrapSdkSettlementRowData { component, axes })
}

fn check_retained(
    owner: &OriginalNativeImport18Bootstrap,
    row: &PacketNativeImport18BootstrapSdkSettlementRowData,
) -> Result<(), ProviderError> {
    let actual = sum(&[
        size_of::<OriginalNativeImport18Bootstrap>(),
        requested_metadata_backing_storage_data(&owner.retained_metadata_data()?)?,
    ])?;
    let admitted = sum(&[
        owner.row.axes[0],
        owner
            .materialization_row
            .as_ref()
            .ok_or_else(invalid)?
            .requested_storage_data()[0],
        owner
            .receive_row
            .as_ref()
            .ok_or_else(invalid)?
            .requested_storage_data()[0],
        row.axes[0],
    ])?;
    if actual > admitted {
        return Err(credit());
    }
    Ok(())
}

fn authenticate_terminal(
    controller: &CnpController,
    hello: &OriginalHelloJournal,
    owner: &OriginalNativeImport18Bootstrap,
) -> Result<(), ProviderError> {
    let cut = owner.cut.ok_or_else(invalid)?;
    // Measure the original clock even if an earlier decoder or SDK move failed.
    let deadline = controller
        .session
        .authenticate_original_bootstrap_effect_cut_data(cut, 3);
    let identity = signing::authenticate_original_identity_data(controller, hello, owner);
    let settled = (|| {
        let history = owner
            .sealing
            .as_ref()
            .ok_or_else(invalid)?
            .borrowed_history_data();
        let original = history
            .assignment
            .ok_or_else(invalid)?
            .original
            .ok_or_else(invalid)?;
        controller
            .session
            .authenticate_original_bootstrap_sdk_settlement_data(
                original,
                cut,
                owner.raw_response.as_ref().ok_or_else(invalid)?,
                owner.settled_request.as_ref().ok_or_else(invalid)?,
                owner.decoded_response.as_ref().ok_or_else(invalid)?,
            )
    })();
    deadline?;
    identity?;
    settled
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    storage::checked_sum_data(values)
}

#[cfg(test)]
#[path = "sdk_settlement/tests.rs"]
mod tests;
