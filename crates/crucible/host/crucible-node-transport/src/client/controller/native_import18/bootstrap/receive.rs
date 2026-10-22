//! Retains the original Bootstrap raw response under unchanged Controller custody.
//!
//! Private Source context and receipt authentication remain with the defining
//! Source. Receipt alone neither settles the SDK original nor completes a phase.

use super::*;
use crate::client::{ClientSession, DeadlineStream};
use crate::connection::Connection;

impl CnpController {
    /// Quotes raw receipt from the same actually published original Bootstrap.
    ///
    /// The caller funds this static counter first, retains the complete returned
    /// row, ends all loans and independently admits its axes beside the whole
    /// Source/Controller/Hello holder and actual supervisor callback.
    ///
    /// # Errors
    /// Refuses spent custody, changed original guards, invalid concrete bank
    /// capacity, checked overflow or demand exceeding the restriction.
    pub fn quote_original_native_import18_bootstrap_receive_data(
        &self,
        hello: &OriginalHelloJournal,
        owner: &OriginalNativeImport18Bootstrap,
        maximum_body_bytes: usize,
        maximum_requested: usize,
    ) -> Result<PacketNativeImport18BootstrapReceiveRowData, ProviderError> {
        require_entry(owner)?;
        publication::authenticate(self, hello, owner, true, true)?;
        self.check_bootstrap_raw_capacity(maximum_body_bytes)?;
        quote(maximum_body_bytes, maximum_requested)
    }

    /// Retains the receipt attempt and row before fallible guards or public I/O.
    ///
    /// The same owner keeps the physical header/body, closed preflight and strict
    /// tree after either outcome. The original SDK request remains pending for
    /// separately admitted typed decoding and private Source receipt verification.
    /// This method supplies no Source completion or subsequent phase permission.
    ///
    /// # Errors
    /// Refuses repeated entry, changed identity/cut/row, physical receipt or parse
    /// failure, changed terminal custody or actual backing beyond admission.
    pub fn receive_original_native_import18_bootstrap_data(
        &mut self,
        hello: &OriginalHelloJournal,
        owner: &mut OriginalNativeImport18Bootstrap,
        row: &PacketNativeImport18BootstrapReceiveRowData,
        maximum_requested: usize,
    ) -> Result<(), ProviderError> {
        require_entry(owner)?;
        owner.receive_started = true;
        owner.receive_row = Some(*row);
        owner.failed = true;

        let result = (|| {
            publication::authenticate(self, hello, owner, true, true)?;
            self.check_bootstrap_raw_capacity(row.component.maximum_body_bytes_data())?;
            if quote(row.component.maximum_body_bytes_data(), maximum_requested)? != *row {
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
            self.session.receive_original_bootstrap_response_into_data(
                original,
                owner.cut.ok_or_else(invalid)?,
                &row.component,
                maximum_requested,
                &mut owner.raw_response,
            )
        })();
        let census = check_retained(owner, row);
        let terminal = authenticate_terminal(self, hello, owner);
        result?;
        census?;
        terminal?;
        owner.received = true;
        owner.failed = false;
        Ok(())
    }

    fn check_bootstrap_raw_capacity(&self, maximum: usize) -> Result<(), ProviderError> {
        if maximum == 0
            || maximum
                > usize::try_from(self.session.authority().limits().frame_bytes.get())
                    .map_err(|_| credit())?
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Names actual receipt, parser, Controller identity and whole-owner controls.
    pub fn original_native_import18_bootstrap_receive_counter_scratch_data() -> usize {
        Self::original_native_import18_bootstrap_sdk_counter_scratch_data()
            + Connection::<DeadlineStream>::original_bootstrap_raw_response_counter_scratch_data()
            + ClientSession::original_bootstrap_effect_cut_counter_scratch_data()
            + size_of::<PacketNativeImport18BootstrapReceiveRowData>() * 2
            + size_of::<Result<PacketNativeImport18BootstrapReceiveRowData, ProviderError>>()
            + size_of::<&mut Self>()
            + size_of::<&OriginalHelloJournal>()
            + size_of::<&mut OriginalNativeImport18Bootstrap>()
            + size_of::<&PacketNativeImport18BootstrapRawResponseData>()
            + size_of::<[usize; 5]>()
            + size_of::<[Result<(), ProviderError>; 3]>()
    }
}

fn require_entry(owner: &OriginalNativeImport18Bootstrap) -> Result<(), ProviderError> {
    if owner.failed
        || !owner.retained
        || !owner.sdk_sealed
        || !owner.published
        || owner.receive_started
        || owner.raw_response.is_some()
        || owner.received
    {
        return Err(invalid());
    }
    Ok(())
}

fn quote(
    maximum_body_bytes: usize,
    maximum_requested: usize,
) -> Result<PacketNativeImport18BootstrapReceiveRowData, ProviderError> {
    let component =
        Connection::<DeadlineStream>::original_bootstrap_raw_response_construction_data(
            maximum_body_bytes,
            maximum_requested,
        )?;
    let mut axes = component.requested_storage_data();
    axes[0] = axes[0]
        .checked_add(size_of::<PacketNativeImport18BootstrapReceiveRowData>())
        .ok_or_else(credit)?;
    axes[1] = axes[1]
        .checked_add(size_of::<PacketNativeImport18BootstrapReceiveRowData>() * 2)
        .ok_or_else(credit)?;
    axes[2] = axes[2]
        .checked_add(
            CnpController::original_native_import18_bootstrap_receive_counter_scratch_data(),
        )
        .ok_or_else(credit)?;
    if storage::checked_sum_data(&axes)? > maximum_requested {
        return Err(credit());
    }
    Ok(PacketNativeImport18BootstrapReceiveRowData { component, axes })
}

fn check_retained(
    owner: &OriginalNativeImport18Bootstrap,
    row: &PacketNativeImport18BootstrapReceiveRowData,
) -> Result<(), ProviderError> {
    let facts = owner.retained_metadata_data()?;
    let actual = size_of::<OriginalNativeImport18Bootstrap>()
        .checked_add(requested_metadata_backing_storage_data(&facts)?)
        .ok_or_else(credit)?;
    let admitted = owner.row.axes[0]
        .checked_add(
            owner
                .materialization_row
                .as_ref()
                .ok_or_else(invalid)?
                .requested_storage_data()[0],
        )
        .and_then(|bytes| bytes.checked_add(row.axes[0]))
        .ok_or_else(credit)?;
    if actual > admitted {
        return Err(credit());
    }
    Ok(())
}

/// Checks original identity/cut and the actual still-pending raw response.
///
/// # Errors
/// Refuses changed identity, time, raw literal or pending SDK request.
pub(super) fn authenticate_terminal(
    controller: &CnpController,
    hello: &OriginalHelloJournal,
    owner: &OriginalNativeImport18Bootstrap,
) -> Result<(), ProviderError> {
    // Original time is checked even after an earlier physical/parser failure.
    let cut = owner.cut.ok_or_else(invalid)?;
    let deadline = controller
        .session
        .authenticate_original_bootstrap_effect_cut_data(cut, 3);
    let identity = signing::authenticate_original_identity_data(controller, hello, owner);
    let received = (|| {
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
            .authenticate_original_bootstrap_received_raw_data(
                original,
                cut,
                owner.raw_response.as_ref().ok_or_else(invalid)?,
            )
    })();
    deadline?;
    identity?;
    received
}

#[cfg(test)]
#[path = "receive/tests.rs"]
mod tests;
