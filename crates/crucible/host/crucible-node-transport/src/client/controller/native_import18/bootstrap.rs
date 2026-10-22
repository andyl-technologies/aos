//! Retains one distinct Bootstrap18 constructor without issuing a request.
//!
//! A genuine caller keeps this owner and row beside its immutable recipe and
//! Initial result. Construction moves fixed typed inputs. Separately admitted
//! unsigned assignment retains each closed Value and Envelope under the original
//! Hello cut. The original reserved slot precedes guarded proof materialization;
//! SDK registration, signing authority and receive remain separate prerequisites.
//!
//! ```text
//! empty -> retaining (failed until checked) -> retained
//! ```
//!
//! A populated output refuses repeated construction. Neither state enables
//! publication or supplies a Controller/Source protocol-once claim.

use super::*;
use crate::client::OriginalHelloJournal;
use crate::hello_frames::OriginalHelloFrameDigests;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT,
    NATIVE_IMPORT18_BOOTSTRAP_FEATURE, PacketNativeImport18BootstrapAssignmentData,
    PacketNativeImport18BootstrapMaterializationRowData,
    PacketNativeImport18BootstrapRawResponseData, PacketNativeImport18BootstrapReceiveRowData,
    PacketNativeImport18BootstrapRequest, PacketNativeImport18BootstrapReservationRowData,
    PacketNativeImport18BootstrapResponseDecodeData, PacketNativeImport18BootstrapSdkRowData,
    PacketNativeImport18BootstrapSdkSettlementRowData, PacketNativeImport18BootstrapSealingData,
};
use crate::retained_metadata::{
    aliases::MetadataSharedKind, requested_metadata_backing_storage_data,
};
use std::mem::size_of;

#[path = "bootstrap/assignment.rs"]
mod assignment;
#[path = "bootstrap/history.rs"]
mod history;
#[path = "bootstrap/materialization.rs"]
mod materialization;
#[path = "bootstrap/publication.rs"]
mod publication;
#[path = "bootstrap/receipt_loan.rs"]
mod receipt_loan;
#[path = "bootstrap/receive.rs"]
mod receive;
#[path = "bootstrap/reservation.rs"]
mod reservation;
#[path = "bootstrap/sdk_settlement.rs"]
mod sdk_settlement;
#[path = "bootstrap/signing.rs"]
mod signing;
#[path = "bootstrap/storage.rs"]
mod storage;

pub use history::{
    OriginalNativeImport18BootstrapHistoryData, OriginalNativeImport18BootstrapRowHistoryData,
};
pub use storage::OriginalNativeImport18BootstrapConstructionData;

/// Retains the same Bootstrap18 row and moved typed inputs after either outcome.
///
/// This noncloneable owner retains original publication progress and failures.
/// The actual Controller, Hello journal, private Source/Birth guards and whole
/// owner debit remain independently retained by the genuine caller.
pub struct OriginalNativeImport18Bootstrap {
    row: OriginalNativeImport18BootstrapConstructionData,
    request_id: Option<Id>,
    request: Option<PacketNativeImport18BootstrapRequest>,
    assignment: Option<PacketNativeImport18BootstrapAssignmentData>,
    cut: Option<OperationalDeadline>,
    reservation_row: Option<PacketNativeImport18BootstrapReservationRowData>,
    reservation_started: bool,
    literal_slot: Option<usize>,
    reserved: bool,
    materialization_row: Option<PacketNativeImport18BootstrapMaterializationRowData>,
    materialization_started: bool,
    sealing: Option<PacketNativeImport18BootstrapSealingData>,
    sdk_row: Option<PacketNativeImport18BootstrapSdkRowData>,
    sdk_started: bool,
    sdk_sealed: bool,
    publication_row: Option<PacketNativeImport18BootstrapSdkRowData>,
    publication_started: bool,
    published: bool,
    receive_row: Option<PacketNativeImport18BootstrapReceiveRowData>,
    receive_started: bool,
    raw_response: Option<PacketNativeImport18BootstrapRawResponseData>,
    received: bool,
    settlement_row: Option<PacketNativeImport18BootstrapSdkSettlementRowData>,
    settlement_started: bool,
    decoded_response: Option<PacketNativeImport18BootstrapResponseDecodeData>,
    settled_request: Option<Envelope>,
    sdk_settled: bool,
    retained: bool,
    failed: bool,
}

impl CnpController {
    /// Retains the actual constructor before any fallible row or input check.
    ///
    /// The caller first retains and independently admits the exact quoted row.
    /// Existing input options remain untouched when the output is occupied or
    /// either input is absent. Once installed, the same output keeps every moved
    /// field and the private row after refusal. This API provides no reset.
    /// No Session sequence, transport credit or Source/native claim is consumed.
    ///
    /// # Errors
    /// Refuses occupied output, absent inputs, a different actor/Hello/frontier,
    /// changed recipe/Initial/request, reused ID or the admitted storage bound.
    pub fn retain_original_native_import18_bootstrap_into_data(
        &self,
        hello: &OriginalHelloJournal,
        recipe: &PacketNativeImport18PrebirthRecipeData,
        initial: &PacketNativeImport18InitialFundingData,
        request_id: &mut Option<Id>,
        request: &mut Option<PacketNativeImport18BootstrapRequest>,
        row: &OriginalNativeImport18BootstrapConstructionData,
        maximum_requested_bytes: usize,
        output: &mut Option<OriginalNativeImport18Bootstrap>,
    ) -> Result<(), ProviderError> {
        if output.is_some() || request_id.is_none() || request.is_none() {
            return Err(invalid());
        }
        *output = Some(OriginalNativeImport18Bootstrap {
            row: row.retaining_data(),
            request_id: request_id.take(),
            request: request.take(),
            assignment: None,
            cut: None,
            reservation_row: None,
            reservation_started: false,
            literal_slot: None,
            reserved: false,
            materialization_row: None,
            materialization_started: false,
            sealing: None,
            sdk_row: None,
            sdk_started: false,
            sdk_sealed: false,
            publication_row: None,
            publication_started: false,
            published: false,
            receive_row: None,
            receive_started: false,
            raw_response: None,
            received: false,
            settlement_row: None,
            settlement_started: false,
            decoded_response: None,
            settled_request: None,
            sdk_settled: false,
            retained: false,
            failed: true,
        });
        let owner = output.as_mut().ok_or_else(invalid)?;
        owner.row.authenticate_data(
            self,
            hello,
            recipe,
            initial,
            owner.request_id.as_ref().ok_or_else(invalid)?,
            owner.request.as_ref().ok_or_else(invalid)?,
            maximum_requested_bytes,
        )?;
        let actual = owner.retained_metadata_data()?;
        let requested = size_of::<OriginalNativeImport18Bootstrap>()
            .checked_add(requested_metadata_backing_storage_data(&actual)?)
            .ok_or_else(credit)?;
        if requested > row.axes[0] {
            return Err(credit());
        }
        owner.retained = true;
        owner.failed = false;
        Ok(())
    }
}

impl OriginalNativeImport18Bootstrap {
    /// Returns the dedicated method DATA independently of all old lifecycle methods.
    pub const fn method_data(&self) -> Method {
        Method::NativeImport18Bootstrap
    }

    /// Counts every actual moved field and shared row association after refusal.
    ///
    /// The enclosing Source separately counts the inline owner header and its
    /// Controller/Hello owners. Equal shared payloads receive no alias discount.
    /// Assignment and materialization add closed fixed-depth Values and a literal
    /// bank, without admitting a raw receive tree.
    ///
    /// # Errors
    /// Refuses a foreign creator or checked metadata traversal exhaustion.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            row,
            request_id,
            request,
            assignment,
            cut: _,
            reservation_row: _,
            reservation_started: _,
            literal_slot: _,
            reserved: _,
            materialization_row: _,
            materialization_started: _,
            sealing,
            sdk_row: _,
            sdk_started: _,
            sdk_sealed: _,
            publication_row: _,
            publication_started: _,
            published: _,
            receive_row: _,
            receive_started: _,
            raw_response,
            received: _,
            settlement_row: _,
            settlement_started: _,
            decoded_response,
            settled_request,
            sdk_settled: _,
            retained: _,
            failed: _,
        } = self;
        row.controller.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.shared_original(MetadataSharedKind::ProtocolOwner, row.controller.as_ref())?;
        observer.observe(request_id)?;
        if let Some(request) = request {
            storage::observe_request_data(request, &mut observer)?;
        }
        if let Some(assignment) = assignment {
            assignment.observe_retained_into_data(&mut observer)?;
        }
        if let Some(sealing) = sealing {
            sealing.observe_retained_into_data(&mut observer)?;
        }
        if let Some(raw) = raw_response {
            raw.observe_retained_into_data(&mut observer)?;
        }
        if let Some(decoded) = decoded_response {
            decoded.observe_retained_into_data(&mut observer)?;
        }
        observer.observe(settled_request)?;
        Ok(observer.finish())
    }

    /// Names this actual fixed-depth census without expanded receive allowances.
    ///
    /// # Errors
    /// Refuses a foreign creator process or thread.
    pub fn retained_metadata_counter_scratch_data(&self) -> Result<usize, ProviderError> {
        self.row.controller.ensure_current()?;
        Ok(if self.settlement_started {
            CnpController::original_native_import18_bootstrap_sdk_settlement_counter_scratch_data()
        } else if self.receive_started {
            CnpController::original_native_import18_bootstrap_receive_counter_scratch_data()
        } else if self.sdk_started || self.publication_started {
            CnpController::original_native_import18_bootstrap_sdk_counter_scratch_data()
        } else if self.materialization_started {
            CnpController::original_native_import18_bootstrap_materialization_counter_scratch_data()
        } else if self.reservation_started {
            CnpController::original_native_import18_bootstrap_reservation_counter_scratch_data()
        } else if self.assignment.is_some() {
            CnpController::original_native_import18_bootstrap_assignment_counter_scratch_data()
        } else {
            CnpController::original_native_import18_bootstrap_counter_scratch_data()
        })
    }
}

#[cfg(test)]
#[path = "bootstrap/tests.rs"]
mod tests;
