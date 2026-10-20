//! Retains one distinct Bootstrap18 constructor without issuing a request.
//!
//! A genuine caller must keep this owner and row beside its immutable recipe and
//! Initial result. This constructor moves fixed typed inputs only; it creates no
//! Value, Envelope, original slot, deadline, proof, receipt or completion witness.
//! Safe receive and the actual Source signer remain separate prerequisites.
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
    NATIVE_IMPORT18_BOOTSTRAP_FEATURE, PacketNativeImport18BootstrapRequest,
};
use crate::retained_metadata::{
    aliases::MetadataSharedKind, requested_metadata_backing_storage_data,
};
use std::mem::size_of;

#[path = "bootstrap/history.rs"]
mod history;
#[path = "bootstrap/storage.rs"]
mod storage;

pub use history::{
    OriginalNativeImport18BootstrapHistoryData, OriginalNativeImport18BootstrapRowHistoryData,
};
pub use storage::OriginalNativeImport18BootstrapConstructionData;

/// Retains the same Bootstrap18 row and moved typed inputs after either outcome.
///
/// This noncloneable owner carries no publishing, decoding or completed getter.
/// The actual Controller, Hello journal, private Source/Birth guards and whole
/// owner debit remain independently retained by the genuine caller.
pub struct OriginalNativeImport18Bootstrap {
    row: OriginalNativeImport18BootstrapConstructionData,
    request_id: Option<Id>,
    request: Option<PacketNativeImport18BootstrapRequest>,
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
    /// This owner contains only fixed-depth typed fields, with no raw Value tree.
    ///
    /// # Errors
    /// Refuses a foreign creator or checked metadata traversal exhaustion.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let Self {
            row,
            request_id,
            request,
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
        Ok(observer.finish())
    }

    /// Names this actual fixed-depth census without expanded receive allowances.
    ///
    /// # Errors
    /// Refuses a foreign creator process or thread.
    pub fn retained_metadata_counter_scratch_data(&self) -> Result<usize, ProviderError> {
        self.row.controller.ensure_current()?;
        Ok(CnpController::original_native_import18_bootstrap_counter_scratch_data())
    }
}

#[cfg(test)]
#[path = "bootstrap/tests.rs"]
mod tests;
