//! Live catalog reconciliation and deferred guest-selection boundaries.
//!
//! The launch descriptor supplies only policy-free declaration and continuation
//! state. This adapter admits exact setup registrations, freezes the catalog at
//! `setup_complete`, and retains a request before asking QEMU to enter VMStop.
//! Semantic narrowing and reply selection stay outside the GPL-side process.

use crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan;

use super::*;
use crate::{
    SelectableCallbackCoordinate, SelectableCatalog, SelectableCatalogError,
    SelectableDoorbellOutcome, SelectableDoorbellServiceError, SelectableRegistrationService,
    SelectableReplyDisposition, SelectableReplyService, WhiteboxGuestInputCapability,
    handle_whitebox_selectable_callback,
};

/// Returns whether bytes claim the standalone selectable-v1 namespace.
pub(super) fn is_message(payload: &[u8]) -> bool {
    payload
        .get(..2)
        .is_some_and(|version| version == 1_u16.to_le_bytes())
}

/// Preallocated live and post-VMState catalog incarnations.
pub(super) struct LiveSelectableState {
    capability: WhiteboxGuestInputCapability,
    catalog: SelectableCatalog,
    restore_catalog: Option<SelectableCatalog>,
    request_vmstop: crate::QemuRequestVmstopFn,
}

impl LiveSelectableState {
    /// Builds a cold priming catalog and exact continuation without duplicating
    /// the potentially large immutable declaration basis.
    pub(super) fn new(
        plan: &SelectableCatalogPlan,
        capability: WhiteboxGuestInputCapability,
        request_vmstop: crate::QemuRequestVmstopFn,
    ) -> Result<Self, SelectableCatalogError> {
        let (catalog, restore_catalog) = SelectableCatalog::launch_pair_from_plan(plan)?;
        Ok(Self {
            capability,
            catalog,
            restore_catalog: Some(restore_catalog),
            request_vmstop,
        })
    }

    /// Dispatches one selectable message through the shared safe callback core.
    pub(super) fn handle(
        &mut self,
        doorbell: &PluginWhiteboxDoorbell,
        apis: LiveWhiteboxApis,
        reader: &mut LiveGuestMemoryReader,
        event: WhiteboxDoorbellTrapEvent,
    ) -> Result<SelectableDoorbellOutcome, LiveWhiteboxError> {
        let capability = self.capability;
        let mut writer = app_random::LiveGuestMemoryWriter::new(apis, event.current_icount());
        handle_whitebox_selectable_callback(doorbell, &capability, reader, self, &mut writer, event)
            .map_err(callback_error)
    }

    /// Freezes the exact setup catalog at the guest readiness marker.
    pub(super) fn freeze(&mut self) -> Result<(), LiveWhiteboxError> {
        self.catalog
            .freeze()
            .map(|_proof| ())
            .map_err(callback_error)
    }

    /// Swaps the exact preallocated continuation after VMState load.
    pub(super) fn restore_continuation(&mut self) -> Result<(), LiveWhiteboxError> {
        let restored = self
            .restore_catalog
            .take()
            .ok_or(LiveWhiteboxError::SelectableRestoreAlreadyApplied)?;
        self.catalog = restored;
        Ok(())
    }

    #[cfg(test)]
    pub(super) const fn catalog(&self) -> &SelectableCatalog {
        &self.catalog
    }
}

impl SelectableRegistrationService for LiveSelectableState {
    fn register_selectable(
        &mut self,
        registration: &crucible_protocol::SelectableRegister,
        _coordinate: SelectableCallbackCoordinate,
    ) -> Result<(), SelectableDoorbellServiceError> {
        self.catalog.register(registration).map_err(service_error)
    }
}

impl SelectableReplyService for LiveSelectableState {
    fn serve_selection(
        &mut self,
        request: &crucible_protocol::SelectionRequest,
        coordinate: SelectableCallbackCoordinate,
        reply_range: crate::GuestMemoryRange,
    ) -> Result<SelectableReplyDisposition, SelectableDoorbellServiceError> {
        self.catalog
            .begin_request(request, coordinate, reply_range)
            .map_err(service_error)?;
        let status = (self.request_vmstop)();
        if status != 0 {
            return Err(SelectableDoorbellServiceError::new(format!(
                "QEMU rejected selectable VMStop request with status {status}"
            )));
        }
        Ok(SelectableReplyDisposition::Pending)
    }
}

fn service_error(error: SelectableCatalogError) -> SelectableDoorbellServiceError {
    SelectableDoorbellServiceError::new(error.to_string())
}

fn callback_error(source: impl ToString) -> LiveWhiteboxError {
    LiveWhiteboxError::Callback {
        message: source.to_string(),
    }
}

#[cfg(test)]
mod tests;
