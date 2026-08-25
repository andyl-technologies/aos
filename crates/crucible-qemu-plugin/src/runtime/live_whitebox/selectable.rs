//! Live catalog reconciliation and deferred guest-selection boundaries.
//!
//! The launch descriptor supplies only policy-free declaration and continuation
//! state. This adapter admits exact setup registrations, freezes the catalog at
//! `setup_complete`, and retains a request before asking QEMU to enter VMStop.
//! Semantic narrowing and reply selection stay outside the GPL-side process.

use crucible_protocol::SelectionReply;
use crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan;
use crucible_protocol::selectable_transport::{
    SelectablePendingTransportRecord, WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING,
    WHITEBOX_SHMEM_KIND_SELECTABLE_REPLY,
};
use crucible_shmem::{RingHeader, WhiteboxMarkerEntry};

use super::*;
use crate::{
    SelectableCallbackCoordinate, SelectableCatalog, SelectableCatalogError,
    SelectableDoorbellOutcome, SelectableDoorbellServiceError, SelectableRegistrationService,
    SelectableReplyDisposition, SelectableReplyService, WhiteboxGuestInputCapability,
    WhiteboxGuestInputWriter, handle_whitebox_selectable_callback,
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
    reply_input: LiveSelectableReplyShmemConsumer,
}

/// Pinned raw consumer view of the VM-local host-to-plugin reply ring.
pub(crate) struct LiveSelectableReplyShmemConsumer {
    header: *const RingHeader,
    entries: *mut WhiteboxMarkerEntry,
    capacity: usize,
}

pub(super) struct LiveSelectableGuestMemoryWriter {
    apis: LiveWhiteboxApis,
    vcpu_index: u32,
    current_icount: u64,
}

impl LiveSelectableGuestMemoryWriter {
    pub(super) const fn new(apis: LiveWhiteboxApis, vcpu_index: u32, current_icount: u64) -> Self {
        Self {
            apis,
            vcpu_index,
            current_icount,
        }
    }
}

impl WhiteboxGuestInputWriter for LiveSelectableGuestMemoryWriter {
    fn write_whitebox_input(
        &mut self,
        delivery_icount: u64,
        range: crate::GuestMemoryRange,
        payload: &[u8],
    ) -> Result<(), crate::WhiteboxGuestInputWriteError> {
        if delivery_icount != self.current_icount {
            return Err(crate::WhiteboxGuestInputWriteError::new(format!(
                "delivery icount {delivery_icount} differs from resume icount {}",
                self.current_icount
            )));
        }
        if !matches!(
            range.address_space(),
            crate::GuestMemoryAddressSpace::Virtual
        ) {
            return Err(crate::WhiteboxGuestInputWriteError::new(
                "live selectable writer requires a virtual reply range",
            ));
        }
        if !(self.apis.write_memory_vaddr_for_vcpu)(
            self.vcpu_index,
            range.guest_address(),
            payload.as_ptr(),
            payload.len(),
        ) {
            return Err(crate::WhiteboxGuestInputWriteError::new(
                "qemu_plugin_crucible_write_memory_vaddr_for_vcpu failed",
            ));
        }
        Ok(())
    }
}

impl LiveSelectableReplyShmemConsumer {
    /// Retains a mapped reply consumer for the process-lifetime callback owner.
    ///
    /// # Safety
    ///
    /// `header` and all `capacity` entries must remain mapped, aligned, and
    /// consumer-exclusive until this owner is destroyed. The host may access
    /// the ring only as its SPSC producer.
    pub(crate) unsafe fn from_raw_parts(
        header: *const RingHeader,
        entries: *mut WhiteboxMarkerEntry,
        capacity: usize,
    ) -> Self {
        Self {
            header,
            entries,
            capacity,
        }
    }

    fn ring_parts(&mut self) -> (&RingHeader, &[WhiteboxMarkerEntry]) {
        // SAFETY: construction retains a valid consumer-exclusive mapped ring,
        // and deterministic RR callbacks serialize all plugin access.
        unsafe {
            (
                &*self.header,
                std::slice::from_raw_parts(self.entries, self.capacity),
            )
        }
    }

    fn peek(&mut self) -> Result<Option<WhiteboxMarkerEntry>, LiveWhiteboxError> {
        let (header, entries) = self.ring_parts();
        header.peek_whitebox_marker(entries).map_err(callback_error)
    }

    fn dequeue(&mut self) -> Result<Option<WhiteboxMarkerEntry>, LiveWhiteboxError> {
        let (header, entries) = self.ring_parts();
        header
            .dequeue_whitebox_marker(entries)
            .map_err(callback_error)
    }
}

impl LiveSelectableState {
    /// Builds a cold priming catalog and exact continuation without duplicating
    /// the potentially large immutable declaration basis.
    pub(super) fn new(
        plan: &SelectableCatalogPlan,
        capability: WhiteboxGuestInputCapability,
        request_vmstop: crate::QemuRequestVmstopFn,
        reply_input: LiveSelectableReplyShmemConsumer,
    ) -> Result<Self, SelectableCatalogError> {
        let (catalog, restore_catalog) = SelectableCatalog::launch_pair_from_plan(plan)?;
        Ok(Self {
            capability,
            catalog,
            restore_catalog: Some(restore_catalog),
            request_vmstop,
            reply_input,
        })
    }

    /// Delivers one exact reply before the resumed vCPU may execute.
    pub(super) fn deliver_reply<W>(
        &mut self,
        current_icount: u64,
        vcpu_index: u32,
        writer: &mut W,
    ) -> Result<(), LiveWhiteboxError>
    where
        W: WhiteboxGuestInputWriter + ?Sized,
    {
        let Some(entry) = self.reply_input.peek()? else {
            return Ok(());
        };
        let entry = entry.validate().map_err(callback_error)?;
        if entry.kind() != WHITEBOX_SHMEM_KIND_SELECTABLE_REPLY {
            return Err(callback_error(format!(
                "selectable reply ring carried unexpected kind {}",
                entry.kind()
            )));
        }
        let pending =
            self.catalog.pending_request().cloned().ok_or_else(|| {
                callback_error("selectable reply arrived without a pending request")
            })?;
        let coordinate = pending.coordinate();
        if entry.current_icount() != coordinate.icount()
            || entry.vcpu_index() != coordinate.vcpu_index()
        {
            return Err(callback_error(format!(
                "selectable reply coordinate ({}, {}) differs from pending ({}, {})",
                entry.current_icount(),
                entry.vcpu_index(),
                coordinate.icount(),
                coordinate.vcpu_index()
            )));
        }
        if vcpu_index != coordinate.vcpu_index() {
            return Ok(());
        }
        if current_icount != coordinate.icount() {
            return Err(callback_error(format!(
                "selectable reply icount {} differs from target vCPU resume {current_icount}",
                coordinate.icount()
            )));
        }
        let consumed = self.reply_input.dequeue()?.ok_or_else(|| {
            callback_error("selectable reply disappeared between peek and consume")
        })?;
        if consumed != entry {
            return Err(callback_error(
                "selectable reply changed between peek and consume",
            ));
        }
        let reply = SelectionReply::decode(entry.payload()).map_err(callback_error)?;
        if reply.sequence() != pending.request().sequence() {
            return Err(callback_error(format!(
                "selectable reply sequence {} differs from pending request {}",
                reply.sequence(),
                pending.request().sequence()
            )));
        }
        let mut bytes = reply.encode().map_err(callback_error)?;
        if bytes.len() > pending.reply_range().len() {
            return Err(callback_error(format!(
                "selectable reply has {} bytes but guest reserved {}",
                bytes.len(),
                pending.reply_range().len()
            )));
        }
        bytes.resize(pending.reply_range().len(), 0);
        writer
            .write_whitebox_input(current_icount, pending.reply_range(), &bytes)
            .map_err(callback_error)?;
        self.catalog
            .complete_request(&pending, &reply)
            .map_err(callback_error)
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

    /// Projects the retained request into the bounded plugin-to-host record.
    pub(super) fn pending_transport_record(
        &self,
    ) -> Result<SelectablePendingTransportRecord, LiveWhiteboxError> {
        let pending =
            self.catalog
                .pending_request()
                .ok_or_else(|| LiveWhiteboxError::Callback {
                    message: "selectable callback reported pending without retained catalog state"
                        .to_owned(),
                })?;
        SelectablePendingTransportRecord::new(
            pending.request().clone(),
            pending.reply_range().guest_address(),
        )
        .map_err(callback_error)
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
        // Validate the stricter marker-transport profile before mutating the
        // catalog or asking QEMU to stop. A standalone guest request may use
        // the full doorbell buffer, while a deferred request must also carry
        // its process-neutral reply address to the host.
        SelectablePendingTransportRecord::new(request.clone(), reply_range.guest_address())
            .map_err(|error| SelectableDoorbellServiceError::new(error.to_string()))?;
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

impl LiveWhiteboxMarkerShmemProducer {
    pub(super) fn record_selectable_pending(
        &mut self,
        current_icount: u64,
        vcpu_index: u32,
        record: &SelectablePendingTransportRecord,
    ) -> Result<(), LiveWhiteboxError> {
        let payload = record.encode().map_err(callback_error)?;
        self.record(
            current_icount,
            vcpu_index,
            WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING,
            &payload,
        )
        .map_err(callback_error)
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
