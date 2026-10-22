//! Live catalog reconciliation and deferred guest-selection boundaries.
//!
//! The launch descriptor supplies only policy-free declaration and continuation
//! state. This adapter admits exact setup registrations, freezes the catalog at
//! `setup_complete`, and retains a request before asking QEMU to enter VMStop.
//! Semantic narrowing and reply selection stay outside the GPL-side process.

pub(super) mod reset;

use crucible_qemu_protocol::SelectionReply;
use crucible_qemu_protocol::selectable_catalog_plan::{
    SELECTABLE_NATIVE_HANDOFF_INSTRUCTIONS, SELECTABLE_NATIVE_HANDOFF_TICKS_PS,
    SelectableCatalogPlan,
};
use crucible_qemu_protocol::selectable_transport::{
    SelectablePendingTransportView, WHITEBOX_SHMEM_KIND_SELECTABLE_COMPLETED,
    WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING, WHITEBOX_SHMEM_KIND_SELECTABLE_REGISTERED,
    WHITEBOX_SHMEM_KIND_SELECTABLE_REPLY,
};
use crucible_qemu_shmem::{RingHeader, WhiteboxMarkerEntry};
use std::sync::Arc;

use super::*;
use crate::{
    SelectableCallbackCoordinate, SelectableCatalog, SelectableCatalogError,
    SelectableDoorbellOutcome, SelectableDoorbellServiceError, SelectableRegistrationService,
    SelectableReplyDisposition, SelectableReplyService, WhiteboxGuestInputCapability,
    WhiteboxGuestInputWriter,
};

const _: () =
    assert!(SELECTABLE_NATIVE_HANDOFF_TICKS_PS == crucible_qemu_shmem::TICKS_PER_INSTRUCTION);

/// Returns whether bytes claim the standalone selectable-v1 namespace.
pub(super) fn is_message(payload: &[u8]) -> bool {
    payload
        .get(..2)
        .is_some_and(|version| version == 1_u16.to_le_bytes())
}

/// Decodes the retained trap snapshot before any selectable service effect.
///
/// # Errors
/// Preserves snapshot, callback-coordinate and protocol validation refusals.
pub(super) fn prepare_trap_snapshot(
    doorbell: &PluginWhiteboxDoorbell,
    event: WhiteboxDoorbellTrapEvent,
    trap_tick_ps: u64,
    payload: &[u8],
) -> Result<crate::whitebox_doorbell::PreparedSelectableTrap, LiveWhiteboxError> {
    let coordinate =
        SelectableCallbackCoordinate::new(event.current_icount(), trap_tick_ps, event.vcpu_index());
    crate::whitebox_doorbell::PreparedSelectableTrap::decode(doorbell, event, coordinate, payload)
        .map_err(|source| LiveWhiteboxError::SelectableCallback { source })
}

/// Preallocated live and post-VMState catalog incarnations.
pub(super) struct LiveSelectableState {
    capability: WhiteboxGuestInputCapability,
    catalog: SelectableCatalog,
    restore_catalog: Option<SelectableCatalog>,
    force_vcpu_tb_exit: super::api::QemuForceVcpuTbExitFn,
    vmstop_handoff: Arc<super::super::live_callbacks::SelectableVmstopHandoff>,
    reply_input: LiveSelectableReplyShmemConsumer,
    catalog_events_enabled: bool,
    reset: reset::ResetSettlement,
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
            return Err(crate::WhiteboxGuestInputWriteError::from_static(
                "live selectable writer requires a virtual reply range",
            ));
        }
        if !(self.apis.write_memory_vaddr_for_vcpu)(
            self.vcpu_index,
            range.guest_address(),
            payload.as_ptr(),
            payload.len(),
        ) {
            return Err(crate::WhiteboxGuestInputWriteError::new(format!(
                "qemu_plugin_crucible_write_memory_vaddr_for_vcpu failed for vCPU {} at guest virtual address {:#x} with {} bytes at resume icount {}",
                self.vcpu_index,
                range.guest_address(),
                payload.len(),
                self.current_icount,
            )));
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

    fn has_reply(&mut self) -> Result<bool, LiveWhiteboxError> {
        let (header, entries) = self.ring_parts();
        header
            .has_whitebox_marker(entries)
            .map_err(|source| LiveWhiteboxError::SelectableReplyRing { source })
    }

    fn peek(&mut self) -> Result<Option<WhiteboxMarkerEntry>, LiveWhiteboxError> {
        let (header, entries) = self.ring_parts();
        header
            .peek_whitebox_marker(entries)
            .map_err(|source| LiveWhiteboxError::SelectableReplyRing { source })
    }

    fn dequeue(&mut self) -> Result<Option<WhiteboxMarkerEntry>, LiveWhiteboxError> {
        let (header, entries) = self.ring_parts();
        header
            .dequeue_whitebox_marker(entries)
            .map_err(|source| LiveWhiteboxError::SelectableReplyRing { source })
    }
}

impl LiveSelectableState {
    /// Builds a cold priming catalog and exact continuation without duplicating
    /// the potentially large immutable declaration basis.
    pub(super) fn new(
        plan: &SelectableCatalogPlan,
        capability: WhiteboxGuestInputCapability,
        force_vcpu_tb_exit: super::api::QemuForceVcpuTbExitFn,
        vmstop_handoff: Arc<super::super::live_callbacks::SelectableVmstopHandoff>,
        reply_input: LiveSelectableReplyShmemConsumer,
    ) -> Result<Self, SelectableCatalogError> {
        let (catalog, restore_catalog) = SelectableCatalog::launch_pair_from_plan(plan)?;
        Ok(Self {
            capability,
            reset: reset::ResetSettlement::default(),
            catalog,
            restore_catalog: Some(restore_catalog),
            force_vcpu_tb_exit,
            vmstop_handoff,
            reply_input,
            catalog_events_enabled: plan.continuation().phase()
                == crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanPhase::Registering,
        })
    }

    /// Delivers one exact reply before the resumed vCPU may execute.
    pub(super) fn deliver_reply<W>(
        &mut self,
        current_icount: u64,
        vcpu_index: u32,
        writer: &mut W,
        reply_buffer: &mut [u8; SELECTABLE_MESSAGE_MAX_BYTES],
    ) -> Result<Option<SelectionReply>, LiveWhiteboxError>
    where
        W: WhiteboxGuestInputWriter + ?Sized,
    {
        if !self.reply_input.has_reply()? {
            return Ok(None);
        }

        self.deliver_available_reply(current_icount, vcpu_index, writer, reply_buffer)
    }

    // Keep entry-sized return values and decoding buffers off the empty resume
    // path. Availability is advisory; this serialized consumer still re-peeks
    // the actual envelope before validation, consumption, or guest writes.
    #[inline(never)]
    fn deliver_available_reply<W>(
        &mut self,
        current_icount: u64,
        vcpu_index: u32,
        writer: &mut W,
        reply_buffer: &mut [u8; SELECTABLE_MESSAGE_MAX_BYTES],
    ) -> Result<Option<SelectionReply>, LiveWhiteboxError>
    where
        W: WhiteboxGuestInputWriter + ?Sized,
    {
        let Some(entry) = self.reply_input.peek()? else {
            return Ok(None);
        };
        let entry = entry
            .validate()
            .map_err(|source| LiveWhiteboxError::SelectableReplyEntry { source })?;
        if entry.kind() != WHITEBOX_SHMEM_KIND_SELECTABLE_REPLY {
            return Err(LiveWhiteboxError::SelectableReplyUnexpectedKind { kind: entry.kind() });
        }
        let reply_input = &mut self.reply_input;
        let disposition = self.catalog.resolve_pending_with(
            |pending| {
                let trap_coordinate = pending.coordinate();
                let stopped_tick_ps = trap_coordinate
                    .tick_ps()
                    .checked_add(SELECTABLE_NATIVE_HANDOFF_TICKS_PS)
                    .ok_or(LiveWhiteboxError::SelectableReplyStoppedTickOverflow)?;
                // The host binds its reply to the stopped request boundary. QEMU's
                // resume callback may report a later raw reservation boundary even
                // though no subsequent guest TB has executed, so the memory write can
                // occur later while the authenticated catalog token remains sealed
                // against the stop derived from its retained trap coordinate.
                if entry.current_icount() != stopped_tick_ps
                    || entry.vcpu_index() != trap_coordinate.vcpu_index()
                {
                    return Err(LiveWhiteboxError::SelectableReplyCoordinate {
                        actual_tick_ps: entry.current_icount(),
                        actual_vcpu: entry.vcpu_index(),
                        expected_tick_ps: stopped_tick_ps,
                        expected_vcpu: trap_coordinate.vcpu_index(),
                    });
                }
                if vcpu_index != trap_coordinate.vcpu_index() {
                    return Ok(SelectableReplyDisposition::Pending);
                }
                if current_icount < stopped_tick_ps {
                    return Err(LiveWhiteboxError::SelectableReplyEarlyResume {
                        current_tick_ps: current_icount,
                        stopped_tick_ps,
                    });
                }
                let consumed = reply_input
                    .dequeue()?
                    .ok_or(LiveWhiteboxError::SelectableReplyDisappeared)?;
                if consumed != entry {
                    return Err(LiveWhiteboxError::SelectableReplyChanged);
                }
                let reply = SelectionReply::decode(entry.payload())
                    .map_err(|source| LiveWhiteboxError::SelectableReplyProtocol { source })?;
                if reply.sequence() != pending.request().sequence() {
                    return Err(LiveWhiteboxError::SelectableReplySequence {
                        expected: pending.request().sequence(),
                        actual: reply.sequence(),
                    });
                }
                let reply_len = reply
                    .encoded_len()
                    .map_err(|source| LiveWhiteboxError::SelectableReplyProtocol { source })?;
                if reply_len > pending.reply_range().len() {
                    return Err(LiveWhiteboxError::SelectableReplyCapacity {
                        len: reply_len,
                        capacity: pending.reply_range().len(),
                    });
                }
                let bytes = reply_buffer
                    .get_mut(..pending.reply_range().len())
                    .ok_or(LiveWhiteboxError::SelectableReplyWorkspace)?;
                bytes.fill(0);
                reply
                    .encode_into(bytes)
                    .map_err(|source| LiveWhiteboxError::SelectableReplyProtocol { source })?;
                writer
                    .write_whitebox_input(current_icount, pending.reply_range(), bytes)
                    .map_err(|source| LiveWhiteboxError::SelectableReplyGuestWrite {
                        trap_icount: trap_coordinate.raw_icount(),
                        trap_vcpu: trap_coordinate.vcpu_index(),
                        resume_tick_ps: current_icount,
                        resume_vcpu: vcpu_index,
                        source,
                    })?;
                Ok(SelectableReplyDisposition::Reply(reply))
            },
            |source| match source {
                SelectableCatalogError::NoPendingRequest => {
                    LiveWhiteboxError::SelectableReplyWithoutPending
                }
                source => LiveWhiteboxError::SelectableCatalog { source },
            },
        )?;

        Ok(match disposition {
            SelectableReplyDisposition::Reply(reply) => Some(reply),
            SelectableReplyDisposition::Pending => None,
        })
    }

    /// Dispatches one selectable message through the shared safe callback core.
    pub(super) fn handle(
        &mut self,
        prepared: crate::whitebox_doorbell::PreparedSelectableTrap,
        apis: LiveWhiteboxApis,
        event: WhiteboxDoorbellTrapEvent,
        reply_buffer: &mut [u8; SELECTABLE_MESSAGE_MAX_BYTES],
    ) -> Result<SelectableDoorbellOutcome, LiveWhiteboxError> {
        let capability = self.capability;
        let mut writer = app_random::LiveGuestMemoryWriter::new(apis, event.current_icount());
        prepared
            .serve_with_reply_buffer(&capability, self, &mut writer, reply_buffer)
            .map_err(|source| LiveWhiteboxError::SelectableCallback { source })
    }

    /// Freezes the exact setup catalog at the guest readiness marker.
    pub(super) fn freeze(&mut self) -> Result<(), LiveWhiteboxError> {
        self.catalog
            .freeze()
            .map(|_proof| ())
            .map_err(|source| LiveWhiteboxError::SelectableCatalog { source })
    }

    /// Swaps the exact preallocated continuation after VMState load.
    pub(super) fn restore_continuation(&mut self) -> Result<(), LiveWhiteboxError> {
        if self.reset.blocks_restore() {
            return Err(LiveWhiteboxError::SelectableRestorePendingReset);
        }
        let restored = self
            .restore_catalog
            .take()
            .ok_or(LiveWhiteboxError::SelectableRestoreAlreadyApplied)?;
        self.catalog = restored;
        self.catalog_events_enabled = true;
        Ok(())
    }

    /// Seals the in-TB request against the deferred stop boundary.
    pub(super) fn rebind_pending_boundary(
        &mut self,
        raw_icount: u64,
        tick_ps: u64,
    ) -> Result<(), LiveWhiteboxError> {
        let pending = self
            .catalog
            .pending_request()
            .ok_or(LiveWhiteboxError::SelectableHandoffWithoutPending)?;
        let request_icount = pending.coordinate().raw_icount();
        let expected_stop_icount = request_icount
            .checked_add(SELECTABLE_NATIVE_HANDOFF_INSTRUCTIONS)
            .ok_or(LiveWhiteboxError::SelectableHandoffIcountOverflow)?;
        let request_tick_ps = pending.coordinate().tick_ps();
        let expected_stop_tick_ps = request_tick_ps
            .checked_add(SELECTABLE_NATIVE_HANDOFF_TICKS_PS)
            .ok_or(LiveWhiteboxError::SelectableHandoffTickOverflow)?;
        if raw_icount != expected_stop_icount || tick_ps != expected_stop_tick_ps {
            return Err(LiveWhiteboxError::SelectableHandoffCoordinate {
                request_icount,
                request_tick_ps,
                actual_icount: raw_icount,
                actual_tick_ps: tick_ps,
                expected_icount: expected_stop_icount,
                expected_tick_ps: expected_stop_tick_ps,
            });
        }
        let coordinate = SelectableCallbackCoordinate::new(
            raw_icount,
            tick_ps,
            pending.coordinate().vcpu_index(),
        );
        self.catalog
            .rebind_pending_boundary(coordinate)
            .map(|_pending| ())
            .map_err(|source| LiveWhiteboxError::SelectableCatalog { source })
    }

    /// Returns whether catalog deltas belong to the authoritative generation.
    #[must_use]
    pub(super) const fn catalog_events_enabled(&self) -> bool {
        self.catalog_events_enabled
    }

    /// Projects the retained request into the bounded plugin-to-host record.
    pub(super) fn pending_transport_record(
        &self,
    ) -> Result<SelectablePendingTransportView<'_>, LiveWhiteboxError> {
        let pending = self
            .catalog
            .pending_request()
            .ok_or(LiveWhiteboxError::SelectablePendingStateMissing)?;
        SelectablePendingTransportView::new(
            pending.request(),
            pending.reply_range().guest_address(),
            pending.coordinate().raw_icount(),
        )
        .map_err(|source| LiveWhiteboxError::SelectablePendingTransport { source })
    }

    #[cfg(test)]
    pub(super) const fn catalog(&self) -> &SelectableCatalog {
        &self.catalog
    }
}

impl SelectableRegistrationService for LiveSelectableState {
    fn register_selectable(
        &mut self,
        registration: &crucible_qemu_protocol::SelectableRegister,
        _coordinate: SelectableCallbackCoordinate,
    ) -> Result<(), SelectableDoorbellServiceError> {
        self.catalog
            .register(registration)
            .map_err(SelectableDoorbellServiceError::from)
    }
}

impl SelectableReplyService for LiveSelectableState {
    fn serve_selection(
        &mut self,
        request: &crucible_qemu_protocol::SelectionRequest,
        coordinate: SelectableCallbackCoordinate,
        reply_range: crate::GuestMemoryRange,
    ) -> Result<SelectableReplyDisposition, SelectableDoorbellServiceError> {
        // Validate the stricter marker-transport profile before mutating the
        // catalog or asking QEMU to stop. A standalone guest request may use
        // the full doorbell buffer, while a deferred request must also carry
        // its process-neutral reply address to the host.
        SelectablePendingTransportView::new(
            request,
            reply_range.guest_address(),
            coordinate.raw_icount(),
        )
        .map_err(SelectableDoorbellServiceError::from)?;
        self.catalog
            .begin_request(request, coordinate, reply_range)
            .map_err(SelectableDoorbellServiceError::from)?;
        match self.vmstop_handoff.defer(self.force_vcpu_tb_exit) {
            Ok(true) => {}
            Ok(false) => {
                return Err(SelectableDoorbellServiceError::HandoffAlreadyPending);
            }
            Err(status) => {
                return Err(SelectableDoorbellServiceError::HandoffRejected { status });
            }
        }
        Ok(SelectableReplyDisposition::Pending)
    }
}

impl LiveWhiteboxMarkerShmemProducer {
    pub(super) fn record_selectable_registration(
        &mut self,
        current_icount: u64,
        vcpu_index: u32,
        registration: &crucible_qemu_protocol::SelectableRegister,
        buffer: &mut [u8; SELECTABLE_MESSAGE_MAX_BYTES],
    ) -> Result<(), LiveWhiteboxError> {
        let written = registration
            .encode_into(buffer)
            .map_err(|source| LiveWhiteboxError::SelectableProtocol { source })?;
        self.record(
            current_icount,
            vcpu_index,
            WHITEBOX_SHMEM_KIND_SELECTABLE_REGISTERED,
            &buffer[..written],
        )
        .map_err(|source| LiveWhiteboxError::SelectablePublication { source })
    }

    pub(super) fn record_selectable_pending(
        &mut self,
        current_icount: u64,
        vcpu_index: u32,
        record: &SelectablePendingTransportView<'_>,
        buffer: &mut [u8; SELECTABLE_MESSAGE_MAX_BYTES],
    ) -> Result<(), LiveWhiteboxError> {
        let written = record
            .encode_into(buffer)
            .map_err(|source| LiveWhiteboxError::SelectablePendingTransport { source })?;
        self.record(
            current_icount,
            vcpu_index,
            WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING,
            &buffer[..written],
        )
        .map_err(|source| LiveWhiteboxError::SelectablePublication { source })
    }

    pub(super) fn record_selectable_completed(
        &mut self,
        current_icount: u64,
        vcpu_index: u32,
        reply: &SelectionReply,
        buffer: &mut [u8; SELECTABLE_MESSAGE_MAX_BYTES],
    ) -> Result<(), LiveWhiteboxError> {
        let written = reply
            .encode_into(buffer)
            .map_err(|source| LiveWhiteboxError::SelectableProtocol { source })?;
        self.record(
            current_icount,
            vcpu_index,
            WHITEBOX_SHMEM_KIND_SELECTABLE_COMPLETED,
            &buffer[..written],
        )
        .map_err(|source| LiveWhiteboxError::SelectablePublication { source })
    }
}

#[cfg(test)]
mod tests;
