//! Selectable live-whitebox request, continuation, and delivery regressions.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use crucible_protocol::{
    SELECTABLE_DIGEST_BYTES, SelectableRegister, SelectionReply, SelectionReplyStatus,
    SelectionRequest, WhiteboxLifecycleMarkerEvent,
    selectable_catalog_plan::{
        SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanDeclaration,
        SelectablePlanLimits, SelectablePlanPendingRequest, SelectablePlanPhase,
        SelectablePlanPresence,
    },
};

use super::*;
use crate::WhiteboxGuestInputWriteError;

#[derive(Default)]
struct RecordingWriter {
    delivery_icount: Option<u64>,
    range: Option<crate::GuestMemoryRange>,
    payload: Vec<u8>,
}

impl WhiteboxGuestInputWriter for RecordingWriter {
    fn write_whitebox_input(
        &mut self,
        delivery_icount: u64,
        range: crate::GuestMemoryRange,
        payload: &[u8],
    ) -> Result<(), WhiteboxGuestInputWriteError> {
        self.delivery_icount = Some(delivery_icount);
        self.range = Some(range);
        self.payload.clear();
        self.payload.extend_from_slice(payload);
        Ok(())
    }
}

thread_local! {
    static FORCE_EXIT_CALLS: Cell<usize> = const { Cell::new(0) };
}

extern "C" fn force_vcpu_exit() {
    FORCE_EXIT_CALLS.set(FORCE_EXIT_CALLS.get() + 1);
}

fn vmstop_handoff() -> Arc<super::super::super::live_callbacks::SelectableVmstopHandoff> {
    Arc::new(super::super::super::live_callbacks::SelectableVmstopHandoff::new())
}

fn live_state(
    plan: &SelectableCatalogPlan,
    reply_input: LiveSelectableReplyShmemConsumer,
) -> Result<LiveSelectableState, SelectableCatalogError> {
    LiveSelectableState::new(
        plan,
        capability(),
        force_vcpu_exit,
        vmstop_handoff(),
        reply_input,
    )
}

fn registration(sequence: u64) -> Result<SelectableRegister, Box<dyn std::error::Error>> {
    Ok(SelectableRegister::new(
        sequence,
        "network.policy",
        vec![1, 2],
        vec![1],
        vec!["recovery".to_owned()],
    )?)
}

fn request(sequence: u64) -> Result<SelectionRequest, Box<dyn std::error::Error>> {
    Ok(SelectionRequest::new(
        sequence,
        "network.policy",
        "epoch/7",
        Some(vec![2]),
        160,
    )?)
}

fn declaration() -> Result<SelectablePlanDeclaration, Box<dyn std::error::Error>> {
    Ok(SelectablePlanDeclaration::new(
        "network.policy",
        vec![1, 2],
        vec![1],
        vec!["recovery".to_owned()],
        SelectablePlanPresence::Required,
    )?)
}

fn cold_plan() -> Result<SelectableCatalogPlan, Box<dyn std::error::Error>> {
    Ok(SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 3, 3)?,
        vec![declaration()?],
        SelectablePlanContinuation::cold(),
    )?)
}

fn restored_plan() -> Result<SelectableCatalogPlan, Box<dyn std::error::Error>> {
    let mut registered = BTreeSet::new();
    registered.insert("network.policy".to_owned());
    let mut completed = BTreeMap::new();
    completed.insert("network.policy".to_owned(), 1);
    let continuation = SelectablePlanContinuation::new(
        SelectablePlanPhase::Frozen,
        registered,
        Some(4),
        completed,
        Some(8),
        Some(SelectablePlanPendingRequest::new(
            request(9)?,
            700,
            2,
            0x4000,
        )),
    )?;
    Ok(SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 3, 3)?,
        vec![declaration()?],
        continuation,
    )?)
}

fn capability() -> WhiteboxGuestInputCapability {
    PluginWhiteboxDoorbell::from_abi(
        PluginSwitch::On,
        WHITEBOX_DOORBELL_X86_64_ABI,
        crucible_shmem::MAX_FRAME_DATA,
    )
    .require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional())
    .unwrap_or_else(|error| panic!("bidirectional test capability should validate: {error}"))
}

fn reply_input() -> LiveSelectableReplyShmemConsumer {
    let header = Box::leak(Box::new(RingHeader::new()));
    let entries = Box::leak(vec![WhiteboxMarkerEntry::default()].into_boxed_slice());
    // SAFETY: test-owned leaked storage remains live and uniquely consumed for
    // the duration of the process.
    unsafe {
        LiveSelectableReplyShmemConsumer::from_raw_parts(
            std::ptr::from_ref(header),
            entries.as_mut_ptr(),
            entries.len(),
        )
    }
}

#[test]
fn live_catalog_retains_request_before_deferring_stop_to_exact_callback()
-> Result<(), Box<dyn std::error::Error>> {
    FORCE_EXIT_CALLS.set(0);
    let plan = cold_plan()?;
    let vmstop_handoff = vmstop_handoff();
    let mut state = LiveSelectableState::new(
        &plan,
        capability(),
        force_vcpu_exit,
        Arc::clone(&vmstop_handoff),
        reply_input(),
    )?;
    state.register_selectable(&registration(1)?, SelectableCallbackCoordinate::new(10, 0))?;
    state.freeze()?;

    let request = request(2)?;
    assert_eq!(
        state.serve_selection(
            &request,
            SelectableCallbackCoordinate::new(50, 1),
            crate::GuestMemoryRange::new(
                crate::GuestMemoryAddressSpace::Virtual,
                0x4000,
                request.reply_capacity(),
            ),
        )?,
        SelectableReplyDisposition::Pending,
    );
    assert_eq!(FORCE_EXIT_CALLS.get(), 1);
    assert!(vmstop_handoff.is_pending());
    let pending = state
        .catalog()
        .pending_request()
        .unwrap_or_else(|| panic!("admitted live request should remain pending"));
    assert_eq!(pending.request(), &request);
    assert_eq!(pending.reply_range().guest_address(), 0x4000);
    assert_eq!(pending.reply_range().len(), request.reply_capacity());
    assert_eq!(
        pending.coordinate(),
        SelectableCallbackCoordinate::new(50, 1)
    );
    assert_eq!(state.catalog().total_completed_requests(), 0);
    let transport = state.pending_transport_record()?;
    assert_eq!(transport.request(), &request);
    assert_eq!(transport.guest_virtual_address(), 0x4000);
    Ok(())
}

#[test]
fn deferred_transport_bound_rejects_before_catalog_mutation_or_forced_exit()
-> Result<(), Box<dyn std::error::Error>> {
    FORCE_EXIT_CALLS.set(0);
    let plan = cold_plan()?;
    let mut state = live_state(&plan, reply_input())?;
    state.register_selectable(&registration(1)?, SelectableCallbackCoordinate::new(10, 0))?;
    state.freeze()?;
    let request = SelectionRequest::new(
        2,
        "network.policy",
        "epoch/7",
        Some(vec![2]),
        crucible_protocol::SELECTABLE_MESSAGE_MAX_BYTES,
    )?;

    assert!(
        state
            .serve_selection(
                &request,
                SelectableCallbackCoordinate::new(50, 1),
                crate::GuestMemoryRange::new(
                    crate::GuestMemoryAddressSpace::Virtual,
                    0x4000,
                    request.reply_capacity(),
                ),
            )
            .is_err()
    );
    assert_eq!(FORCE_EXIT_CALLS.get(), 0);
    assert!(state.catalog().pending_request().is_none());
    Ok(())
}

#[test]
fn logical_restore_discards_priming_catalog_and_recovers_exact_continuation()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = restored_plan()?;
    let mut state = live_state(&plan, reply_input())?;
    state.register_selectable(&registration(1)?, SelectableCallbackCoordinate::new(10, 0))?;
    state.freeze()?;
    assert_eq!(state.catalog().total_completed_requests(), 0);

    state.restore_continuation()?;
    assert_eq!(state.catalog().to_plan()?, plan);
    assert!(matches!(
        state.restore_continuation(),
        Err(LiveWhiteboxError::SelectableRestoreAlreadyApplied)
    ));
    Ok(())
}

#[test]
fn resume_delivery_binds_reply_to_pending_coordinate_and_zero_fills_reservation()
-> Result<(), Box<dyn std::error::Error>> {
    let header = RingHeader::new();
    let mut entries = vec![WhiteboxMarkerEntry::default()];
    // SAFETY: the stack-owned header and entry remain live and uniquely
    // consumer-owned until `state` is dropped at the end of this test.
    let reply_input = unsafe {
        LiveSelectableReplyShmemConsumer::from_raw_parts(
            std::ptr::from_ref(&header),
            entries.as_mut_ptr(),
            entries.len(),
        )
    };
    let reply = SelectionReply::selected(9, [0x11; 32], [0x22; 32], vec![2])?;
    let payload = reply.encode()?;
    let entry = WhiteboxMarkerEntry::new(700, 2, WHITEBOX_SHMEM_KIND_SELECTABLE_REPLY, &payload)?;
    header.enqueue_whitebox_marker(&mut entries, entry)?;

    let plan = restored_plan()?;
    let mut state = live_state(&plan, reply_input)?;
    state.restore_continuation()?;
    let mut writer = RecordingWriter::default();
    state.deliver_reply(700, 1, &mut writer)?;
    assert!(writer.payload.is_empty());
    assert!(state.catalog().pending_request().is_some());
    state.deliver_reply(700, 2, &mut writer)?;

    assert_eq!(writer.delivery_icount, Some(700));
    assert_eq!(
        writer.range,
        Some(crate::GuestMemoryRange::new(
            crate::GuestMemoryAddressSpace::Virtual,
            0x4000,
            160,
        ))
    );
    assert_eq!(&writer.payload[..payload.len()], payload);
    assert!(
        writer.payload[payload.len()..]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(state.catalog().pending_request().is_none());
    assert_eq!(state.catalog().total_completed_requests(), 2);
    Ok(())
}

#[test]
fn live_reply_rebinds_the_in_block_trap_to_the_exact_stop_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let header = RingHeader::new();
    let mut entries = vec![WhiteboxMarkerEntry::default()];
    // SAFETY: the stack-owned ring storage outlives the state and has one
    // consumer in this test.
    let reply_input = unsafe {
        LiveSelectableReplyShmemConsumer::from_raw_parts(
            std::ptr::from_ref(&header),
            entries.as_mut_ptr(),
            entries.len(),
        )
    };
    let reply = SelectionReply::selected(2, [0x11; 32], [0x22; 32], vec![2])?;
    header.enqueue_whitebox_marker(
        &mut entries,
        WhiteboxMarkerEntry::new(
            60,
            1,
            WHITEBOX_SHMEM_KIND_SELECTABLE_REPLY,
            &reply.encode()?,
        )?,
    )?;

    let plan = cold_plan()?;
    let mut state = live_state(&plan, reply_input)?;
    state.register_selectable(&registration(1)?, SelectableCallbackCoordinate::new(10, 0))?;
    state.freeze()?;
    let request = request(2)?;
    state.serve_selection(
        &request,
        SelectableCallbackCoordinate::new(50, 1),
        crate::GuestMemoryRange::new(
            crate::GuestMemoryAddressSpace::Virtual,
            0x4000,
            request.reply_capacity(),
        ),
    )?;

    let mut writer = RecordingWriter::default();
    state.deliver_reply(60, 1, &mut writer)?;

    assert_eq!(writer.delivery_icount, Some(60));
    assert!(state.catalog().pending_request().is_none());
    assert_eq!(state.catalog().total_completed_requests(), 1);
    Ok(())
}

#[test]
fn stale_reply_coordinate_fails_before_guest_write_or_catalog_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let header = RingHeader::new();
    let mut entries = vec![WhiteboxMarkerEntry::default()];
    // SAFETY: the stack-owned ring storage outlives the state and has one
    // consumer in this test.
    let reply_input = unsafe {
        LiveSelectableReplyShmemConsumer::from_raw_parts(
            std::ptr::from_ref(&header),
            entries.as_mut_ptr(),
            entries.len(),
        )
    };
    let reply = SelectionReply::selected(9, [0x11; 32], [0x22; 32], vec![2])?;
    let entry = WhiteboxMarkerEntry::new(
        701,
        2,
        WHITEBOX_SHMEM_KIND_SELECTABLE_REPLY,
        &reply.encode()?,
    )?;
    header.enqueue_whitebox_marker(&mut entries, entry)?;

    let plan = restored_plan()?;
    let mut state = live_state(&plan, reply_input)?;
    state.restore_continuation()?;
    let mut writer = RecordingWriter::default();

    assert!(state.deliver_reply(700, 2, &mut writer).is_err());
    assert!(writer.payload.is_empty());
    assert!(state.catalog().pending_request().is_some());
    assert_eq!(state.catalog().total_completed_requests(), 1);
    Ok(())
}

#[test]
fn occupied_vmstop_handoff_keeps_the_exact_request_pending()
-> Result<(), Box<dyn std::error::Error>> {
    FORCE_EXIT_CALLS.set(0);
    let plan = cold_plan()?;
    let vmstop_handoff = vmstop_handoff();
    assert!(vmstop_handoff.defer(force_vcpu_exit));
    let mut state = LiveSelectableState::new(
        &plan,
        capability(),
        force_vcpu_exit,
        Arc::clone(&vmstop_handoff),
        reply_input(),
    )?;
    state.register_selectable(&registration(1)?, SelectableCallbackCoordinate::new(10, 0))?;
    state.freeze()?;
    let request = request(2)?;

    assert!(
        state
            .serve_selection(
                &request,
                SelectableCallbackCoordinate::new(50, 1),
                crate::GuestMemoryRange::new(
                    crate::GuestMemoryAddressSpace::Virtual,
                    0x4000,
                    request.reply_capacity(),
                ),
            )
            .is_err()
    );
    assert_eq!(FORCE_EXIT_CALLS.get(), 1);
    assert!(vmstop_handoff.is_pending());
    assert_eq!(
        state
            .catalog()
            .pending_request()
            .map(|pending| pending.request()),
        Some(&request),
    );
    Ok(())
}

#[test]
fn selectable_prefix_is_disjoint_from_marker_frames() -> Result<(), Box<dyn std::error::Error>> {
    assert!(is_message(&registration(1)?.encode()?));
    assert!(is_message(&request(2)?.encode()?));
    let reply = SelectionReply::rejected(
        2,
        SelectionReplyStatus::Unavailable,
        [0; SELECTABLE_DIGEST_BYTES],
        [0; SELECTABLE_DIGEST_BYTES],
    )?;
    assert!(is_message(&reply.encode()?));
    let setup_complete = crucible_protocol::encode_whitebox_marker_frame(
        &WhiteboxMarkerPayload::Lifecycle(WhiteboxLifecycleMarkerEvent::SetupComplete),
    )?;
    assert!(!is_message(&setup_complete));
    assert!(super::super::is_setup_complete_marker(&setup_complete));
    let test_done = crucible_protocol::encode_whitebox_marker_frame(
        &WhiteboxMarkerPayload::Lifecycle(WhiteboxLifecycleMarkerEvent::TestDone),
    )?;
    assert!(!super::super::is_setup_complete_marker(&test_done));
    Ok(())
}
