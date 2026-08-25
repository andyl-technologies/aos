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

thread_local! {
    static VMSTOP_STATUS: Cell<i32> = const { Cell::new(0) };
    static VMSTOP_CALLS: Cell<usize> = const { Cell::new(0) };
}

extern "C" fn request_vmstop() -> i32 {
    VMSTOP_CALLS.set(VMSTOP_CALLS.get() + 1);
    VMSTOP_STATUS.get()
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

#[test]
fn live_catalog_freezes_and_retains_a_request_before_vmstop()
-> Result<(), Box<dyn std::error::Error>> {
    VMSTOP_STATUS.set(0);
    VMSTOP_CALLS.set(0);
    let plan = cold_plan()?;
    let mut state = LiveSelectableState::new(&plan, capability(), request_vmstop)?;
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
    assert_eq!(VMSTOP_CALLS.get(), 1);
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
fn deferred_transport_bound_rejects_before_catalog_mutation_or_vmstop()
-> Result<(), Box<dyn std::error::Error>> {
    VMSTOP_STATUS.set(0);
    VMSTOP_CALLS.set(0);
    let plan = cold_plan()?;
    let mut state = LiveSelectableState::new(&plan, capability(), request_vmstop)?;
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
    assert_eq!(VMSTOP_CALLS.get(), 0);
    assert!(state.catalog().pending_request().is_none());
    Ok(())
}

#[test]
fn logical_restore_discards_priming_catalog_and_recovers_exact_continuation()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = restored_plan()?;
    let mut state = LiveSelectableState::new(&plan, capability(), request_vmstop)?;
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
fn vmstop_rejection_keeps_the_exact_request_pending() -> Result<(), Box<dyn std::error::Error>> {
    VMSTOP_STATUS.set(-1);
    VMSTOP_CALLS.set(0);
    let plan = cold_plan()?;
    let mut state = LiveSelectableState::new(&plan, capability(), request_vmstop)?;
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
    assert_eq!(VMSTOP_CALLS.get(), 1);
    assert_eq!(
        state
            .catalog()
            .pending_request()
            .map(|pending| pending.request()),
        Some(&request),
    );
    VMSTOP_STATUS.set(0);
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
