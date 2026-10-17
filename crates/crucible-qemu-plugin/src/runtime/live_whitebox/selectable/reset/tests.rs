//! Exact loaded catalog controls for native reset settlement.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible_protocol::selectable_catalog_plan::{
    SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanDeclaration,
    SelectablePlanLimits, SelectablePlanPendingRequest, SelectablePlanPhase,
    SelectablePlanPresence,
};
use crucible_protocol::selectable_transport::WHITEBOX_SHMEM_KIND_SELECTABLE_REPLY;
use crucible_protocol::{SelectionReply, SelectionRequest};
use crucible_shmem::{RingHeader, WhiteboxMarkerEntry};

use super::*;
use crate::{PluginSwitch, PluginWhiteboxDoorbell, WhiteboxDoorbellCapabilities};

struct ReplyRing {
    header: Box<RingHeader>,
    entries: Vec<WhiteboxMarkerEntry>,
}

impl ReplyRing {
    fn new() -> Self {
        Self {
            header: Box::new(RingHeader::new()),
            entries: vec![WhiteboxMarkerEntry::default()],
        }
    }

    fn consumer(&mut self) -> super::super::LiveSelectableReplyShmemConsumer {
        // SAFETY: this test retains the storage without resizing it until the
        // unique consumer has been dropped.
        unsafe {
            super::super::LiveSelectableReplyShmemConsumer::from_raw_parts(
                std::ptr::from_ref(&*self.header),
                self.entries.as_mut_ptr(),
                self.entries.len(),
            )
        }
    }
}

thread_local! {
    static FORCE_EXIT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

extern "C" fn force_exit() -> i32 {
    FORCE_EXIT_CALLS.set(FORCE_EXIT_CALLS.get() + 1);
    0
}

fn plan() -> Result<SelectableCatalogPlan, Box<dyn std::error::Error>> {
    let request = SelectionRequest::new(9, "network.policy", "epoch/7", Some(vec![2]), 160)?;
    let declaration = SelectablePlanDeclaration::new(
        "network.policy",
        vec![1, 2],
        vec![1],
        vec!["recovery".to_owned()],
        SelectablePlanPresence::Required,
    )?;
    let continuation = SelectablePlanContinuation::new(
        SelectablePlanPhase::Frozen,
        BTreeSet::from(["network.policy".to_owned()]),
        Some(4),
        BTreeMap::from([("network.policy".to_owned(), 1)]),
        Some(8),
        Some(SelectablePlanPendingRequest::new(
            request, 700, 1_000_037, 2, 0x4000,
        )),
    )?;
    Ok(SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 3, 3)?,
        vec![declaration],
        continuation,
    )?)
}

fn state(ring: &mut ReplyRing) -> Result<LiveSelectableState, Box<dyn std::error::Error>> {
    let capability = PluginWhiteboxDoorbell::from_abi(
        PluginSwitch::On,
        crate::WHITEBOX_DOORBELL_X86_64_ABI,
        crucible_shmem::MAX_FRAME_DATA,
    )
    .require_guest_input_capability(WhiteboxDoorbellCapabilities::bidirectional())?;
    let mut state = LiveSelectableState::new(
        &plan()?,
        capability,
        force_exit,
        Arc::new(crate::runtime::live_callbacks::SelectableVmstopHandoff::new()),
        ring.consumer(),
    )?;
    state.restore_continuation()?;
    Ok(state)
}

fn command(state: &LiveSelectableState) -> (Vec<u8>, NativeResetRequest) {
    let pending = state
        .catalog
        .pending_request()
        .expect("fixture has a real pending token");
    let bytes = pending.request().encode().expect("fixture request encodes");
    let coordinate = pending.coordinate();
    let request = NativeResetRequest {
        schema_version: 1,
        vcpu_index: coordinate.vcpu_index(),
        correlation: 1,
        request_sequence: pending.request().sequence(),
        raw_icount: coordinate.raw_icount(),
        trap_tick_ps: coordinate.tick_ps(),
        reply_address: pending.reply_range().guest_address(),
        request: bytes.as_ptr(),
        request_length: bytes.len(),
    };
    (bytes, request)
}

fn call(state: &mut LiveSelectableState, action: u32, request: &NativeResetRequest) -> i32 {
    native_reset_callback(action, request, std::ptr::from_mut(state).cast())
}

#[test]
fn exact_terminal_commit_abandons_without_completing_or_redeclaring()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ring = ReplyRing::new();
    let mut state = state(&mut ring)?;
    let (_bytes, request) = command(&state);
    let declarations = state.catalog.to_plan()?.declarations().clone();

    assert_eq!(call(&mut state, PREPARE, &request), 0);
    assert!(state.reset.blocks_restore());
    assert_eq!(call(&mut state, CHECK, &request), 0);
    assert_eq!(state.catalog.total_abandoned_requests(), 0);
    assert_eq!(call(&mut state, COMMIT, &request), 0);

    assert!(state.catalog.pending_request().is_none());
    assert_eq!(state.catalog.total_completed_requests(), 1);
    assert_eq!(state.catalog.last_completed_request_sequence(), Some(8));
    assert_eq!(state.catalog.total_abandoned_requests(), 1);
    assert_eq!(state.catalog.last_abandoned_request_sequence(), Some(9));
    assert_eq!(state.catalog.to_plan()?.declarations(), &declarations);
    assert!(!state.reset.blocks_restore());
    assert_eq!(FORCE_EXIT_CALLS.get(), 0);
    assert_eq!(call(&mut state, COMMIT, &request), -libc::EBUSY);
    assert_eq!(state.catalog.total_abandoned_requests(), 1);
    Ok(())
}

#[test]
fn every_original_coordinate_and_full_request_are_required()
-> Result<(), Box<dyn std::error::Error>> {
    for field in 0..5 {
        let mut ring = ReplyRing::new();
        let mut state = state(&mut ring)?;
        let (mut bytes, mut request) = command(&state);
        match field {
            0 => {
                // Native derives this scalar from the canonical bytes. Keep
                // that relationship valid to test the original-token check.
                let changed =
                    SelectionRequest::new(10, "network.policy", "epoch/7", Some(vec![2]), 160)?;
                bytes.copy_from_slice(&changed.encode()?);
                request.request = bytes.as_ptr();
                request.request_sequence = changed.sequence();
            }
            1 => request.raw_icount += 1,
            2 => request.trap_tick_ps += 1,
            3 => request.vcpu_index += 1,
            _ => request.reply_address += 1,
        }
        assert_eq!(call(&mut state, PREPARE, &request), -libc::ESTALE);
        assert!(state.catalog.pending_request().is_some());
        assert_eq!(state.catalog.total_abandoned_requests(), 0);
    }

    let mut ring = ReplyRing::new();
    let mut state = state(&mut ring)?;
    let (mut bytes, mut request) = command(&state);
    let changed = SelectionRequest::new(9, "network.policy", "epoch/8", Some(vec![2]), 160)?;
    bytes.copy_from_slice(&changed.encode()?);
    request.request = bytes.as_ptr();
    assert_eq!(call(&mut state, PREPARE, &request), -libc::ESTALE);
    assert_eq!(state.catalog.total_abandoned_requests(), 0);
    Ok(())
}

#[test]
fn scalar_sequence_disagreeing_with_canonical_bytes_keeps_invalid_command_priority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ring = ReplyRing::new();
    let mut state = state(&mut ring)?;
    let (_bytes, mut request) = command(&state);
    request.request_sequence += 1;

    assert_eq!(call(&mut state, PREPARE, &request), -libc::EINVAL);
    assert!(state.catalog.pending_request().is_some());
    assert_eq!(state.catalog.total_abandoned_requests(), 0);
    assert!(state.reset.blocks_restore());
    Ok(())
}

#[test]
fn same_scalars_in_a_different_catalog_incarnation_cannot_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ring = ReplyRing::new();
    let mut state = state(&mut ring)?;
    let (_bytes, request) = command(&state);
    assert_eq!(call(&mut state, PREPARE, &request), 0);
    let retained = state
        .reset
        .pending
        .clone()
        .expect("prepared token retained");
    state.catalog = crate::SelectableCatalog::from_plan(&plan()?)?;

    assert_eq!(call(&mut state, COMMIT, &request), -libc::ESTALE);
    assert_eq!(state.reset.pending.as_ref(), Some(&retained));
    assert!(state.reset.blocks_restore());
    assert_eq!(state.catalog.total_abandoned_requests(), 0);
    Ok(())
}

#[test]
fn reply_arriving_after_prepare_refuses_without_consumption_or_abandonment()
-> Result<(), Box<dyn std::error::Error>> {
    let mut ring = ReplyRing::new();
    let mut state = state(&mut ring)?;
    let (_bytes, request) = command(&state);
    assert_eq!(call(&mut state, PREPARE, &request), 0);
    let reply = SelectionReply::selected(9, [0x11; 32], [0x22; 32], vec![2])?;
    let entry = WhiteboxMarkerEntry::new(
        1_000_087,
        2,
        WHITEBOX_SHMEM_KIND_SELECTABLE_REPLY,
        &reply.encode()?,
    )?;
    ring.header
        .enqueue_whitebox_marker(&mut ring.entries, entry)?;

    assert_eq!(call(&mut state, CHECK, &request), -libc::EBUSY);
    assert!(state.reply_input.has_reply()?);
    assert!(state.catalog.pending_request().is_some());
    assert_eq!(state.catalog.total_completed_requests(), 1);
    assert_eq!(state.catalog.total_abandoned_requests(), 0);
    Ok(())
}

#[test]
fn prepared_and_failed_tokens_block_lifecycle_restore() -> Result<(), Box<dyn std::error::Error>> {
    let mut ring = ReplyRing::new();
    let mut state = state(&mut ring)?;
    let (_bytes, request) = command(&state);
    assert_eq!(call(&mut state, PREPARE, &request), 0);
    assert!(state.restore_continuation().is_err());
    assert!(state.reset.pending.is_some());
    assert_eq!(call(&mut state, PREPARE, &request), -libc::EBUSY);
    assert!(state.restore_continuation().is_err());
    assert!(state.catalog.pending_request().is_some());
    Ok(())
}

#[test]
fn first_refusal_keeps_the_original_panic_payload() {
    let mut settlement = ResetSettlement::default();
    assert_eq!(
        settlement.refuse(ResetRefusal::Panic(Box::new(41_u64))),
        -libc::EFAULT
    );
    assert_eq!(
        settlement.refuse(ResetRefusal::InvalidCommand),
        -libc::EFAULT
    );
    let Some(ResetRefusal::Panic(payload)) = settlement.failure.as_ref() else {
        panic!("first panic payload must remain accessible");
    };
    assert_eq!(payload.downcast_ref::<u64>(), Some(&41));
    assert!(settlement.blocks_restore());
}
