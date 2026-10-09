//! Original accounted native output-stop publication before control acceptance.
//!
//! The installed READY owner registers this callback on its pinned runtime.
//! Native code retains the genuine stopped occurrence and authentic inventory
//! lease; the original slot writer supplies storage framing only. No ring read,
//! accepted frontier, odd control ACK or execution grant is produced here.

use std::cell::Cell;
use std::sync::atomic::Ordering;

use crucible_protocol::native_console::NativeConsoleError;
use crucible_shmem::{NodeBoundaryPublication, NodeBoundaryPublicationError};

use super::LiveVcpuTimeCallbackState;

impl LiveVcpuTimeCallbackState {
    fn publish_console_stopped(
        &self,
        raw: u64,
        logical: u64,
        commit: impl FnOnce(NodeBoundaryPublication) -> u32,
    ) -> u32 {
        // The native owner already retained a bounded settled raw/logical
        // observation under its actual inventory lease. Do not call the live
        // clock getter here: it would re-query that native clock while held.
        let Some(offset) = raw
            .checked_mul(crucible_shmem::TICKS_PER_INSTRUCTION)
            .and_then(|raw_ps| logical.checked_sub(raw_ps))
        else {
            return 0;
        };
        if raw < self.last_raw_icount.load(Ordering::Acquire)
            || logical < self.last_icount.load(Ordering::Acquire)
        {
            return 0;
        }

        let status = Cell::new(0);
        let published =
            self.slot
                .get()
                .publish_pause_quiesced_with_effect(logical, raw, |publication| {
                    let disposition = commit(publication);
                    status.set(disposition);
                    match disposition {
                        2 => Ok(()),
                        1 => Err(NativeConsoleError::Sequence),
                        _ => Err(NativeConsoleError::Binding),
                    }
                });
        match published {
            Ok(()) => {
                self.logical_icount_offset.store(offset, Ordering::Release);
                self.last_raw_icount.store(raw, Ordering::Release);
                self.last_icount.store(logical, Ordering::Release);
                2
            }
            Err(NodeBoundaryPublicationError::Effect(NativeConsoleError::Sequence))
                if status.get() == 1 =>
            {
                1
            }
            _ => 0,
        }
    }
}

/// Borrows the original stopped occurrence without crossing the process boundary.
///
/// # Safety
///
/// The sole native registration retains this pinned callback allocation. It
/// holds authentic native inventory custody and its invocation-local stopped
/// scope through this call, releasing both after the original writer closes.
pub(in crate::runtime) unsafe extern "C" fn crucible_qemu_plugin_live_console_stopped_cb(
    userdata: *mut std::ffi::c_void,
    generation: u64,
    raw: u64,
    logical: u64,
    advance: u64,
    ack: u32,
) -> u32 {
    if userdata.is_null() {
        return 0;
    }
    // SAFETY: native registration retains the original pinned live state for
    // the process lifetime; no caller-provided pointer is admitted over IPC.
    let state = unsafe { &*userdata.cast::<LiveVcpuTimeCallbackState>() };
    let Some(_in_flight) = state.callback_guard() else {
        return 1;
    };
    let Some(installed) = state.native_console else {
        return 0;
    };
    // A panic closes the original writer before returning refusal to C. C
    // releases its real lock/scope before reporting the fatal host error.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.publish_console_stopped(raw, logical, |publication| {
            installed.publish_stopped(generation, advance, ack, publication)
        })
    }))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_protocol::native_console::{NativeConsoleOperationStop, NativeConsoleOwner};
    use crucible_shmem::native_console::NativeConsoleOperationStopTable;
    use crucible_shmem::{KIND_VM, NodeSlot, STATUS_IDLE};

    use crate::runtime::live_callbacks::LiveVcpuTimeCallbackError;
    use crate::runtime::live_callbacks::tests::test_live_state;

    // This owner is deliberately external. These controls execute the original
    // Rust writer/table/ACK effects, not QEMU's stopped or inventory authority.
    fn modeled_stop(
        publication: u64,
        fields: NodeBoundaryPublication,
        ack: u32,
    ) -> NativeConsoleOperationStop {
        NativeConsoleOperationStop {
            publication,
            ring_end: 1,
            node_sequence: 1,
            logical_ps: fields.logical(),
            raw_prefix: fields.raw(),
            owner: NativeConsoleOwner {
                slot: 0,
                region: [4; 16],
                process: 1,
                authorization: 1,
            },
            authorization_advance: 2,
            logical_generation: 0,
            vcpu: 0,
            closed_generation: fields.closed_generation(),
            control_boundary_ack: ack,
            stopped_advance: 4,
        }
    }

    #[test]
    fn original_stopped_writer_busy_then_republication_preserves_accounted_origin_and_ack()
    -> Result<(), LiveVcpuTimeCallbackError> {
        let node = NodeSlot::new(KIND_VM);
        let state = test_live_state(316, 1, 0, &node)?;
        let table = NativeConsoleOperationStopTable::default();
        let request = node
            .request_control_boundary(0, None)
            .unwrap_or_else(|error| panic!("fixture request: {error}"));

        assert_eq!(state.publish_console_stopped(8, 400, |_| 1), 1);
        assert!(table.snapshot().is_err());
        assert_eq!(node.control_boundary_token(), request);
        assert!(node.try_snapshot().is_some());

        for (publication, raw, logical) in [(2, 8, 400), (4, 8, 400)] {
            let result = state.publish_console_stopped(raw, logical, |fields| {
                assert!(node.try_snapshot().is_none());
                assert_eq!(node.control_boundary_token(), request);
                assert!(fields.advance().is_none());
                table
                    .store(modeled_stop(publication, fields, request))
                    .unwrap_or_else(|error| panic!("modeled stopped store: {error}"));
                2
            });
            assert_eq!(result, 2);
            let stopped = table
                .snapshot()
                .unwrap_or_else(|error| panic!("stopped table: {error}"));
            let snapshot = node.snapshot();
            assert_eq!(stopped.closed_generation, snapshot.publish_gen);
            assert_eq!((stopped.raw_prefix, stopped.logical_ps), (8, 400));
            assert_eq!(snapshot.status, STATUS_IDLE);
            assert_eq!(node.control_boundary_token(), request);
            // Another original publication can replace storage framing before
            // discovery; the retained owner republishes unchanged accounting.
            node.publish_pause_quiesced(logical, raw)
                .unwrap_or_else(|error| panic!("original pause publication: {error}"));
        }
        assert_eq!(state.last_raw_icount.load(Ordering::Acquire), 8);
        assert_eq!(state.last_icount.load(Ordering::Acquire), 400);
        Ok(())
    }

    #[test]
    fn original_stopped_writer_refusal_and_unwind_close_without_table_or_control_ack()
    -> Result<(), LiveVcpuTimeCallbackError> {
        let node = NodeSlot::new(KIND_VM);
        let state = test_live_state(316, 1, 0, &node)?;
        let table = NativeConsoleOperationStopTable::default();
        let request = node
            .request_control_boundary(0, None)
            .unwrap_or_else(|error| panic!("fixture request: {error}"));

        for disposition in [0, 1] {
            assert_eq!(
                state.publish_console_stopped(8, 400, |_| disposition),
                disposition
            );
            assert!(node.try_snapshot().is_some());
            assert!(table.snapshot().is_err());
            assert_eq!(node.control_boundary_token(), request);
            assert_eq!(state.last_raw_icount.load(Ordering::Acquire), 0);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.publish_console_stopped(8, 400, |_| panic!("modeled stopped refusal"))
        }));
        assert!(result.is_err());
        assert!(node.try_snapshot().is_some());
        assert!(table.snapshot().is_err());
        assert_eq!(node.control_boundary_token(), request);
        assert_eq!(state.last_raw_icount.load(Ordering::Acquire), 0);
        Ok(())
    }

    #[test]
    fn original_stopped_writer_rejects_accounting_regression_before_callback()
    -> Result<(), LiveVcpuTimeCallbackError> {
        let node = NodeSlot::new(KIND_VM);
        node.publish_scheduler_advance(
            crucible_shmem::authorize_advance_ceiling(0, 400, None)
                .unwrap_or_else(|error| panic!("fixture initial ceiling: {error}")),
            crucible_shmem::AdvanceStopCondition::Ceiling,
        )
        .unwrap_or_else(|error| panic!("fixture initial advance: {error}"));
        node.publish_pause_quiesced(400, 8)
            .unwrap_or_else(|error| panic!("fixture initial accounted boundary: {error}"));
        let state = test_live_state(316, 1, 8, &node)?;
        let before = node.snapshot();
        let calls = Cell::new(0);

        for (raw, logical) in [(7, 350), (8, 399), (u64::MAX, u64::MAX)] {
            assert_eq!(
                state.publish_console_stopped(raw, logical, |_| {
                    calls.set(calls.get() + 1);
                    2
                }),
                0
            );
        }
        assert_eq!(calls.get(), 0);
        assert_eq!(node.snapshot(), before);
        Ok(())
    }
}
