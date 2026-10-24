//! One source-authenticated stopped HOLD of the original six directed headers.
//!
//! The private tuple144 and source status-pointer predicate run before any
//! original Arc, RR TLS or mapping guard. The same engine retains its tuple,
//! mapped snapshot and prepared status88 before the post-guard native recapture.
//! Status7 reserves callback/worker fields as zero and never proves full HOLD,
//! adoption, an epoch, endpoint service or readiness.

use super::*;
use crate::QemuPluginHotForkBarrierStatus;

const HOLD: u32 = 1;
const MAPPING_STATUS_VERSION: u32 = 7;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeMappingHold {
    version: u32,
    size: u32,
    phase: u32,
    cpu_index: u32,
    plugin_id: u64,
    process: u64,
    actual_tid: u64,
    loader_tid: u64,
    deadline_ns: u64,
    callback: usize,
    userdata: *mut c_void,
    constructor: *const c_void,
    cpu: *const c_void,
    permit: *const c_void,
    engine: *mut c_void,
    ring_count: u32,
    action: u32,
    setup_digest: [u8; 32],
}

impl Default for NativeMappingHold {
    fn default() -> Self {
        Self {
            version: 1,
            size: 144,
            phase: 0,
            cpu_index: 0,
            plugin_id: 0,
            process: 0,
            actual_tid: 0,
            loader_tid: 0,
            deadline_ns: 0,
            callback: 0,
            userdata: std::ptr::null_mut(),
            constructor: std::ptr::null(),
            cpu: std::ptr::null(),
            permit: std::ptr::null(),
            engine: std::ptr::null_mut(),
            ring_count: 0,
            action: 0,
            setup_digest: [0; 32],
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeMappingHold>() == 144);
    assert!(std::mem::offset_of!(NativeMappingHold, callback) == 56);
    assert!(std::mem::offset_of!(NativeMappingHold, permit) == 88);
    assert!(std::mem::offset_of!(NativeMappingHold, engine) == 96);
    assert!(std::mem::offset_of!(NativeMappingHold, ring_count) == 104);
    assert!(std::mem::offset_of!(NativeMappingHold, action) == 108);
    assert!(std::mem::offset_of!(NativeMappingHold, setup_digest) == 112);
    assert!(std::mem::size_of::<QemuPluginHotForkBarrierStatus>() == 88);
};

type ReadMappingHold = extern "C" fn(*mut NativeMappingHold) -> c_int;
type AuthenticateStatus = extern "C" fn(*const QemuPluginHotForkBarrierStatus) -> c_int;

#[derive(Clone, Copy)]
pub(super) struct MappingHoldApis {
    read: ReadMappingHold,
    authenticate_status: AuthenticateStatus,
}

impl MappingHoldApis {
    pub(super) fn resolve() -> Option<Self> {
        // SAFETY: Only the frozen GPL-local source declares these symbols.
        // Resolution is capability discovery, never source or mode authority.
        let read = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_whole_read_mapping_hold_v1".as_ptr(),
            )
        };
        // SAFETY: The source predicate compares the native original pointer
        // without dereferencing a candidate supplied by this callback.
        let authenticate = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"qemu_plugin_crucible_whole_authenticate_mapping_status_v1".as_ptr(),
            )
        };
        if read.is_null() || authenticate.is_null() {
            return None;
        }
        Some(Self {
            // SAFETY: The edition/size-initialized tuple matches native144.
            read: unsafe { std::mem::transmute::<*mut c_void, ReadMappingHold>(read) },
            // SAFETY: The frozen native predicate has this exact const-pointer ABI.
            authenticate_status: unsafe {
                std::mem::transmute::<*mut c_void, AuthenticateStatus>(authenticate)
            },
        })
    }

    fn capture(&self, action: u32) -> Result<NativeMappingHold, c_int> {
        let mut tuple = NativeMappingHold::default();
        let status = (self.read)(&mut tuple);
        if status != 0 {
            return Err(refusal(status));
        }
        let now = super::super::monotonic_ns().map_err(|_| -libc::ESTALE)?;
        if tuple.version != 1
            || tuple.size != 144
            || tuple.phase != 1
            || tuple.cpu_index != 0
            || tuple.plugin_id == 0
            || tuple.process != u64::from(std::process::id())
            || tuple.actual_tid != current_tid()?
            || tuple.loader_tid == 0
            || now >= tuple.deadline_ns
            || tuple.callback != super::super::closed_barrier as *const () as usize
            || tuple.userdata.is_null()
            || tuple.constructor.is_null()
            || tuple.cpu.is_null()
            || tuple.permit.is_null()
            || tuple.engine.is_null()
            || tuple.ring_count != 6
            || tuple.action != HOLD
            || action != HOLD
        {
            return Err(-libc::ESTALE);
        }
        Ok(tuple)
    }

    fn authenticate(&self, destination: *mut QemuPluginHotForkBarrierStatus) -> Result<(), c_int> {
        let status = (self.authenticate_status)(destination.cast_const());
        if status != 0 || destination.is_null() {
            return Err(refusal(status));
        }
        Ok(())
    }
}

fn refusal(status: c_int) -> c_int {
    if status < 0 { status } else { -libc::EPROTO }
}

/// Preowns the complete local mapping attempt inside the same retained engine.
#[derive(Default)]
pub(super) struct MappingHoldJournal {
    tuple: Option<NativeMappingHold>,
    snapshot: Option<crucible_qemu_shmem::PreparedDirectedRingHoldSnapshot>,
    prepared_status: Option<QemuPluginHotForkBarrierStatus>,
}

pub(super) fn hold_on_rr(
    action: u32,
    destination: *mut QemuPluginHotForkBarrierStatus,
    userdata: *mut c_void,
) -> c_int {
    if !callback_process_current() {
        return -libc::ESTALE;
    }
    let captured = APIS
        .get()
        .and_then(|apis| apis.mapping_hold)
        .ok_or(-libc::ENOTSUP)
        .and_then(|apis| {
            let tuple = apis.capture(action)?;
            apis.authenticate(destination)?;
            Ok((apis, tuple))
        });
    let Some(original) = super::super::ORIGINAL_CALLBACK.get() else {
        return -libc::ESTALE;
    };
    let result = captured.and_then(|(apis, tuple)| {
        if tuple.userdata != userdata
            || userdata != Arc::as_ptr(original).cast_mut().cast()
            || tuple.plugin_id != original.plugin_id
            || tuple.process != u64::from(original.process)
            || tuple.loader_tid != original.loader_tid
            || tuple.setup_digest != original.setup_digest
            || tuple.constructor as usize != original.constructor_identity.load(Ordering::Acquire)
            || tuple.cpu as usize != original.cpu_identities[0].load(Ordering::Acquire)
            || original.observed_vcpus.load(Ordering::Acquire) != 15
            || original.failed.load(Ordering::Acquire)
        {
            return Err(-libc::ESTALE);
        }
        let status = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            retain_and_hold(original, tuple)
        }))
        .map_err(|_| -libc::EFAULT)??;

        // Every engine/mapping guard has ended. A changed or missing source
        // leaves the original tuple, snapshot and prepared status retained.
        if apis.capture(action)? != tuple {
            return Err(-libc::ESTALE);
        }
        apis.authenticate(destination)?;
        if original.failed.load(Ordering::Acquire) {
            return Err(-libc::ESTALE);
        }
        // SAFETY: The source reauthenticated this exact original preowned88B
        // destination in its still-live callback after the fresh getter. No
        // Rust guard crosses this write, and no candidate pointer was chased.
        unsafe { destination.write(status) };
        Ok(())
    });
    match result {
        Ok(()) => 0,
        Err(status) => {
            // Unauthenticated callbacks can touch only this scalar fence.
            // The library retains any partial mapping mutation under its ticket.
            original.refuse_callback();
            status
        }
    }
}

fn retain_and_hold(
    original: &Arc<SharedCallbackCustody>,
    tuple: NativeMappingHold,
) -> Result<QemuPluginHotForkBarrierStatus, c_int> {
    ENGINE
        .try_with(|cell| {
            let mut slot = cell.try_borrow_mut().map_err(|_| -libc::EBUSY)?;
            let engine = slot.as_mut().ok_or(-libc::ESTALE)?;
            if tuple.engine != std::ptr::from_mut(engine.as_mut()).cast()
                || !Arc::ptr_eq(&engine._original, original)
                || !engine.native_visible
                || engine.registered_families != 31
                || tuple.plugin_id != engine._birth.plugin_id
                || tuple.process != engine._birth.process
                || tuple.actual_tid != engine._birth.actual_tid
                || tuple.loader_tid != engine._birth.loader_tid
                || tuple.deadline_ns != engine._birth.deadline_ns
                || tuple.constructor != engine._birth.constructor
                || tuple.cpu != engine._birth.cpu
                || tuple.setup_digest != engine._birth.setup_digest
                || tuple.permit == engine._birth.permit
                || engine.mapping_hold_journal.tuple.is_some()
            {
                return Err(-libc::ESTALE);
            }
            engine.mapping_hold_journal.tuple = Some(tuple);
            let setup = original.setup.get().ok_or(-libc::ESTALE)?;
            let snapshot =
                match setup.hold_whole_prepared_directed_rings(&mut engine.mapping_roster) {
                    Ok(snapshot) => snapshot,
                    Err(crucible_qemu_shmem::PreparedDirectedRingHoldError::NotQuiescent {
                        snapshot,
                    }) => {
                        engine.mapping_hold_journal.snapshot = Some(snapshot);
                        return Err(-libc::ESTALE);
                    }
                    Err(_) => return Err(-libc::ESTALE),
                };
            engine.mapping_hold_journal.snapshot = Some(snapshot);
            if !snapshot.quiescent() || !snapshot.mapping_excluded() || snapshot.ring_count() != 6 {
                return Err(-libc::ESTALE);
            }
            let status = QemuPluginHotForkBarrierStatus {
                schema_version: MAPPING_STATUS_VERSION,
                struct_size: 88,
                flags: crate::QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_HELD
                    | crate::QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_MAPPING_DONTFORK,
                reserved: 0,
                // Status7 reserves these callback/worker fields; only the six
                // mapped ring counts below carry observed census facts.
                in_flight: 0,
                ring_count: snapshot.ring_count(),
                rings_held: snapshot.held_rings(),
                ring_producers_in_flight: snapshot.producers_in_flight(),
                ring_consumers_in_flight: snapshot.consumers_in_flight(),
                worker_mask: 0,
                parked_worker_mask: 0,
                pending_worker_mask: 0,
                worker_operations_in_flight: 0,
            };
            engine.mapping_hold_journal.prepared_status = Some(status);
            Ok(status)
        })
        .map_err(|_| -libc::ESTALE)?
}

#[cfg(test)]
#[path = "mapping_hold/tests.rs"]
pub(super) mod tests;

#[cfg(test)]
#[path = "mapping_hold/coupled.rs"]
mod coupled;
