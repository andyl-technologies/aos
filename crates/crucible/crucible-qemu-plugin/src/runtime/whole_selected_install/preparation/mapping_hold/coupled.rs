//! Executes the exact C mapping window against the original Rust/Linux helper.
//!
//! This test-only DSO models QOM/BQL/clock/endpoint/module setup. Actual C
//! request/dispatch/getter/pointer identity/read slots/revocation cross the real
//! Rust callback, same RR-local engine and Linux six-HOLD. It is not an
//! installed emulator/plugin qualification or a source readiness issuer.

#![cfg(test)]
#![expect(
    clippy::unwrap_used,
    reason = "These controls panic on failed invariants."
)]

use super::*;
use sha2::{Digest, Sha256};
use std::cell::Cell;

thread_local! {
    static ACTIVE: Cell<Option<MappingHoldApis>> = const { Cell::new(None) };
}

#[repr(C)]
#[derive(Debug)]
struct Inspection {
    version: u32,
    size: u32,
    phase: u32,
    reads: u32,
    status: i32,
    flags: u32,
    process: u64,
}

const _: () = assert!(std::mem::size_of::<Inspection>() == 32);

type Barrier = extern "C" fn(u32, *mut QemuPluginHotForkBarrierStatus, *mut c_void) -> c_int;
type Invoke = extern "C" fn(
    *const NativePreparation,
    *mut c_void,
    *mut c_void,
    Barrier,
    *mut QemuPluginHotForkBarrierStatus,
    u32,
) -> c_int;
type Inspect = extern "C" fn() -> Inspection;

/// Retains the original loaded code and its private native journal until exit.
struct RetainedLibrary {
    _handle: usize,
    apis: MappingHoldApis,
    invoke: Invoke,
    inspect: Inspect,
}

static LIBRARY: OnceLock<RetainedLibrary> = OnceLock::new();

pub(super) fn active_apis() -> Option<MappingHoldApis> {
    ACTIVE.get()
}

pub(super) fn requested() -> bool {
    matches!(
        std::env::var("RFC0025_MAPPING_HOLD_CONTROL").as_deref(),
        Ok("native-pair" | "native-stale")
    )
}

fn library() -> &'static RetainedLibrary {
    LIBRARY.get_or_init(|| {
        let path = "/tmp/rfc0025-native-mapping-rust-coupling-shim-v1/libcrucible-mapping-shim.so";
        let body = std::fs::read(path).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&body)),
            "fa4b2ebefa9ab39140ab2c98d96d080019d2f396e96899f38b1356b490875b1e"
        );
        let name = std::ffi::CString::new(path).unwrap();
        // SAFETY: This exact pinned test-only DSO and its runtime dependencies
        // are AOS-built. Its original handle is retained, never closed/reloaded.
        let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        assert!(!handle.is_null());
        let symbol = |name: &std::ffi::CStr| {
            // SAFETY: The live pinned handle declares these exact test-only ABIs.
            let pointer = unsafe { libc::dlsym(handle, name.as_ptr()) };
            assert!(!pointer.is_null());
            pointer
        };
        RetainedLibrary {
            _handle: handle as usize,
            apis: MappingHoldApis {
                // SAFETY: This wrapper delegates the exact source getter144.
                read: unsafe {
                    std::mem::transmute::<*mut c_void, ReadMappingHold>(symbol(
                        c"crucible_test_mapping_hold_read_v1",
                    ))
                },
                // SAFETY: This is the literal native original-status predicate.
                authenticate_status: unsafe {
                    std::mem::transmute::<*mut c_void, AuthenticateStatus>(symbol(
                        c"qemu_plugin_crucible_whole_authenticate_mapping_status_v1",
                    ))
                },
            },
            // SAFETY: The pinned fixture declares birth128, callback and status88.
            invoke: unsafe {
                std::mem::transmute::<*mut c_void, Invoke>(symbol(
                    c"crucible_test_mapping_hold_invoke_v1",
                ))
            },
            // SAFETY: The pinned inspection ABI returns exactly32B by value.
            inspect: unsafe {
                std::mem::transmute::<*mut c_void, Inspect>(symbol(
                    c"crucible_test_mapping_hold_inspection_v1",
                ))
            },
        }
    })
}

pub(super) fn exercise(original: &Arc<SharedCallbackCustody>, birth: NativePreparation) {
    let library = library();
    let loss =
        u32::from(std::env::var("RFC0025_MAPPING_HOLD_CONTROL").as_deref() == Ok("native-stale"));
    let engine = super::super::tests::bound_engine_for_mapping_control();
    ACTIVE.set(Some(library.apis));
    let mut status = QemuPluginHotForkBarrierStatus::default();
    let result = (library.invoke)(
        &birth,
        birth.userdata,
        engine,
        super::super::super::closed_barrier,
        &mut status,
        loss,
    );
    let inspected = (library.inspect)();
    assert_eq!(inspected.version, 1);
    assert_eq!(inspected.size, 32);
    assert_eq!(inspected.process, u64::from(std::process::id()));
    ENGINE.with_borrow(|slot| {
        let engine = slot.as_ref().unwrap();
        let snapshot = engine.mapping_hold_journal.snapshot.unwrap();
        assert_eq!(snapshot.ring_count(), 6);
        assert_eq!(snapshot.held_rings(), 6);
        assert!(snapshot.mapping_excluded());
        assert!(snapshot.quiescent());
        assert!(engine.mapping_hold_journal.tuple.is_some());
        assert!(engine.mapping_hold_journal.prepared_status.is_some());
    });
    if loss == 0 {
        assert_eq!(result, 0);
        assert_eq!(inspected.phase, 1);
        assert_eq!(inspected.reads, 2);
        assert_eq!(inspected.status, 0);
        assert_eq!(inspected.flags, 0);
        assert_eq!(status.schema_version, 7);
        assert_eq!(status.ring_count, 6);
        assert_eq!(status.rings_held, 6);
        assert_eq!(status.in_flight, 0);
        assert_eq!(status.worker_mask, 0);
        assert!(!original.failed.load(Ordering::Acquire));
    } else {
        assert_eq!(result, -libc::ESTALE);
        assert_eq!(inspected.phase, 2);
        assert_eq!(inspected.reads, 1);
        assert_eq!(inspected.status, -libc::ESTALE);
        assert_eq!(inspected.flags, 1);
        assert_eq!(status, QemuPluginHotForkBarrierStatus::default());
        assert!(original.failed.load(Ordering::Acquire));
    }
    let mut revoked = NativeMappingHold::default();
    assert_eq!((library.apis.read)(&mut revoked), -libc::ESTALE);
    println!(
        "C_RUST_MAPPING_HOLD loss={} phase={} native_reads={} status={} six_held=6 revoked=1 ready=0",
        loss, inspected.phase, inspected.reads, inspected.status
    );
}
