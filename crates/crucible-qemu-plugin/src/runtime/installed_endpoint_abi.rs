//! Process-private registration for the original installed endpoint owner.
//!
//! The source compares the complete original Root328, sealed descriptor cookies
//! and actual self-registered worker lifetimes. Local holding is an observation
//! of those retained owners; it supplies no RootSeal, effect cut, Ready or capture
//! closure. None of these native pointers enters a socket or shared-memory body.

use std::ffi::{c_int, c_void};

use crate::native_node_control::NativeRootPolicy;

/// Identifies the retained source object without exposing its native layout.
#[repr(C)]
pub(crate) struct NativeInstalledEndpointOwner {
    _private: [u8; 0],
}

/// Identifies one actual source-enrolled thread lifetime, without a public token.
#[repr(C)]
pub(super) struct NativeEndpointWorker {
    _private: [u8; 0],
}

/// Supplies the original process-private allocations to the source registrar.
///
/// The source copies the original policy during registration and retains the
/// role and callback references rather than owning their Rust allocations.
/// Those allocations and callback code remain live after source retention.
#[repr(C)]
pub(super) struct NativeEndpointOwnerRegistration {
    pub(super) version: u32,
    pub(super) size: u32,
    pub(super) original: *const NativeRootPolicy,
    pub(super) runtime: *mut c_void,
    pub(super) administration: *mut c_void,
    pub(super) run: *mut c_void,
    pub(super) teardown: *mut c_void,
    pub(super) try_hold: Option<RetainEndpointCustody>,
    pub(super) validate_held: Option<RetainEndpointCustody>,
}

/// Names the three separately retained actual worker roles.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeEndpointWorkerKind {
    Administration = 1,
    #[cfg(not(test))]
    Run = 2,
    #[cfg(not(test))]
    Teardown = 3,
}

/// Retains the complete optional source ABI without an implicit fallback.
pub(super) struct NativeEndpointOwnerApi {
    #[cfg(not(test))]
    pub(super) register: RegisterEndpointOwner,
    pub(super) register_current_worker: RegisterCurrentEndpointWorker,
    pub(super) try_hold_local: TryHoldEndpointOwner,
}

impl NativeEndpointOwnerApi {
    /// Resolves every separately named source export before accepting this opt-in.
    #[cfg(not(test))]
    pub(super) fn resolve() -> Option<Self> {
        // SAFETY: These names identify the fixed GPL-local Registration64 API.
        // Symbols and callback pointers remain inside the original QEMU process.
        let (register, register_worker, try_hold) = unsafe {
            (
                libc::dlsym(
                    libc::RTLD_DEFAULT,
                    c"qemu_plugin_register_crucible_endpoint_owner".as_ptr(),
                ),
                libc::dlsym(
                    libc::RTLD_DEFAULT,
                    c"qemu_plugin_crucible_endpoint_register_current_worker".as_ptr(),
                ),
                libc::dlsym(
                    libc::RTLD_DEFAULT,
                    c"qemu_plugin_crucible_endpoint_try_hold_local".as_ptr(),
                ),
            )
        };
        if register.is_null() || register_worker.is_null() || try_hold.is_null() {
            return None;
        }

        // SAFETY: The independently compiled source header fixes these exact
        // scalar signatures. Runtime callers must retain all original pointees.
        Some(unsafe {
            Self {
                register: std::mem::transmute::<*mut c_void, RegisterEndpointOwner>(register),
                register_current_worker: std::mem::transmute::<
                    *mut c_void,
                    RegisterCurrentEndpointWorker,
                >(register_worker),
                try_hold_local: std::mem::transmute::<*mut c_void, TryHoldEndpointOwner>(try_hold),
            }
        })
    }
}

const _: () = {
    assert!(std::mem::size_of::<NativeEndpointOwnerRegistration>() == 64);
    assert!(std::mem::offset_of!(NativeEndpointOwnerRegistration, original) == 8);
    assert!(std::mem::offset_of!(NativeEndpointOwnerRegistration, runtime) == 16);
    assert!(std::mem::offset_of!(NativeEndpointOwnerRegistration, administration) == 24);
    assert!(std::mem::offset_of!(NativeEndpointOwnerRegistration, run) == 32);
    assert!(std::mem::offset_of!(NativeEndpointOwnerRegistration, teardown) == 40);
    assert!(std::mem::offset_of!(NativeEndpointOwnerRegistration, try_hold) == 48);
    assert!(std::mem::offset_of!(NativeEndpointOwnerRegistration, validate_held) == 56);
};

/// Borrows the exact installed runtime and original role allocations synchronously.
///
/// The installer retains every pointee and the callback code for process life.
/// EAGAIN preserves partial holds and cannot install an effect scope.
///
/// # Safety
/// The caller supplies the same four process-lifetime allocations retained by
/// the original registration. Runtime userdata is readable and aligned; the
/// other role addresses are compared against their retained Arc identities.
pub(super) type RetainEndpointCustody = unsafe extern "C" fn(
    runtime: *mut c_void,
    administration: *mut c_void,
    run: *mut c_void,
    teardown: *mut c_void,
) -> c_int;

/// Registers original ownership only after the existing native manifest is sealed.
///
/// # Safety
/// Registration, original policy and output point to valid aligned storage for
/// the call. Runtime and role allocations and callback code remain live for the
/// process lifetime after source retention, including later installation failure.
#[cfg(not(test))]
pub(super) type RegisterEndpointOwner = unsafe extern "C" fn(
    original: *const NativeEndpointOwnerRegistration,
    output: *mut *mut NativeInstalledEndpointOwner,
) -> c_int;

/// Enrolls the calling thread using its actual source PID, TID and TLS lifetime.
///
/// # Safety
/// The owner and role address come from the same retained registration; output
/// is writable, aligned pointer storage. The caller preserves original endpoint
/// ownership and invokes enrollment from the actual worker being registered.
pub(super) type RegisterCurrentEndpointWorker = unsafe extern "C" fn(
    owner: *mut NativeInstalledEndpointOwner,
    kind: NativeEndpointWorkerKind,
    original_role: *mut c_void,
    descriptor: c_int,
    output: *mut *mut NativeEndpointWorker,
) -> c_int;

/// Names the original source registration address without exposing its layout.
pub(super) type InstalledOwnerPointer = *mut NativeInstalledEndpointOwner;

/// Observes local custody at the authentic fresh RR preparation seam.
///
/// # Safety
/// The caller supplies its original retained native owner address. The source
/// authenticates that identity before dereference and invokes only process-life
/// callbacks; the Rust caller keeps their original allocations and endpoints.
pub(super) type TryHoldEndpointOwner = unsafe extern "C" fn(owner: InstalledOwnerPointer) -> c_int;
