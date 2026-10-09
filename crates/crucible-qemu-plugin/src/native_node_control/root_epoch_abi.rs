//! Process-private source-owned root and effect capability callback declarations.
//!
//! These incomplete native types are never decoded from socket or shared-memory
//! bytes. The independently installed source validates the exact live root/cut,
//! original policy, RR/BQL owner and lifetime before invoking a callback. Merely
//! registering these callbacks supplies neither a RootSeal nor Ready. No scalar
//! context layout is declared before the authentic source dispatcher defines it.

use std::ffi::{c_int, c_void};

use super::root_policy::NativeRootPolicy;

/// Names a live source-owned root without exposing its layout or constructors.
#[repr(C)]
pub(crate) struct NativeSourceRootSeal {
    _private: [u8; 0],
}

/// Names an original source-selected effect cut without exposing its layout.
#[repr(C)]
pub(crate) struct NativeSourceEffectCut {
    _private: [u8; 0],
}

/// Acquires retained plugin ownership from a genuinely admitted source root.
///
/// EAGAIN leaves the output NULL and retains partial original holds privately.
/// Successful original retries return the same stable owned-epoch pointer.
///
/// # Safety
/// The caller supplies its actual live source root and registration's retained
/// userdata. A non-NULL output must identify writable, aligned pointer storage
/// for the synchronous call. It must not alias the retained owner or mapping.
pub(crate) type AcquireRootEpoch =
    unsafe extern "C" fn(*const NativeSourceRootSeal, *mut *mut c_void, *mut c_void) -> c_int;

/// Installs a scope only for the same epoch and native original effect cut.
///
/// EAGAIN retains the pending original cut and installs no callback/ring scope.
///
/// # Safety
/// The caller preserves the registered userdata allocation and original
/// source-owned root/cut lifetimes throughout the synchronous callback. An epoch
/// address must come from that same registration's acquisition, never wire data.
pub(crate) type BeginRootEffect = unsafe extern "C" fn(
    *const NativeSourceRootSeal,
    *mut c_void,
    *const NativeSourceEffectCut,
    *mut c_void,
) -> c_int;

/// Clears scoped permission before reporting success or failure to the source.
///
/// Failure retains tainted original ownership and forbids a successful stopped
/// inventory. Neither this callback nor token drop releases the global holds.
pub(crate) type EndRootEffect = BeginRootEffect;

/// Registers original callbacks before the first V9 resource manifest seal.
///
/// # Safety
/// The policy must point to readable, aligned Root328 storage for the call.
/// Installed callback code and non-NULL userdata must remain valid for the
/// process lifetime, including failures after the source retains registration.
/// Each callback must obey its declared source identity and output contract.
pub(crate) type RegisterRootEpoch = unsafe extern "C" fn(
    u32,
    *const NativeRootPolicy,
    Option<AcquireRootEpoch>,
    Option<BeginRootEffect>,
    Option<EndRootEffect>,
    *mut c_void,
) -> c_int;

/// Resolves the explicitly versioned GPL-side registration without fallback.
pub(crate) fn resolve_register_root_epoch() -> Option<RegisterRootEpoch> {
    // SAFETY: This static name denotes the independently versioned native source
    // callback ABI. No QEMU structure or pointer crosses the process boundary.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_register_crucible_node_root_epoch".as_ptr(),
        )
    };
    if symbol.is_null() {
        return None;
    }
    // SAFETY: The source header fixes version1 and this exact registration ABI.
    // The caller must pin its original Root328 and retain userdata before calling.
    Some(unsafe { std::mem::transmute::<*mut c_void, RegisterRootEpoch>(symbol) })
}

/// Retains the old manifest prefix and records installed callback edition1.
#[repr(C)]
pub(crate) struct NativeRootEpochManifest {
    pub(crate) root: super::manifest::RootResourceManifest,
    pub(crate) epoch_version: u32,
    pub(crate) reserved: u32,
}

/// Adds actual installed source callbacks without changing earlier ALL masks.
pub(crate) const RESOURCE_NATIVE_ROOT_EPOCH: u64 = 1 << 20;
pub(crate) const CALLBACK_NATIVE_ROOT_EPOCH: u64 = 1 << 17;

const _: () = {
    assert!(std::mem::size_of::<NativeRootEpochManifest>() == 264);
    assert!(std::mem::offset_of!(NativeRootEpochManifest, epoch_version) == 256);
};
