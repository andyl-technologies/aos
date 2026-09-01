//! Dynamic QEMU symbol resolution for canonical guest network receive.
//!
//! The inject export attempts one frame without transferring ownership on
//! backpressure. Resolution is fail-closed at plugin installation, before any
//! frame can be accepted from shared memory.

use std::os::raw::{c_int, c_void};

/// QEMU patch export used to attempt one inbound frame delivery.
pub const QEMU_PLUGIN_NET_INJECT_SYMBOL: &str = "qemu_plugin_net_inject";
const QEMU_PLUGIN_NET_INJECT_SYMBOL_C: &[u8] = b"qemu_plugin_net_inject\0";

/// QEMU's canonical network RX injection function.
///
/// The patched QEMU API returns zero after complete guest delivery, one when
/// guest backpressure requires the caller to retain canonical ownership, and a
/// negative status on a permanent capability or link failure.
pub type QemuPluginNetInjectFn = extern "C" fn(*const u8, usize) -> c_int;

/// Resolves QEMU's canonical network RX injection export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_net_inject_symbol() -> Option<QemuPluginNetInjectFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. The QEMU patch defines this
    // symbol with the exact `QemuPluginNetInjectFn` ABI; callers fail closed
    // when it is absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_NET_INJECT_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for `qemu_plugin_net_inject`,
        // whose patched QEMU declaration matches `QemuPluginNetInjectFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuPluginNetInjectFn>(symbol) })
    }
}

/// Resolves QEMU's canonical network RX injection export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_net_inject_symbol() -> Option<QemuPluginNetInjectFn> {
    None
}
