//! Controller-nine callback entry gates for the output-disabled subset.
//!
//! Queued initialization is authenticated by the native constructor row before
//! touching userdata. Notifications observe only a staged source context;
//! backend, FIFO and fork entries terminate before legacy effects.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::{c_uint, c_void};

use super::{callback_userdata_or_abort, crucible_qemu_plugin_live_vcpu_init_cb};
use crate::native_node_control::NativeNodeControl;

/// Stops unsupported prefix-profile writers before touching callback userdata.
///
/// The exhaustive output-free dispatcher has no modeled backend/FIFO or fork
/// publication branch. A source call into one of those entries taints custody
/// by terminating the child; it cannot silently fall through legacy effects.
pub(crate) fn reject_prefix_modeled_entry() {
    if crate::native_node_control::registered_owner().is_some_and(|owner| owner.prefix.is_some()) {
        std::process::abort();
    }
}

/// Performs only the original source-authenticated queued initialization.
pub(super) fn initialize_if_selected(vcpu_index: c_uint, userdata: *mut c_void) -> bool {
    let Some(prefix) =
        crate::native_node_control::registered_owner().and_then(|owner| owner.prefix.as_ref())
    else {
        return false;
    };
    if prefix
        .validate_initialization_callback(
            vcpu_index,
            crucible_qemu_plugin_live_vcpu_init_cb as *const () as usize,
            userdata,
        )
        .is_err()
    {
        std::process::abort();
    }

    let state = callback_userdata_or_abort(userdata);
    if state.on_vcpu_init(vcpu_index).is_err() {
        std::process::abort();
    }
    true
}

/// Observes the actual source context without admitting legacy notification work.
pub(super) fn observe_notification(owner: &NativeNodeControl) {
    if let Some(prefix) = &owner.prefix
        && prefix.observe_active_if_staged().is_err()
    {
        std::process::abort();
    }
}
