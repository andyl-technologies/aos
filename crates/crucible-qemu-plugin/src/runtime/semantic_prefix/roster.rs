//! Original native callback registration after all thirty real install seams.
//!
//! Metadata is borrowed from the same process-life runtime. Native source must
//! compare its own callback storage and fence writers after installation; this
//! registrar alone supplies no epoch, callback or modeled-output permission.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::{c_int, c_void};

use super::{PrefixPolicy, SemanticPrefixOwner};
use crate::runtime::{
    OwnedCallbackRegistrationError, OwnedCallbackRuntimeState, PluginRuntimeInstallError,
};

use crate::runtime::live_callbacks::callback_roster::CallbackTuple;

#[repr(C)]
pub(super) struct NativeRosterRegistration {
    version: u32,
    size: u32,
    original_policy: *const PrefixPolicy,
    entries: *const CallbackTuple,
    original_plugin_id: u64,
    retained_runtime: *mut c_void,
    number_of_entries: u32,
    reserved: u32,
}

pub(super) type RegisterRoster = extern "C" fn(*const NativeRosterRegistration) -> c_int;
pub(super) type QueryInitialization = extern "C" fn(u32, usize, *const c_void) -> c_int;

/// Retains the two hot-fork tuples and registers a selected prefix roster.
///
/// # Errors
/// Rejects changed tuple custody or native roster registration. Legacy profiles
/// retain the same hot-fork tuples without invoking a prefix registrar.
pub(crate) fn retain_installed_callbacks(
    plugin_id: u64,
    callback_runtime: *mut c_void,
    runtime: &OwnedCallbackRuntimeState,
) -> Result<(), PluginRuntimeInstallError> {
    runtime
        .callback_roster
        .retain_hot_fork(callback_runtime)
        .map_err(|source| PluginRuntimeInstallError::OwnedCallbacks {
            source: OwnedCallbackRegistrationError::LiveVcpuTime { source },
        })?;

    if let Some(prefix) =
        crate::native_node_control::registered_owner().and_then(|owner| owner.prefix.as_ref())
    {
        prefix
            .register_callback_roster(plugin_id, runtime)
            .map_err(|status| PluginRuntimeInstallError::InstalledEndpointOwner { status })?;
    }
    Ok(())
}

impl SemanticPrefixOwner {
    /// Supplies exact retained tuples for independent native table comparison.
    ///
    /// # Errors
    /// Rejects incomplete tuples, changed runtime userdata or a native refusal.
    pub(crate) fn register_callback_roster(
        &self,
        plugin_id: u64,
        runtime: &OwnedCallbackRuntimeState,
    ) -> Result<(), c_int> {
        if self.process_id != std::process::id() || plugin_id == 0 {
            return Err(-libc::ESTALE);
        }
        let rows = runtime
            .callback_roster
            .complete_original()
            .map_err(|_| -libc::ESTALE)?
            .ok_or(-libc::EAGAIN)?;
        let runtime_address = std::ptr::from_ref(runtime).cast_mut().cast::<c_void>();
        if rows[28].userdata != runtime_address as usize
            || rows[29].userdata != runtime_address as usize
        {
            return Err(-libc::ESTALE);
        }
        let registration = NativeRosterRegistration {
            version: 1,
            size: 48,
            original_policy: &self.policy,
            entries: rows.as_ptr(),
            original_plugin_id: plugin_id,
            retained_runtime: runtime_address,
            number_of_entries: 30,
            reserved: 0,
        };
        let result = (self.api.register_roster)(&registration);
        if result != 0 {
            return Err(result);
        }
        Ok(())
    }

    /// Verifies the one genuine queued native initialization callback scope.
    ///
    /// # Errors
    /// Rejects a foreign process, row tuple or callback outside native construction.
    pub(crate) fn validate_initialization_callback(
        &self,
        cpu_index: u32,
        function: usize,
        userdata: *const c_void,
    ) -> Result<(), c_int> {
        if self.process_id != std::process::id() {
            return Err(-libc::ESTALE);
        }
        let status = (self.api.query_initialization)(cpu_index, function, userdata);
        if status != 0 {
            return Err(status);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::NativeRosterRegistration;
    use std::mem::{offset_of, size_of};

    #[test]
    fn native_roster_registration_matches_the_closed_source_offsets() {
        assert_eq!(size_of::<NativeRosterRegistration>(), 48);
        assert_eq!(offset_of!(NativeRosterRegistration, original_policy), 8);
        assert_eq!(offset_of!(NativeRosterRegistration, entries), 16);
        assert_eq!(offset_of!(NativeRosterRegistration, original_plugin_id), 24);
        assert_eq!(offset_of!(NativeRosterRegistration, retained_runtime), 32);
        assert_eq!(offset_of!(NativeRosterRegistration, number_of_entries), 40);
        assert_eq!(offset_of!(NativeRosterRegistration, reserved), 44);
    }
}
