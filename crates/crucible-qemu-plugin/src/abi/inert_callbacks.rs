//! Inert scaffold device and vCPU callbacks for the QEMU plugin ABI.
//!
//! Each callback is registered into the plugin's device-callback partition
//! while the plugin runs inert (simulation-off / scaffold phase); later tasks
//! replace the bodies with the real Crucible behaviour. They are grouped here to
//! keep the parent `abi` module within the RFC-0010 file-shape limits.

use super::*;

/// Inert scaffold network-TX callback.
pub extern "C" fn crucible_qemu_plugin_inert_network_tx_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold network-RX callback.
pub extern "C" fn crucible_qemu_plugin_inert_network_rx_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold block-submit callback.
pub extern "C" fn crucible_qemu_plugin_inert_block_submit_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold block-poll callback.
pub extern "C" fn crucible_qemu_plugin_inert_block_poll_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold 9p-submit callback.
pub extern "C" fn crucible_qemu_plugin_inert_9p_submit_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold 9p-poll callback.
pub extern "C" fn crucible_qemu_plugin_inert_9p_poll_cb(_id: QemuPluginId, _userdata: *mut c_void) {
}

/// Inert scaffold white-box doorbell callback.
pub extern "C" fn crucible_qemu_plugin_inert_whitebox_doorbell_cb(
    _id: QemuPluginId,
    _userdata: *mut c_void,
) {
}

/// Inert scaffold vCPU init callback.
pub extern "C" fn crucible_qemu_plugin_inert_vcpu_init_cb(_id: QemuPluginId, _vcpu_index: c_uint) {
    if let Some(force_vcpu_exit) = resolve_qemu_force_vcpu_exit_symbol() {
        force_vcpu_exit();
    }
}

/// Inert scaffold vCPU idle callback.
pub extern "C" fn crucible_qemu_plugin_inert_vcpu_idle_cb(_id: QemuPluginId, _vcpu_index: c_uint) {}

/// Inert scaffold vCPU resume callback.
pub extern "C" fn crucible_qemu_plugin_inert_vcpu_resume_cb(
    _id: QemuPluginId,
    _vcpu_index: c_uint,
) {
}
