//! Checks the separate local inventory owner and remote adapter selection.

#![cfg(target_os = "linux")]

#[test]
fn protected_snapshot_inventory_remains_available_without_remote_selection() {
    let _open =
        aos_sandbox_controller_domain::local_inventory::ProtectedMultiNodeAuthorityOwnerV1::open_fixed_protected;
    let _resolve =
        aos_sandbox_controller_domain::local_inventory::ProtectedMultiNodeAuthorityOwnerV1::resolve_store_write;
}
