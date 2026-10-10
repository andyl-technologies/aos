//! Checks local lease/inventory reachability and explicit remote adapter selection.

#![cfg(target_os = "linux")]

use aos_sandbox::local_ownership::ProtectedFixedLocalLeaseOwnerV1;
use aos_sandbox::ownership_service::OwnershipProtocolRequestHandler;

#[test]
fn local_lease_owner_is_a_protocol_handler_without_remote_selection() {
    fn require_handler<T: OwnershipProtocolRequestHandler>() {}

    require_handler::<ProtectedFixedLocalLeaseOwnerV1>();
    let _open = ProtectedFixedLocalLeaseOwnerV1::open_fixed_protected;
    let _recover = ProtectedFixedLocalLeaseOwnerV1::recover;
}

#[test]
fn protected_snapshot_inventory_remains_available_without_remote_selection() {
    let _open =
        aos_sandbox::local_inventory::ProtectedMultiNodeAuthorityOwnerV1::open_fixed_protected;
    let _resolve =
        aos_sandbox::local_inventory::ProtectedMultiNodeAuthorityOwnerV1::resolve_store_write;
}

#[cfg(feature = "multi-node")]
#[test]
fn explicit_multi_node_selection_retains_protected_transport() {
    let _transport =
        aos_sandbox::local_inventory::ProtectedMultiNodeAuthorityOwnerV1::authenticate_dormant_transport;
}
