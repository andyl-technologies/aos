//! VM-only Controller client qualification of the fixed Host inventory channel.
//!
//! The Services Host broker fixture owns the root scheduler and retains peer
//! custody until this client completes both terminal currentness checks.
//! Empty inventory qualifies this read-only channel, not Host effects or readiness.

use std::fs::OpenOptions;

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, InventoryRuntimeResponse};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
use buffa::Message as _;

use super::activation::read_node_id;
use super::{CycleFailure, connect_controller_session};
use crate::{DormantHostRuntimeInventoryOwnerV1, ProtectedBrokerSessionFixedEndpointV1};

const CLIENT_DONE: &str = "/run/aos/controller-qualification/host-inventory-complete";

#[test]
#[ignore = "Controller VM client requires the fixed UID and Host broker custody"]
fn fixed_controller_host_inventory_client() {
    assert_eq!(rustix::process::geteuid().as_raw(), 811);
    let node = read_node_id().unwrap();
    let session = connect_controller_session(
        ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient,
        node,
    )
    .unwrap_or_else(|error| match error {
        CycleFailure::Retryable(message) | CycleFailure::Fatal(message) => {
            panic!("fixed Host handshake failed: {message}")
        }
    });
    let mut inventory = DormantHostRuntimeInventoryOwnerV1::from_protected_session(session);

    let first = inventory
        .qualification_current_inventory_observation()
        .unwrap();
    let second = inventory
        .qualification_current_inventory_observation()
        .unwrap();
    for outcome in [&first, &second] {
        assert_eq!(
            outcome.method(),
            BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
        );
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            panic!("Host Inventory returned a signed error")
        };
        let response = InventoryRuntimeResponse::decode_from_slice(exact_body).unwrap();
        assert!(response.runtimes.is_empty());
    }
    assert!(second.broker_sequence() > first.broker_sequence());

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(CLIENT_DONE)
        .unwrap();
    println!("FIXED_CONTROLLER_HOST_INVENTORY_PASS");
}
