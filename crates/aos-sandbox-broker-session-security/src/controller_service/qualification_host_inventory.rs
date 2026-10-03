//! VM-only qualification of the fixed Controller-to-Host runtime Inventory channel.
//!
//! The root broker retains all three production Host listeners and uses the
//! protected Host authority, state store, worker, and dispatch. Empty runtime
//! inventory proves this one read-only channel, not Host effects or readiness.

use std::fs::OpenOptions;
use std::path::Path;
use std::time::{Duration, Instant};

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, InventoryRuntimeResponse};
use aos_sandbox_host::DormantHostBrokerCompositionV1;
use aos_sandbox_host::authorization::HostAuthorityV1;
use aos_sandbox_host::broker::HostBroker;
use aos_sandbox_host::catalog::{FileHostCatalog, FileHostCatalogPublisher};
use aos_sandbox_host::state::FileHostStateStore;
use aos_sandbox_host::worker::SystemdOneShotWorker;
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
use buffa::Message as _;

use super::{CycleFailure, connect_controller_session, read_node_id};
use crate::{
    DormantHostRuntimeInventoryOwnerV1, ProductionBrokerSessionActivationV1,
    ProtectedBrokerSessionFixedEndpointV1, production_deadline_after,
};

const CONTROLLER_SOCKET: &str = "/run/aos/sandbox-host/control.sock";
const ROOT_MOUNT_SOCKET: &str = "/run/aos/sandbox-host/root-mount.sock";
const STORAGE_SOCKET: &str = "/run/aos/sandbox-host/storage.sock";
const CATALOG_ROOT: &str = "/run/aos/sandbox-host";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-host";
const CLIENT_DONE: &str = "/run/aos/controller-qualification/host-inventory-complete";

fn wait_for_client_completion(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}

#[test]
fn missing_host_client_completion_expires_closed() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing");

    assert!(!wait_for_client_completion(
        &missing,
        Duration::from_millis(20)
    ));
}

#[test]
#[ignore = "root VM runs the fixed Host broker with protected deployed credentials"]
fn fixed_host_inventory_broker() {
    assert!(rustix::process::geteuid().is_root());
    let controller = RecordSubjectListener::bind(Path::new(CONTROLLER_SOCKET), 8).unwrap();
    let root_mount = RecordSubjectListener::bind(Path::new(ROOT_MOUNT_SOCKET), 8).unwrap();
    let storage = RecordSubjectListener::bind(Path::new(STORAGE_SOCKET), 8).unwrap();
    let activation =
        ProductionBrokerSessionActivationV1::adopt_host_listeners(controller, root_mount, storage)
            .unwrap();
    let mut service = activation.into_host_service().unwrap();

    let catalog = FileHostCatalog::open_root_owned(CATALOG_ROOT).unwrap();
    let publisher = FileHostCatalogPublisher::open_root_owned(CATALOG_ROOT).unwrap();
    let state = FileHostStateStore::open(STATE_ROOT).unwrap();
    let cgroup_fd = rustix::fs::open(
        "/sys/fs/cgroup",
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let worker = SystemdOneShotWorker::new(BeneathRoot::from_owned(cgroup_fd).unwrap());
    let authority = HostAuthorityV1::from_protected_directory(
        std::env::var_os("CREDENTIALS_DIRECTORY").unwrap(),
    )
    .unwrap();
    let mut broker = HostBroker::open(catalog, state, worker, None, authority).unwrap();
    let mut host = DormantHostBrokerCompositionV1::new(&mut broker);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        for _ in 0..2 {
            let deadline = production_deadline_after(Duration::from_secs(15)).unwrap();
            service
                .serve_next(&mut host, &publisher, deadline)
                .await
                .unwrap();
        }
    });

    // Retain the peer pidfd until the client completes both terminal rechecks.
    assert!(
        wait_for_client_completion(Path::new(CLIENT_DONE), Duration::from_secs(5)),
        "Controller did not finish both Host currentness checks"
    );
    println!("FIXED_HOST_BROKER_INVENTORY_PASS");
}

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
