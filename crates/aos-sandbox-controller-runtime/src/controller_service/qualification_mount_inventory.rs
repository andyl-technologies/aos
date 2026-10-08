//! VM-only qualification of the fixed Controller-to-Mount Inventory channel.
//!
//! The broker uses the production Mount journal, descriptor worker, fixed
//! endpoint custody, method profile, and dispatch. An empty inventory proves
//! this one healthy channel; it does not qualify the other three brokers or
//! Controller reconciliation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::journal::{Journal, JournalLimits};
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_mount::DormantMountBrokerCompositionV1;
use aos_sandbox_mount::authorization::MountAuthorityV1;
use aos_sandbox_mount::broker::MountBroker;
use aos_sandbox_mount::catalog::{FileMountCatalog, PreparedMountCatalog};
use aos_sandbox_mount::helper::PosixSpawnNamespaceHelper;
use aos_sandbox_mount::keeper::SystemdFdStore;
use aos_sandbox_mount::worker::DescriptorMountWorker;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;

use super::{CycleFailure, connect_controller_session, read_node_id};
use crate::{
    DormantMountLifecycleInventoryOwnerV1, ProductionBrokerSessionActivationV1,
    ProductionMountBrokerOwnersV1, ProtectedBrokerSessionFixedEndpointV1,
    production_deadline_after,
};

const SOCKET: &str = "/run/aos/sandbox-mount/control.sock";
const CATALOG_ROOT: &str = "/run/aos/sandbox-mount-catalog";
const STATE_ROOT: &str = "/var/lib/aos/sandbox-mount";
const CLIENT_DONE: &str = "/run/aos/controller-qualification/mount-inventory-complete";

fn wait_for_client_completion(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}

#[test]
fn missing_client_completion_expires_closed() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing");

    assert!(!wait_for_client_completion(
        &missing,
        Duration::from_millis(20)
    ));
}

#[test]
#[ignore = "root VM runs a real fixed Mount broker with externally staged credentials"]
fn fixed_mount_inventory_broker() {
    assert!(rustix::process::geteuid().is_root());
    let listener = RecordSubjectListener::bind(Path::new(SOCKET), 8).unwrap();
    let listener_fd = listener.as_fd().try_clone_to_owned().unwrap();
    let mut activation =
        ProductionBrokerSessionActivationV1::adopt_mount_listener(listener_fd).unwrap();
    drop(listener);

    let (journal, _) = Journal::open_protected_at(
        Path::new(STATE_ROOT),
        "mount.journal",
        JournalLimits::default(),
    )
    .unwrap();
    let catalog =
        PreparedMountCatalog::new(FileMountCatalog::open_root_owned(CATALOG_ROOT).unwrap());
    let helper = PosixSpawnNamespaceHelper::new(PathBuf::from(
        std::env::var_os("AOS_QUALIFICATION_MOUNT_HELPER").unwrap(),
    ))
    .unwrap();
    let keeper = Arc::new(
        SystemdFdStore::from_environment_with_inventories(BTreeSet::new(), BTreeSet::new(), 1_024)
            .unwrap(),
    );
    let worker = DescriptorMountWorker::new(catalog, helper, keeper, BTreeMap::new()).unwrap();
    let authority = MountAuthorityV1::from_protected_directory(
        std::env::var_os("CREDENTIALS_DIRECTORY").unwrap(),
    )
    .unwrap();
    let mut broker =
        MountBroker::new_with_destination_slots(journal, worker, authority, CATALOG_ROOT, 0)
            .unwrap();
    let mut mount = DormantMountBrokerCompositionV1::new(&mut broker);

    let deadline = production_deadline_after(Duration::from_secs(15)).unwrap();
    let mut session = activation.accept_authenticated(deadline).unwrap();
    for _ in 0..2 {
        let deadline = production_deadline_after(Duration::from_secs(15)).unwrap();
        session = session
            .serve_production_mount_request(
                ProductionMountBrokerOwnersV1 {
                    mount: &mut mount,
                    catalog_scope: None,
                },
                deadline,
            )
            .unwrap();
    }

    // The peer pidfd must stay live through the client's final currentness check.
    assert!(
        wait_for_client_completion(Path::new(CLIENT_DONE), Duration::from_secs(5)),
        "Controller did not finish both currentness checks"
    );
    println!("FIXED_MOUNT_BROKER_INVENTORY_PASS");
}

#[test]
#[ignore = "Controller VM client requires the fixed UID and mounted broker custody"]
fn fixed_controller_mount_inventory_client() {
    assert_eq!(rustix::process::geteuid().as_raw(), 811);
    let node = read_node_id().unwrap();
    let session = connect_controller_session(
        ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
        node,
    )
    .unwrap_or_else(|error| match error {
        CycleFailure::Retryable(message) | CycleFailure::Fatal(message) => {
            panic!("fixed Mount handshake failed: {message}")
        }
    });
    let mut inventory = DormantMountLifecycleInventoryOwnerV1::from_protected_session(session);

    let mounts = inventory.current_inventory_observation().unwrap();
    assert_eq!(
        mounts.method(),
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
    );
    assert!(matches!(
        mounts.result(),
        AuthenticatedBrokerMethodResultV1::Success { .. }
    ));

    let destinations = inventory.current_destination_slot_observation().unwrap();
    assert_eq!(
        destinations.method(),
        BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
    );
    assert!(matches!(
        destinations.result(),
        AuthenticatedBrokerMethodResultV1::Success { .. }
    ));
    assert!(destinations.broker_sequence() > mounts.broker_sequence());

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(CLIENT_DONE)
        .unwrap();
    println!("FIXED_CONTROLLER_MOUNT_INVENTORY_PASS");
}
