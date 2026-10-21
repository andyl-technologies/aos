//! VM-only refusal checks for a Host scheduler without installed startup Control.
//!
//! The headless fixture has genuine peer credentials but no PID 1 startup
//! originals. Even read-only inventory must refuse that missing financial owner.
//! Positive Host qualification belongs to the funded installed-service VM.

use std::path::Path;
use std::time::{Duration, Instant};

use aos_sandbox_broker_session_security::{
    ProductionBrokerSessionActivationV1, production_deadline_after,
};
use aos_sandbox_host::authorization::HostAuthorityV1;
use aos_sandbox_host::broker::HostBroker;
use aos_sandbox_host::catalog::{FileHostCatalog, FileHostCatalogPublisher};
use aos_sandbox_host::state::FileHostStateStore;
use aos_sandbox_host::worker::SystemdOneShotWorker;
use aos_sandbox_host::{DormantHostBrokerCallErrorV1, DormantHostBrokerCompositionV1, HostError};
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;

use super::{ProductionHostBrokerServiceErrorV1, ProductionHostBrokerServiceV1};
use aos_sandbox_broker_session_security::ProductionBrokerSessionActivationErrorV1;

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
#[ignore = "root VM supplies protected credentials but no PID 1 startup Control"]
fn fixed_host_inventory_without_startup_control_is_rejected() {
    assert!(rustix::process::geteuid().is_root());
    let controller = RecordSubjectListener::bind(Path::new(CONTROLLER_SOCKET), 8).unwrap();
    let root_mount = RecordSubjectListener::bind(Path::new(ROOT_MOUNT_SOCKET), 8).unwrap();
    let storage = RecordSubjectListener::bind(Path::new(STORAGE_SOCKET), 8).unwrap();
    let activation =
        ProductionBrokerSessionActivationV1::adopt_host_listeners(controller, root_mount, storage)
            .unwrap();
    let mut service = ProductionHostBrokerServiceV1::new(activation).unwrap();

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
    let deadline = production_deadline_after(Duration::from_secs(15)).unwrap();
    let error = runtime
        .block_on(service.serve_next(&mut host, &publisher, deadline))
        .unwrap_err();
    assert!(matches!(
        error,
        ProductionHostBrokerServiceErrorV1::Activation(
            ProductionBrokerSessionActivationErrorV1::HostColdCallsite(
                DormantHostBrokerCallErrorV1::Broker(HostError::Fence(
                    "Host cold cleanup has no captured startup Control"
                ))
            )
        )
    ));
    drop(service);

    // Close the refused endpoint before waiting for the client's observation.
    assert!(
        wait_for_client_completion(Path::new(CLIENT_DONE), Duration::from_secs(5)),
        "Controller did not observe the missing-startup rejection"
    );
    println!("FIXED_HOST_MISSING_STARTUP_REJECTED");
}
