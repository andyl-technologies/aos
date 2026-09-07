//! End-to-end controller and Network service qualification on real cgroup v2.

#![allow(
    clippy::unwrap_used,
    reason = "Kernel fixture failures intentionally panic."
)]

use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use aos_sandbox::{
    ActivatedOperationCompiler, ControllerRequestScopeV1, EffectFailure, EffectObservation,
    EffectPlan, EffectReceipt, Journal, JournalLimits, NetworkResourceInventoryClient,
    NodeController, NodeControllerLimits, OperationCompilationError, OperationPlan, Reconciler,
    ResourceInventoryServiceIdentity, SingleNodeEffectExecutor,
};
use aos_sandbox_core::{ObjectDigest, OperationId};
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};

use super::*;

const TEST_CGROUP: &str = "aos-local-identity-tests";

struct UnusedCompiler;

impl ActivatedOperationCompiler for UnusedCompiler {
    fn compile(
        &mut self,
        _canonical_request: &[u8],
        _request_digest: [u8; 32],
    ) -> Result<OperationPlan, OperationCompilationError> {
        Err(OperationCompilationError::Rejected)
    }
}

struct UnusedExecutor;

impl SingleNodeEffectExecutor for UnusedExecutor {
    fn observe(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        _plan: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        Err(EffectFailure::Permanent(
            "unused Network inventory test executor".to_owned(),
        ))
    }

    fn apply(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        _plan: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        Err(EffectFailure::Permanent(
            "unused Network inventory test executor".to_owned(),
        ))
    }
}

#[test]
fn controller_records_authenticated_netd_inventory_over_record_subject_session() {
    let catalog_state = tempfile::tempdir().unwrap();
    let pin_root = tempfile::tempdir().unwrap();
    let socket_root = tempfile::tempdir().unwrap();
    // The protected opener intentionally rejects /tmp's world-writable
    // ancestry. This fixture runs as root on a writable qualification image.
    let controller_state = tempfile::tempdir_in("/").unwrap();
    for directory in [&catalog_state, &pin_root, &controller_state] {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let catalog = NetworkNamespaceCatalogV1::open_for_test(
        catalog_state.path(),
        pin_root.path(),
        [31; 16],
        [32; 16],
    )
    .unwrap();
    let identity = (
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
    );
    let mut service = NetworkInventoryService::new(catalog, current_cgroup(), identity).unwrap();
    let socket_path = socket_root.path().join("network.sock");
    let mut listener = RecordSubjectListener::bind(&socket_path, 4).unwrap();

    let service_thread = std::thread::spawn(move || service.serve_once(&mut listener).unwrap());
    let client_fd = connect_client(&socket_path);
    let client = NetworkResourceInventoryClient::from_connected(
        client_fd,
        ResourceInventoryServiceIdentity {
            uid: identity.0,
            gid: identity.1,
            cgroup: current_cgroup(),
        },
    )
    .unwrap();
    let (journal, _) = Journal::open_protected_at_for_uid(
        controller_state.path(),
        "controller.journal",
        JournalLimits::default(),
        std::fs::metadata(controller_state.path()).unwrap().uid(),
    )
    .unwrap();
    let scope = ControllerRequestScopeV1::new(ObjectDigest::from_bytes([33; 32])).unwrap();
    let mut controller = NodeController::new(
        scope,
        NodeControllerLimits::default(),
        UnusedCompiler,
        Reconciler::new(journal, UnusedExecutor),
    );

    let snapshot = controller
        .record_network_resource_inventory(client)
        .unwrap();

    assert_eq!(snapshot.inventory().kernel_boot_id(), &[31; 16]);
    assert_eq!(snapshot.inventory().broker_instance_id(), &[32; 16]);
    assert_eq!(snapshot.inventory().catalog_generation(), 1);
    assert!(snapshot.inventory().networks().is_empty());
    assert_eq!(
        service_thread.join().unwrap(),
        NetworkConnectionOutcome::Served
    );
}

fn current_cgroup() -> RetainedCgroupAnchor {
    let root: OwnedFd = File::open("/sys/fs/cgroup").unwrap().into();
    CgroupV2Root::from_owned(root)
        .unwrap()
        .resolve(Path::new(TEST_CGROUP))
        .unwrap()
}

fn connect_client(path: &Path) -> OwnedFd {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    connect(&socket, &SocketAddrUnix::new(path).unwrap()).unwrap();
    socket
}
