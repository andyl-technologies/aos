//! Root-only complete client exchanges with real kernel descriptor tables.
//!
//! The synthetic responder deliberately does not implement Host admission or
//! claim to be a launched payload supervisor. These tests cover the Mount
//! client's transport, exact response binding, and kernel descriptor validation;
//! Host signed admission is tested independently in the Host crate.

use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{
    BrokerDescriptorRole, ObserveMountScopeRequest, ObserveMountScopeResponse,
};
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_protocol::mount_scope::MOUNT_SCOPE_DESCRIPTOR_ROLES;
use aos_sandbox_protocol::semantics::host::runtime_handle_v1;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{
    AuthorizationArtifactBytes, decode_mount_request, encode_success_response_envelope,
    negotiate_client_hello,
};
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

use super::*;
use crate::catalog::{FileMountCatalog, MountCatalog, PreparedMountCatalog};
use crate::host_scope::HostMountScopeClient;

#[derive(Clone, Copy, Debug)]
enum ResponseCase {
    Valid,
    ReplacementScope,
    WrongNamespaceType,
    IncompleteRights,
    ReorderedRoles,
}

#[test]
fn root_mount_client_accepts_exact_kernel_scope_and_rejects_response_substitution() {
    assert!(
        rustix::process::geteuid().is_root(),
        "run this fixture in the root VM"
    );

    let artifact_fixture = AuthorityFixture::new();
    let launch_template = request(91);
    let artifacts = artifact_fixture.artifacts(
        &launch_template,
        Some(ObjectDigest::from_bytes([77; 32])),
        1,
        &[&launch_template],
    );

    for case in [
        ResponseCase::Valid,
        ResponseCase::ReplacementScope,
        ResponseCase::WrongNamespaceType,
        ResponseCase::IncompleteRights,
        ResponseCase::ReorderedRoles,
    ] {
        let template = ApplyMountRequest::decode_from_slice(&launch_template).unwrap();
        let mut query = ObserveMountScopeRequest {
            header: template.header.clone(),
            fence: template.fence.clone(),
            runtime_handle: runtime_handle_v1(&[2; 16], 1, &[6; 32]).to_vec(),
            payload_scope_handle: vec![72; 32],
            ..Default::default()
        };
        let header = query.header.get_or_insert_default();
        header.protocol_minor = 3;
        header.audience = Audience::AUDIENCE_ROOT_MOUNT.into();
        header.deadline_boottime_nanoseconds = boottime() + 10_000_000_000;
        header.maximum_response_bytes = 16 * 1024;

        let observed = observe_scope(&query, &artifacts, case);

        if matches!(case, ResponseCase::Valid) {
            let observed = observed.unwrap();
            observed.recheck().unwrap();
            assert_eq!(observed.metadata().payload_scope_handle(), &[72; 32]);
            assert_eq!(
                observed.root().identity(),
                aos_sandbox_linux::path::BeneathRoot::from_owned(open_path("/"))
                    .unwrap()
                    .identity()
            );
            assert_prepared_catalog(template, observed, &query, &artifacts);
        } else {
            assert!(observed.is_err(), "accepted substituted response: {case:?}");
        }
    }
}

fn assert_prepared_catalog(
    mut mount_wire: ApplyMountRequest,
    observed: crate::host_scope::ObservedMountScope,
    host_request: &ObserveMountScopeRequest,
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
) {
    let header = mount_wire.header.get_or_insert_default();
    header.protocol_minor = 2;
    header.deadline_boottime_nanoseconds = observed.valid_until_boottime_nanoseconds();
    let mount = decode_mount_request(
        &mount_wire.encode_to_vec(),
        PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(std::process::id()),
        },
        PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        boottime(),
    )
    .unwrap();

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let source_path = directory.path().join("source");
    let slot_path = directory.path().join("slot");
    std::fs::create_dir(&source_path).unwrap();
    std::fs::create_dir(&slot_path).unwrap();
    let relative_slot = slot_path.strip_prefix("/").unwrap().to_str().unwrap();
    let source = std::fs::metadata(&source_path).unwrap();
    let slot = std::fs::metadata(&slot_path).unwrap();
    let root = observed.root().identity();
    let mount_namespace = observed.mount_namespace().identity();
    let user_namespace = observed.user_namespace().identity();
    let view = mount.view_revision().unwrap();
    let snapshot = serde_json::json!({
        "generation": 1,
        "entries": [{
            "assignment": {
                "sandbox_id": mount.fence().sandbox_id(),
                "incarnation_id": mount.fence().incarnation_id(),
                "assignment_epoch": mount.fence().assignment_epoch(),
                "desired_generation": mount.fence().desired_generation(),
                "assignment_digest": mount.fence().assignment_digest(),
            },
            "attachment_id": mount.attachment_id(),
            "destination_slot_id": mount.destination_slot_id(),
            "view_revision": view,
            "source_generation": mount.source_generation(),
            "namespace_generation": mount.namespace_generation(),
            "source_path": "source",
            "mount_namespace_path": "unused/mount",
            "user_namespace_path": "unused/user",
            "target_root_path": "unused/root",
            "target_slot_path": "slot",
            "target_relative_path": relative_slot,
            "source_identity": { "device": source.dev(), "inode": source.ino() },
            "mount_namespace_identity": {
                "device": mount_namespace.device,
                "inode": mount_namespace.inode,
            },
            "user_namespace_identity": {
                "device": user_namespace.device,
                "inode": user_namespace.inode,
            },
            "target_root_identity": { "device": root.device, "inode": root.inode },
            "target_slot_identity": { "device": slot.dev(), "inode": slot.ino() },
        }],
    });
    std::fs::write(
        directory.path().join("catalog.json"),
        serde_json::to_vec(&snapshot).unwrap(),
    )
    .unwrap();

    let mut catalog =
        PreparedMountCatalog::new(FileMountCatalog::open_root_owned(directory.path()).unwrap());
    let commitment = catalog.prepare(&mount, observed).unwrap();
    let resources = catalog.resolve(&mount).unwrap();
    assert_eq!(resources.authorization_commitment.digest(), commitment);
    assert_eq!(resources.target_root.identity(), root);
    assert_eq!(resources.target_slot.identity().device, slot.dev());
    assert_eq!(resources.target_slot.identity().inode, slot.ino());
    assert_eq!(resources.mount_namespace.identity(), mount_namespace);
    assert_eq!(resources.user_namespace.identity(), user_namespace);

    let refresh = observe_scope(host_request, artifacts, ResponseCase::Valid).unwrap();
    assert_eq!(catalog.prepare(&mount, refresh).unwrap(), commitment);

    let mut replacement_request = host_request.clone();
    replacement_request.payload_scope_handle[0] ^= 1;
    let replacement = observe_scope(&replacement_request, artifacts, ResponseCase::Valid).unwrap();
    assert!(matches!(
        catalog.prepare(&mount, replacement),
        Err(MountError::Fence(_))
    ));
}

fn observe_scope(
    query: &ObserveMountScopeRequest,
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
    case: ResponseCase,
) -> std::result::Result<crate::host_scope::ObservedMountScope, crate::host_scope::HostScopeError> {
    let (client_fd, server_fd) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let client = HostMountScopeClient::from_connected(client_fd, current_cgroup()).unwrap();
    let server_socket = DescriptorSubjectSocket::from_owned(server_fd).unwrap();
    let server = std::thread::spawn(move || respond(server_socket, case));
    let observed = client.observe(
        &query.encode_to_vec(),
        AuthorizationArtifactBytes {
            broker_plan: artifacts.broker_plan(),
            broker_plan_signature: artifacts.broker_plan_signature(),
            ownership_lease: artifacts.ownership_lease(),
            ownership_lease_signature: artifacts.ownership_lease_signature(),
        },
    );
    server.join().unwrap();
    observed
}

fn respond(mut socket: DescriptorSubjectSocket, case: ResponseCase) {
    let hello = receive(&mut socket);
    let feature = aos_sandbox_core::FeatureRef::new(
        aos_sandbox_protocol::session::SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(),
        1,
        0,
    )
    .unwrap();
    let method = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE;
    let session = negotiate_client_hello(
        hello.payload(),
        PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(std::process::id()),
        },
        PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_ROOT_MOUNT,
        },
        ProtocolId::HostBroker,
        &[feature],
        &[method],
    )
    .unwrap();
    socket
        .send(&session.server_hello().encode_to_vec())
        .unwrap();

    let record = receive(&mut socket);
    let envelope = session.decode_request(record.payload(), 0).unwrap();
    let query = ObserveMountScopeRequest::decode_from_slice(envelope.body()).unwrap();
    let mut response = ObserveMountScopeResponse {
        fence: query.fence,
        runtime_handle: query.runtime_handle,
        payload_scope_handle: query.payload_scope_handle,
        ..Default::default()
    };
    if matches!(case, ResponseCase::ReplacementScope) {
        response.payload_scope_handle[0] ^= 1;
    }

    let roles: &[BrokerDescriptorRole] = &MOUNT_SCOPE_DESCRIPTOR_ROLES;
    let mut bytes = encode_success_response_envelope(
        query
            .header
            .as_option()
            .unwrap()
            .request_id
            .as_slice()
            .try_into()
            .unwrap(),
        &envelope,
        response.encode_to_vec(),
        roles,
        &[],
        16 * 1024,
    )
    .unwrap();
    if matches!(case, ResponseCase::ReorderedRoles) {
        let mut raw =
            aos_proto::aos::sandbox::local::v1::BrokerResponseEnvelope::decode_from_slice(&bytes)
                .unwrap();
        let first = raw.descriptors[0].role;
        raw.descriptors[0].role = raw.descriptors[1].role;
        raw.descriptors[1].role = first;
        bytes = raw.encode_to_vec();
    }

    let payload = aos_sandbox_linux::pidfd::PidFd::open(
        std::num::NonZeroU32::new(std::process::id()).unwrap(),
    )
    .unwrap();
    let anchor = current_cgroup();
    let root = open_path("/");
    let mount = open_namespace("/proc/self/ns/mnt");
    let user = open_namespace("/proc/self/ns/user");
    let user_role = if matches!(case, ResponseCase::WrongNamespaceType) {
        mount.as_fd()
    } else {
        user.as_fd()
    };
    let descriptors = [
        payload.as_fd(),
        anchor.as_fd(),
        root.as_fd(),
        mount.as_fd(),
        user_role,
    ];
    let count = if matches!(case, ResponseCase::IncompleteRights) {
        4
    } else {
        5
    };

    send_rights(&socket, &bytes, &descriptors[..count]);
}

fn receive(
    socket: &mut DescriptorSubjectSocket,
) -> aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord {
    let deadline = boottime() + 10_000_000_000;

    loop {
        assert!(
            boottime() < deadline,
            "synthetic responder receive deadline"
        );

        match socket.receive(aos_sandbox_protocol::MAXIMUM_REQUEST_BYTES, 0) {
            Ok(record) => return record,
            Err(
                aos_sandbox_linux::seqpacket::SeqpacketError::WouldBlock
                | aos_sandbox_linux::seqpacket::SeqpacketError::Interrupted,
            ) => std::thread::yield_now(),
            Err(error) => panic!("synthetic responder: {error}"),
        }
    }
}

fn send_rights(socket: &DescriptorSubjectSocket, bytes: &[u8], descriptors: &[BorrowedFd<'_>]) {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(5))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    assert!(control.push(SendAncillaryMessage::ScmRights(descriptors)));

    let written = sendmsg(
        socket.as_fd().unwrap(),
        &[IoSlice::new(bytes)],
        &mut control,
        SendFlags::NOSIGNAL,
    )
    .unwrap();
    assert_eq!(written, bytes.len());
}

fn current_cgroup() -> RetainedCgroupAnchor {
    let root = CgroupV2Root::from_owned(open_path("/sys/fs/cgroup")).unwrap();
    let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .unwrap();

    root.resolve(Path::new(if relative.is_empty() { "." } else { relative }))
        .unwrap()
}

fn open_path(path: &str) -> OwnedFd {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap()
}

fn open_namespace(path: &str) -> OwnedFd {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap()
}

fn boottime() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);

    u64::try_from(now.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(now.tv_nsec).unwrap()
}
