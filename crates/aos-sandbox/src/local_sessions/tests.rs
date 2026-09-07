//! Real socket-pair tests of the volatile session primitive, not capability issuance.
//!
//! Fixtures install sessions through the crate-private preparation API. They do
//! not claim that the synthetic scope was authorized by a production controller.

#![allow(
    clippy::expect_used,
    reason = "Kernel fixture failures intentionally panic."
)]

use std::fs::File;
use std::os::fd::AsFd;
use std::path::Path;

use aos_sandbox_linux::cgroup::CgroupV2Root;

use super::frame::encode_test_frame;
use super::*;

fn scope() -> LocalSessionScope {
    LocalSessionScope {
        holder: PrincipalId::from_bytes([1; 16]),
        project: ProjectId::from_bytes([2; 16]),
        sandbox: SandboxId::from_bytes([3; 16]),
        incarnation: IncarnationId::from_bytes([4; 16]),
        epoch: AssignmentEpoch::new(1),
        cache_resource: ResourceId::from_bytes([5; 16]),
    }
}

fn current_anchor() -> RetainedCgroupAnchor {
    let root = CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").expect("cgroup root").into())
        .expect("admit cgroup root");
    let membership = std::fs::read_to_string("/proc/self/cgroup").expect("own membership");
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .expect("unified hierarchy");
    root.resolve(Path::new(if relative.is_empty() { "." } else { relative }))
        .expect("current cgroup anchor")
}

fn registry(capacity: usize) -> LocalSessionRegistry {
    LocalSessionRegistry::new(LocalSessionLimits {
        maximum_sessions: capacity,
    })
    .expect("session table")
}

fn install(
    registry: &mut LocalSessionRegistry,
) -> (
    LocalSessionId,
    CapabilityId,
    ChannelBinding,
    SeqpacketSocket,
) {
    let prepared = registry
        .prepare(scope(), current_anchor())
        .expect("prepare fixture session");
    prepared
        .check_pending_anchor()
        .expect("pending anchor remains active");
    assert_eq!(prepared.scope(), &scope());
    let id = prepared.session_id();
    let capability = prepared.capability_id();
    let binding = prepared.channel_binding();
    let endpoint = prepared.activate();
    assert_eq!(endpoint.session_id(), id);
    assert_eq!(endpoint.capability_id(), capability);
    assert_eq!(endpoint.channel_binding(), binding);
    (
        id,
        capability,
        binding,
        SeqpacketSocket::from_owned(endpoint.into_fd()).expect("fixture client"),
    )
}

#[test]
fn empty_registry_and_preparation_are_bounded_and_nonpublishing() {
    for maximum_sessions in [0, 4097] {
        assert!(matches!(
            LocalSessionRegistry::new(LocalSessionLimits { maximum_sessions }),
            Err(LocalSessionError::InvalidLimit)
        ));
    }
    let mut table = registry(1);
    assert_eq!(table.slots.len(), 1);
    let initial_capacity = table.slots.capacity();
    let prepared = table
        .prepare(scope(), current_anchor())
        .expect("prepare only slot");
    let id = prepared.session_id();
    let duplicate = prepared
        .client
        .as_fd()
        .try_clone_to_owned()
        .expect("retain test client");
    let mut client = SeqpacketSocket::from_owned(duplicate).expect("adopt duplicate client");
    drop(prepared);
    assert!(matches!(
        table.receive(id),
        Err(LocalSessionError::UnknownSession)
    ));
    assert!(client.send(b"server closed").is_err());
    assert!(table.slots[0].is_none());
    let _endpoint = table
        .prepare(scope(), current_anchor())
        .expect("slot reusable after abort")
        .activate();
    assert_eq!(table.slots.capacity(), initial_capacity);
    assert!(matches!(
        table.prepare(scope(), current_anchor()),
        Err(LocalSessionError::Capacity)
    ));
}

#[test]
fn record_metadata_comes_from_issued_channel_not_application_payload() {
    let mut table = registry(2);
    let (first, capability, binding, mut first_client) = install(&mut table);
    let (second, second_capability, second_binding, _second_client) = install(&mut table);
    assert_ne!(first, second);
    assert_ne!(capability, second_capability);
    assert_ne!(binding, second_binding);
    assert_eq!(
        table.capability_id(first).expect("lookup handle"),
        capability
    );

    // Another session's identity remains untrusted application bytes; the
    // authenticated metadata cannot be substituted by their presence.
    let mut payload = second.as_bytes().to_vec();
    payload.extend_from_slice(second_capability.as_bytes());
    payload.extend_from_slice(second_binding.as_bytes());
    first_client
        .send(&encode_test_frame(b"", &payload))
        .expect("send first channel");
    assert!(matches!(
        table.receive(second),
        Err(LocalSessionError::Transport(SeqpacketError::WouldBlock))
    ));
    let record = table.receive(first).expect("receive first channel");
    assert_eq!(record.session_id(), first);
    assert_eq!(record.capability_id(), capability);
    assert_eq!(record.channel_binding(), binding);
    assert_eq!(record.scope(), &scope());
    assert_eq!(record.payload(), payload);
    assert_eq!(record.process_info().pid(), std::process::id());
    assert_eq!(
        record
            .recheck_execution_scope()
            .expect("recheck retained subject")
            .pid(),
        std::process::id()
    );
}

#[test]
fn invalidation_closes_before_return_and_reconnect_mints_new_bindings() {
    let mut table = registry(1);
    let (first, capability, binding, mut client) = install(&mut table);
    assert_eq!(table.invalidate(first).expect("invalidate"), capability);
    assert!(client.send(b"closed").is_err());
    assert!(matches!(
        table.receive(first),
        Err(LocalSessionError::UnknownSession)
    ));
    let (second, new_capability, new_binding, _new_client) = install(&mut table);
    assert_ne!(first, second);
    assert_ne!(capability, new_capability);
    assert_ne!(binding, new_binding);
    assert!(matches!(
        table.invalidate(first),
        Err(LocalSessionError::UnknownSession)
    ));
}

#[test]
fn malformed_frame_and_payload_ceilings_close_and_release_session() {
    let mut malformed = vec![
        b"wrong frame".to_vec(),
        encode_test_frame(b"", b""),
        encode_test_frame(b"", &vec![7; 32769]),
        encode_test_frame(&vec![b'x'; 4097], b"payload"),
    ];
    let mut truncated = encode_test_frame(b"", b"payload");
    truncated[8..10].copy_from_slice(&4000_u16.to_be_bytes());
    malformed.push(truncated);
    for wire in malformed {
        let mut table = registry(1);
        let (id, _, _, mut client) = install(&mut table);
        client.send(&wire).expect("send malformed frame");
        assert!(matches!(
            table.receive(id),
            Err(LocalSessionError::InvalidFrame(_))
        ));
        assert!(matches!(
            table.receive(id),
            Err(LocalSessionError::UnknownSession)
        ));
        assert!(client.send(b"closed").is_err());
    }
    let mut table = registry(1);
    let (id, _, _, mut client) = install(&mut table);
    client
        .send(&vec![0; frame::MAXIMUM_FRAME_BYTES + 1])
        .expect("send oversized packet");
    assert!(matches!(
        table.receive(id),
        Err(LocalSessionError::Transport(
            SeqpacketError::RecordTooLarge { .. }
        ))
    ));
    assert!(matches!(
        table.capability_id(id),
        Err(LocalSessionError::UnknownSession)
    ));
}

#[test]
fn forged_membership_hints_are_rejected_without_rebinding_scope() {
    for hint in [
        b".".as_slice(),
        b"../outside",
        b"/sys/fs/cgroup",
        b"bad\0name",
        b"cgroup.procs",
    ] {
        let mut table = registry(1);
        let (id, _, _, mut client) = install(&mut table);
        client
            .send(&encode_test_frame(hint, b"payload"))
            .expect("send forged hint");
        assert!(matches!(
            table.receive(id),
            Err(LocalSessionError::Membership(_))
        ));
        assert!(matches!(
            table.receive(id),
            Err(LocalSessionError::UnknownSession)
        ));
    }
}

#[test]
fn full_payload_limit_is_accepted_and_zero_scope_is_not_prepared() {
    let mut table = registry(1);
    let mut invalid = scope();
    invalid.holder = PrincipalId::from_bytes([0; 16]);
    assert!(matches!(
        table.prepare(invalid, current_anchor()),
        Err(LocalSessionError::InvalidScope)
    ));
    let (id, _, _, mut client) = install(&mut table);
    let payload = vec![5; 32768];
    client
        .send(&encode_test_frame(b"", &payload))
        .expect("send maximum payload");
    assert_eq!(
        table.receive(id).expect("maximum payload record").payload(),
        payload
    );
}
