//! Relay ownership, replacement, and transport regressions.

use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

#[test]
fn read_only_relay_allows_fragmented_queries_and_transport_acknowledgements() {
    let mut filter = ReadOnlyGdbFilter::default();
    let packet = rsp_packet(b"m1000,20");
    let split = packet.len() / 2;

    assert_eq!(filter.accept(&packet[..split]), Ok(Vec::new()));
    assert_eq!(filter.accept(&packet[split..]), Ok(packet));
    assert_eq!(filter.accept(b"+-"), Ok(b"+-".to_vec()));
    assert_eq!(
        filter.accept(&rsp_packet(b"QStartNoAckMode")),
        Ok(rsp_packet(b"QStartNoAckMode"))
    );
}

#[test]
fn read_only_relay_rejects_every_state_changing_command_family() {
    let commands: &[&[u8]] = &[
        b"P0=00",
        b"G00",
        b"M1000,1:00",
        b"X1000,1:0",
        b"c",
        b"s",
        b"C05",
        b"S05",
        b"vCont;c",
        b"k",
        b"D",
        b"R00",
        b"Z0,1000,1",
        b"z0,1000,1",
        b"qRcmd,7265736574",
        b"QNonStop:1",
    ];
    for command in commands {
        let mut filter = ReadOnlyGdbFilter::default();
        assert_eq!(
            filter.accept(&rsp_packet(command)),
            Err(DebugRelayError::ReadOnlyCommand),
            "state-changing command was accepted: {}",
            String::from_utf8_lossy(command)
        );
    }
    let mut filter = ReadOnlyGdbFilter::default();
    assert_eq!(
        filter.accept(&[0x03]),
        Err(DebugRelayError::InvalidReadOnlyPacket)
    );
}

fn rsp_packet(payload: &[u8]) -> Vec<u8> {
    let checksum = payload
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    format!("${}#{checksum:02x}", String::from_utf8_lossy(payload)).into_bytes()
}

fn client(name: &str) -> DebugClientId {
    DebugClientId::new(name)
        .unwrap_or_else(|error| panic!("test client identity should be valid: {error}"))
}

fn session(id: u64, epoch: u64) -> SessionRef {
    SessionRef::new(
        crate::SessionId::new(id),
        epoch,
        crucible::Seed::from_u64(id),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn relay_connects_only_to_private_unix_gateway_endpoint() {
    let directory = tempfile::tempdir().expect("temporary gateway directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private gateway directory");
    let socket = directory.path().join("operator.sock");
    let listener = tokio::net::UnixListener::bind(&socket).expect("operator socket");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .expect("owner operator socket");
    let endpoint = format!("unix:{}", socket.display());

    assert!(matches!(
        DebugRelayRegistry::connect(&endpoint).await,
        Ok(DebugRelayStream::Unix(_))
    ));
    let _accepted = listener.accept().await.expect("private relay connection");

    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))
        .expect("public socket fixture");
    assert!(matches!(
        DebugRelayRegistry::connect(&endpoint).await,
        Err(DebugRelayError::InvalidGatewayEndpoint)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn relay_is_loopback_bounded_and_lease_owned() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("test gateway should bind: {error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("test gateway should have address: {error}"));
    let gateway = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("relay should connect: {error}"));
        let mut bytes = [0_u8; 16];
        let length = stream
            .read(&mut bytes)
            .await
            .unwrap_or_else(|error| panic!("gateway should read: {error}"));
        stream
            .write_all(&bytes[..length])
            .await
            .unwrap_or_else(|error| panic!("gateway should echo: {error}"));
    });
    let owner = client("owner");
    let session_ref = session(3, 11);
    let lease = DebugControllerLease {
        client: owner.clone(),
        generation: 7,
    };
    let holder = uuid::Uuid::from_u128(7);
    let mut registry = DebugRelayRegistry::default();
    let stream = DebugRelayRegistry::connect(&address.to_string())
        .await
        .unwrap_or_else(|error| panic!("loopback relay should open: {error}"));
    let id = registry
        .register(
            stream,
            session_ref,
            lease,
            holder,
            DebugRelayAccess::ReadWrite,
        )
        .unwrap_or_else(|error| panic!("loopback relay should register: {error}"));
    assert_eq!(
        registry.existing(
            session_ref,
            &DebugControllerLease {
                client: owner.clone(),
                generation: 7,
            },
            holder,
        ),
        Some(id),
        "relay open retries must be idempotent"
    );
    assert!(registry.has_for_lease(
        session_ref,
        &DebugControllerLease {
            client: owner.clone(),
            generation: 7,
        }
    ));
    assert!(registry.has_holder(
        session_ref,
        &DebugControllerLease {
            client: owner.clone(),
            generation: 7,
        },
        holder,
    ));
    let (stream, bytes) = registry
        .prepare_write(id, session_ref, &owner, 7, holder, b"gdb")
        .unwrap_or_else(|error| panic!("relay stream should be lease-owned: {error}"));
    let readable_stream = Arc::clone(&stream);
    assert_eq!(
        DebugRelayRegistry::write_stream(stream, &bytes)
            .await
            .unwrap_or_else(|error| panic!("relay write should succeed: {error}")),
        3
    );
    gateway
        .await
        .unwrap_or_else(|error| panic!("test gateway should join: {error}"));
    {
        let stream = readable_stream.lock().await;
        stream
            .readable()
            .await
            .unwrap_or_else(|error| panic!("relay echo should become readable: {error}"));
    }
    assert_eq!(
        registry.read(id, session_ref, &client("foreign"), 7, holder, 16),
        Err(DebugRelayError::StaleOrForeignLease)
    );
    assert_eq!(
        registry.read(id, session(4, 11), &owner, 7, holder, 16),
        Err(DebugRelayError::StaleOrForeignLease),
        "the same lease generation on another session must not authorize"
    );
    let mut chunk = DebugRelayChunk {
        bytes: Vec::new(),
        eof: false,
    };
    for _ in 0..64 {
        chunk = registry
            .read(id, session_ref, &owner, 7, holder, 16)
            .unwrap_or_else(|error| panic!("relay read should succeed: {error}"));
        if !chunk.bytes.is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(chunk.bytes, b"gdb");
    if let Some(relay) = registry.relays.get_mut(&id) {
        relay.last_activity = relay_clock_now() - DEBUG_RELAY_STALE_AFTER;
    } else {
        panic!("registered relay disappeared before stale cleanup");
    }
    assert_eq!(
        registry.remove_stale(session_ref),
        vec![(
            DebugControllerLease {
                client: owner.clone(),
                generation: 7,
            },
            holder,
        )]
    );
    assert!(!registry.has_for_lease(
        session_ref,
        &DebugControllerLease {
            client: owner.clone(),
            generation: 7,
        }
    ));

    let replacement_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("replacement gateway should bind: {error}"));
    let replacement_address = replacement_listener
        .local_addr()
        .unwrap_or_else(|error| panic!("replacement gateway should have address: {error}"));
    let replacement_gateway = tokio::spawn(async move {
        let (_stream, _) = replacement_listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("replacement relay should connect: {error}"));
    });
    let stream = DebugRelayRegistry::connect(&replacement_address.to_string())
        .await
        .unwrap_or_else(|error| panic!("replacement relay should open: {error}"));
    let replacement_holder = uuid::Uuid::from_u128(8);
    let id = registry
        .register(
            stream,
            session_ref,
            DebugControllerLease {
                client: owner.clone(),
                generation: 8,
            },
            replacement_holder,
            DebugRelayAccess::ReadWrite,
        )
        .unwrap_or_else(|error| panic!("replacement relay should register: {error}"));
    let closed = registry
        .close(id, session_ref, &owner, 8, replacement_holder)
        .unwrap_or_else(|error| panic!("relay close should succeed: {error}"));
    assert_eq!(closed.holder, uuid::Uuid::from_u128(8));
    let retried = registry
        .close(id, session_ref, &owner, 8, replacement_holder)
        .unwrap_or_else(|error| panic!("relay close retry should succeed: {error}"));
    assert_eq!(retried.holder, closed.holder);
    assert!(!registry.has_for_lease(
        session_ref,
        &DebugControllerLease {
            client: owner.clone(),
            generation: 8,
        }
    ));
    assert_eq!(
        registry.read(id, session_ref, &owner, 8, replacement_holder, 16),
        Err(DebugRelayError::NotFound)
    );
    replacement_gateway
        .await
        .unwrap_or_else(|error| panic!("replacement gateway should join: {error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn relay_rejects_non_loopback_and_oversized_requests() {
    let owner = client("owner");
    let mut registry = DebugRelayRegistry::default();
    assert!(matches!(
        DebugRelayRegistry::connect("192.0.2.1:1234").await,
        Err(DebugRelayError::GatewayEndpointNotLoopback)
    ));
    assert_eq!(
        registry.read(
            DebugRelayId(1),
            session(1, 1),
            &owner,
            1,
            uuid::Uuid::from_u128(1),
            0,
        ),
        Err(DebugRelayError::InvalidReadMaximum { maximum: 0 })
    );
}
