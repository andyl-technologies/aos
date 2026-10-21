//! Independent protected client process for the installed Storage RPC VM fixture.
//!
//! The VM provisions role-local credentials after boot. Positive requests use
//! the production handshake, request reservation and terminal journal commit;
//! only the explicit malformed-request case writes outside that transport.

use std::os::fd::BorrowedFd;
use std::path::Path;
use std::time::Duration;

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerRequestPreparationV1,
    DormantBrokerRequestSendProgressV1, DormantBrokerResponseProgressV1,
    DormantControllerClientHandshakeProgressV1, ProtectedBrokerOutcomeCommitResultV1,
    ProtectedBrokerSessionFixedCustodyV1, ProtectedBrokerSessionFixedEndpointV1,
    production_deadline_after,
};
use aos_sandbox_api::aos::sandbox::local::v1::{
    ApplyStorageRequest, Audience, BrokerMethod, BrokerRequestEnvelope, InventoryStorageRequest,
    PrepareStorageCatalogRequest, RepairStorageWorkspacePinRequest,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, authenticated_broker_method_profile_v1,
    profile::production_broker_client_hello_v1,
};
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use buffa::Message as _;

const RESPONSE_BYTES: u32 = 1_048_576;

fn wait_for_handshake_readiness(
    descriptor: BorrowedFd<'_>,
    write: bool,
    deadline: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    let remaining = deadline
        .checked_sub(aos_sandbox_linux::seqpacket::bounded::boottime()?)
        .filter(|remaining| *remaining != 0)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))?;
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000)?,
    };
    let mut descriptors = [PollFd::from_borrowed_fd(
        descriptor,
        if write { PollFlags::OUT } else { PollFlags::IN },
    )];
    match poll(&mut descriptors, Some(&timeout)) {
        Ok(0) => Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into()),
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn connect(
    method: BrokerMethod,
    minor: Option<u32>,
) -> Result<(DormantAuthenticatedBrokerSessionV1, u64), Box<dyn std::error::Error>> {
    let deadline = production_deadline_after(Duration::from_secs(15))?;
    let custody = ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
        ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
    )?;
    let socket = SeqpacketSocket::connect(Path::new("/run/aos/sandbox-storage/control.sock"))?;
    let mut hello = production_broker_client_hello_v1(
        BrokerSessionProtocolV1::Storage,
        Audience::AUDIENCE_NODE_CONTROLLER,
        RESPONSE_BYTES,
    )?;
    hello.required_methods = vec![method.into()];
    // Inventory-only negotiation names the separate operator-Recover slot.
    // This fixture exercises ordinary Storage history across fresh clients.
    if method == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES {
        hello
            .required_methods
            .push(BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG.into());
    }
    let profiles: Vec<_> = hello
        .required_methods
        .iter()
        .map(|method| authenticated_broker_method_profile_v1(method.as_known().unwrap()).unwrap())
        .collect();
    hello.required_features.retain(|feature| {
        feature.namespace == aos_sandbox_model::BROKER_SESSION_AUTHENTICATION_FEATURE_NAMESPACE
            || profiles.iter().any(|profile| {
                profile
                    .required_features()
                    .iter()
                    .any(|required| required.namespace() == feature.namespace)
            })
    });
    if let Some(minor) = minor {
        hello.protocol_minor = minor;
    }
    let mut handshake = custody.begin_client_handshake(socket, hello)?;

    loop {
        wait_for_handshake_readiness(handshake.as_fd()?, handshake.wants_write(), deadline)?;
        match handshake.advance()? {
            DormantControllerClientHandshakeProgressV1::Pending(pending) => handshake = pending,
            DormantControllerClientHandshakeProgressV1::Complete(session) => {
                return Ok((session, deadline));
            }
        }
    }
}

fn exchange(
    method: BrokerMethod,
    mut envelope: BrokerRequestEnvelope,
) -> Result<AuthenticatedBrokerMethodOutcomeV1, crate::DormantBrokerSessionHandshakeErrorV1> {
    let (mut session, deadline) = connect(method, None).unwrap();
    let prepared = session
        .prepare_authenticated_request(method, |coordinates| {
            // The signed plan commits to portable arguments. Its finite byte
            // bound also covers the protected, session-selected header.
            let header = coordinates.request_header();
            envelope.body = match method {
                BrokerMethod::BROKER_METHOD_STORAGE_APPLY => {
                    let mut request =
                        ApplyStorageRequest::decode_from_slice(&envelope.body).unwrap();
                    request.header = Some(header).into();
                    request.encode_to_vec()
                }
                BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => {
                    let mut request =
                        RepairStorageWorkspacePinRequest::decode_from_slice(&envelope.body)
                            .unwrap();
                    request.header = Some(header).into();
                    request.encode_to_vec()
                }
                BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG => {
                    let mut request =
                        PrepareStorageCatalogRequest::decode_from_slice(&envelope.body).unwrap();
                    request.header = Some(header).into();
                    request.encode_to_vec()
                }
                BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => {
                    let request = InventoryStorageRequest {
                        header: Some(header).into(),
                        ..Default::default()
                    };
                    request.encode_to_vec()
                }
                other => panic!("unsupported Storage qualification method {other:?}"),
            };
            envelope
        })
        .unwrap();
    let mut request = match prepared {
        DormantBrokerRequestPreparationV1::Prepared(request) => request,
        DormantBrokerRequestPreparationV1::InitializationRecoveryRequired { error, .. } => {
            panic!("Storage qualification initialization requires protected recovery: {error}");
        }
        DormantBrokerRequestPreparationV1::SuccessorRecoveryRequired { error, .. } => {
            panic!("Storage qualification successor requires protected recovery: {error}");
        }
    };

    let exact_request = request.0.canonical_packet().to_vec();

    let mut outstanding = loop {
        wait_for_handshake_readiness(session.as_fd().unwrap(), true, deadline).unwrap();
        match session.send_authenticated_request(request).unwrap() {
            DormantBrokerRequestSendProgressV1::Pending(pending) => request = pending,
            DormantBrokerRequestSendProgressV1::Sent(sent) => break sent,
        }
    };

    loop {
        wait_for_handshake_readiness(session.as_fd().unwrap(), false, deadline).unwrap();
        match session.receive_authenticated_response(outstanding)? {
            DormantBrokerResponseProgressV1::Pending(pending) => outstanding = pending,
            DormantBrokerResponseProgressV1::Committed(committed) => {
                let ProtectedBrokerOutcomeCommitResultV1::Committed(committed) = committed else {
                    panic!("Storage qualification terminal requires protected recovery");
                };
                let (outcome, currentness) = committed.into_outcome_and_currentness();
                drop(currentness);
                if matches!(
                    method,
                    BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
                        | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                ) {
                    assert_exact_terminal_replay(&mut session, &exact_request, &outcome, deadline);
                }
                return Ok(outcome);
            }
        }
    }
}

/// Replays the actual signed packet on its retained live transport.
///
/// The first terminal has already passed production verification and durable
/// commit. Its byte-identical replay needs no second reservation or commit.
fn assert_exact_terminal_replay(
    session: &mut DormantAuthenticatedBrokerSessionV1,
    request: &[u8],
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    deadline: u64,
) {
    use crate::handshake::DormantBrokerSessionHandshakeErrorV1::Transport;

    loop {
        wait_for_handshake_readiness(session.as_fd().unwrap(), true, deadline).unwrap();
        match session.0.send_request_packet(request) {
            Ok(()) => break,
            Err(Transport) => continue,
            Err(cause) => panic!("exact Storage request replay failed: {cause}"),
        }
    }

    loop {
        wait_for_handshake_readiness(session.as_fd().unwrap(), false, deadline).unwrap();
        match session.0.receive_response_packet(RESPONSE_BYTES as usize) {
            Ok(packet) => {
                assert!(
                    packet == outcome.canonical_packet(),
                    "signed terminal replay bytes differ"
                );
                break;
            }
            Err(Transport) => continue,
            Err(cause) => panic!("exact Storage terminal replay failed: {cause}"),
        }
    }
}

fn reject_missing_authority(packet: &[u8]) {
    let (session, deadline) = connect(
        BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN,
        None,
    )
    .unwrap();
    // Deliberately act as a hostile client after a genuine signed handshake.
    // The duplicate stays in this process; it is used solely to prove that a
    // malformed unsigned request cannot acquire an authenticated outcome.
    let duplicate = rustix::io::dup(session.as_fd().unwrap()).unwrap();
    let mut socket = SeqpacketSocket::from_owned(duplicate).unwrap();
    aos_sandbox_linux::seqpacket::bounded::send(&mut socket, packet, deadline).unwrap();
    let result = aos_sandbox_linux::seqpacket::bounded::receive(
        &mut socket,
        RESPONSE_BYTES as usize,
        deadline,
    );
    assert!(
        matches!(
            result,
            Err(aos_sandbox_linux::seqpacket::bounded::BoundedRecordError::Transport(_))
        ),
        "the broker must reject the malformed record, not wait for its deadline"
    );
}

/// Runs only as a child of the installed Storage fixture's Controller unit.
#[test]
#[ignore = "requires installed Storage, protected client custody and its systemd cgroup"]
fn installed_storage_rpc_client() {
    use std::fs;
    use std::io::Read as _;

    let action = std::env::var("AOS_STORAGE_RPC_CLIENT_ACTION").unwrap();
    let requested_method = std::env::var("AOS_STORAGE_RPC_CLIENT_METHOD").unwrap();
    let method = [
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
        BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN,
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
        BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
    ]
    .into_iter()
    .find(|candidate| format!("{candidate:?}") == requested_method)
    .expect("unsupported installed Storage client method");
    let input = std::env::var_os("AOS_STORAGE_RPC_CLIENT_INPUT").unwrap();
    let output = std::env::var_os("AOS_STORAGE_RPC_CLIENT_OUTPUT").unwrap();
    let mut packet = Vec::new();
    fs::File::open(input)
        .unwrap()
        .take(u64::from(RESPONSE_BYTES) + 1)
        .read_to_end(&mut packet)
        .unwrap();
    assert!(packet.len() <= RESPONSE_BYTES as usize);

    let result = match action.as_str() {
        "exchange" => {
            let envelope = BrokerRequestEnvelope::decode_from_slice(&packet).unwrap();
            assert_eq!(envelope.method, method);
            exchange(method, envelope)
                .unwrap()
                .canonical_packet()
                .to_vec()
        }
        "reject-unresolved-history" => {
            assert_eq!(
                method,
                BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            );
            let (mut session, _) = connect(method, None).unwrap();
            let prepared = session.prepare_authenticated_request(method, |coordinates| {
                BrokerRequestEnvelope {
                    method: method.into(),
                    body: InventoryStorageRequest {
                        header: Some(coordinates.request_header()).into(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                    ..Default::default()
                }
            });
            assert!(matches!(
                prepared,
                Err(crate::BrokerSessionSecurityError::Currentness)
            ));
            b"unresolved-history-rejected-v1".to_vec()
        }
        "reject-conflicting-operation" => {
            assert!(matches!(
                method,
                BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN
                    | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            ));
            let envelope = BrokerRequestEnvelope::decode_from_slice(&packet).unwrap();
            assert_eq!(envelope.method, method);
            // A fresh session selects a fresh request header. Reusing an
            // already committed operation under that header is a conflicting
            // request, not an exact replay of its original signed packet.
            assert!(matches!(
                exchange(method, envelope),
                Err(crate::DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)
            ));
            b"conflicting-operation-rejected-v1".to_vec()
        }
        "reject-unavailable-method" => {
            assert!(matches!(
                method,
                BrokerMethod::BROKER_METHOD_STORAGE_APPLY
                    | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            ));
            let envelope = BrokerRequestEnvelope::decode_from_slice(&packet).unwrap();
            assert_eq!(envelope.method, method);
            assert!(matches!(
                exchange(method, envelope),
                Err(crate::DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)
            ));
            b"unavailable-method-rejected-v1".to_vec()
        }
        "reject-downgrade" => {
            let error = connect(method, Some(2)).err().unwrap();
            assert!(
                matches!(
                    error.downcast_ref::<crate::DormantBrokerSessionHandshakeErrorV1>(),
                    Some(crate::DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)
                        | Some(crate::DormantBrokerSessionHandshakeErrorV1::Protected(
                            crate::BrokerSessionSecurityError::Manifest { .. }
                        ))
                ),
                "unexpected downgrade rejection: {error}"
            );
            b"downgrade-rejected-v1".to_vec()
        }
        "reject-missing-authority" => {
            reject_missing_authority(&packet);
            b"missing-authority-rejected-v1".to_vec()
        }
        other => panic!("unsupported installed Storage client action: {other}"),
    };
    assert!(result.len() <= RESPONSE_BYTES as usize);
    fs::write(output, result).unwrap();
}
