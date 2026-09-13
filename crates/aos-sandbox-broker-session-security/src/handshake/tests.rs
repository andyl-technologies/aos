//! End-to-end tests for the private same-channel hello composition.

use std::fs;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox_broker_session_protocol::{
    BrokerSessionKeyUsageV1, BrokerSessionProtocolV1, BrokerSessionSignerReferenceV1,
    hello_message::{Audience, BrokerClientHello, BrokerMethod, BrokerServerHello, Feature},
};
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use ed25519_dalek::SigningKey;
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use tempfile::TempDir;

use super::traffic::{RemotePeerExpectation, TrafficTransition};
use super::*;
use crate::endpoint::{
    load_broker_for_handshake_scripted_test, load_broker_for_handshake_test,
    load_client_for_handshake_scripted_test, load_client_for_handshake_test,
};
use crate::manifest::{
    BrokerSessionSecurityAudienceV1, BrokerSessionSecurityKeyPinV1, BrokerSessionSecurityManifestV1,
};
use aos_sandbox_protocol::authenticated_session::AuthenticatedNetworkInventoryTerminalErrorV1;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};

const MANIFEST: &str = "broker-session-manifest";
const CLIENT_NAMES: [&str; 2] = ["client-hello-signing-key", "client-record-signing-key"];
const BROKER_NAMES: [&str; 2] = ["broker-hello-signing-key", "broker-outcome-signing-key"];

struct Fixture {
    _temporary: TempDir,
    client: PathBuf,
    broker: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("temporary directory failed: {error}"));
        let client = temporary.path().join("client");
        let broker = temporary.path().join("broker");
        fs::create_dir(&client).unwrap_or_else(|error| panic!("client directory failed: {error}"));
        fs::create_dir(&broker).unwrap_or_else(|error| panic!("broker directory failed: {error}"));
        let (manifest, secrets) = manifest_and_secrets();
        write_protected(&client.join(MANIFEST), &manifest.encode());
        write_protected(&broker.join(MANIFEST), &manifest.encode());
        for (name, index) in CLIENT_NAMES.into_iter().zip([0, 2]) {
            write_protected(&client.join(name), &secrets[index]);
        }
        for (name, index) in BROKER_NAMES.into_iter().zip([1, 3]) {
            write_protected(&broker.join(name), &secrets[index]);
        }
        fs::set_permissions(&client, fs::Permissions::from_mode(0o500))
            .unwrap_or_else(|error| panic!("client permissions failed: {error}"));
        fs::set_permissions(&broker, fs::Permissions::from_mode(0o500))
            .unwrap_or_else(|error| panic!("broker permissions failed: {error}"));
        Self {
            _temporary: temporary,
            client,
            broker,
        }
    }
}

fn manifest_and_secrets() -> (BrokerSessionSecurityManifestV1, [[u8; 48]; 4]) {
    let usages = [
        BrokerSessionKeyUsageV1::ClientHello,
        BrokerSessionKeyUsageV1::BrokerHello,
        BrokerSessionKeyUsageV1::ClientRecord,
        BrokerSessionKeyUsageV1::BrokerOutcome,
    ];
    let mut secrets = [[0_u8; 48]; 4];
    let pins = core::array::from_fn(|index| {
        let byte = u8::try_from(index).unwrap_or(0);
        let seed = [byte + 1; 32];
        let key_id = [0x50 + byte; 16];
        secrets[index][..16].copy_from_slice(&key_id);
        secrets[index][16..].copy_from_slice(&seed);
        let key = SigningKey::from_bytes(&seed);
        let signer = BrokerSessionSignerReferenceV1::for_signing_key(
            [0x30 + byte; 16],
            10 + u64::try_from(index).unwrap_or(0),
            [0x40 + byte; 32],
            key_id,
            20 + u64::try_from(index).unwrap_or(0),
            usages[index],
            &key,
        )
        .unwrap_or_else(|error| panic!("signer failed: {error}"));
        BrokerSessionSecurityKeyPinV1::new(
            signer,
            key.verifying_key().to_bytes(),
            1,
            1,
            false,
            None,
        )
        .unwrap_or_else(|error| panic!("pin failed: {error}"))
    });
    let manifest = BrokerSessionSecurityManifestV1::new(
        BrokerSessionProtocolV1::Network,
        BrokerSessionSecurityAudienceV1::NodeController,
        1,
        0,
        [1; 16],
        [2; 16],
        1,
        [3; 32],
        1,
        [4; 32],
        1,
        [5; 32],
        [6; 16],
        pins,
    )
    .unwrap_or_else(|error| panic!("manifest failed: {error}"));
    (manifest, secrets)
}

fn write_protected(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap_or_else(|error| panic!("protected write failed: {error}"));
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))
        .unwrap_or_else(|error| panic!("protected permissions failed: {error}"));
}

fn mutate_protected(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("mutation permission failed: {error}"));
    let mut bytes = fs::read(path).unwrap_or_else(|error| panic!("mutation read failed: {error}"));
    let final_index = bytes.len() - 1;
    bytes[final_index] ^= 1;
    fs::write(path, bytes).unwrap_or_else(|error| panic!("mutation write failed: {error}"));
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))
        .unwrap_or_else(|error| panic!("mutation permission restore failed: {error}"));
}

fn authentication_feature() -> Feature {
    Feature {
        namespace: "aos.sandbox.authentication.broker-session".to_owned(),
        major: 1,
        ..Default::default()
    }
}

fn client_hello() -> BrokerClientHello {
    BrokerClientHello {
        protocol_major: 1,
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        required_features: vec![authentication_feature()],
        maximum_response_bytes: 65_536,
        required_methods: vec![BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES.into()],
        ..Default::default()
    }
}

fn broker_hello() -> BrokerServerHello {
    BrokerServerHello {
        protocol_major: 1,
        features: vec![authentication_feature()],
        maximum_request_bytes: 1_048_576,
        maximum_response_bytes: 65_536,
        methods: vec![BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES.into()],
        ..Default::default()
    }
}

fn finish_handshake(
    fixture: &Fixture,
    client_carrier: HandshakeCarrier,
    broker_carrier: HandshakeCarrier,
) -> (InertProvisionalClientSession, InertProvisionalBrokerSession) {
    let client_custody = load_client_for_handshake_test(&fixture.client, 0x21)
        .unwrap_or_else(|error| panic!("client custody failed: {error}"));
    let broker_custody = load_broker_for_handshake_test(&fixture.broker, 0x31)
        .unwrap_or_else(|error| panic!("broker custody failed: {error}"));
    let broker = BrokerPublicationFlight::begin(broker_custody, broker_carrier, broker_hello())
        .unwrap_or_else(|error| panic!("broker begin failed: {error:?}"));
    let broker = match broker.send() {
        Transition::Complete(state) => state,
        other => panic_transition("publication send", other),
    };
    let client = ClientAwaitPublication::begin(client_custody, client_carrier, client_hello())
        .unwrap_or_else(|error| panic!("client begin failed: {error:?}"));
    let client = match client.receive() {
        Transition::Complete(state) => state,
        other => panic_transition("publication receive", other),
    };
    let client = match client.send() {
        Transition::Complete(state) => state,
        other => panic_transition("client hello send", other),
    };
    let broker = match broker.receive() {
        Transition::Complete(state) => state,
        other => panic_transition("client hello receive", other),
    };
    let broker = match broker.send() {
        Transition::Complete(state) => state,
        other => panic_transition("broker hello send", other),
    };
    let client = match client.receive() {
        Transition::Complete(state) => state,
        other => panic_transition("broker hello receive", other),
    };
    (client, broker)
}

fn local_peer_expectation() -> RemotePeerExpectation {
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    RemotePeerExpectation::for_test(
        PeerCredentials {
            uid,
            gid,
            pid: Some(
                u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
                    .unwrap_or_else(|error| panic!("pid conversion failed: {error}")),
            ),
        },
        PeerPolicy {
            uid,
            gid: Some(gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
    )
}

#[test]
fn mandatory_sequence_one_error_proves_both_traffic_keys() {
    for descriptor in [false, true] {
        let fixture = Fixture::new();
        let (client_carrier, broker_carrier) = carrier_pair(descriptor);
        let (client, broker) = finish_handshake(&fixture, client_carrier, broker_carrier);

        let client = client
            .prepare_traffic_proof(local_peer_expectation())
            .unwrap_or_else(|error| panic!("client traffic plan failed: {error:?}"));
        let broker = broker
            .await_traffic_proof(local_peer_expectation())
            .unwrap_or_else(|error| panic!("broker traffic wait failed: {error:?}"));
        let client = match client.send() {
            TrafficTransition::Complete(client) => client,
            _ => panic!("ClientRecord did not send"),
        };
        let broker = match broker.receive() {
            TrafficTransition::Complete(broker) => broker,
            _ => panic!("ClientRecord did not authenticate"),
        };
        let broker = broker
            .prepare_terminal_error(AuthenticatedNetworkInventoryTerminalErrorV1::IntegrityFailure)
            .unwrap_or_else(|error| panic!("outcome plan failed: {error:?}"));
        let broker = match broker.send() {
            TrafficTransition::Complete(broker) => broker,
            _ => panic!("BrokerOutcome did not send"),
        };
        let client = match client.receive() {
            TrafficTransition::Complete(client) => client,
            _ => panic!("BrokerOutcome did not authenticate"),
        };
        assert!(broker.has_exact_initial_proof());
        assert!(client.has_exact_initial_proof());
        assert!(broker.outcome_packet_len_for_test() <= 4_096);
        assert!(client.outcome_packet_len_for_test() <= 4_096);
    }
}

#[test]
fn mandatory_sequence_one_success_proves_both_traffic_keys() {
    let fixture = Fixture::new();
    let (client_socket, broker_fd) = SeqpacketSocket::pair_with_record_subjects()
        .unwrap_or_else(|error| panic!("ordinary pair failed: {error}"));
    let broker_socket = SeqpacketSocket::from_owned(broker_fd)
        .unwrap_or_else(|error| panic!("broker adoption failed: {error}"));
    let client_carrier = HandshakeCarrier::ordinary(client_socket)
        .unwrap_or_else(|error| panic!("client carrier failed: {error:?}"));
    let broker_carrier = HandshakeCarrier::ordinary(broker_socket)
        .unwrap_or_else(|error| panic!("broker carrier failed: {error:?}"));
    let (client, broker) = finish_handshake(&fixture, client_carrier, broker_carrier);
    let broker_process = broker._transcript.broker_process();
    let boot_id = broker
        ._custody
        .context_for_handshake(broker._transcript.client_process())
        .unwrap_or_else(|error| panic!("broker context failed: {error}"))
        .boot_id();

    let client = client
        .prepare_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("client traffic plan failed: {error:?}"));
    let broker = broker
        .await_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("broker traffic wait failed: {error:?}"));
    let client = match client.send() {
        TrafficTransition::Complete(client) => client,
        _ => panic!("ClientRecord did not send"),
    };
    let broker = match broker.receive() {
        TrafficTransition::Complete(broker) => broker,
        _ => panic!("ClientRecord did not authenticate"),
    };
    let mut inventory = Vec::with_capacity(40);
    inventory.extend_from_slice(&[0x0a, 16]);
    inventory.extend_from_slice(&boot_id);
    inventory.extend_from_slice(&[0x10, 1, 0x18, 1, 0x2a, 16]);
    inventory.extend_from_slice(&broker_process);
    let broker = broker
        .prepare_success(inventory)
        .unwrap_or_else(|error| panic!("success plan failed: {error:?}"));
    let broker = match broker.send() {
        TrafficTransition::Complete(broker) => broker,
        _ => panic!("BrokerOutcome did not send"),
    };
    let client = match client.receive() {
        TrafficTransition::Complete(client) => client,
        _ => panic!("BrokerOutcome did not authenticate"),
    };
    assert!(broker.has_exact_initial_proof());
    assert!(client.has_exact_initial_proof());
    assert!(broker.outcome_packet_len_for_test() <= 4_096);
    assert!(client.outcome_packet_len_for_test() <= 4_096);
}

#[test]
fn expired_authenticated_request_receives_a_signed_traffic_proving_outcome() {
    let fixture = Fixture::new();
    let (client_carrier, broker_carrier) = carrier_pair(false);
    let (client, broker) = finish_handshake(&fixture, client_carrier, broker_carrier);
    let client = client
        .prepare_expiring_traffic_proof_for_test(local_peer_expectation())
        .unwrap_or_else(|error| panic!("client expiring plan failed: {error:?}"));
    let broker = broker
        .await_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("broker traffic wait failed: {error:?}"));
    let client = match client.send() {
        TrafficTransition::Complete(client) => client,
        _ => panic!("expiring ClientRecord did not send"),
    };
    let broker = match broker.receive() {
        TrafficTransition::Complete(broker) => broker,
        _ => panic!("expired ClientRecord did not authenticate"),
    };
    assert!(broker.is_expired_for_test());
    let broker = broker
        .prepare_terminal_error(AuthenticatedNetworkInventoryTerminalErrorV1::DeadlineExpired)
        .unwrap_or_else(|error| panic!("deadline outcome plan failed: {error:?}"));
    let broker = match broker.send() {
        TrafficTransition::Complete(broker) => broker,
        _ => panic!("deadline BrokerOutcome did not send"),
    };
    let client = match client.receive() {
        TrafficTransition::Complete(client) => client,
        _ => panic!("deadline BrokerOutcome did not authenticate"),
    };
    assert!(broker.has_exact_initial_proof());
    assert!(client.has_exact_initial_proof());
    assert!(broker.outcome_packet_len_for_test() <= 4_096);
    assert!(client.outcome_packet_len_for_test() <= 4_096);
}

#[test]
fn traffic_packets_and_states_survive_interrupted_io_exactly() {
    let fixture = Fixture::new();
    let (client_carrier, broker_carrier) = carrier_pair(false);
    let (client, broker) = finish_handshake(&fixture, client_carrier, broker_carrier);
    let mut client = client
        .prepare_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("client traffic plan failed: {error:?}"));
    let request_packet = client.packet_for_test().to_vec();
    client.would_block_next_send();
    let client = match client.send() {
        TrafficTransition::Retry(client) => client,
        _ => panic!("would-block ClientRecord send did not retry"),
    };
    assert_eq!(client.packet_for_test(), request_packet);

    let mut broker = broker
        .await_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("broker traffic wait failed: {error:?}"));
    broker.interrupt_next_receive();
    let broker = match broker.receive() {
        TrafficTransition::Retry(broker) => broker,
        _ => panic!("interrupted ClientRecord receive did not retry"),
    };
    let mut client = match client.send() {
        TrafficTransition::Complete(client) => client,
        _ => panic!("ClientRecord retry did not complete"),
    };
    let broker = match broker.receive() {
        TrafficTransition::Complete(broker) => broker,
        _ => panic!("ClientRecord receive retry did not complete"),
    };
    client.would_block_next_receive();
    let client = match client.receive() {
        TrafficTransition::Retry(client) => client,
        _ => panic!("would-block BrokerOutcome receive did not retry"),
    };

    let mut broker = broker
        .prepare_terminal_error(AuthenticatedNetworkInventoryTerminalErrorV1::IntegrityFailure)
        .unwrap_or_else(|error| panic!("outcome plan failed: {error:?}"));
    let outcome_packet = broker.packet_for_test().to_vec();
    broker.interrupt_next_send();
    let broker = match broker.send() {
        TrafficTransition::Retry(broker) => broker,
        _ => panic!("interrupted BrokerOutcome send did not retry"),
    };
    assert_eq!(broker.packet_for_test(), outcome_packet);
    let _broker = match broker.send() {
        TrafficTransition::Complete(broker) => broker,
        _ => panic!("BrokerOutcome retry did not complete"),
    };
    let _client = match client.receive() {
        TrafficTransition::Complete(client) => client,
        _ => panic!("BrokerOutcome receive retry did not complete"),
    };
}

#[test]
fn traffic_proof_rejects_a_peer_expectation_not_bound_to_the_socket() {
    let fixture = Fixture::new();
    let (client_carrier, broker_carrier) = carrier_pair(false);
    let (client, broker) = finish_handshake(&fixture, client_carrier, broker_carrier);
    drop(broker);

    let uid = rustix::process::geteuid().as_raw().wrapping_add(1);
    let gid = rustix::process::getegid().as_raw();
    let expectation = RemotePeerExpectation::for_test(
        PeerCredentials {
            uid,
            gid,
            pid: None,
        },
        PeerPolicy {
            uid,
            gid: Some(gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
    );
    assert!(client.prepare_traffic_proof(expectation).is_err());
}

#[test]
fn traffic_finalizers_reject_role_local_second_key_mutation() {
    let client_fixture = Fixture::new();
    let (client_carrier, broker_carrier) = carrier_pair(false);
    let (client, broker) = finish_handshake(&client_fixture, client_carrier, broker_carrier);
    drop(broker);
    mutate_protected(&client_fixture.client.join(CLIENT_NAMES[1]));
    assert!(matches!(
        client.prepare_traffic_proof(local_peer_expectation()),
        Err(super::traffic::TrafficProofError::Local)
    ));

    let broker_fixture = Fixture::new();
    let (client_carrier, broker_carrier) = carrier_pair(false);
    let (client, broker) = finish_handshake(&broker_fixture, client_carrier, broker_carrier);
    let client = client
        .prepare_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("client traffic plan failed: {error:?}"));
    let broker = broker
        .await_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("broker traffic wait failed: {error:?}"));
    let _client = match client.send() {
        TrafficTransition::Complete(client) => client,
        _ => panic!("ClientRecord did not send"),
    };
    let broker = match broker.receive() {
        TrafficTransition::Complete(broker) => broker,
        _ => panic!("ClientRecord did not authenticate"),
    };
    mutate_protected(&broker_fixture.broker.join(BROKER_NAMES[1]));
    assert!(matches!(
        broker
            .prepare_terminal_error(AuthenticatedNetworkInventoryTerminalErrorV1::IntegrityFailure),
        Err(super::traffic::TrafficProofError::Local)
    ));
}

#[test]
fn traffic_subject_and_post_send_currentness_fail_closed() {
    let subject_fixture = Fixture::new();
    let (client_carrier, broker_carrier) = carrier_pair(false);
    let (client, broker) = finish_handshake(&subject_fixture, client_carrier, broker_carrier);
    let client = client
        .prepare_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("client traffic plan failed: {error:?}"));
    let mut broker = broker
        .await_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("broker traffic wait failed: {error:?}"));
    let _client = match client.send() {
        TrafficTransition::Complete(client) => client,
        _ => panic!("ClientRecord did not send"),
    };
    broker.corrupt_client_subject_for_test();
    assert!(matches!(
        broker.receive(),
        TrafficTransition::Failed(super::traffic::TrafficProofError::RemoteInvalid)
    ));

    let post_fixture = Fixture::new();
    let (client_carrier, broker_carrier) = carrier_pair(false);
    let (client, broker) = finish_handshake(&post_fixture, client_carrier, broker_carrier);
    let mut client = client
        .prepare_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("client traffic plan failed: {error:?}"));
    let _broker = broker
        .await_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("broker traffic wait failed: {error:?}"));
    client.corrupt_peer_after_next_send();
    assert!(matches!(
        client.send(),
        TrafficTransition::Failed(super::traffic::TrafficProofError::RemoteInvalid)
    ));
}

#[test]
fn descriptor_traffic_rejects_and_drops_an_unexpected_fd() {
    let fixture = Fixture::new();
    let (client_carrier, broker_carrier) = carrier_pair(true);
    let (client, broker) = finish_handshake(&fixture, client_carrier, broker_carrier);
    let mut client = client
        .prepare_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("client traffic plan failed: {error:?}"));
    let broker = broker
        .await_traffic_proof(local_peer_expectation())
        .unwrap_or_else(|error| panic!("broker traffic wait failed: {error:?}"));
    let (descriptor, retained_writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .unwrap_or_else(|error| panic!("descriptor fixture failed: {error}"));
    let descriptor_link = fs::read_link(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
        .unwrap_or_else(|error| panic!("descriptor identity failed: {error}"));
    client
        .send_with_unexpected_descriptor(descriptor.as_fd())
        .unwrap_or_else(|error| panic!("descriptor traffic send failed: {error:?}"));
    drop(descriptor);
    assert!(matches!(
        broker.receive(),
        TrafficTransition::Failed(super::traffic::TrafficProofError::RemoteInvalid)
    ));
    let matching_descriptors = fs::read_dir("/proc/self/fd")
        .unwrap_or_else(|error| panic!("post-failure fd inventory failed: {error}"))
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .filter(|target| target == &descriptor_link)
        .count();
    assert_eq!(matching_descriptors, 1);
    drop(retained_writer);
}

fn start_client_hello_flight(fixture: &Fixture) -> (ClientHelloFlight, SeqpacketSocket) {
    let (client_socket, broker_fd) = SeqpacketSocket::pair_with_record_subjects()
        .unwrap_or_else(|error| panic!("ordinary pair failed: {error}"));
    let mut broker_socket = SeqpacketSocket::from_owned(broker_fd)
        .unwrap_or_else(|error| panic!("broker adoption failed: {error}"));
    let mut broker_custody = load_broker_for_handshake_test(&fixture.broker, 0x31)
        .unwrap_or_else(|error| panic!("broker custody failed: {error}"));
    let publication = broker_custody
        .finalize_endpoint_publication()
        .unwrap_or_else(|error| panic!("publication failed: {error}"));
    broker_socket
        .send(&publication)
        .unwrap_or_else(|error| panic!("publication send failed: {error}"));
    let carrier = HandshakeCarrier::ordinary(client_socket)
        .unwrap_or_else(|error| panic!("client carrier failed: {error:?}"));
    let client_custody = load_client_for_handshake_test(&fixture.client, 0x21)
        .unwrap_or_else(|error| panic!("client custody failed: {error}"));
    let client = ClientAwaitPublication::begin(client_custody, carrier, client_hello())
        .unwrap_or_else(|error| panic!("client begin failed: {error:?}"));
    let client = match client.receive() {
        Transition::Complete(state) => state,
        other => panic_transition("publication receive", other),
    };
    (client, broker_socket)
}

fn carrier_pair(descriptor: bool) -> (HandshakeCarrier, HandshakeCarrier) {
    if descriptor {
        let (client_fd, broker_fd) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .unwrap_or_else(|error| panic!("descriptor pair failed: {error}"));
        let client_socket = DescriptorSubjectSocket::from_owned(client_fd)
            .unwrap_or_else(|error| panic!("descriptor client adoption failed: {error}"));
        let broker_socket = DescriptorSubjectSocket::from_owned(broker_fd)
            .unwrap_or_else(|error| panic!("descriptor broker adoption failed: {error}"));
        let client = HandshakeCarrier::descriptor(client_socket)
            .unwrap_or_else(|error| panic!("descriptor client carrier failed: {error:?}"));
        let broker = HandshakeCarrier::descriptor(broker_socket)
            .unwrap_or_else(|error| panic!("descriptor broker carrier failed: {error:?}"));
        (client, broker)
    } else {
        let (client_socket, broker_fd) = SeqpacketSocket::pair_with_record_subjects()
            .unwrap_or_else(|error| panic!("ordinary pair failed: {error}"));
        let broker_socket = SeqpacketSocket::from_owned(broker_fd)
            .unwrap_or_else(|error| panic!("ordinary broker adoption failed: {error}"));
        let client = HandshakeCarrier::ordinary(client_socket)
            .unwrap_or_else(|error| panic!("ordinary client carrier failed: {error:?}"));
        let broker = HandshakeCarrier::ordinary(broker_socket)
            .unwrap_or_else(|error| panic!("ordinary broker carrier failed: {error:?}"));
        (client, broker)
    }
}

fn start_broker_hello_flight(fixture: &Fixture) -> (BrokerHelloFlight, ClientAwaitBrokerHello) {
    let (client_carrier, broker_carrier) = carrier_pair(false);
    let client_custody = load_client_for_handshake_test(&fixture.client, 0x21)
        .unwrap_or_else(|error| panic!("client custody failed: {error}"));
    let broker_custody = load_broker_for_handshake_test(&fixture.broker, 0x31)
        .unwrap_or_else(|error| panic!("broker custody failed: {error}"));
    let broker = BrokerPublicationFlight::begin(broker_custody, broker_carrier, broker_hello())
        .unwrap_or_else(|error| panic!("broker begin failed: {error:?}"));
    let broker = match broker.send() {
        Transition::Complete(state) => state,
        other => panic_transition("publication send", other),
    };
    let client = ClientAwaitPublication::begin(client_custody, client_carrier, client_hello())
        .unwrap_or_else(|error| panic!("client begin failed: {error:?}"));
    let client = match client.receive() {
        Transition::Complete(state) => state,
        other => panic_transition("publication receive", other),
    };
    let client = match client.send() {
        Transition::Complete(state) => state,
        other => panic_transition("ClientHello send", other),
    };
    let broker = match broker.receive() {
        Transition::Complete(state) => state,
        other => panic_transition("ClientHello receive", other),
    };
    (broker, client)
}

fn fill_send_queue(carrier: &mut HandshakeCarrier) {
    loop {
        match carrier.send(&[0x55; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES]) {
            Ok(()) => {}
            Err(SeqpacketError::WouldBlock) => return,
            Err(error) => panic!("send-queue fill failed: {error}"),
        }
    }
}

fn panic_transition<Complete, Retry>(stage: &str, transition: Transition<Complete, Retry>) -> ! {
    match transition {
        Transition::Complete(_) => panic!("{stage} unexpectedly completed"),
        Transition::Retry(_) => panic!("{stage} unexpectedly blocked"),
        Transition::Failed(error) => panic!("{stage} failed: {error:?}"),
    }
}

#[test]
fn ordinary_and_descriptor_carriers_reach_only_provisional() {
    let ordinary_fixture = Fixture::new();
    let (client_carrier, broker_carrier) = carrier_pair(false);
    let (client, broker) = finish_handshake(&ordinary_fixture, client_carrier, broker_carrier);
    assert_eq!(
        client._transcript.phase(),
        aos_sandbox_broker_session_protocol::BrokerSessionTranscriptPhaseV1::Provisional
    );
    assert_eq!(client._transcript, broker._transcript);

    let descriptor_fixture = Fixture::new();
    let (client_carrier, broker_carrier) = carrier_pair(true);
    let (client, broker) = finish_handshake(&descriptor_fixture, client_carrier, broker_carrier);
    assert_eq!(client._transcript, broker._transcript);
}

#[test]
fn every_receive_state_retries_without_consuming_typestate_on_both_carriers() {
    for descriptor in [false, true] {
        let fixture = Fixture::new();
        let (client_carrier, broker_carrier) = carrier_pair(descriptor);
        let client_custody = load_client_for_handshake_test(&fixture.client, 0x21)
            .unwrap_or_else(|error| panic!("client custody failed: {error}"));
        let broker_custody = load_broker_for_handshake_test(&fixture.broker, 0x31)
            .unwrap_or_else(|error| panic!("broker custody failed: {error}"));
        let broker = BrokerPublicationFlight::begin(broker_custody, broker_carrier, broker_hello())
            .unwrap_or_else(|error| panic!("broker begin failed: {error:?}"));
        let mut client =
            ClientAwaitPublication::begin(client_custody, client_carrier, client_hello())
                .unwrap_or_else(|error| panic!("client begin failed: {error:?}"));

        client.carrier.interrupt_next_receive();
        let client = match client.receive() {
            Transition::Retry(state) => state,
            other => panic_transition("interrupted publication receive", other),
        };
        let client = match client.receive() {
            Transition::Retry(state) => state,
            other => panic_transition("blocked publication receive", other),
        };
        let publication = broker.pending;
        let broker = match broker.send() {
            Transition::Complete(state) => state,
            other => panic_transition("publication send", other),
        };
        let client = match client.receive() {
            Transition::Complete(state) => state,
            other => panic_transition("publication receive", other),
        };
        assert_eq!(client.publication_packet, publication);

        let mut broker = broker;
        broker.carrier.interrupt_next_receive();
        let broker = match broker.receive() {
            Transition::Retry(state) => state,
            other => panic_transition("interrupted ClientHello receive", other),
        };
        let broker = match broker.receive() {
            Transition::Retry(state) => state,
            other => panic_transition("blocked ClientHello receive", other),
        };
        let exact_client = client.client_packet.clone();
        let client = match client.send() {
            Transition::Complete(state) => state,
            other => panic_transition("ClientHello send", other),
        };
        let broker = match broker.receive() {
            Transition::Complete(state) => state,
            other => panic_transition("ClientHello receive", other),
        };
        assert_eq!(broker.client_packet, exact_client);

        let mut client = client;
        client.carrier.interrupt_next_receive();
        let client = match client.receive() {
            Transition::Retry(state) => state,
            other => panic_transition("interrupted BrokerHello receive", other),
        };
        let client = match client.receive() {
            Transition::Retry(state) => state,
            other => panic_transition("blocked BrokerHello receive", other),
        };
        let exact_broker = broker.broker_packet.clone();
        let broker = match broker.send() {
            Transition::Complete(state) => state,
            other => panic_transition("BrokerHello send", other),
        };
        let client = match client.receive() {
            Transition::Complete(state) => state,
            other => panic_transition("BrokerHello receive", other),
        };
        assert_eq!(client._broker_packet, exact_broker);
        assert_eq!(client._transcript, broker._transcript);
    }
}

#[test]
fn descriptor_flight_rejects_every_transferred_descriptor() {
    let (receiver_fd, sender_fd) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )
    .unwrap_or_else(|error| panic!("descriptor pair failed: {error}"));
    let receiver = DescriptorSubjectSocket::from_owned(receiver_fd)
        .unwrap_or_else(|error| panic!("receiver adoption failed: {error}"));
    let mut sender = DescriptorSubjectSocket::from_owned(sender_fd)
        .unwrap_or_else(|error| panic!("sender adoption failed: {error}"));
    let file =
        tempfile::tempfile().unwrap_or_else(|error| panic!("temporary file failed: {error}"));
    sender
        .send_with_descriptors(b"hostile", &[file.as_fd()])
        .unwrap_or_else(|error| panic!("descriptor send failed: {error}"));
    let mut carrier = HandshakeCarrier::descriptor(receiver)
        .unwrap_or_else(|error| panic!("receiver carrier failed: {error:?}"));
    assert!(matches!(
        carrier.receive(BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES),
        Err(HandshakeError::RemoteInvalid)
    ));
}

#[test]
fn wrong_manifest_publication_closes_before_client_hello() {
    let fixture = Fixture::new();
    let (client_socket, broker_fd) = SeqpacketSocket::pair_with_record_subjects()
        .unwrap_or_else(|error| panic!("ordinary pair failed: {error}"));
    let mut broker_socket = SeqpacketSocket::from_owned(broker_fd)
        .unwrap_or_else(|error| panic!("broker adoption failed: {error}"));
    let hostile =
        UntrustedBrokerSessionEndpointPublicationV1::from_untrusted_broker_claims([9; 16], [8; 32])
            .unwrap_or_else(|error| panic!("hostile publication failed: {error}"))
            .to_canonical_bytes();
    broker_socket
        .send(&hostile)
        .unwrap_or_else(|error| panic!("hostile send failed: {error}"));
    let carrier = HandshakeCarrier::ordinary(client_socket)
        .unwrap_or_else(|error| panic!("client carrier failed: {error:?}"));
    let custody = load_client_for_handshake_test(&fixture.client, 0x21)
        .unwrap_or_else(|error| panic!("client custody failed: {error}"));
    let client = ClientAwaitPublication::begin(custody, carrier, client_hello())
        .unwrap_or_else(|error| panic!("client begin failed: {error:?}"));
    assert!(matches!(
        client.receive(),
        Transition::Failed(HandshakeError::RemoteInvalid)
    ));
}

#[test]
fn malformed_replayed_and_over_ceiling_flights_fail_closed() {
    let publication_fixture = Fixture::new();
    for packet in [vec![0_u8; 64], vec![0_u8; 65]] {
        let (client_socket, broker_fd) = SeqpacketSocket::pair_with_record_subjects()
            .unwrap_or_else(|error| panic!("publication pair failed: {error}"));
        let mut broker_socket = SeqpacketSocket::from_owned(broker_fd)
            .unwrap_or_else(|error| panic!("publication broker adoption failed: {error}"));
        broker_socket
            .send(&packet)
            .unwrap_or_else(|error| panic!("hostile publication send failed: {error}"));
        let carrier = HandshakeCarrier::ordinary(client_socket)
            .unwrap_or_else(|error| panic!("publication carrier failed: {error:?}"));
        let custody = load_client_for_handshake_test(&publication_fixture.client, 0x21)
            .unwrap_or_else(|error| panic!("publication custody failed: {error}"));
        let client = ClientAwaitPublication::begin(custody, carrier, client_hello())
            .unwrap_or_else(|error| panic!("publication begin failed: {error:?}"));
        assert!(matches!(
            client.receive(),
            Transition::Failed(HandshakeError::RemoteInvalid)
        ));
    }

    let client_hello_fixture = Fixture::new();
    let (mut client, broker_carrier) = carrier_pair(false);
    let broker_custody = load_broker_for_handshake_test(&client_hello_fixture.broker, 0x31)
        .unwrap_or_else(|error| panic!("broker custody failed: {error}"));
    let broker = BrokerPublicationFlight::begin(broker_custody, broker_carrier, broker_hello())
        .unwrap_or_else(|error| panic!("broker begin failed: {error:?}"));
    let broker = match broker.send() {
        Transition::Complete(state) => state,
        other => panic_transition("publication send", other),
    };
    client
        .receive(BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES)
        .unwrap_or_else(|error| panic!("publication drain failed: {error:?}"));
    client
        .send(&vec![0_u8; CLIENT_HELLO_MAXIMUM_BYTES + 1])
        .unwrap_or_else(|error| panic!("oversize ClientHello send failed: {error}"));
    assert!(matches!(
        broker.receive(),
        Transition::Failed(HandshakeError::RemoteInvalid)
    ));

    let replay_fixture = Fixture::new();
    let (mut client, broker_carrier) = carrier_pair(false);
    let broker_custody = load_broker_for_handshake_test(&replay_fixture.broker, 0x31)
        .unwrap_or_else(|error| panic!("replay broker custody failed: {error}"));
    let broker = BrokerPublicationFlight::begin(broker_custody, broker_carrier, broker_hello())
        .unwrap_or_else(|error| panic!("replay broker begin failed: {error:?}"));
    let publication = broker.pending;
    let broker = match broker.send() {
        Transition::Complete(state) => state,
        other => panic_transition("replay publication send", other),
    };
    client
        .receive(BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES)
        .unwrap_or_else(|error| panic!("replay publication drain failed: {error:?}"));
    client
        .send(&publication)
        .unwrap_or_else(|error| panic!("replayed publication send failed: {error}"));
    assert!(matches!(
        broker.receive(),
        Transition::Failed(HandshakeError::RemoteInvalid)
    ));

    let broker_hello_fixture = Fixture::new();
    let (mut broker, client) = start_broker_hello_flight(&broker_hello_fixture);
    broker
        .carrier
        .send(&vec![0_u8; SERVER_HELLO_MAXIMUM_BYTES + 1])
        .unwrap_or_else(|error| panic!("oversize BrokerHello send failed: {error}"));
    assert!(matches!(
        client.receive(),
        Transition::Failed(HandshakeError::RemoteInvalid)
    ));
}

#[test]
fn publication_packet_is_retained_exactly_across_retry() {
    let fixture = Fixture::new();
    let (client_socket, broker_fd) = SeqpacketSocket::pair_with_record_subjects()
        .unwrap_or_else(|error| panic!("ordinary pair failed: {error}"));
    let mut broker_socket = SeqpacketSocket::from_owned(broker_fd)
        .unwrap_or_else(|error| panic!("broker adoption failed: {error}"));
    loop {
        match broker_socket.send(&[0x55; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES]) {
            Ok(()) => {}
            Err(SeqpacketError::WouldBlock) => break,
            Err(error) => panic!("send-queue fill failed: {error}"),
        }
    }
    let carrier = HandshakeCarrier::ordinary(broker_socket)
        .unwrap_or_else(|error| panic!("broker carrier failed: {error:?}"));
    let custody = load_broker_for_handshake_test(&fixture.broker, 0x31)
        .unwrap_or_else(|error| panic!("broker custody failed: {error}"));
    let state = BrokerPublicationFlight::begin(custody, carrier, broker_hello())
        .unwrap_or_else(|error| panic!("broker begin failed: {error:?}"));
    let exact = state.pending;
    let state = match state.send() {
        Transition::Retry(state) => state,
        other => panic_transition("first blocked publication", other),
    };
    assert_eq!(state.pending, exact);
    let state = match state.send() {
        Transition::Retry(state) => state,
        other => panic_transition("second blocked publication", other),
    };
    assert_eq!(state.pending, exact);
    assert!(matches!(
        HandshakeError::transport(SeqpacketError::Interrupted),
        HandshakeError::Transport
    ));
    drop(client_socket);
}

#[test]
fn signed_hello_packets_survive_interrupted_and_would_block_send_retries() {
    let client_fixture = Fixture::new();
    let (mut client, _broker_socket) = start_client_hello_flight(&client_fixture);
    let exact_client = client.client_packet.clone();
    client.carrier.interrupt_next_send();
    let mut client = match client.send() {
        Transition::Retry(state) => state,
        other => panic_transition("interrupted ClientHello send", other),
    };
    assert_eq!(client.client_packet, exact_client);
    fill_send_queue(&mut client.carrier);
    let client = match client.send() {
        Transition::Retry(state) => state,
        other => panic_transition("blocked ClientHello send", other),
    };
    assert_eq!(client.client_packet, exact_client);

    let broker_fixture = Fixture::new();
    let (mut broker, _client) = start_broker_hello_flight(&broker_fixture);
    let exact_broker = broker.broker_packet.clone();
    broker.carrier.interrupt_next_send();
    let mut broker = match broker.send() {
        Transition::Retry(state) => state,
        other => panic_transition("interrupted BrokerHello send", other),
    };
    assert_eq!(broker.broker_packet, exact_broker);
    fill_send_queue(&mut broker.carrier);
    let broker = match broker.send() {
        Transition::Retry(state) => state,
        other => panic_transition("blocked BrokerHello send", other),
    };
    assert_eq!(broker.broker_packet, exact_broker);
}

#[test]
fn client_send_and_broker_receive_prechecks_suppress_io() {
    use std::sync::atomic::Ordering;

    let send_fixture = Fixture::new();
    let (mut client, mut broker_socket) = start_client_hello_flight(&send_fixture);
    let send_trace = client.carrier.io_trace();
    let sends_before = send_trace.sends.load(Ordering::Relaxed);
    client.carrier.peer.process_id ^= 1;
    assert!(matches!(
        client.send(),
        Transition::Failed(HandshakeError::KernelEvidence)
    ));
    assert_eq!(send_trace.sends.load(Ordering::Relaxed), sends_before);
    assert!(broker_socket.receive(CLIENT_HELLO_MAXIMUM_BYTES).is_err());

    let receive_fixture = Fixture::new();
    let (client, _broker_socket) = start_client_hello_flight(&receive_fixture);
    let mut client = match client.send() {
        Transition::Complete(state) => state,
        other => panic_transition("client hello send", other),
    };
    let receive_trace = client.carrier.io_trace();
    let receives_before = receive_trace.receives.load(Ordering::Relaxed);
    client.publication_subject.evidence.process_id ^= 1;
    assert!(matches!(
        client.receive(),
        Transition::Failed(HandshakeError::KernelEvidence)
    ));
    assert_eq!(
        receive_trace.receives.load(Ordering::Relaxed),
        receives_before
    );
}

#[test]
fn protected_mutation_before_send_releases_no_publication() {
    let fixture = Fixture::new();
    let (mut client_socket, broker_fd) = SeqpacketSocket::pair_with_record_subjects()
        .unwrap_or_else(|error| panic!("ordinary pair failed: {error}"));
    let broker_socket = SeqpacketSocket::from_owned(broker_fd)
        .unwrap_or_else(|error| panic!("broker adoption failed: {error}"));
    let carrier = HandshakeCarrier::ordinary(broker_socket)
        .unwrap_or_else(|error| panic!("broker carrier failed: {error:?}"));
    let custody = load_broker_for_handshake_test(&fixture.broker, 0x31)
        .unwrap_or_else(|error| panic!("broker custody failed: {error}"));
    let state = BrokerPublicationFlight::begin(custody, carrier, broker_hello())
        .unwrap_or_else(|error| panic!("broker begin failed: {error:?}"));

    let manifest_path = fixture.broker.join(MANIFEST);
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("manifest mutation permission failed: {error}"));
    let mut bytes =
        fs::read(&manifest_path).unwrap_or_else(|error| panic!("manifest read failed: {error}"));
    bytes[56] ^= 1;
    fs::write(&manifest_path, bytes)
        .unwrap_or_else(|error| panic!("manifest mutation failed: {error}"));
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o400))
        .unwrap_or_else(|error| panic!("manifest restore permission failed: {error}"));

    assert!(matches!(
        state.send(),
        Transition::Failed(HandshakeError::Local(_))
    ));
    assert!(
        client_socket
            .receive(BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES)
            .is_err()
    );
}

#[test]
fn hello_finalizer_postcheck_failure_releases_no_packet_and_poisons() {
    let fixture = Fixture::new();
    let postcheck_failure = (0..7)
        .map(|_| Ok(()))
        .chain([Err(BrokerSessionSecurityError::ExecutionChanged)]);
    let mut client =
        load_client_for_handshake_scripted_test(&fixture.client, 0x21, postcheck_failure)
            .unwrap_or_else(|error| panic!("scripted client load failed: {error}"));
    assert!(matches!(
        client.finalize_client_hello(client_hello(), [0x44; 16]),
        Err(BrokerSessionSecurityError::ExecutionChanged)
    ));
    assert!(matches!(
        client.revalidate_handshake_custody(),
        Err(BrokerSessionSecurityError::Poisoned)
    ));
    drop(client);

    let mut client = load_client_for_handshake_test(&fixture.client, 0x21)
        .unwrap_or_else(|error| panic!("client custody failed: {error}"));
    let client_packet = client
        .finalize_client_hello(client_hello(), [0x44; 16])
        .unwrap_or_else(|error| panic!("client finalization failed: {error}"));
    let canonical_client = decode_canonical_client_hello_v1(&client_packet)
        .unwrap_or_else(|error| panic!("client decode failed: {error}"));
    drop(client);

    let postcheck_failure = (0..7)
        .map(|_| Ok(()))
        .chain([Err(BrokerSessionSecurityError::ExecutionChanged)]);
    let mut broker =
        load_broker_for_handshake_scripted_test(&fixture.broker, 0x31, postcheck_failure)
            .unwrap_or_else(|error| panic!("scripted broker load failed: {error}"));
    assert!(matches!(
        broker.finalize_broker_hello(broker_hello(), &canonical_client),
        Err(BrokerSessionSecurityError::ExecutionChanged)
    ));
    assert!(matches!(
        broker.revalidate_handshake_custody(),
        Err(BrokerSessionSecurityError::Poisoned)
    ));
}

#[test]
fn retained_peer_and_subject_evidence_close_every_drift_dimension() {
    let baseline = ProcessEvidence {
        process_id: 1,
        thread_group_id: 2,
        start_time_ticks: 3,
        cgroup_id: 4,
        real_user_id: 5,
        real_group_id: 6,
        effective_user_id: 7,
        effective_group_id: 8,
        saved_user_id: 9,
        saved_group_id: 10,
        filesystem_user_id: 11,
        filesystem_group_id: 12,
    };
    let changed = [
        ProcessEvidence {
            process_id: 13,
            ..baseline
        },
        ProcessEvidence {
            thread_group_id: 13,
            ..baseline
        },
        ProcessEvidence {
            start_time_ticks: 13,
            ..baseline
        },
        ProcessEvidence {
            cgroup_id: 13,
            ..baseline
        },
        ProcessEvidence {
            real_user_id: 13,
            ..baseline
        },
        ProcessEvidence {
            real_group_id: 13,
            ..baseline
        },
        ProcessEvidence {
            effective_user_id: 13,
            ..baseline
        },
        ProcessEvidence {
            effective_group_id: 13,
            ..baseline
        },
        ProcessEvidence {
            saved_user_id: 13,
            ..baseline
        },
        ProcessEvidence {
            saved_group_id: 13,
            ..baseline
        },
        ProcessEvidence {
            filesystem_user_id: 13,
            ..baseline
        },
        ProcessEvidence {
            filesystem_group_id: 13,
            ..baseline
        },
    ];
    for current in changed {
        assert!(matches!(
            baseline.require_current_observation(current, true),
            Err(HandshakeError::KernelEvidence)
        ));
    }
    assert!(matches!(
        baseline.require_current_observation(baseline, false),
        Err(HandshakeError::KernelEvidence)
    ));
}

fn scripted_credentials() -> ProcessCredentials {
    ProcessCredentials {
        real_user_id: 5,
        real_group_id: 6,
        effective_user_id: 7,
        effective_group_id: 8,
        saved_user_id: 9,
        saved_group_id: 10,
        filesystem_user_id: 11,
        filesystem_group_id: 12,
    }
}

fn scripted_information() -> ProcessInformation {
    ProcessInformation {
        process_id: 1,
        thread_group_id: 2,
        parent_process_id: 3,
        credentials: Some(scripted_credentials()),
        cgroup_id: Some(4),
    }
}

fn scripted_identity() -> ProcessIdentity {
    ProcessIdentity {
        process_id: 1,
        thread_group_id: 2,
        start_time_ticks: 13,
        cgroup_id: Some(4),
    }
}

#[test]
fn process_observation_sandwich_closes_every_incoherent_shape() {
    let information = scripted_information();
    let identity = scripted_identity();
    let baseline = ProcessEvidence::from_observation_sandwich(
        Some(information),
        information,
        identity,
        information,
        Ok(true),
    )
    .unwrap_or_else(|error| panic!("stable observation failed: {error:?}"));

    let credential_drifts = [
        ProcessCredentials {
            real_user_id: 99,
            ..scripted_credentials()
        },
        ProcessCredentials {
            real_group_id: 99,
            ..scripted_credentials()
        },
        ProcessCredentials {
            effective_user_id: 99,
            ..scripted_credentials()
        },
        ProcessCredentials {
            effective_group_id: 99,
            ..scripted_credentials()
        },
        ProcessCredentials {
            saved_user_id: 99,
            ..scripted_credentials()
        },
        ProcessCredentials {
            saved_group_id: 99,
            ..scripted_credentials()
        },
        ProcessCredentials {
            filesystem_user_id: 99,
            ..scripted_credentials()
        },
        ProcessCredentials {
            filesystem_group_id: 99,
            ..scripted_credentials()
        },
    ];
    for credentials in credential_drifts {
        let changed = ProcessInformation {
            credentials: Some(credentials),
            ..information
        };
        assert!(matches!(
            ProcessEvidence::from_observation_sandwich(
                Some(information),
                changed,
                identity,
                changed,
                Ok(true),
            ),
            Err(HandshakeError::KernelEvidence)
        ));
    }

    let changed_parent = ProcessInformation {
        parent_process_id: 99,
        ..information
    };
    let changed_cgroup = ProcessInformation {
        cgroup_id: Some(99),
        ..information
    };
    for changed in [changed_parent, changed_cgroup] {
        assert!(matches!(
            ProcessEvidence::from_observation_sandwich(
                Some(information),
                information,
                identity,
                changed,
                Ok(true),
            ),
            Err(HandshakeError::KernelEvidence)
        ));
        assert!(matches!(
            ProcessEvidence::from_observation_sandwich(
                Some(information),
                changed,
                identity,
                changed,
                Ok(true),
            ),
            Err(HandshakeError::KernelEvidence)
        ));
    }

    for malformed in [
        ProcessInformation {
            credentials: None,
            ..information
        },
        ProcessInformation {
            cgroup_id: None,
            ..information
        },
        ProcessInformation {
            cgroup_id: Some(0),
            ..information
        },
    ] {
        assert!(matches!(
            ProcessEvidence::from_observation_sandwich(
                None,
                malformed,
                identity,
                malformed,
                Ok(true),
            ),
            Err(HandshakeError::KernelEvidence)
        ));
    }

    for mismatched_identity in [
        ProcessIdentity {
            process_id: 99,
            ..identity
        },
        ProcessIdentity {
            thread_group_id: 99,
            ..identity
        },
        ProcessIdentity {
            cgroup_id: Some(99),
            ..identity
        },
    ] {
        assert!(matches!(
            ProcessEvidence::from_observation_sandwich(
                None,
                information,
                mismatched_identity,
                information,
                Ok(true),
            ),
            Err(HandshakeError::KernelEvidence)
        ));
    }

    assert!(matches!(
        ProcessEvidence::from_observation_sandwich(
            None,
            information,
            identity,
            information,
            Ok(false),
        ),
        Err(HandshakeError::KernelEvidence)
    ));
    assert!(matches!(
        ProcessEvidence::from_observation_sandwich(
            None,
            information,
            identity,
            information,
            Err(HandshakeError::KernelEvidence),
        ),
        Err(HandshakeError::KernelEvidence)
    ));

    let next_parent = ProcessInformation {
        parent_process_id: 77,
        ..information
    };
    let next = ProcessEvidence::from_observation_sandwich(
        None,
        next_parent,
        identity,
        next_parent,
        Ok(true),
    )
    .unwrap_or_else(|error| panic!("cross-transition parent failed: {error:?}"));
    assert!(baseline == next);
}

#[test]
fn prior_process_publication_cannot_bootstrap_a_restarted_broker() {
    let fixture = Fixture::new();
    let mut old_broker = load_broker_for_handshake_test(&fixture.broker, 0x31)
        .unwrap_or_else(|error| panic!("old broker custody failed: {error}"));
    let old_publication = old_broker
        .finalize_endpoint_publication()
        .unwrap_or_else(|error| panic!("old publication failed: {error}"));
    drop(old_broker);

    let (client_socket, broker_fd) = SeqpacketSocket::pair_with_record_subjects()
        .unwrap_or_else(|error| panic!("ordinary pair failed: {error}"));
    let mut broker_socket = SeqpacketSocket::from_owned(broker_fd)
        .unwrap_or_else(|error| panic!("broker adoption failed: {error}"));
    broker_socket
        .send(&old_publication)
        .unwrap_or_else(|error| panic!("old publication send failed: {error}"));
    let client_carrier = HandshakeCarrier::ordinary(client_socket)
        .unwrap_or_else(|error| panic!("client carrier failed: {error:?}"));
    let broker_carrier = HandshakeCarrier::ordinary(broker_socket)
        .unwrap_or_else(|error| panic!("broker carrier failed: {error:?}"));

    let client_custody = load_client_for_handshake_test(&fixture.client, 0x21)
        .unwrap_or_else(|error| panic!("client custody failed: {error}"));
    let client = ClientAwaitPublication::begin(client_custody, client_carrier, client_hello())
        .unwrap_or_else(|error| panic!("client begin failed: {error:?}"));
    let client = match client.receive() {
        Transition::Complete(state) => state,
        other => panic_transition("old publication receive", other),
    };
    let client = match client.send() {
        Transition::Complete(state) => state,
        other => panic_transition("old-context ClientHello send", other),
    };

    let broker_custody = load_broker_for_handshake_test(&fixture.broker, 0x41)
        .unwrap_or_else(|error| panic!("new broker custody failed: {error}"));
    let broker = BrokerAwaitClientHello {
        custody: broker_custody,
        carrier: broker_carrier,
        publication: old_publication,
        broker_hello: broker_hello(),
    };
    assert!(matches!(
        broker.receive(),
        Transition::Failed(HandshakeError::RemoteInvalid)
    ));
    drop(client);
}
