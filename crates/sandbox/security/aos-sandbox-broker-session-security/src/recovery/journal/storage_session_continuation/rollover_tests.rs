//! Signed-history and real temporary-writer rollover tests.
//!
//! These exercise DATA qualification and the existing exact installation engine.
//! The shared fixture uses its real test-UID writer and unscoped test floor; it
//! does not manufacture a successful installed Storage resource/original loan.

use super::*;
use crate::recovery::journal::lifecycle_test_fixture::LifecycleTerminalFixture;
use crate::endpoint::ProtectedBrokerSessionClientV1;
use aos_sandbox_api::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerServerHello, BrokerRequestEnvelope,
    Feature, InventoryStorageRequest, RequestHeader,
};
use aos_sandbox_broker_session_protocol::{
    decode_canonical_client_hello_v1, decode_canonical_server_hello_v1,
    verify_broker_session_transcript_v1,
};
use buffa::Message as _;

fn model() -> (LifecycleTerminalFixture, RetiredStorageTranscriptV1, StoredProtocolHistoryV1) {
    let mut fixture = LifecycleTerminalFixture::storage_broker();
    let current = fixture.journal.read_optional(BrokerSessionProtocolV1::Storage)
        .unwrap().unwrap();
    let checkpoint = current.checkpoint.clone().unwrap();
    // DATA fixtures capture the same fixed coordinates as the sole private
    // positive-disposal constructor. They do not create its production owner.
    let committed = fixture.committed.take().unwrap();
    let original = committed.currentness_owner;
    let retired = RetiredStorageTranscriptV1 {
        endpoint: BrokerSessionDurableEndpointV1::Broker,
        protected_generation: original.protected_generation,
        protected_head: original.protected_head,
        protected_bindings: original.protected_bindings,
        peer_binding: original.peer_binding,
        session_binding: original.transcript.session_binding(),
        checkpoint,
        first_request: None,
        phase: RetiredStorageTranscriptPhaseV1::Pending,
    };
    (fixture, retired, current)
}

fn next_request(fixture: &mut LifecycleTerminalFixture) -> (
    VerifiedBrokerSessionTranscriptV1,
    HistoricalSessionCheckpointV1,
    AuthenticatedBrokerMethodRequestV1,
) {
    let mut client = ProtectedBrokerSessionClientV1::load(&fixture.client_path).unwrap();
    let broker = match &mut fixture.journal.endpoint {
        ProtectedEndpointV1::Broker(broker) => broker,
        ProtectedEndpointV1::Client(_) => panic!("expected actual Broker endpoint"),
    };
    let method = BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES;
    let feature = Feature {
        namespace: "aos.sandbox.authentication.broker-session".to_owned(),
        major: 1,
        ..Default::default()
    };
    // Match the original ordinary Storage fixture's signed profile. A signed
    // Inventory-only transcript belongs to the separate Recover journal slot.
    let features = vec![feature, Feature {
        namespace: aos_sandbox_protocol::session::SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(),
        major: 1,
        ..Default::default()
    }];
    let methods = vec![method.into(), BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG.into()];
    let client_packet = client.finalize_client_hello(
        BrokerClientHello {
            protocol_major: 1,
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            required_features: features.clone(),
            required_methods: methods.clone(),
            maximum_response_bytes: 65_536,
            ..Default::default()
        },
        broker.process_execution_id_bytes(),
    ).unwrap();
    let client_hello = decode_canonical_client_hello_v1(&client_packet).unwrap();
    let broker_packet = broker.finalize_broker_hello(
        BrokerServerHello {
            protocol_major: 1,
            features,
            methods,
            maximum_request_bytes: 65_536,
            maximum_response_bytes: 65_536,
            ..Default::default()
        },
        &client_hello,
    ).unwrap();
    let broker_hello = decode_canonical_server_hello_v1(&broker_packet).unwrap();
    let context = client.context_for_handshake(broker.process_execution_id_bytes()).unwrap();
    let transcript = verify_broker_session_transcript_v1(
        &client_hello, &broker_hello, &context,
    ).unwrap();
    assert!(!aos_sandbox_broker_session_protocol::profile::
        is_storage_operator_recover_transcript_v1(&transcript));
    let credentials = fixture.socket.peer().credentials();
    let peer = aos_sandbox_protocol::PeerCredentials {
        uid: credentials.uid(),
        gid: credentials.gid(),
        pid: Some(credentials.pid().get()),
    };
    let checkpoint = HistoricalSessionCheckpointV1::new(
        context, &client_packet, &broker_packet, peer, &transcript,
    ).unwrap();
    let now = crate::handshake::protected_boottime_nanoseconds().unwrap();
    let request_id = [8; 16];
    let packet = client.finalize_method_request(
        BrokerRequestEnvelope {
            method: method.into(),
            body: InventoryStorageRequest {
                header: Some(RequestHeader {
                    protocol_major: 1,
                    request_id: request_id.to_vec(),
                    audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                    deadline_boottime_nanoseconds: now.checked_add(30_000_000_000).unwrap(),
                    maximum_response_bytes: 65_536,
                    ..Default::default()
                }).into(),
                ..Default::default()
            }.encode_to_vec(),
            ..Default::default()
        },
        method,
        transcript.session_binding(),
        client.process_execution_id_bytes(),
        1,
        request_id,
    ).unwrap();
    let canonical = decode_canonical_request_v1(&packet).unwrap();
    let bindings = authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method).unwrap();
    let traffic = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript.clone()).unwrap();
    let admitted = aos_sandbox_protocol::authenticated_session::all_methods::admit_server_received_authenticated_broker_method_request_v1(
        &traffic,
        &packet,
        None,
        0,
        peer,
        aos_sandbox_protocol::PeerPolicy {
            uid: peer.uid,
            gid: Some(peer.gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        now,
        bindings,
        checkpoint.context(),
    ).unwrap();
    let request = match admitted {
        AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. } => request,
        AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => panic!("new transcript replayed"),
    };
    (transcript, checkpoint, request)
}

fn target(
    fixture: &mut LifecycleTerminalFixture,
    current: &StoredProtocolHistoryV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
    checkpoint: HistoricalSessionCheckpointV1,
    request: AuthenticatedBrokerMethodRequestV1,
) -> ProtectedBrokerSessionInitializationRecoveryV1 {
    let catalog = request.catalog_binding().unwrap_or_else(|| request.semantic_commitment());
    let snapshot = ProtectedBrokerSessionJournalSnapshotV1::new(
        current.generation, current.endpoint_publication, catalog, [0; 32], None,
    ).unwrap();
    let peer = fixture.journal.observe_peer(&transcript, fixture.socket.peer()).unwrap();
    let write = ProtectedBrokerRequestWriteV1::prepare_initial_from_snapshot(
        &request, checkpoint.context(), &transcript, &peer, &snapshot,
    ).unwrap();
    let replacement = StoredProtocolHistoryV1::from_request_write(
        BrokerSessionProtocolV1::Storage,
        BrokerSessionDurableEndpointV1::Broker,
        current.stable_endpoint_identity,
        current.endpoint_publication,
        catalog,
        write,
        Some(checkpoint),
    ).unwrap();
    ProtectedBrokerSessionInitializationRecoveryV1 {
        expected_generation: current.generation,
        expected_head: current.current_head,
        expected_publication: current.endpoint_publication,
        target: replacement,
        transcript,
    }
}

#[test]
fn actual_signed_terminal_qualifies_only_a_fresh_same_process_transcript() {
    let (mut fixture, retired, current) = model();
    let old = retired.checkpoint.verify().unwrap();
    let history = current.history_model().unwrap();
    let (next, _, _) = next_request(&mut fixture);

    assert_eq!(old.broker_process(), next.broker_process());
    assert_ne!(old.session_binding(), next.session_binding());
    retired.require_exact_predecessor(&current, &history, &next).unwrap();
    assert!(retired.require_exact_predecessor(&current, &history, &old).is_err());
}

#[test]
fn stale_head_generation_publication_or_checkpoint_cannot_qualify() {
    let (mut fixture, retired, current) = model();
    let history = current.history_model().unwrap();
    let (next, next_checkpoint, _) = next_request(&mut fixture);
    for changed in 0..4 {
        let mut stale = current.clone();
        match changed {
            0 => stale.generation += 1,
            1 => stale.current_head[0] ^= 1,
            2 => stale.endpoint_publication[0] ^= 1,
            _ => stale.checkpoint = Some(next_checkpoint.clone()),
        }
        assert!(retired.require_exact_predecessor(&stale, &history, &next).is_err());
    }
}

#[test]
fn nonterminal_history_and_already_attempted_or_consumed_predecessor_refuse() {
    let (mut fixture, mut retired, current) = model();
    let (next, checkpoint, request) = next_request(&mut fixture);
    let replacement = target(&mut fixture, &current, next.clone(), checkpoint, request);
    let nonterminal = replacement.target.history_model().unwrap();

    assert!(retired.require_exact_predecessor(&current, &nonterminal, &next).is_err());
    for phase in [RetiredStorageTranscriptPhaseV1::Attempted, RetiredStorageTranscriptPhaseV1::Consumed] {
        retired.phase = phase;
        assert!(retired.require_exact_predecessor(&current, &current.history_model().unwrap(), &next).is_err());
    }
}

#[test]
fn hello_alone_keeps_old_history_and_no_predecessor_still_refuses_initialization() {
    let (mut fixture, _retired, current) = model();
    let (next, checkpoint, request) = next_request(&mut fixture);

    assert_eq!(fixture.journal.read_optional(BrokerSessionProtocolV1::Storage).unwrap(), Some(current.clone()));
    assert!(fixture.journal.initialize_authenticated_request(
        &request, &next, fixture.socket.peer(), &checkpoint,
    ).is_err());
    assert_eq!(fixture.journal.read_optional(BrokerSessionProtocolV1::Storage).unwrap(), Some(current));
}

#[test]
fn shared_exact_cas_keeps_generation_monotone_and_original_checkpoint_resident() {
    let (mut fixture, retired, current) = model();
    let (next, checkpoint, request) = next_request(&mut fixture);
    retired.require_exact_predecessor(&current, &current.history_model().unwrap(), &next).unwrap();
    let recovery = target(&mut fixture, &current, next, checkpoint, request);
    let expected = recovery.target.clone();

    assert!(matches!(fixture.journal.recover_initialization(recovery, fixture.socket.peer()),
        ProtectedBrokerSessionInitializationResultV1::Initialized));
    assert_eq!(expected.generation, current.generation + 1);
    assert_eq!(fixture.journal.read_optional(BrokerSessionProtocolV1::Storage).unwrap(), Some(expected));
    assert_eq!(retired.protected_head, current.current_head);
}

#[test]
fn exact_target_recovery_after_actual_durable_append_does_not_append_again() {
    let (mut fixture, retired, current) = model();
    let (next, checkpoint, request) = next_request(&mut fixture);
    retired.require_exact_predecessor(&current, &current.history_model().unwrap(), &next).unwrap();
    let recovery = target(&mut fixture, &current, next, checkpoint, request);
    let expected = recovery.target.clone();
    // Model the durable-target/readback interruption using the REAL common
    // native append. The recovery call must classify that exact target.
    fixture.journal.commit_stored(&expected).unwrap();
    let native_path = fixture.journal.directory.join(&fixture.journal.name);
    let before_bytes = std::fs::metadata(&native_path).unwrap().len();

    assert!(matches!(fixture.journal.recover_initialization(recovery, fixture.socket.peer()),
        ProtectedBrokerSessionInitializationResultV1::Initialized));

    assert_eq!(fixture.journal.read_optional(BrokerSessionProtocolV1::Storage).unwrap(), Some(expected));
    assert_eq!(std::fs::metadata(native_path).unwrap().len(), before_bytes);
}

#[test]
fn stale_cas_preserves_the_original_predecessor_and_whole_recovery_target() {
    let (mut fixture, retired, current) = model();
    let (next, checkpoint, request) = next_request(&mut fixture);
    let mut recovery = target(&mut fixture, &current, next, checkpoint, request);
    let expected_target = recovery.target.clone();
    recovery.expected_head[0] ^= 1;

    match fixture.journal.recover_initialization(recovery, fixture.socket.peer()) {
        ProtectedBrokerSessionInitializationResultV1::RecoveryRequired { recovery, .. } => {
            assert_eq!(recovery.target, expected_target);
            assert_ne!(recovery.expected_head, current.current_head);
        }
        ProtectedBrokerSessionInitializationResultV1::Initialized => panic!("stale CAS installed"),
    }

    assert_eq!(fixture.journal.read_optional(BrokerSessionProtocolV1::Storage).unwrap(), Some(current.clone()));
    assert_eq!(retired.protected_head, current.current_head);
}

#[test]
fn first_request_identity_does_not_qualify_another_signed_transcript_or_sequence() {
    let (mut fixture, _retired, _current) = model();
    let (_, _, request) = next_request(&mut fixture);
    let mut first = RetiredStorageFirstRequestV1 {
        signed_digest: request.signed_request_digest(),
        request_id: request.request_id(),
        session_binding: request.session_binding(),
        client_sequence: request.client_sequence(),
    };
    assert!(first.matches(&request));

    let (_, _, different_transcript) = next_request(&mut fixture);
    assert!(!first.matches(&different_transcript));
    first.client_sequence += 1;
    assert!(!first.matches(&request));
}

#[test]
fn only_attempted_exact_predecessor_can_be_consumed_by_the_shared_cas_result() {
    let (mut fixture, mut retired, current) = model();
    let (next, checkpoint, request) = next_request(&mut fixture);
    let mut recovery = target(&mut fixture, &current, next, checkpoint, request);

    assert!(!retired.matches_completed_initialization(&recovery));
    retired.phase = RetiredStorageTranscriptPhaseV1::Attempted;
    assert!(retired.matches_completed_initialization(&recovery));
    recovery.expected_head[0] ^= 1;
    assert!(!retired.matches_completed_initialization(&recovery));
    recovery.expected_head[0] ^= 1;
    retired.phase = RetiredStorageTranscriptPhaseV1::Consumed;
    assert!(!retired.matches_completed_initialization(&recovery));
}

#[test]
fn wrong_endpoint_data_cannot_reuse_the_actual_signed_broker_predecessor() {
    let (mut fixture, mut retired, current) = model();
    let history = current.history_model().unwrap();
    let (next, checkpoint, request) = next_request(&mut fixture);
    let recovery = target(&mut fixture, &current, next.clone(), checkpoint, request);

    retired.require_exact_predecessor(&current, &history, &next).unwrap();
    retired.endpoint = BrokerSessionDurableEndpointV1::Client;
    assert!(retired.require_exact_predecessor(&current, &history, &next).is_err());
    retired.phase = RetiredStorageTranscriptPhaseV1::Attempted;
    assert!(!retired.matches_completed_initialization(&recovery));
}
