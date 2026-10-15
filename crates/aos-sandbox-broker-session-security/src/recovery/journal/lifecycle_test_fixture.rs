//! Real signed terminal custody for lifecycle attestation regression tests.
//!
//! The temporary root keeps native file and writer checks, but deliberately
//! uses the existing test-only unscoped floor. It is no installed-floor proof.

use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerClientHello, BrokerRequestEnvelope, BrokerResponseEnvelope, BrokerServerHello,
    Feature, InventoryRuntimeRequest, InventoryRuntimeResponse, RequestHeader,
};
use aos_sandbox_broker_session_protocol::{
    decode_canonical_client_hello_v1, decode_canonical_server_hello_v1,
    verify_broker_session_transcript_v1,
};
use aos_sandbox_linux::seqpacket::SeqpacketSocket;
use aos_sandbox_protocol::PeerPolicy;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestAdmissionV1,
    prepare_client_sent_authenticated_broker_method_request_v1,
};
use buffa::Message as _;
use tempfile::TempDir;

use super::*;
use crate::endpoint::{ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1};
use crate::recovery::{ProtectedBrokerOutcomeAdmissionV1, ProtectedBrokerOutcomeCurrentV1};
use crate::test_signed_endpoint::{TestEndpointRole, install_endpoint, manifest_and_secrets};

pub(crate) struct LifecycleTerminalFixture {
    pub(crate) journal: ProtectedBrokerSessionJournalV1,
    pub(crate) currentness: Option<crate::ProtectedBrokerOutcomeCurrentnessOwnerV1>,
    pub(crate) socket: SeqpacketSocket,
    pub(crate) client_path: PathBuf,
    _peer_socket: OwnedFd,
    _temporary: TempDir,
}

impl LifecycleTerminalFixture {
    pub(crate) fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let client_path = temporary.path().join("client");
        let broker_path = temporary.path().join("broker");
        let journal_path = temporary.path().join("journal");
        for path in [&client_path, &broker_path, &journal_path] {
            fs::create_dir(path).unwrap();
        }
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o700)).unwrap();
        let (manifest, secrets) = manifest_and_secrets(BrokerSessionProtocolV1::Host);
        install_endpoint(&client_path, &manifest, &secrets, TestEndpointRole::Client);
        install_endpoint(&broker_path, &manifest, &secrets, TestEndpointRole::Broker);
        let mut client = ProtectedBrokerSessionClientV1::load(&client_path).unwrap();
        let mut broker = ProtectedBrokerSessionBrokerV1::load(&broker_path).unwrap();
        let (socket, peer_socket) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let credentials = socket.peer().credentials();
        let peer = aos_sandbox_protocol::PeerCredentials {
            uid: credentials.uid(),
            gid: credentials.gid(),
            pid: Some(credentials.pid().get()),
        };
        let method = BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME;
        let feature = Feature {
            namespace: "aos.sandbox.authentication.broker-session".to_owned(),
            major: 1,
            ..Default::default()
        };
        let client_packet = client
            .finalize_client_hello(
                BrokerClientHello {
                    protocol_major: 1,
                    audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                    required_features: vec![feature.clone()],
                    maximum_response_bytes: 65_536,
                    required_methods: vec![method.into()],
                    ..Default::default()
                },
                broker.process_execution_id_bytes(),
            )
            .unwrap();
        let client_hello = decode_canonical_client_hello_v1(&client_packet).unwrap();
        let broker_packet = broker
            .finalize_broker_hello(
                BrokerServerHello {
                    protocol_major: 1,
                    features: vec![feature],
                    maximum_request_bytes: 65_536,
                    maximum_response_bytes: 65_536,
                    methods: vec![method.into()],
                    ..Default::default()
                },
                &client_hello,
            )
            .unwrap();
        let broker_hello = decode_canonical_server_hello_v1(&broker_packet).unwrap();
        let context = client
            .context_for_handshake(broker.process_execution_id_bytes())
            .unwrap();
        let transcript =
            verify_broker_session_transcript_v1(&client_hello, &broker_hello, &context).unwrap();
        let checkpoint = HistoricalSessionCheckpointV1::new(
            context,
            &client_packet,
            &broker_packet,
            peer,
            &transcript,
        )
        .unwrap();

        let now = crate::handshake::protected_boottime_nanoseconds().unwrap();
        let request_id = [7; 16];
        let body = InventoryRuntimeRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: request_id.to_vec(),
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: now.checked_add(30_000_000_000).unwrap(),
                maximum_response_bytes: 65_536,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
        .encode_to_vec();
        let packet = client
            .finalize_method_request(
                BrokerRequestEnvelope {
                    method: method.into(),
                    body,
                    ..Default::default()
                },
                method,
                transcript.session_binding(),
                client.process_execution_id_bytes(),
                1,
                request_id,
            )
            .unwrap();
        let canonical = decode_canonical_request_v1(&packet).unwrap();
        let bindings =
            authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method).unwrap();
        let prior =
            BrokerSessionTrafficStateV1::from_provisional_transcript(transcript.clone()).unwrap();
        let request = match prepare_client_sent_authenticated_broker_method_request_v1(
            &prior,
            &packet,
            None,
            0,
            peer,
            PeerPolicy {
                uid: peer.uid,
                gid: Some(peer.gid),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            now,
            bindings,
            checkpoint.context(),
        )
        .unwrap()
        {
            AuthenticatedBrokerMethodRequestAdmissionV1::New { request, .. } => request,
            AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
                panic!("fresh request replayed")
            }
        };
        let outcome_packet = broker
            .finalize_method_outcome(
                BrokerResponseEnvelope {
                    request_id: request_id.to_vec(),
                    method: method.into(),
                    body: InventoryRuntimeResponse::default().encode_to_vec(),
                    ..Default::default()
                },
                method,
                transcript.session_binding(),
                broker.process_execution_id_bytes(),
                1,
                request_id,
                request.signed_request_digest(),
            )
            .unwrap();

        let limits = protected_session_journal_limits();
        let uid = fs::metadata(&journal_path).unwrap().uid();
        let (native, _) =
            Journal::open_protected_at_uid(&journal_path, "session.journal", limits, uid).unwrap();
        let mut journal = ProtectedBrokerSessionJournalV1 {
            floor: tpm_floor::runtime::BrokerFloorV1::test_not_scoped(),
            journal: Some(native),
            directory: journal_path,
            name: "session.journal".to_owned(),
            limits,
            owner: JournalOwnerV1::capture(BrokerSessionDurableEndpointV1::Client),
            endpoint: ProtectedEndpointV1::Client(client),
            #[cfg(feature = "online-nix")]
            online_schema: None,
        };
        assert!(matches!(
            journal
                .initialize_authenticated_request(&request, &transcript, socket.peer(), &checkpoint)
                .unwrap(),
            ProtectedBrokerSessionInitializationResultV1::Initialized
        ));
        let gate = journal
            .reopen_broker_outcome(&request, &transcript, socket.peer())
            .unwrap();
        let canonical = decode_canonical_response_v1(&outcome_packet).unwrap();
        let pending = match gate.admit_outcome(&canonical).unwrap() {
            ProtectedBrokerOutcomeAdmissionV1::New { advancement } => advancement,
            ProtectedBrokerOutcomeAdmissionV1::ExactReplay { .. } => {
                panic!("fresh outcome replayed")
            }
        };
        let committed = match journal.commit_broker_outcome(pending, socket.peer()) {
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => committed,
            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. } => {
                panic!("terminal commit failed: {error}")
            }
        };
        Self {
            journal,
            currentness: Some(committed.into_currentness_owner()),
            socket,
            client_path,
            _peer_socket: peer_socket,
            _temporary: temporary,
        }
    }

    pub(crate) fn current(&mut self) -> ProtectedBrokerOutcomeCurrentV1<'_> {
        self.journal
            .revalidate_broker_outcome(self.currentness.take().unwrap(), self.socket.peer())
            .unwrap()
    }

    pub(crate) fn replace_client_key(path: &std::path::Path) {
        let key = path.join("client-record-signing-key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let mut bytes = fs::read(&key).unwrap();
        bytes[47] ^= 1;
        fs::write(&key, bytes).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
    }
}
