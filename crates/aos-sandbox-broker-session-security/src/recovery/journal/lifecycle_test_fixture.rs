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
    Feature, InventoryRuntimeRequest, InventoryRuntimeResponse, InventoryStorageRequest,
    InventoryStorageResourcesResponse, RequestHeader,
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
    admit_server_received_authenticated_broker_method_request_v1,
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
    pub(crate) committed: Option<crate::ProtectedBrokerOutcomeCommittedAdvancementV1>,
    pub(crate) socket: SeqpacketSocket,
    pub(crate) client_path: PathBuf,
    _peer_socket: OwnedFd,
    _temporary: TempDir,
}

impl LifecycleTerminalFixture {
    pub(crate) fn new() -> Self {
        Self::new_for_endpoint(BrokerSessionDurableEndpointV1::Client)
    }

    pub(crate) fn storage_broker() -> Self {
        Self::new_for_endpoint(BrokerSessionDurableEndpointV1::Broker)
    }

    pub(crate) fn storage_client() -> Self {
        Self::new_for_protocol(BrokerSessionDurableEndpointV1::Client, BrokerSessionProtocolV1::Storage)
    }

    fn new_for_endpoint(role: BrokerSessionDurableEndpointV1) -> Self {
        let protocol = match role {
            BrokerSessionDurableEndpointV1::Client => BrokerSessionProtocolV1::Host,
            BrokerSessionDurableEndpointV1::Broker => BrokerSessionProtocolV1::Storage,
        };
        Self::new_for_protocol(role, protocol)
    }

    pub(crate) fn storage_recover_client() -> Self {
        Self::new_for_protocol_and_purpose(BrokerSessionDurableEndpointV1::Client,
            BrokerSessionProtocolV1::Storage, true)
    }

    fn new_for_protocol(role: BrokerSessionDurableEndpointV1, protocol: BrokerSessionProtocolV1) -> Self {
        Self::new_for_protocol_and_purpose(role, protocol, false)
    }

    fn new_for_protocol_and_purpose(role: BrokerSessionDurableEndpointV1,
        protocol: BrokerSessionProtocolV1, recover: bool,
    ) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let client_path = temporary.path().join("client");
        let broker_path = temporary.path().join("broker");
        let journal_path = temporary.path().join("journal");
        for path in [&client_path, &broker_path, &journal_path] {
            fs::create_dir(path).unwrap();
        }
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o700)).unwrap();
        let (manifest, secrets) = manifest_and_secrets(protocol);
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
        let method = match protocol {
            BrokerSessionProtocolV1::Host => BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            BrokerSessionProtocolV1::Storage => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            _ => panic!("unsupported lifecycle fixture protocol"),
        };
        let feature = Feature {
            namespace: "aos.sandbox.authentication.broker-session".to_owned(),
            major: 1,
            ..Default::default()
        };
        let mut features = vec![feature];
        if protocol == BrokerSessionProtocolV1::Storage && !recover {
            // PrepareCatalog requires the signed-plan feature on both HELLOs.
            features.push(Feature {
                namespace: aos_sandbox_protocol::session::SIGNED_PLAN_LEASE_FEATURE_NAMESPACE.to_owned(),
                major: 1,
                ..Default::default()
            });
        }
        let methods = if protocol == BrokerSessionProtocolV1::Storage && !recover {
            vec![method.into(), BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG.into()]
        } else { vec![method.into()] };
        let client_packet = client
            .finalize_client_hello(
                BrokerClientHello {
                    protocol_major: 1,
                    audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                    required_features: features.clone(),
                    maximum_response_bytes: 65_536,
                    required_methods: methods.clone(),
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
                    features,
                    maximum_request_bytes: 65_536,
                    maximum_response_bytes: 65_536,
                    methods,
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
        let header = RequestHeader {
            protocol_major: 1,
            request_id: request_id.to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: now.checked_add(30_000_000_000).unwrap(),
            maximum_response_bytes: 65_536,
            ..Default::default()
        };
        let body = match protocol {
            BrokerSessionProtocolV1::Host => InventoryRuntimeRequest {
                header: Some(header).into(),
                ..Default::default()
            }.encode_to_vec(),
            BrokerSessionProtocolV1::Storage => InventoryStorageRequest {
                header: Some(header).into(),
                ..Default::default()
            }.encode_to_vec(),
            _ => panic!("unsupported lifecycle fixture protocol"),
        };
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
        let admit = match role {
            BrokerSessionDurableEndpointV1::Client => prepare_client_sent_authenticated_broker_method_request_v1,
            BrokerSessionDurableEndpointV1::Broker => admit_server_received_authenticated_broker_method_request_v1,
        };
        let request = match admit(
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
                    body: match protocol {
                        BrokerSessionProtocolV1::Host => InventoryRuntimeResponse::default().encode_to_vec(),
                        BrokerSessionProtocolV1::Storage => InventoryStorageResourcesResponse {
                            kernel_boot_id: vec![1; 16],
                            broker_instance_id: vec![2; 16],
                            journal_sequence: 1,
                            catalog_generation: 1,
                            ..Default::default()
                        }.encode_to_vec(),
                        _ => panic!("unsupported lifecycle fixture protocol"),
                    },
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
            purpose: if recover { SessionPurpose::OperatorRecoverInventory } else { SessionPurpose::Ordinary },
            floor_currentness: None,
            floor_currentness_admission: None,
            floor_currentness_binding: None,
            client_retired_transcript: None,
            controller_initial_open: None, storage_host_open: None,
            floor_preparation: None,
            floor: tpm_floor::runtime::BrokerFloorV1::test_not_scoped(),
            journal: Some(native),
            captured_native_failure: None,
            floor_main: super::tpm_floor::StorageFloorMainArchiveV3::new(),
            session_replays: Default::default(),
            schema_original: None,
        storage_receiving_open: None,
            directory: journal_path,
            name: "session.journal".to_owned(),
            limits,
            // The real temporary writer belongs to the test UID. Selecting a
            // Broker protocol endpoint does not fabricate installed root-owned
            // Storage custody or its independently paid Native original.
            owner: JournalOwnerV1::ServiceClient(uid),
            endpoint: match role {
                BrokerSessionDurableEndpointV1::Client => ProtectedEndpointV1::Client(client),
                BrokerSessionDurableEndpointV1::Broker => ProtectedEndpointV1::Broker(broker),
            },
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
        let (currentness, committed) = match role {
            BrokerSessionDurableEndpointV1::Client => (Some(committed.into_currentness_owner()), None),
            BrokerSessionDurableEndpointV1::Broker => (None, Some(committed)),
        };
        Self {
            journal,
            currentness,
            committed,
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
