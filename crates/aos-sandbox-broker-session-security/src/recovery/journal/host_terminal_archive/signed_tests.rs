//! Signed Host-session fixtures for archive rollover and hostile replay.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerAuthorizationArtifactsV1, BrokerClientHello, BrokerMethod,
    BrokerRequestEnvelope, BrokerResponseEnvelope, BrokerServerHello, Feature,
    HostNoApplySettlementPhaseV2, ObserveHostExecutionArgumentRequestV1,
    QueryHostExecutionArgumentNoApplyRequestV1, RequestHeader, ReserveHostExecutionOutputRequestV1,
    SettleHostExecutionNoApplyRequestV2, TerminalHostExecutionArgumentNoApplyRequestV1,
    TerminalHostExecutionArgumentNoApplyResponseV1,
};
use aos_sandbox::Journal;
use aos_sandbox::controller_execution_preissue::ControllerExecutionReserveSourceV1;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionDurableHistoryV1, BrokerSessionDurableRecordV1,
    BrokerSessionKeyUsageV1, BrokerSessionOutcomeCompanionV1, BrokerSessionPeerBindingV1,
    BrokerSessionProtectedBindingsV1, BrokerSessionProtocolV1, BrokerSessionRequestCompanionV1,
    BrokerSessionSignerReferenceV1, BrokerSessionTrafficStateV1, VerifiedBrokerSessionTranscriptV1,
    decode_canonical_client_hello_v1, decode_canonical_request_v1, decode_canonical_response_v1,
    decode_canonical_server_hello_v1, maximum_broker_session_request_bytes_v1,
    verify_broker_session_transcript_v1,
};
use aos_sandbox_core::format::{
    descriptor_for_bytes, encode_broker_authorization_plan, encode_ownership_lease,
    encode_signature,
};
use aos_sandbox_core::model::{
    KeyReference, KeyUsage, Signature, SignatureBytes, SignaturePurpose, SignatureStatement,
    StableKeyId,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
    DesiredGeneration, IncarnationId, LeaseAssignment, MediaType, NodeId, ObjectDescriptor,
    ObjectDigest, OwnershipLease, PortableMediaType, ProtocolId, ProtocolVersion,
    RevocationScopeId, SandboxId, TrustScopeId,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodOutcomeV1,
    AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodRequestV1,
    admit_client_received_authenticated_broker_method_outcome_v1,
    admit_server_received_authenticated_broker_method_request_v1,
    authenticated_semantic_bindings_from_envelope_v1,
    prepare_client_sent_authenticated_broker_method_request_v1,
};
use aos_sandbox_protocol::host_execution_no_apply::{
    HostExecutionNoApplyRecordFieldsV1, HostExecutionNoApplyRecordV1,
    decode_host_no_apply_settlement_request_v2, match_archived_host_no_apply_outcome_v2,
    signed_host_no_apply_terminal_outcome_digest_v2,
};
use aos_sandbox_protocol::host_output::decode_host_output_reserve_request_v1;
use aos_sandbox_protocol::semantics::host_execution_argument::{
    host_execution_argument_no_apply_grant_v1, host_execution_argument_observe_grant_v1,
    host_execution_argument_query_no_apply_grant_v1,
};
use aos_sandbox_protocol::semantics::host_output_reserve_grant_v1;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use ed25519_dalek::SigningKey;
use rustix::time::{ClockId, clock_gettime};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

use super::super::{JournalOwnerV1, ProtectedEndpointV1};
use super::*;
use crate::endpoint::{ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1};
use crate::manifest::{
    BrokerSessionSecurityAudienceV1, BrokerSessionSecurityKeyPinV1, BrokerSessionSecurityManifestV1,
};
use crate::recovery::HistoricalSessionCheckpointV1;

const ORIGINAL_ID: [u8; 16] = [7; 16];
const TERMINAL_ID: [u8; 16] = [9; 16];
const QUERY_ID: [u8; 16] = [10; 16];
const RESPONSE_MAXIMUM: u32 = 8192;

struct Fixture {
    _temporary: TempDir,
    client_path: PathBuf,
    broker_path: PathBuf,
    journal_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let client_path = temporary.path().join("client");
        let broker_path = temporary.path().join("broker");
        let journal_path = temporary.path().join("journal");
        for path in [&client_path, &broker_path, &journal_path] {
            fs::create_dir(path).unwrap();
        }
        let (manifest, secrets) = manifest_and_secrets();
        write_protected(
            &client_path.join("broker-session-manifest"),
            &manifest.encode(),
        );
        write_protected(
            &broker_path.join("broker-session-manifest"),
            &manifest.encode(),
        );
        for (name, index) in [
            ("client-hello-signing-key", 0),
            ("client-record-signing-key", 2),
        ] {
            write_protected(&client_path.join(name), &secrets[index]);
        }
        for (name, index) in [
            ("broker-hello-signing-key", 1),
            ("broker-outcome-signing-key", 3),
        ] {
            write_protected(&broker_path.join(name), &secrets[index]);
        }
        fs::set_permissions(&client_path, fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(&broker_path, fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _temporary: temporary,
            client_path,
            broker_path,
            journal_path,
        }
    }

    fn client(&self) -> ProtectedBrokerSessionClientV1 {
        ProtectedBrokerSessionClientV1::load(&self.client_path).unwrap()
    }

    fn broker(&self) -> ProtectedBrokerSessionBrokerV1 {
        ProtectedBrokerSessionBrokerV1::load(&self.broker_path).unwrap()
    }
}

fn write_protected(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
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
        let byte = index as u8;
        let seed = [byte + 1; 32];
        let key_id = [0x50 + byte; 16];
        secrets[index][..16].copy_from_slice(&key_id);
        secrets[index][16..].copy_from_slice(&seed);
        let key = SigningKey::from_bytes(&seed);
        let signer = BrokerSessionSignerReferenceV1::for_signing_key(
            [0x30 + byte; 16],
            10 + index as u64,
            [0x40 + byte; 32],
            key_id,
            20 + index as u64,
            usages[index],
            &key,
        )
        .unwrap();
        BrokerSessionSecurityKeyPinV1::new(
            signer,
            key.verifying_key().to_bytes(),
            1,
            1,
            false,
            None,
        )
        .unwrap()
    });
    let manifest = BrokerSessionSecurityManifestV1::new(
        BrokerSessionProtocolV1::Host,
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
    .unwrap();
    (manifest, secrets)
}

fn feature(namespace: &str) -> Feature {
    Feature {
        namespace: namespace.to_owned(),
        major: 1,
        ..Default::default()
    }
}

fn session(
    client: &mut ProtectedBrokerSessionClientV1,
    broker: &mut ProtectedBrokerSessionBrokerV1,
    methods: &[BrokerMethod],
) -> (
    VerifiedBrokerSessionTranscriptV1,
    HistoricalSessionCheckpointV1,
) {
    let features = vec![
        feature("aos.sandbox.authentication.broker-session"),
        feature("aos.sandbox.authorization.signed-plan-lease"),
    ];
    let broker_process = broker.process_execution_id_bytes();
    let client_packet = client
        .finalize_client_hello(
            BrokerClientHello {
                protocol_major: 1,
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                required_features: features.clone(),
                maximum_response_bytes: 65_536,
                required_methods: methods.iter().copied().map(Into::into).collect(),
                ..Default::default()
            },
            broker_process,
        )
        .unwrap();
    let canonical_client = decode_canonical_client_hello_v1(&client_packet).unwrap();
    let broker_packet = broker
        .finalize_broker_hello(
            BrokerServerHello {
                protocol_major: 1,
                features,
                maximum_request_bytes: maximum_broker_session_request_bytes_v1(
                    BrokerSessionProtocolV1::Host,
                ) as u32,
                maximum_response_bytes: 65_536,
                methods: methods.iter().copied().map(Into::into).collect(),
                ..Default::default()
            },
            &canonical_client,
        )
        .unwrap();
    let canonical_broker = decode_canonical_server_hello_v1(&broker_packet).unwrap();
    let context = client.context_for_handshake(broker_process).unwrap();
    let transcript =
        verify_broker_session_transcript_v1(&canonical_client, &canonical_broker, &context)
            .unwrap();
    let checkpoint = HistoricalSessionCheckpointV1::new(
        context,
        &client_packet,
        &broker_packet,
        peer(),
        &transcript,
    )
    .unwrap();
    (transcript, checkpoint)
}

fn peer() -> PeerCredentials {
    PeerCredentials {
        uid: 0,
        gid: 0,
        pid: Some(9),
    }
}

fn policy() -> PeerPolicy {
    PeerPolicy {
        uid: 0,
        gid: Some(0),
        audience: Audience::AUDIENCE_NODE_CONTROLLER,
    }
}

fn header(request_id: [u8; 16]) -> RequestHeader {
    RequestHeader {
        protocol_major: 1,
        request_id: request_id.to_vec(),
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        deadline_boottime_nanoseconds: 100,
        maximum_response_bytes: RESPONSE_MAXIMUM,
        ..Default::default()
    }
}

fn current_boottime_nanoseconds() -> u64 {
    let now = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).unwrap();
    let nanoseconds = u64::try_from(now.tv_nsec).unwrap();
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .unwrap()
}

fn source() -> [u8; 336] {
    let mut source = [0; 336];
    source[..8].copy_from_slice(b"AOSCIA02");
    source[8..24].copy_from_slice(&[1; 16]);
    source[24..40].copy_from_slice(&[2; 16]);
    source[40..56].copy_from_slice(&ORIGINAL_ID);
    source[56..184].fill(3);
    source[184..216].copy_from_slice(&[5; 32]);
    source[216..248].fill(6);
    source[248..264].copy_from_slice(&[8; 16]);
    source[264..296].fill(9);
    source[296..304].copy_from_slice(&100_u64.to_be_bytes());
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
        .chain_update(&source[..304])
        .finalize();
    source[304..].copy_from_slice(&digest);
    source
}

fn output_source() -> [u8; 688] {
    let mut source = [0; 688];
    source[..8].copy_from_slice(b"AOSCIR01");
    source[8..16].copy_from_slice(b"AOSCIP01");
    source[16..32].copy_from_slice(&[1; 16]);
    source[32..48].copy_from_slice(&[2; 16]);
    source[48..80].fill(3);
    source[80..88].copy_from_slice(&5_u64.to_be_bytes());
    source[88..96].copy_from_slice(&7_u64.to_be_bytes());
    source[96..104].copy_from_slice(&9_u64.to_be_bytes());
    source[104..120].fill(8);
    source[120..128].copy_from_slice(&100_u64.to_be_bytes());
    source[128..160].fill(9);
    let preissue_digest = Sha256::new()
        .chain_update(b"aos.sandbox.controller-execution-preissue.v1\0")
        .chain_update(&source[8..160])
        .finalize();
    source[160..192].copy_from_slice(&preissue_digest);

    source[192..200].copy_from_slice(b"AOSEOR02");
    source[200..216].copy_from_slice(&[1; 16]);
    source[216..232].copy_from_slice(&[2; 16]);
    for (offset, value) in [(232, 1), (264, 2), (328, 3), (360, 4), (392, 5), (456, 6)] {
        source[offset..offset + 32].fill(value);
    }
    source[296..328].fill(5);
    source[424..432].copy_from_slice(&12_u64.to_be_bytes());
    source[432..440].copy_from_slice(&20_u64.to_be_bytes());
    source[440..448].copy_from_slice(&5_u64.to_be_bytes());
    source[448..456].copy_from_slice(&7_u64.to_be_bytes());
    let claim_digest = Sha256::digest(&source[192..488]);
    source[488..520].copy_from_slice(&claim_digest);

    source[520..552].fill(7);
    source[552..568].fill(1);
    source[568..584].fill(2);
    source[584..600].fill(7);
    source[600..608].copy_from_slice(&3_u64.to_be_bytes());
    source[608..616].copy_from_slice(&4_u64.to_be_bytes());
    source[616..624].copy_from_slice(&13_u64.to_be_bytes());
    source[624..656].fill(5);
    let carrier_digest = Sha256::new()
        .chain_update(b"aos.sandbox.controller-execution-reserve-source.v1\0")
        .chain_update(&source[..656])
        .finalize();
    source[656..688].copy_from_slice(&carrier_digest);
    source
}

fn authorization_key(name: &str, usage: KeyUsage, byte: u8) -> KeyReference {
    KeyReference::new(
        StableKeyId::new(name.to_owned()).unwrap(),
        1,
        ObjectDigest::from_bytes([byte; 32]),
        usage,
    )
}

fn artifact_signature(
    kind: PortableMediaType,
    bytes: &[u8],
    signer: KeyReference,
    purpose: SignaturePurpose,
) -> Vec<u8> {
    // Only the broker-session packet signatures are authenticated here. These
    // canonical plan/lease artifacts exercise transport structure, not a
    // Controller grant or Host owner authority decision.
    let subject = descriptor_for_bytes(MediaType::new(kind.as_str().to_owned()).unwrap(), bytes);
    let policy = ObjectDescriptor::new(
        MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
        ObjectDigest::from_bytes([14; 32]),
        1,
    );
    let statement = SignatureStatement::new(
        subject,
        TrustScopeId::from_bytes([21; 16]),
        signer,
        purpose,
        1,
        Some(200),
        policy,
    )
    .unwrap();
    encode_signature(&Signature::new(statement, SignatureBytes::new([22; 64])))
}

fn authorization_artifacts(
    method: BrokerMethod,
    request_id: [u8; 16],
    canonical_source: &[u8],
    original_session_binding: [u8; 32],
    original_signed_request_digest: [u8; 32],
) -> BrokerAuthorizationArtifactsV1 {
    let assignment = BrokerAssignment::new(
        SandboxId::from_bytes([1; 16]),
        IncarnationId::from_bytes([2; 16]),
        AssignmentEpoch::new(3),
        DesiredGeneration::new(4),
        ObjectDigest::from_bytes([5; 32]),
    )
    .unwrap();
    let (verb, target, commitment) = match method {
        BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT => {
            let semantics =
                host_output_reserve_grant_v1(assignment, request_id, canonical_source).unwrap();
            (semantics.verb(), semantics.target(), semantics.commitment())
        }
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT => {
            let semantics =
                host_execution_argument_observe_grant_v1(assignment, request_id, canonical_source)
                    .unwrap();
            (semantics.verb(), semantics.target(), semantics.commitment())
        }
        BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY => {
            let semantics = host_execution_argument_no_apply_grant_v1(
                assignment,
                request_id,
                canonical_source,
                original_session_binding,
                original_signed_request_digest,
            )
            .unwrap();
            (semantics.verb(), semantics.target(), semantics.commitment())
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY => {
            let semantics = host_execution_argument_query_no_apply_grant_v1(
                assignment,
                request_id,
                canonical_source,
                original_session_binding,
                original_signed_request_digest,
            )
            .unwrap();
            (semantics.verb(), semantics.target(), semantics.commitment())
        }
        _ => panic!("unexpected Host method"),
    };
    let authority = authorization_key("ownership-authority", KeyUsage::OwnershipLease, 6);
    let grant = BrokerGrant::new(verb, target, commitment, 4 * 1024, 0).unwrap();
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Host,
        ProtocolId::HostBroker,
        ProtocolVersion::new(1, 0),
        assignment,
        NodeId::from_bytes([7; 16]),
        authority.clone(),
        vec![grant],
        ObjectDigest::from_bytes([8; 32]),
        RevocationScopeId::from_bytes([9; 16]),
        1,
        200,
        Vec::new(),
    )
    .unwrap();
    let broker_plan = encode_broker_authorization_plan(&plan);
    let broker_plan_signature = artifact_signature(
        PortableMediaType::BrokerAuthorizationPlan,
        &broker_plan,
        authorization_key("broker-controller", KeyUsage::BrokerAuthorization, 10),
        SignaturePurpose::BrokerAuthorization,
    );
    let lease = OwnershipLease::new(
        LeaseAssignment::new(
            assignment.sandbox(),
            assignment.incarnation(),
            assignment.epoch(),
            assignment.digest(),
        )
        .unwrap(),
        NodeId::from_bytes([7; 16]),
        1,
        1,
        200,
        10,
        [12; 16],
    )
    .unwrap();
    let ownership_lease = encode_ownership_lease(&lease);
    let ownership_lease_signature = artifact_signature(
        PortableMediaType::OwnershipLease,
        &ownership_lease,
        authority,
        SignaturePurpose::OwnershipLease,
    );
    BrokerAuthorizationArtifactsV1 {
        broker_plan,
        broker_plan_signature,
        ownership_lease,
        ownership_lease_signature,
        ..Default::default()
    }
}

fn signed_request(
    client: &mut ProtectedBrokerSessionClientV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    checkpoint: &HistoricalSessionCheckpointV1,
    method: BrokerMethod,
    request_id: [u8; 16],
    body: Vec<u8>,
    canonical_source: &[u8],
    original_session_binding: [u8; 32],
    original_signed_request_digest: [u8; 32],
) -> (
    AuthenticatedBrokerMethodRequestV1,
    Box<BrokerSessionTrafficStateV1>,
) {
    let packet = client
        .finalize_method_request(
            BrokerRequestEnvelope {
                method: method.into(),
                body,
                authorization: Some(authorization_artifacts(
                    method,
                    request_id,
                    canonical_source,
                    original_session_binding,
                    original_signed_request_digest,
                ))
                .into(),
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
    match prepare_client_sent_authenticated_broker_method_request_v1(
        &prior,
        &packet,
        None,
        0,
        peer(),
        policy(),
        99,
        bindings,
        checkpoint.context(),
    )
    .unwrap()
    {
        AuthenticatedBrokerMethodRequestAdmissionV1::New {
            request,
            next_traffic,
        } => (request, next_traffic),
        AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
            panic!("new request replayed")
        }
    }
}

fn signed_outcome(
    broker: &mut ProtectedBrokerSessionBrokerV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    checkpoint: &HistoricalSessionCheckpointV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    pending: &BrokerSessionTrafficStateV1,
    body: Vec<u8>,
) -> AuthenticatedBrokerMethodOutcomeV1 {
    let packet = broker
        .finalize_method_outcome(
            BrokerResponseEnvelope {
                request_id: request.request_id().to_vec(),
                method: request.method().into(),
                body,
                ..Default::default()
            },
            request.method(),
            transcript.session_binding(),
            broker.process_execution_id_bytes(),
            1,
            request.request_id(),
            request.signed_request_digest(),
        )
        .unwrap();
    let canonical = decode_canonical_response_v1(&packet).unwrap();
    match admit_client_received_authenticated_broker_method_outcome_v1(
        pending,
        request,
        &packet,
        None,
        canonical.message().descriptors.len(),
        checkpoint.context(),
    )
    .unwrap()
    {
        AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. } => outcome,
        AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(_) => {
            panic!("new outcome replayed")
        }
    }
}

fn stored(
    journal: &mut ProtectedBrokerSessionJournalV1,
    checkpoint: HistoricalSessionCheckpointV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    outcome: Option<&AuthenticatedBrokerMethodOutcomeV1>,
    generation: u64,
) -> StoredProtocolHistoryV1 {
    let publication = journal
        .endpoint_publication(BrokerSessionProtocolV1::Host)
        .unwrap();
    let catalog = request.semantic_commitment();
    let bindings = BrokerSessionProtectedBindingsV1::new(
        checkpoint.context().protected_context_digest(),
        publication,
        catalog,
    )
    .unwrap();
    let packet = request.canonical_packet();
    let signed = decode_canonical_request_v1(packet)
        .unwrap()
        .signed_artifact()
        .clone();
    let companion = BrokerSessionRequestCompanionV1::try_from_parts(
        BrokerSessionProtocolV1::Host,
        request.method(),
        request.deadline_boottime_nanoseconds(),
        RESPONSE_MAXIMUM,
        signed,
    )
    .unwrap();
    let prepared = BrokerSessionDurableRecordV1::new_request(
        1,
        [0; 32],
        BrokerSessionDurableEndpointV1::Client,
        request.session_binding(),
        BrokerSessionPeerBindingV1::new([11; 32]).unwrap(),
        bindings,
        catalog,
        request.request_id(),
        companion,
        packet.to_vec(),
    )
    .unwrap();
    let mut records = vec![prepared.clone()];
    if let Some(outcome) = outcome {
        let signed_outcome = decode_canonical_response_v1(outcome.canonical_packet())
            .unwrap()
            .signed_artifact()
            .clone();
        let companion = BrokerSessionOutcomeCompanionV1::try_from_parts(
            BrokerSessionProtocolV1::Host,
            request.method(),
            request.request_id(),
            1,
            RESPONSE_MAXIMUM,
            request.signed_request_digest(),
            signed_outcome,
        )
        .unwrap();
        let terminal = prepared
            .with_terminal_outcome(
                2,
                prepared.commitment().unwrap(),
                bindings,
                outcome.semantic_commitment(),
                companion,
                outcome.canonical_packet().to_vec(),
            )
            .unwrap();
        records.push(terminal);
    }
    let history = BrokerSessionDurableHistoryV1::from_records(records).unwrap();
    StoredProtocolHistoryV1 {
        protocol: BrokerSessionProtocolV1::Host,
        endpoint: BrokerSessionDurableEndpointV1::Client,
        generation,
        stable_endpoint_identity: journal
            .stable_endpoint_identity(BrokerSessionProtocolV1::Host)
            .unwrap(),
        endpoint_publication: publication,
        current_catalog: catalog,
        current_head: history.head_commitment(),
        history: history.encode().unwrap(),
        checkpoint: Some(checkpoint),
    }
}

fn marker(
    original: &AuthenticatedBrokerMethodRequestV1,
    terminal: &AuthenticatedBrokerMethodRequestV1,
    source: &[u8; 336],
) -> HostExecutionNoApplyRecordV1 {
    HostExecutionNoApplyRecordV1::new(HostExecutionNoApplyRecordFieldsV1 {
        execution_id: [1; 16],
        create_operation_id: [2; 16],
        original_request_id: ORIGINAL_ID,
        terminal_request_id: terminal.request_id(),
        host_boot_id: [8; 16],
        assignment_digest: [5; 32],
        source_record_digest: source[304..336].try_into().unwrap(),
        original_session_binding: original.session_binding(),
        original_signed_request_digest: original.signed_request_digest(),
        terminal_session_binding: terminal.session_binding(),
        terminal_signed_request_digest: terminal.signed_request_digest(),
        runtime_handle: [16; 32],
        execution_store_binding: [17; 32],
        commit_sequence: 18,
    })
    .unwrap()
}

fn open_test_journal(
    client: ProtectedBrokerSessionClientV1,
    directory: &Path,
) -> ProtectedBrokerSessionJournalV1 {
    // The fixture preserves final-directory/file checks but cannot satisfy
    // production root ancestry inside a caller-owned temporary directory.
    let limits = super::super::protected_session_journal_limits();
    let uid = fs::metadata(directory).unwrap().uid();
    let (journal, _) =
        Journal::open_protected_at_uid(directory, "session.journal", limits, uid).unwrap();
    let mut owner = ProtectedBrokerSessionJournalV1 {
        journal: Some(journal),
        directory: directory.to_path_buf(),
        name: "session.journal".to_owned(),
        limits,
        owner: JournalOwnerV1::capture(BrokerSessionDurableEndpointV1::Client),
        endpoint: ProtectedEndpointV1::Client(client),
    };
    owner.validate_all().unwrap();
    owner
}

#[test]
fn signed_method35_packet_replays_without_proving_protected_output_custody() {
    // Only the broker-session packet signer is authenticated here. The test
    // artifacts are not verified Host plan/lease authority or an AOSEOR02 append.
    let fixture = Fixture::new();
    let mut client = fixture.client();
    let mut broker = fixture.broker();
    let method = BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT;
    let (session, checkpoint) = session(&mut client, &mut broker, &[method]);
    let source = output_source();
    ControllerExecutionReserveSourceV1::decode_structural(&source).unwrap();
    let request_id = [6; 16];
    let body = ReserveHostExecutionOutputRequestV1 {
        header: Some(header(request_id)).into(),
        canonical_source: source.to_vec(),
        ..Default::default()
    }
    .encode_to_vec();
    let (sent, _) = signed_request(
        &mut client,
        &session,
        &checkpoint,
        method,
        request_id,
        body.clone(),
        &source,
        [0; 32],
        [0; 32],
    );

    let packet = sent.canonical_packet();
    let canonical = decode_canonical_request_v1(packet).unwrap();
    let bindings =
        authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method).unwrap();
    let traffic = BrokerSessionTrafficStateV1::from_provisional_transcript(session).unwrap();
    let (received, next_traffic) =
        match admit_server_received_authenticated_broker_method_request_v1(
            &traffic,
            packet,
            None,
            0,
            peer(),
            policy(),
            99,
            bindings,
            checkpoint.context(),
        )
        .unwrap()
        {
            AuthenticatedBrokerMethodRequestAdmissionV1::New {
                request,
                next_traffic,
            } => (request, next_traffic),
            AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
                panic!("fresh method-35 packet replayed")
            }
        };
    assert_eq!(received.canonical_packet(), packet);
    assert_eq!(received.exact_body(), body);
    assert!(received.authorization().is_some());
    let decoded = decode_host_output_reserve_request_v1(
        received.exact_body(),
        received.peer(),
        received.peer_policy(),
        99,
    )
    .unwrap();
    assert_eq!(decoded.source(), &source);

    assert!(matches!(
        admit_server_received_authenticated_broker_method_request_v1(
            &next_traffic,
            packet,
            Some(&received),
            0,
            peer(),
            policy(),
            99,
            bindings,
            checkpoint.context(),
        ),
        Ok(AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_))
    ));
    let mut tampered = packet.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        admit_server_received_authenticated_broker_method_request_v1(
            &traffic,
            &tampered,
            None,
            0,
            peer(),
            policy(),
            99,
            bindings,
            checkpoint.context(),
        )
        .is_err()
    );
}

#[test]
fn signed_method37_to_method42_preliminary_request_survives_archive_rollover() {
    let fixture = Fixture::new();
    let mut client = fixture.client();
    let mut broker = fixture.broker();
    let source = source();
    let methods = [
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT,
        BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY,
    ];
    let (original_session, original_checkpoint) = session(&mut client, &mut broker, &methods);
    let (original, _) = signed_request(
        &mut client,
        &original_session,
        &original_checkpoint,
        methods[0],
        ORIGINAL_ID,
        ObserveHostExecutionArgumentRequestV1 {
            header: Some(header(ORIGINAL_ID)).into(),
            canonical_attempt: source.to_vec(),
            ..Default::default()
        }
        .encode_to_vec(),
        &source,
        [0; 32],
        [0; 32],
    );
    let (terminal_session, terminal_checkpoint) = session(&mut client, &mut broker, &methods);
    assert_ne!(
        original_session.session_binding(),
        terminal_session.session_binding()
    );
    let (terminal, pending) = signed_request(
        &mut client,
        &terminal_session,
        &terminal_checkpoint,
        methods[1],
        TERMINAL_ID,
        TerminalHostExecutionArgumentNoApplyRequestV1 {
            header: Some(header(TERMINAL_ID)).into(),
            canonical_attempt: source.to_vec(),
            original_session_binding: original.session_binding().to_vec(),
            original_signed_request_digest: original.signed_request_digest().to_vec(),
            ..Default::default()
        }
        .encode_to_vec(),
        &source,
        original.session_binding(),
        original.signed_request_digest(),
    );
    let marker = marker(&original, &terminal, &source);
    let terminal_outcome = signed_outcome(
        &mut broker,
        &terminal_session,
        &terminal_checkpoint,
        &terminal,
        &pending,
        TerminalHostExecutionArgumentNoApplyResponseV1 {
            canonical_record: marker.encode_canonical().to_vec(),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let mut hostile_fields = marker.fields();
    hostile_fields.original_signed_request_digest = [44; 32];
    let hostile_marker = HostExecutionNoApplyRecordV1::new(hostile_fields).unwrap();
    let hostile_packet = broker
        .finalize_method_outcome(
            BrokerResponseEnvelope {
                request_id: TERMINAL_ID.to_vec(),
                method: methods[1].into(),
                body: TerminalHostExecutionArgumentNoApplyResponseV1 {
                    canonical_record: hostile_marker.encode_canonical().to_vec(),
                    ..Default::default()
                }
                .encode_to_vec(),
                ..Default::default()
            },
            methods[1],
            terminal_session.session_binding(),
            broker.process_execution_id_bytes(),
            1,
            TERMINAL_ID,
            terminal.signed_request_digest(),
        )
        .unwrap();
    assert!(
        admit_client_received_authenticated_broker_method_outcome_v1(
            &pending,
            &terminal,
            &hostile_packet,
            None,
            0,
            terminal_checkpoint.context(),
        )
        .is_err()
    );
    let (successor_session, successor_checkpoint) = session(&mut client, &mut broker, &methods);
    assert_ne!(
        terminal_session.session_binding(),
        successor_session.session_binding()
    );
    let (successor, _) = signed_request(
        &mut client,
        &successor_session,
        &successor_checkpoint,
        methods[2],
        QUERY_ID,
        QueryHostExecutionArgumentNoApplyRequestV1 {
            header: Some(header(QUERY_ID)).into(),
            canonical_attempt: source.to_vec(),
            original_session_binding: original.session_binding().to_vec(),
            original_signed_request_digest: original.signed_request_digest().to_vec(),
            ..Default::default()
        }
        .encode_to_vec(),
        &source,
        original.session_binding(),
        original.signed_request_digest(),
    );

    let mut journal = open_test_journal(client, &fixture.journal_path);
    let original_stored = stored(&mut journal, original_checkpoint, &original, None, 1);
    journal.commit_stored(&original_stored).unwrap();
    let terminal_stored = stored(
        &mut journal,
        terminal_checkpoint,
        &terminal,
        Some(&terminal_outcome),
        2,
    );
    journal.commit_stored(&terminal_stored).unwrap();
    assert!(journal.commit_stored(&terminal_stored).is_err());
    let successor_stored = stored(&mut journal, successor_checkpoint, &successor, None, 3);
    journal.commit_stored(&successor_stored).unwrap();
    drop(journal);

    let reopened_client = fixture.client();
    let mut reopened = open_test_journal(reopened_client, &fixture.journal_path);
    let joined = reopened
        .read_host_terminal_archive(ORIGINAL_ID)
        .unwrap()
        .unwrap();
    assert_eq!(joined.original().source().canonical_bytes(), source);
    assert_eq!(joined.no_apply_record(), marker);
    assert_eq!(
        joined.no_apply_outcome().canonical_packet(),
        terminal_outcome.canonical_packet()
    );
    drop(reopened);

    // The new session authenticates Controller's H/T assertions, but cannot
    // by itself prove that Host still holds the marker or append AOSCHA01.
    let mut settlement_client = fixture.client();
    let method = BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2;
    let (settlement_session, settlement_checkpoint) =
        session(&mut settlement_client, &mut broker, &[method]);
    let now = current_boottime_nanoseconds();
    let deadline = now.checked_add(30_000_000_000).unwrap();
    let request_id = [21; 16];
    let body = SettleHostExecutionNoApplyRequestV2 {
        header: Some(RequestHeader {
            deadline_boottime_nanoseconds: deadline,
            ..header(request_id)
        })
        .into(),
        canonical_attempt: source.to_vec(),
        original_session_binding: joined.original().request().session_binding().to_vec(),
        original_signed_request_digest: joined
            .original()
            .request()
            .signed_request_digest()
            .to_vec(),
        archive_head: joined.original().archive_head().to_vec(),
        signed_terminal_outcome: signed_host_no_apply_terminal_outcome_digest_v2(
            joined.no_apply_outcome(),
        )
        .as_bytes()
        .to_vec(),
        phase: HostNoApplySettlementPhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_PRELIMINARY.into(),
        challenge: request_id.to_vec(),
        ..Default::default()
    };
    let envelope = BrokerRequestEnvelope {
        method: method.into(),
        body: body.encode_to_vec(),
        ..Default::default()
    };
    let packet = settlement_client
        .finalize_method_request(
            envelope.clone(),
            method,
            settlement_session.session_binding(),
            settlement_client.process_execution_id_bytes(),
            1,
            request_id,
        )
        .unwrap();
    let canonical = decode_canonical_request_v1(&packet).unwrap();
    let bindings =
        authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method).unwrap();
    let traffic =
        BrokerSessionTrafficStateV1::from_provisional_transcript(settlement_session.clone())
            .unwrap();
    let (admitted, next_traffic) =
        match admit_server_received_authenticated_broker_method_request_v1(
            &traffic,
            &packet,
            None,
            0,
            peer(),
            policy(),
            now,
            bindings,
            settlement_checkpoint.context(),
        )
        .unwrap()
        {
            AuthenticatedBrokerMethodRequestAdmissionV1::New {
                request,
                next_traffic,
            } => (request, next_traffic),
            AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
                panic!("new settlement request replayed")
            }
        };
    assert!(admitted.authorization().is_none());
    assert_eq!(admitted.canonical_packet(), packet);
    let decoded = decode_host_no_apply_settlement_request_v2(
        admitted.exact_body(),
        admitted.peer(),
        admitted.peer_policy(),
        now,
    )
    .unwrap();
    assert_eq!(
        match_archived_host_no_apply_outcome_v2(
            &decoded,
            ObjectDigest::from_bytes(joined.original().archive_head()),
            joined.no_apply_outcome(),
        )
        .unwrap(),
        marker
    );

    assert!(matches!(
        admit_server_received_authenticated_broker_method_request_v1(
            &next_traffic,
            &packet,
            Some(&admitted),
            0,
            peer(),
            policy(),
            deadline + 1,
            bindings,
            settlement_checkpoint.context(),
        ),
        Ok(AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_))
    ));
    assert!(
        admit_server_received_authenticated_broker_method_request_v1(
            &traffic,
            &packet,
            None,
            0,
            peer(),
            policy(),
            deadline,
            bindings,
            settlement_checkpoint.context(),
        )
        .is_err()
    );

    let mut foreign_body = body;
    foreign_body.archive_head[0] ^= 1;
    let foreign_packet = settlement_client
        .finalize_method_request(
            BrokerRequestEnvelope {
                body: foreign_body.encode_to_vec(),
                ..envelope
            },
            method,
            settlement_session.session_binding(),
            settlement_client.process_execution_id_bytes(),
            1,
            request_id,
        )
        .unwrap();
    assert!(
        admit_server_received_authenticated_broker_method_request_v1(
            &next_traffic,
            &foreign_packet,
            Some(&admitted),
            0,
            peer(),
            policy(),
            now,
            bindings,
            settlement_checkpoint.context(),
        )
        .is_err()
    );
}
