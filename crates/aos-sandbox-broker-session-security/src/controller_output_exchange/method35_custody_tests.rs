//! Normal signed Host method-35 custody through the protected output owner.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_proto::aos::sandbox::local::v1::{
    ApplyRuntimeRequest, AssignmentFence, Audience, BrokerAuthorizationArtifactsV1,
    BrokerClientHello, BrokerMethod, BrokerRequestEnvelope, BrokerResponseEnvelope,
    BrokerServerHello, Feature, ObserveHostStorageOutputRequestV1, RequestHeader,
    ReserveHostExecutionOutputRequestV1, ReserveStorageExecutionOutputRequestV1, RuntimeAction,
};
use aos_sandbox::controller_execution_preissue::ControllerExecutionReserveSourceV1;
use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionOwnerV1, ProtectedHostOutputReservationV1,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, BrokerSessionTrafficStateV1, VerifiedBrokerSessionTranscriptV1,
    decode_canonical_client_hello_v1, decode_canonical_request_v1,
    decode_canonical_server_hello_v1, maximum_broker_session_request_bytes_v1,
    verify_broker_session_transcript_v1,
};
use aos_sandbox_core::format::{
    encode_broker_authorization_plan, encode_ownership_lease, encode_signature, encode_trust_policy,
};
use aos_sandbox_core::model::{
    KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
    BrokerPlanTrustAnchor, DecodeLimits, DesiredGeneration, IncarnationId, LeaseAssignment,
    MediaType, NodeId, ObjectDescriptor, ObjectDigest, OwnershipLease, OwnershipLeaseTrustAnchor,
    PortableMediaType, ProtocolId, ProtocolVersion, RawClockProvenance, RawPairedClockSample,
    RevocationScopeId, SandboxId, TrustScopeId, descriptor_for_bytes, sign_statement,
};
use aos_sandbox_host::authorization::HostAuthorityV1;
use aos_sandbox_host::authorization::semantics_v1::canonical_host_semantics_v1;
use aos_sandbox_host::broker::HostBroker;
use aos_sandbox_host::plan::{HostCatalog, ResolvedLaunchResources};
use aos_sandbox_host::state::FileHostStateStore;
use aos_sandbox_host::worker::{
    HostRuntimeIdentity, HostWorker, ObservedRuntimeState, PinnedLeader, PinnedPayloadLeader,
    WorkerObservation, WorkerOperation,
};
use aos_sandbox_host::{
    DormantHostBrokerCallsiteV1, DormantHostBrokerCompositionV1, HostError, Result as HostResult,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodRequestAdmissionV1,
    AuthenticatedBrokerMethodRequestV1,
    admit_server_received_authenticated_broker_method_request_v1,
    authenticated_semantic_bindings_from_envelope_v1,
    prepare_server_sent_authenticated_broker_method_outcome_v1,
};
use aos_sandbox_protocol::host_storage_output_readback::{
    decode_host_storage_output_readback_request_v1,
    decode_host_storage_output_readback_response_v1, host_storage_output_readback_grant_v1,
};
use aos_sandbox_protocol::semantics::host_output_reserve_grant_v1;
use aos_sandbox_protocol::session::decode_request_envelope;
use aos_sandbox_protocol::storage_output_reserve::{
    StorageOutputReserveRecordsV1, storage_output_reserve_grant_v1,
};
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ValidatedAssignmentFence, ValidatedRuntimePlan,
    decode_runtime_request,
};
use async_trait::async_trait;
use buffa::Message as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

use crate::endpoint::{ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1};
use crate::host_execution_handoff::dispatch_host_storage_output_with_claim_for_test_v1;
use crate::test_signed_endpoint::{
    TestEndpointRole, install_endpoint, manifest_and_secrets, manifest_and_secrets_for_audience,
};

const ASSIGNMENT_DIGEST: [u8; 32] = [5; 32];
const NODE: NodeId = NodeId::from_bytes([3; 16]);
const BASE_REQUEST_ID: [u8; 16] = [33; 16];
const RESERVE_REQUEST_ID: [u8; 16] = [35; 16];
const STORAGE_RESERVE_REQUEST_ID: [u8; 16] = [46; 16];
const HOST_READBACK_REQUEST_ID: [u8; 16] = [48; 16];

struct EndpointCleanup<'a>(&'a Path, &'a Path);

impl Drop for EndpointCleanup<'_> {
    fn drop(&mut self) {
        for directory in [self.0, self.1] {
            let _ = fs::set_permissions(directory, fs::Permissions::from_mode(0o700));
        }
    }
}

struct NoCatalog;

impl HostCatalog for NoCatalog {
    fn resolve(
        &self,
        _fence: &ValidatedAssignmentFence,
        _plan: &ValidatedRuntimePlan,
    ) -> HostResult<ResolvedLaunchResources> {
        Err(HostError::Catalog(
            "fixture has no launch resources".to_owned(),
        ))
    }
}

struct FreezeWorker;

#[async_trait]
impl HostWorker for FreezeWorker {
    async fn execute(
        &self,
        _fence: &ValidatedAssignmentFence,
        operation: WorkerOperation,
        before_effect: &mut (dyn FnMut() -> HostResult<()> + Send),
    ) -> HostResult<WorkerObservation> {
        assert!(matches!(operation, WorkerOperation::Freeze));
        before_effect()?;
        Ok(WorkerObservation {
            state: ObservedRuntimeState::Frozen,
            invocation_id: None,
            leader: None,
            payload: None,
        })
    }

    async fn observe(&self, _identity: &HostRuntimeIdentity) -> HostResult<WorkerObservation> {
        Err(HostError::Worker("fixture has no observation".to_owned()))
    }

    async fn refresh_payload_scope(
        &self,
        _identity: &HostRuntimeIdentity,
        _invocation_id: [u8; 16],
        _supervisor: &PinnedLeader,
        _payload: &PinnedPayloadLeader,
    ) -> HostResult<WorkerObservation> {
        Err(HostError::Worker("fixture has no payload".to_owned()))
    }
}

struct SignedHostAuthority {
    plan_key: SigningKey,
    lease_key: SigningKey,
    plan_signer: KeyReference,
    lease_signer: KeyReference,
    plan_policy: Vec<u8>,
    lease_policy: Vec<u8>,
    plan_policy_descriptor: ObjectDescriptor,
    lease_policy_descriptor: ObjectDescriptor,
    plan_scope: TrustScopeId,
    lease_scope: TrustScopeId,
    revocation_scope: RevocationScopeId,
    issued_at: i64,
    expires_at: i64,
}

impl SignedHostAuthority {
    fn new(wall_seconds: i64) -> Self {
        let plan_key = SigningKey::from_bytes(&[41; 32]);
        let lease_key = SigningKey::from_bytes(&[42; 32]);
        let plan_signer = key_reference("method35-plan", KeyUsage::BrokerAuthorization, &plan_key);
        let lease_signer = key_reference("method35-lease", KeyUsage::OwnershipLease, &lease_key);
        let plan_scope = TrustScopeId::from_bytes([43; 16]);
        let lease_scope = TrustScopeId::from_bytes([44; 16]);
        let (plan_policy, plan_policy_descriptor) = policy(
            plan_scope,
            SignaturePurpose::BrokerAuthorization,
            plan_signer.clone(),
        );
        let (lease_policy, lease_policy_descriptor) = policy(
            lease_scope,
            SignaturePurpose::OwnershipLease,
            lease_signer.clone(),
        );
        Self {
            plan_key,
            lease_key,
            plan_signer,
            lease_signer,
            plan_policy,
            lease_policy,
            plan_policy_descriptor,
            lease_policy_descriptor,
            plan_scope,
            lease_scope,
            revocation_scope: RevocationScopeId::from_bytes([45; 16]),
            issued_at: wall_seconds - 60,
            expires_at: wall_seconds + 300,
        }
    }

    fn authority(&self) -> HostAuthorityV1 {
        let plan_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
            self.plan_policy.clone(),
            self.plan_policy_descriptor.clone(),
            self.plan_scope,
            self.plan_signer.clone(),
            self.plan_key.verifying_key().to_bytes(),
            self.revocation_scope,
            DecodeLimits::default(),
        )
        .unwrap();
        let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            self.lease_policy.clone(),
            self.lease_policy_descriptor.clone(),
            self.lease_scope,
            self.lease_signer.clone(),
            self.lease_key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )
        .unwrap();
        HostAuthorityV1::new(plan_anchor, lease_anchor, NODE, [46; 16], [47; 32]).unwrap()
    }

    fn artifacts(
        &self,
        grant: BrokerGrant,
        lease_generation: u64,
    ) -> BrokerAuthorizationArtifactsV1 {
        let assignment = assignment();
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Host,
            ProtocolId::HostBroker,
            ProtocolVersion::new(1, 0),
            assignment,
            NODE,
            self.lease_signer.clone(),
            vec![grant],
            ObjectDigest::from_bytes([48; 32]),
            self.revocation_scope,
            self.issued_at,
            self.expires_at,
            Vec::new(),
        )
        .unwrap();
        let broker_plan = encode_broker_authorization_plan(&plan);
        let broker_plan_signature = self.signature(
            &broker_plan,
            PortableMediaType::BrokerAuthorizationPlan,
            self.plan_scope,
            self.plan_signer.clone(),
            SignaturePurpose::BrokerAuthorization,
            &self.plan_policy_descriptor,
            &self.plan_key,
        );
        let lease = OwnershipLease::new(
            LeaseAssignment::new(
                assignment.sandbox(),
                assignment.incarnation(),
                assignment.epoch(),
                assignment.digest(),
            )
            .unwrap(),
            NODE,
            lease_generation,
            self.issued_at,
            self.expires_at,
            10,
            [u8::try_from(lease_generation).unwrap(); 16],
        )
        .unwrap();
        let ownership_lease = encode_ownership_lease(&lease);
        let ownership_lease_signature = self.signature(
            &ownership_lease,
            PortableMediaType::OwnershipLease,
            self.lease_scope,
            self.lease_signer.clone(),
            SignaturePurpose::OwnershipLease,
            &self.lease_policy_descriptor,
            &self.lease_key,
        );
        BrokerAuthorizationArtifactsV1 {
            broker_plan,
            broker_plan_signature,
            ownership_lease,
            ownership_lease_signature,
            ..Default::default()
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn signature(
        &self,
        bytes: &[u8],
        media_type: PortableMediaType,
        scope: TrustScopeId,
        signer: KeyReference,
        purpose: SignaturePurpose,
        policy: &ObjectDescriptor,
        key: &SigningKey,
    ) -> Vec<u8> {
        let subject = descriptor_for_bytes(
            MediaType::new(media_type.as_str().to_owned()).unwrap(),
            bytes,
        );
        let statement = SignatureStatement::new(
            subject,
            scope,
            signer,
            purpose,
            self.issued_at,
            Some(self.expires_at),
            policy.clone(),
        )
        .unwrap();
        encode_signature(&sign_statement(statement, key).unwrap())
    }
}

fn key_reference(id: &str, usage: KeyUsage, key: &SigningKey) -> KeyReference {
    KeyReference::new(
        StableKeyId::new(id.to_owned()).unwrap(),
        1,
        ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
        usage,
    )
}

fn policy(
    scope: TrustScopeId,
    purpose: SignaturePurpose,
    signer: KeyReference,
) -> (Vec<u8>, ObjectDescriptor) {
    let bytes =
        encode_trust_policy(&TrustPolicy::new(scope, purpose, vec![signer], Vec::new()).unwrap());
    let descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
        &bytes,
    );
    (bytes, descriptor)
}

fn assignment() -> BrokerAssignment {
    BrokerAssignment::new(
        SandboxId::from_bytes([1; 16]),
        IncarnationId::from_bytes([2; 16]),
        AssignmentEpoch::new(4),
        DesiredGeneration::new(6),
        ObjectDigest::from_bytes(ASSIGNMENT_DIGEST),
    )
    .unwrap()
}

fn peer() -> PeerCredentials {
    PeerCredentials {
        uid: 0,
        gid: 0,
        pid: Some(9),
    }
}

fn peer_policy() -> PeerPolicy {
    PeerPolicy {
        uid: 0,
        gid: Some(0),
        audience: Audience::AUDIENCE_NODE_CONTROLLER,
    }
}

fn header(request_id: [u8; 16], deadline: u64) -> RequestHeader {
    RequestHeader {
        protocol_major: 1,
        request_id: request_id.to_vec(),
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        deadline_boottime_nanoseconds: deadline,
        maximum_response_bytes: 8192,
        ..Default::default()
    }
}

fn base_request(deadline: u64) -> Vec<u8> {
    ApplyRuntimeRequest {
        header: Some(header(BASE_REQUEST_ID, deadline)).into(),
        fence: Some(AssignmentFence {
            sandbox_id: vec![1; 16],
            incarnation_id: vec![2; 16],
            assignment_epoch: 4,
            desired_generation: 6,
            assignment_digest: ASSIGNMENT_DIGEST.to_vec(),
            ..Default::default()
        })
        .into(),
        action: RuntimeAction::RUNTIME_ACTION_FREEZE.into(),
        ..Default::default()
    }
    .encode_to_vec()
}

fn output_source(boot: [u8; 16], deadline: u64) -> [u8; 688] {
    let mut source = [0; 688];
    source[..8].copy_from_slice(b"AOSCIR01");
    source[8..16].copy_from_slice(b"AOSCIP01");
    source[16..32].fill(1);
    source[32..48].fill(2);
    source[48..80].fill(3);
    source[96..104].copy_from_slice(&9_u64.to_be_bytes());
    source[104..120].copy_from_slice(&boot);
    source[120..128].copy_from_slice(&deadline.to_be_bytes());
    source[128..160].fill(9);
    let preissue_digest = Sha256::new()
        .chain_update(b"aos.sandbox.controller-execution-preissue.v1\0")
        .chain_update(&source[8..160])
        .finalize();
    source[160..192].copy_from_slice(&preissue_digest);

    source[192..200].copy_from_slice(b"AOSEOR02");
    source[200..216].fill(1);
    source[216..232].fill(2);
    for (offset, value) in [(232, 1), (264, 2), (328, 3), (360, 4), (392, 5), (456, 6)] {
        source[offset..offset + 32].fill(value);
    }
    source[296..328].copy_from_slice(&ASSIGNMENT_DIGEST);
    source[432..440].copy_from_slice(&20_u64.to_be_bytes());
    let claim_digest = Sha256::digest(&source[192..488]);
    source[488..520].copy_from_slice(&claim_digest);

    source[520..552].fill(7);
    source[552..568].fill(1);
    source[568..584].fill(2);
    source[584..600].fill(3);
    source[600..608].copy_from_slice(&4_u64.to_be_bytes());
    source[608..616].copy_from_slice(&6_u64.to_be_bytes());
    source[616..624].copy_from_slice(&7_u64.to_be_bytes());
    source[624..656].copy_from_slice(&ASSIGNMENT_DIGEST);
    let carrier_digest = Sha256::new()
        .chain_update(b"aos.sandbox.controller-execution-reserve-source.v1\0")
        .chain_update(&source[..656])
        .finalize();
    source[656..688].copy_from_slice(&carrier_digest);
    source
}

fn feature(namespace: &str) -> Feature {
    Feature {
        namespace: namespace.to_owned(),
        major: 1,
        ..Default::default()
    }
}

fn signed_method35_request(
    client_path: &Path,
    broker_path: &Path,
    body: Vec<u8>,
    artifacts: BrokerAuthorizationArtifactsV1,
    boottime: u64,
) -> aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1 {
    signed_method_request(
        client_path,
        broker_path,
        BrokerMethod::BROKER_METHOD_HOST_RESERVE_EXECUTION_OUTPUT,
        Audience::AUDIENCE_NODE_CONTROLLER,
        RESERVE_REQUEST_ID,
        body,
        artifacts,
        boottime,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_method_request(
    client_path: &Path,
    broker_path: &Path,
    method: BrokerMethod,
    audience: Audience,
    request_id: [u8; 16],
    body: Vec<u8>,
    artifacts: BrokerAuthorizationArtifactsV1,
    boottime: u64,
) -> aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1 {
    signed_method_request_with_context(
        client_path,
        broker_path,
        method,
        audience,
        request_id,
        body,
        artifacts,
        boottime,
    )
    .request
}

struct SignedHostRequestContext {
    request: AuthenticatedBrokerMethodRequestV1,
    pending: Box<BrokerSessionTrafficStateV1>,
    broker: ProtectedBrokerSessionBrokerV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
    client_process: [u8; 16],
}

#[allow(clippy::too_many_arguments)]
fn signed_method_request_with_context(
    client_path: &Path,
    broker_path: &Path,
    method: BrokerMethod,
    audience: Audience,
    request_id: [u8; 16],
    body: Vec<u8>,
    artifacts: BrokerAuthorizationArtifactsV1,
    boottime: u64,
) -> SignedHostRequestContext {
    let mut client = ProtectedBrokerSessionClientV1::load(client_path).unwrap();
    let mut broker = ProtectedBrokerSessionBrokerV1::load(broker_path).unwrap();
    let features = vec![
        feature("aos.sandbox.authentication.broker-session"),
        feature("aos.sandbox.authorization.signed-plan-lease"),
    ];
    let broker_process = broker.process_execution_id_bytes();
    let client_packet = client
        .finalize_client_hello(
            BrokerClientHello {
                protocol_major: 1,
                audience: audience.into(),
                required_features: features.clone(),
                maximum_response_bytes: 65_536,
                required_methods: vec![method.into()],
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
                methods: vec![method.into()],
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
    let traffic =
        BrokerSessionTrafficStateV1::from_provisional_transcript(transcript.clone()).unwrap();
    let packet = client
        .finalize_method_request(
            BrokerRequestEnvelope {
                method: method.into(),
                body,
                authorization: Some(artifacts).into(),
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
    match admit_server_received_authenticated_broker_method_request_v1(
        &traffic,
        &packet,
        None,
        0,
        peer(),
        PeerPolicy {
            audience,
            ..peer_policy()
        },
        boottime,
        bindings,
        &context,
    )
    .unwrap()
    {
        AuthenticatedBrokerMethodRequestAdmissionV1::New {
            request,
            next_traffic,
        } => SignedHostRequestContext {
            request,
            pending: next_traffic,
            broker,
            transcript,
            client_process: client.process_execution_id_bytes(),
        },
        AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(_) => {
            panic!("fresh signed Host request replayed")
        }
    }
}

fn seal_controller_record(domain: &[u8], record: &mut [u8], checksum_start: usize) {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(&record[..checksum_start])
        .finalize();
    record[checksum_start..checksum_start + 32].copy_from_slice(&digest);
}

fn storage_readback_body(
    source: &ControllerExecutionReserveSourceV1,
    protected: ProtectedHostOutputReservationV1,
    deadline: u64,
) -> Vec<u8> {
    let mut attempt = [0_u8; 816];
    attempt[..8].copy_from_slice(b"AOSCIA01");
    attempt[8..696].copy_from_slice(&source.canonical_bytes());
    attempt[696..712].copy_from_slice(&RESERVE_REQUEST_ID);
    attempt[712..744].copy_from_slice(protected.plan_digest().as_bytes());
    attempt[744..776].copy_from_slice(protected.semantic_request_digest().as_bytes());
    attempt[776..784].copy_from_slice(&deadline.to_be_bytes());
    seal_controller_record(
        b"aos.sandbox.controller-output-attempt.v1\0",
        &mut attempt,
        784,
    );

    let mut settlement = [0_u8; 208];
    settlement[..8].copy_from_slice(b"AOSCIS01");
    settlement[8..24].copy_from_slice(source.preissue().execution().as_bytes());
    settlement[24..40].copy_from_slice(source.preissue().create_operation().as_bytes());
    settlement[40..72].copy_from_slice(&attempt[784..816]);
    settlement[72..104].copy_from_slice(protected.correlation_digest().as_bytes());
    settlement[104..112].copy_from_slice(&protected.original_journal_sequence().to_be_bytes());
    settlement[112..144].fill(17);
    settlement[144..176].fill(18);
    seal_controller_record(
        b"aos.sandbox.controller-output-settlement.v1\0",
        &mut settlement,
        176,
    );

    // These Controller-shaped records are only structural fixture inputs.
    // The real Host pair and distinct signed method-48 grant are checked later.
    let original = ReserveStorageExecutionOutputRequestV1 {
        header: Some(header(STORAGE_RESERVE_REQUEST_ID, deadline)).into(),
        canonical_controller_attempt: attempt.to_vec(),
        canonical_controller_settlement: settlement.to_vec(),
        ..Default::default()
    }
    .encode_to_vec();
    let records =
        StorageOutputReserveRecordsV1::from_canonical_records(&attempt, &settlement).unwrap();
    let storage_semantics =
        storage_output_reserve_grant_v1(assignment(), STORAGE_RESERVE_REQUEST_ID, &original)
            .unwrap();
    let original_plan_digest = [21_u8; 32];
    let attempt_digest = Sha256::new()
        .chain_update(b"aos.sandbox.controller-storage-output-attempt.v1\0")
        .chain_update(b"AOSCST01")
        .chain_update(records.host_locator().execution().as_bytes())
        .chain_update(records.host_locator().create_operation().as_bytes())
        .chain_update(STORAGE_RESERVE_REQUEST_ID)
        .chain_update(original_plan_digest)
        .chain_update(storage_semantics.argument_commitment().digest().as_bytes())
        .chain_update(u16::try_from(original.len()).unwrap().to_be_bytes())
        .chain_update(&original)
        .finalize();

    let mut readback_header = header(HOST_READBACK_REQUEST_ID, deadline);
    readback_header.audience = Audience::AUDIENCE_STORAGE_BROKER.into();
    ObserveHostStorageOutputRequestV1 {
        header: Some(readback_header).into(),
        canonical_original_storage_reserve_request: original,
        original_storage_signed_plan_digest: original_plan_digest.to_vec(),
        original_storage_semantic_digest: storage_semantics
            .argument_commitment()
            .digest()
            .as_bytes()
            .to_vec(),
        controller_storage_attempt_digest: attempt_digest.to_vec(),
        ..Default::default()
    }
    .encode_to_vec()
}

#[tokio::test]
async fn signed_method35_custody_supports_protected_method48_readback() {
    let temporary = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
    let client_path = temporary.path().join("client");
    let broker_path = temporary.path().join("broker");
    let owner_path = temporary.path().join("owner");
    let state_path = temporary.path().join("state");
    for path in [&client_path, &broker_path, &owner_path, &state_path] {
        fs::create_dir(path).unwrap();
    }
    fs::set_permissions(&owner_path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o700)).unwrap();
    let (manifest, secrets) = manifest_and_secrets(BrokerSessionProtocolV1::Host);
    install_endpoint(&client_path, &manifest, &secrets, TestEndpointRole::Client);
    install_endpoint(&broker_path, &manifest, &secrets, TestEndpointRole::Broker);
    let _endpoint_cleanup = EndpointCleanup(&client_path, &broker_path);

    let owner_uid = fs::metadata(&owner_path).unwrap().uid();
    let mut owner = DormantRuntimeExecutionOwnerV1::provisioned_protected_at_uid_for_test(
        &owner_path,
        owner_uid,
    )
    .unwrap();
    let mut claim = owner.claim().unwrap();
    let boot = KernelBootId::current().unwrap().into_bytes();
    let wall = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let boottime =
        u64::try_from(rustix::time::clock_gettime(rustix::time::ClockId::Boottime).tv_sec).unwrap()
            * 1_000_000_000;
    let deadline = boottime + 60_000_000_000;
    let clock = RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
        boot,
        wall,
        boottime,
    )
    .unwrap();
    let signed = SignedHostAuthority::new(wall);
    let base = base_request(deadline);
    let decoded_base = decode_runtime_request(&base, peer(), peer_policy(), boottime).unwrap();
    let base_semantics = canonical_host_semantics_v1(&decoded_base).unwrap();
    let base_grant = BrokerGrant::new(
        base_semantics.verb(),
        base_semantics.target(),
        base_semantics.commitment(),
        u32::try_from(base.len()).unwrap(),
        0,
    )
    .unwrap();
    let base_artifacts = signed.artifacts(base_grant, 1);
    let validated_base = decode_request_envelope(
        &BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME.into(),
            body: base.clone(),
            authorization: Some(base_artifacts).into(),
            ..Default::default()
        }
        .encode_to_vec(),
        ProtocolId::HostBroker,
        0,
    )
    .unwrap();
    let mut host = HostBroker::open(
        NoCatalog,
        FileHostStateStore::open_exclusive(&state_path).unwrap(),
        FreezeWorker,
        None,
        signed.authority(),
    )
    .unwrap();
    host.apply_runtime(
        &base,
        validated_base.authorization().unwrap(),
        ProtocolVersion::new(1, 0),
        peer(),
        peer_policy(),
        || Ok(clock.clone()),
    )
    .await
    .unwrap();

    // This Controller-shaped carrier is structural test input. The signed Host
    // grant authenticates method 35; Controller AOSCIA01 custody remains a
    // separate prerequisite for the later 35 -> 37 -> 39 -> 42 bridge.
    let source_bytes = output_source(boot, deadline);
    let source = ControllerExecutionReserveSourceV1::decode_structural(&source_bytes).unwrap();
    let body = ReserveHostExecutionOutputRequestV1 {
        header: Some(header(RESERVE_REQUEST_ID, deadline)).into(),
        canonical_source: source_bytes.to_vec(),
        ..Default::default()
    }
    .encode_to_vec();
    let semantics =
        host_output_reserve_grant_v1(assignment(), RESERVE_REQUEST_ID, &source_bytes).unwrap();
    let grant = BrokerGrant::new(
        semantics.verb(),
        semantics.target(),
        semantics.commitment(),
        u32::try_from(body.len()).unwrap(),
        0,
    )
    .unwrap();
    let mut invalid_artifacts = signed.artifacts(grant.clone(), 2);
    let last_signature_byte = invalid_artifacts.broker_plan_signature.len() - 1;
    invalid_artifacts.broker_plan_signature[last_signature_byte] ^= 1;
    let invalid_packet = signed_method35_request(
        &client_path,
        &broker_path,
        body.clone(),
        invalid_artifacts,
        boottime,
    );
    assert!(
        host.reserve_host_execution(&claim, &invalid_packet, None, boot, || Ok(clock.clone()))
            .is_err()
    );

    let authenticated = signed_method35_request(
        &client_path,
        &broker_path,
        body,
        signed.artifacts(grant, 2),
        boottime,
    );
    assert!(
        host.reserve_host_execution(&claim, &authenticated, None, [99; 16], || Ok(clock.clone()))
            .is_err()
    );
    let reservation = host
        .reserve_host_execution(&claim, &authenticated, None, boot, || Ok(clock.clone()))
        .unwrap();
    let verified = reservation.verified_output_source().unwrap();
    let protected = claim.reserve_host_output_v1(verified).unwrap();
    assert_eq!(protected.carrier_digest(), source.carrier_digest());
    assert_eq!(protected.original_request_id(), RESERVE_REQUEST_ID);
    host.complete_host_execution_reservation(&reservation, &claim, b"AOSHOP01")
        .unwrap();

    drop(claim);
    drop(owner);
    drop(host);
    let mut reopened =
        DormantRuntimeExecutionOwnerV1::open_protected_at_uid_for_test(&owner_path, owner_uid)
            .unwrap();
    let mut cold_claim = reopened.claim().unwrap();
    assert_eq!(
        cold_claim.reserve_host_output_v1(verified).unwrap(),
        protected
    );
    let cold = cold_claim
        .query_host_output_v1(
            source.preissue().execution(),
            source.preissue().create_operation(),
            source.preissue().record_digest(),
            source.output_claim_digest(),
            source.carrier_digest(),
            RESERVE_REQUEST_ID,
            assignment().digest(),
            boot,
        )
        .unwrap()
        .unwrap();
    assert_eq!(cold, protected);
    assert!(
        cold_claim
            .query_host_output_v1(
                source.preissue().execution(),
                source.preissue().create_operation(),
                source.preissue().record_digest(),
                source.output_claim_digest(),
                source.carrier_digest(),
                [99; 16],
                assignment().digest(),
                boot,
            )
            .is_err()
    );
    let storage_client_path = temporary.path().join("storage-client");
    let storage_broker_path = temporary.path().join("storage-broker");
    for path in [&storage_client_path, &storage_broker_path] {
        fs::create_dir(path).unwrap();
    }
    let (storage_manifest, storage_secrets) = manifest_and_secrets_for_audience(
        BrokerSessionProtocolV1::Host,
        crate::manifest::BrokerSessionSecurityAudienceV1::StorageBroker,
    );
    install_endpoint(
        &storage_client_path,
        &storage_manifest,
        &storage_secrets,
        TestEndpointRole::Client,
    );
    install_endpoint(
        &storage_broker_path,
        &storage_manifest,
        &storage_secrets,
        TestEndpointRole::Broker,
    );
    let _storage_endpoint_cleanup = EndpointCleanup(&storage_client_path, &storage_broker_path);

    let readback_body = storage_readback_body(&source, protected, deadline);
    let storage_policy = PeerPolicy {
        audience: Audience::AUDIENCE_STORAGE_BROKER,
        ..peer_policy()
    };
    let readback_request = decode_host_storage_output_readback_request_v1(
        &readback_body,
        peer(),
        storage_policy,
        boottime,
    )
    .unwrap();
    let readback_grant = host_storage_output_readback_grant_v1(
        assignment(),
        HOST_READBACK_REQUEST_ID,
        &readback_body,
    )
    .unwrap();
    let mut signed_readback = signed_method_request_with_context(
        &storage_client_path,
        &storage_broker_path,
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT,
        Audience::AUDIENCE_STORAGE_BROKER,
        HOST_READBACK_REQUEST_ID,
        readback_body,
        signed.artifacts(readback_grant, 2),
        boottime,
    );
    let mut cold_host = HostBroker::open(
        NoCatalog,
        FileHostStateStore::open_exclusive(&state_path).unwrap(),
        FreezeWorker,
        None,
        signed.authority(),
    )
    .unwrap();
    let mut callsite = DormantHostBrokerCompositionV1::new(&mut cold_host);
    let response = dispatch_host_storage_output_with_claim_for_test_v1(
        &cold_claim,
        signed_readback.request.method(),
        signed_readback.request.authorization().is_some(),
        false,
        boot,
        || {
            callsite.observe_authenticated_storage_output(
                &cold_claim,
                &signed_readback.request,
                boot,
            )
        },
        || Ok(()),
    )
    .unwrap();
    let observed =
        decode_host_storage_output_readback_response_v1(&response, &readback_request).unwrap();
    assert_eq!(
        observed.reservation().correlation_digest(),
        Some(protected.correlation_digest())
    );
    assert_eq!(
        observed.reservation().original_host_journal_sequence(),
        Some(protected.original_journal_sequence())
    );
    assert_eq!(observed.current_assignment(), assignment());
    assert_eq!(
        observed.controller_storage_attempt_digest(),
        readback_request.controller_storage_attempt_digest()
    );
    assert!(observed.protected_head_sequence() >= protected.original_journal_sequence());

    // A read-only replay must reread the same protected pair without moving
    // the Host journal head or minting a new output reservation.
    let replay = dispatch_host_storage_output_with_claim_for_test_v1(
        &cold_claim,
        signed_readback.request.method(),
        signed_readback.request.authorization().is_some(),
        false,
        boot,
        || {
            callsite.observe_authenticated_storage_output(
                &cold_claim,
                &signed_readback.request,
                boot,
            )
        },
        || Ok(()),
    )
    .unwrap();
    assert_eq!(replay, response);

    let packet = signed_readback
        .broker
        .finalize_method_outcome(
            BrokerResponseEnvelope {
                request_id: HOST_READBACK_REQUEST_ID.to_vec(),
                method: BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT.into(),
                body: response.clone(),
                ..Default::default()
            },
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT,
            signed_readback.transcript.session_binding(),
            signed_readback.broker.process_execution_id_bytes(),
            1,
            HOST_READBACK_REQUEST_ID,
            signed_readback.request.signed_request_digest(),
        )
        .unwrap();
    let broker_context = signed_readback
        .broker
        .context_for_handshake(signed_readback.client_process)
        .unwrap();
    let (outcome, next_traffic) = match prepare_server_sent_authenticated_broker_method_outcome_v1(
        &signed_readback.pending,
        &signed_readback.request,
        &packet,
        None,
        0,
        &broker_context,
    )
    .unwrap()
    {
        AuthenticatedBrokerMethodOutcomeAdmissionV1::New {
            outcome,
            next_traffic,
        } => (outcome, next_traffic),
        AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(_) => {
            panic!("fresh protected Host readback outcome replayed")
        }
    };
    assert!(matches!(
        outcome.result(),
        aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success { exact_body, .. }
            if exact_body == &response
    ));
    assert!(matches!(
        prepare_server_sent_authenticated_broker_method_outcome_v1(
            &next_traffic,
            &signed_readback.request,
            &packet,
            Some(&outcome),
            0,
            &broker_context,
        ),
        Ok(AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(_))
    ));
}
