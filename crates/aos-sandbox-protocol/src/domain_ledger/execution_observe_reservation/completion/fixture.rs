//! Synthetic real-signature historical DATA for complete first-Observe tests.
//!
//! This module creates no endpoint, currentness owner, Host claim, physical
//! Storage proof, native completion grant or live Guest. Plan/lease detached
//! signatures are canonical transport structure; the BSA and Guest packets use
//! real fixed test keys and the existing complete crypto/semantic engines.

use super::*;
use aos_sandbox_broker_session_protocol::*;
use aos_sandbox_core::*;
use aos_sandbox_core::model::spec::ResourceProfile;
use aos_sandbox_core::model::view::Environment;
use aos_sandbox_core::model::{AssignmentManifestV1, SandboxAncestry,
    KeyReference, Signature, SignatureBytes, SignatureStatement, StableKeyId};
use aos_sandbox_core::format::{encode_broker_authorization_plan, encode_ownership_lease, encode_signature};
use aos_sandbox_core::runtime_backend::EffectOperationV1;
use aos_proto::aos::sandbox::local::v1::*;
use ed25519_dalek::{SigningKey, Signer as _};
use crate::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointV1;
use crate::authenticated_session::all_methods::*;
use crate::execution_spec_attempt::ControllerExecutionSpecSourceHeadsV1;
use crate::host_execution::HostExecutionSpecContentFieldsV1;
use crate::PeerCredentials;

mod capture_fixture;
pub use capture_fixture::signed_ongoing_capture_observe_completion_fixture_v3;

const METHODS: [BrokerMethod; 3] = [BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION,
    BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2,
    BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2];
const RESPONSE: u32 = 65_536;
const CUTOFF: u64 = 90_000;

struct SignedCheckpoint {
    checkpoint: HistoricalSessionCheckpointV1,
    keys: [SigningKey; 4],
    signers: [BrokerSessionSignerReferenceV1; 4],
}

/// Contains synthetic complete signed DATA for a real protected journal test.
pub struct SignedObserveCompletionFixtureV1 {
    /// Exact canonical specification row.
    pub specification: Vec<u8>,
    /// Exact canonical Controller receipt row pinning the signed59 packet.
    pub argument_receipt: Vec<u8>,
    /// Exact canonical Controller argument source row.
    pub argument_attempt: Vec<u8>,
    /// Original exact inert child reservation.
    pub reservation: ControllerExecutionObserveReservationV1,
    /// Fully validated signed historical completion DATA.
    pub completion: ObserveChildCompletionDataV1,
    /// Exact original first-Observe receipt.
    pub receipt: [u8; 40],
}

fn signed_checkpoint(nonce: u8) -> SignedCheckpoint {
    signed_checkpoint_for(BrokerSessionProtocolV1::Host, &METHODS, nonce)
}

fn signed_checkpoint_for(protocol: BrokerSessionProtocolV1, methods: &[BrokerMethod], nonce: u8) -> SignedCheckpoint {
    let keys = std::array::from_fn::<_, 4, _>(|index| {
        SigningKey::from_bytes(&[21 + index as u8; 32])
    });
    let usages = [
        BrokerSessionKeyUsageV1::ClientHello,
        BrokerSessionKeyUsageV1::BrokerHello,
        BrokerSessionKeyUsageV1::ClientRecord,
        BrokerSessionKeyUsageV1::BrokerOutcome,
    ];
    let signers = std::array::from_fn::<_, 4, _>(|index| {
        BrokerSessionSignerReferenceV1::for_signing_key(
            [31 + index as u8; 16],
            1,
            [41 + index as u8; 32],
            [51 + index as u8; 16],
            1,
            usages[index],
            &keys[index],
        )
        .unwrap()
    });
    let protected = std::array::from_fn(|index| {
        ProtectedBrokerSessionKeyV1::new(
            signers[index].clone(),
            keys[index].verifying_key().to_bytes(),
            1,
            1,
            false,
            None,
        )
        .unwrap()
    });
    let context = ProtectedBrokerSessionVerificationContextV1::new(
        [61; 16],
        [62; 16],
        1,
        [63; 32],
        1,
        [64; 32],
        1,
        [65; 32],
        [11; 16],
        [12; 16],
        protocol,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        [13; 16],
        [14; 16],
        protected,
    )
    .unwrap();
    let mut namespaces = std::collections::BTreeSet::from([
        "aos.sandbox.authentication.broker-session",
        "aos.sandbox.authorization.signed-plan-lease",
    ]);
    for &method in methods {
        for feature in authenticated_broker_method_profile_v1(method).unwrap().required_features() {
            namespaces.insert(feature.namespace());
        }
    }
    // FeatureRef uses canonical length/byte ordering, which differs from
    // BTreeSet's namespace lexical ordering for this complete method union.
    let mut namespaces: Vec<_> = namespaces.into_iter().collect();
    namespaces.sort_by(|left, right| left.len().cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes())));
    let features: Vec<_> = namespaces.into_iter().map(|namespace| Feature {
        namespace: namespace.to_owned(), major: 1, ..Default::default()
    }).collect();

    let client_message = BrokerClientHello {
        protocol_major: 1,
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        required_features: features.clone(),
        maximum_response_bytes: 65_536,
        required_methods: methods.iter().copied().map(Into::into).collect(),
        ..Default::default()
    };
    let client_subject = BrokerClientHelloSubjectV1::new(
        [11; 16],
        [12; 16],
        protocol,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        [13; 16],
        [nonce; 32],
        context.protected_context_digest(),
        client_hello_fields_digest_v1(&client_message).unwrap(),
    )
    .unwrap();
    let client = sign_client_hello_v1(client_subject, signers[0].clone(), &keys[0]).unwrap();
    let client_packet = encode_signed_client_hello_packet_v1(client_message, &client).unwrap();

    let broker_message = BrokerServerHello {
        protocol_major: 1,
        features,
        maximum_request_bytes: maximum_broker_session_request_bytes_v1(
            protocol,
        ) as u32,
        maximum_response_bytes: 65_536,
        methods: methods.iter().copied().map(Into::into).collect(),
        ..Default::default()
    };
    let broker_subject = BrokerHelloSubjectV1::new(
        [11; 16],
        [12; 16],
        protocol,
        1,
        0,
        Audience::AUDIENCE_NODE_CONTROLLER,
        [14; 16],
        [16; 32],
        context.protected_context_digest(),
        complete_signed_client_hello_digest_v1(&client),
        server_hello_fields_digest_v1(&broker_message).unwrap(),
    )
    .unwrap();
    let broker = sign_broker_hello_v1(broker_subject, signers[1].clone(), &keys[1]).unwrap();
    let broker_packet = encode_signed_server_hello_packet_v1(broker_message, &broker).unwrap();

    let client = decode_canonical_client_hello_v1(&client_packet).unwrap();
    let broker = decode_canonical_server_hello_v1(&broker_packet).unwrap();
    let transcript = verify_broker_session_transcript_v1(&client, &broker, &context).unwrap();
    let checkpoint = HistoricalSessionCheckpointV1::new(
        context, &client_packet, &broker_packet,
        PeerCredentials { uid: 1000, gid: 1000, pid: Some(123) }, &transcript,
    ).unwrap();
    SignedCheckpoint { checkpoint, keys, signers }
}

fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
    ObjectDescriptor::new(
        MediaType::new(kind.as_str().to_owned()).unwrap(),
        ObjectDigest::from_bytes([byte; 32]),
        u64::from(byte),
    )
}

fn fixture_spec(argument_bytes: usize) -> ExecutionSpecV1 {
    fixture_spec_for_io_v5(argument_bytes, ExecutionIoV1::new(
        ExecutionTerminalModeV1::None,
        ExecutionOutputModeV1::Capture { maximum_stdout_bytes: 0, maximum_stderr_bytes: 0 },
        ExecutionDisconnectPolicyV1::Continue, ExecutionAccessRouteV1::Detached,
    ).unwrap())
}

fn fixture_spec_for_io_v5(argument_bytes: usize, io: ExecutionIoV1) -> ExecutionSpecV1 {
    let sandbox = SandboxId::from_bytes([1; 16]);
    let environment = Environment::new(vec![], vec![], vec![], vec![]).unwrap();
    let environment_descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::Environment.as_str().to_owned()).unwrap(),
        &aos_sandbox_core::format::encode_environment(&environment),
    );
    let profile = ResourceProfile::new(vec![]).unwrap();
    let profile_digest = resource_profile_digest_v1(&profile);
    let runtime_profile = FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap();
    let assignment = aos_sandbox_core::CanonicalAssignmentManifestV1::new(
        AssignmentManifestV1::new(
            sandbox,
            ProjectId::from_bytes([2; 16]),
            SandboxAncestry::new(sandbox, vec![]).unwrap(),
            IncarnationId::from_bytes([3; 16]),
            NodeId::from_bytes([4; 16]),
            AssignmentEpoch::new(5),
            DesiredGeneration::new(6),
            NamespaceGeneration::new(7),
            descriptor(PortableMediaType::SandboxSpec, 8),
            descriptor(PortableMediaType::Policy, 9),
            environment_descriptor.clone(),
            descriptor(PortableMediaType::View, 10),
            vec![],
            profile_digest,
            ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 4096),
            vec![runtime_profile.clone()],
        )
        .unwrap(),
    );
    let target = ExecutionTargetV1::new(
        sandbox,
        assignment.manifest().incarnation(),
        assignment.manifest().epoch(),
        assignment.digest(),
        assignment.manifest().namespace_generation(),
        PayloadBootId::new([11; 16]).unwrap(),
    )
    .unwrap();
    let argument_limit = ExecutionRuntimeArgumentLimitV1::new(
        runtime_profile,
        ObjectDigest::from_bytes([12; 32]),
        target.clone(),
        131_072,
    )
    .unwrap();
    let weights = [
        aos_sandbox_core::model::spec::LimitDimension::CpuWeight,
        aos_sandbox_core::model::spec::LimitDimension::IoWeight,
    ];
    let requested = weights
        .into_iter()
        .map(|dimension| {
            ExecutionResourceRequestV1::new(
                dimension,
                ExecutionResourceRequestValueV1::RelativeWeight(100),
            )
            .unwrap()
        })
        .collect();
    let admitted = weights
        .into_iter()
        .map(|dimension| {
            ExecutionResourceSublimitV1::new(
                dimension,
                ExecutionResourceSublimitValueV1::RelativeWeight(100),
            )
            .unwrap()
        })
        .collect();
    let resources = ExecutionResourceAdmissionV1::new(
        requested,
        admitted,
        profile,
        profile_digest,
        ExecutionOutputByteAdmissionV1::new(0, 0, assignment).unwrap(),
    )
    .unwrap();
    let command = ExecutionCommandV1::new(
        vec![b"/bin/true".to_vec(), vec![b'x'; argument_bytes]],
        vec![],
        RelativePath::new(vec![]).unwrap(),
        ExecutionCredentialsV1::new(1000, 1000, vec![]).unwrap(),
    )
    .unwrap();
    ExecutionSpecV1::new(
        ExecutionId::from_bytes([1; 16]),
        target,
        environment_descriptor,
        environment,
        Revision::new(11),
        command,
        argument_limit,
        resources,
        io,
        ExecutionTimeoutV1::new(1_000_000_000).unwrap(),
        PrincipalId::from_bytes([13; 16]),
        AuditId::from_bytes([2; 16]),
    )
    .unwrap()
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

fn authorization_artifacts_with_grant(
    assignment: BrokerAssignment,
    grant: BrokerGrant,
) -> BrokerAuthorizationArtifactsV1 {
    authorization_artifacts_for(assignment, grant, BrokerAudience::Host, ProtocolId::HostBroker)
}

fn authorization_artifacts_for(assignment: BrokerAssignment, grant: BrokerGrant, audience: BrokerAudience, protocol: ProtocolId) -> BrokerAuthorizationArtifactsV1 {
    let authority = authorization_key("ownership-authority", KeyUsage::OwnershipLease, 6);
    let plan = BrokerAuthorizationPlan::new(
        audience,
        protocol,
        ProtocolVersion::new(1, 0),
        assignment,
        NodeId::from_bytes([4; 16]),
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
        NodeId::from_bytes([4; 16]),
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

fn argument_source(spec: &ExecutionSpecV1, request: [u8; 16]) -> [u8; 336] {
    let mut source = [7; 336];
    source[..8].copy_from_slice(b"AOSCIA02");
    source[8..24].copy_from_slice(spec.execution().as_bytes());
    source[24..40].copy_from_slice(&[2; 16]);
    source[40..56].copy_from_slice(&request);
    source[184..216].copy_from_slice(spec.target().assignment_digest().as_bytes());
    source[248..264].copy_from_slice(&[4; 16]);
    source[296..304].copy_from_slice(&CUTOFF.to_be_bytes());
    let checksum = Sha256::new().chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
        .chain_update(&source[..304]).finalize();
    source[304..].copy_from_slice(&checksum);
    source
}

fn fresh_guest_receipt(spec: &ExecutionSpecV1, source: [u8; 336])
    -> crate::host_execution_argument::receipt::HostExecutionArgumentFreshReceiptV1
{
    use aos_sandbox_agent::{AgentRuntimeBindingV1, AgentSessionBindingV1,
        GuestRuntimeArgumentObserveRequestV1, verify_guest_runtime_argument_readback_v1};
    let assignment = spec.resources().output_bytes().assignment().broker_assignment().unwrap();
    let runtime = AgentRuntimeBindingV1::new(assignment.sandbox(), assignment.incarnation(),
        assignment.epoch(), assignment.digest(), assignment.desired_generation(), NamespaceGeneration::new(7), [11; 16]).unwrap();
    let request = GuestRuntimeArgumentObserveRequestV1::new(runtime,
        AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes([7; 32])).unwrap(),
        ObjectDigest::from_bytes([8; 32]), [9; 32],
        FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(), ObjectDigest::from_bytes([12; 32])).unwrap();
    let request_bytes = request.encode();
    let mut packet = b"AOSARP01".to_vec();
    packet.extend_from_slice(&(request_bytes.len() as u16).to_be_bytes());
    packet.extend_from_slice(&request_bytes);
    packet.extend_from_slice(&131_072_u64.to_be_bytes());
    let key = SigningKey::from_bytes(&[11; 32]);
    let mut message = b"aos.sandbox.guest-argument-readback.v1\0".to_vec();
    message.extend_from_slice(&packet);
    packet.extend_from_slice(&key.sign(&message).to_bytes());
    let verified = verify_guest_runtime_argument_readback_v1(&packet, &request, &key.verifying_key()).unwrap();
    crate::host_execution_argument::receipt::HostExecutionArgumentFreshReceiptV1::new(source,
        ObjectDigest::from_bytes([12; 32]), ObjectDigest::from_bytes([15; 32]), 16,
        &request, &packet, &verified).unwrap()
}

fn header(id: [u8; 16]) -> RequestHeader {
    RequestHeader { protocol_major: 1, request_id: id.to_vec(),
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        deadline_boottime_nanoseconds: 100_000, maximum_response_bytes: RESPONSE, ..Default::default() }
}

fn evidence(operation: EffectOperationV1, id: OperationId, spec: &ExecutionSpecV1, sequence: u64) -> Vec<u8> {
    let mut bytes = vec![5; 298];
    bytes[..8].copy_from_slice(b"AOSEEO01");
    bytes[8] = operation.code();
    bytes[9..25].copy_from_slice(id.as_bytes());
    bytes[25..33].copy_from_slice(&1_u64.to_be_bytes());
    bytes[33..65].copy_from_slice(&[4; 32]);
    bytes[65..81].copy_from_slice(spec.execution().as_bytes());
    bytes[81..113].copy_from_slice(execution_spec_digest_v1(spec).as_bytes());
    bytes[225] = 3;
    bytes[226..234].copy_from_slice(&sequence.to_be_bytes());
    let checksum = Sha256::new().chain_update(b"aos-sandbox-runtime-execution-evidence-v1\0")
        .chain_update(266_u64.to_be_bytes()).chain_update(&bytes[..266]).finalize();
    bytes[266..].copy_from_slice(&checksum);
    bytes
}

fn successful_body(operation: EffectOperationV1, id: OperationId, spec: &ExecutionSpecV1, sequence: u64)
    -> (Vec<u8>, [u8; 40])
{
    let completion = evidence(operation, id, spec, sequence);
    let digest: [u8; 32] = Sha256::new().chain_update(b"aos-sandbox-execution-effect-result-v1\0")
        .chain_update((completion.len() as u64).to_be_bytes()).chain_update(&completion).finalize().into();
    let receipt = controller_execution_receipt_v1(id.as_bytes(), *spec.execution().as_bytes(), [4; 32],
        [6; 32], digest, sequence, &completion, None);
    let body = HostExecutionOutcomeV1 { operation_id: id.as_bytes().to_vec(), execution_id: spec.execution().as_bytes().to_vec(),
        source_operation_commitment: vec![4; 32], phase: HostExecutionPhaseV1::HOST_EXECUTION_PHASE_COMPLETE.into(),
        effect_commitment: vec![6; 32], completion_digest: digest.to_vec(), completion_bytes: completion,
        completion_status: HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_SUCCEEDED.into(),
        observation_sequence: sequence, ..Default::default() };
    (body.encode_to_vec(), receipt)
}

struct HistoryFixture {
    signed: SignedCheckpoint,
    records: Vec<BrokerSessionDurableRecordV1>,
    catalog: [u8; 32],
}

impl HistoryFixture {
    fn append(&mut self, method: BrokerMethod, id: [u8; 16], body: Vec<u8>,
        authorization: BrokerAuthorizationArtifactsV1, response: Vec<u8>) -> AuthenticatedBrokerMethodOutcomeV1
    {
        self.append_with_response(method, id, body, authorization, |_| response)
    }

    fn append_with_response(&mut self, method: BrokerMethod, id: [u8; 16], body: Vec<u8>,
        authorization: BrokerAuthorizationArtifactsV1,
        response: impl FnOnce(&AuthenticatedBrokerMethodRequestV1) -> Vec<u8>) -> AuthenticatedBrokerMethodOutcomeV1
    {
        let checkpoint = &self.signed.checkpoint;
        let transcript = checkpoint.verify().unwrap();
        let sequence = self.records.len() as u64 / 2 + 1;
        let profile = authenticated_broker_method_profile_v1(method).unwrap();
        let roles = profile.request_descriptor_roles();
        let envelope = BrokerRequestEnvelope { method: method.into(), body,
            descriptors: roles.iter().enumerate().map(|(index, role)| BrokerDescriptorEntry {
                index: index as u32, role: (*role).into(), ..Default::default() }).collect(),
            authorization: Some(authorization).into(), ..Default::default() };
        let request_subject = BrokerRequestSubjectV1::new(transcript.session_binding(), [13; 16], sequence, id,
            request_fields_digest_v1(&envelope).unwrap()).unwrap();
        let signed_request = sign_request_v1(method, request_subject, self.signed.signers[2].clone(), &self.signed.keys[2]).unwrap();
        let request_packet = encode_signed_request_packet_v1(envelope, &signed_request).unwrap();
        let prior = verify_historical_traffic_records_v1(&self.records, &transcript, checkpoint.context()).unwrap();
        let canonical = decode_canonical_request_v1(&request_packet).unwrap();
        let bindings = authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method).unwrap();
        let peer = checkpoint.peer();
        let policy = crate::PeerPolicy { uid: peer.uid, gid: Some(peer.gid), audience: Audience::AUDIENCE_NODE_CONTROLLER };
        let (request, pending) = match prepare_client_sent_authenticated_broker_method_request_v1(&prior, &request_packet,
            None, roles.len(), peer, policy, 50_000, bindings, checkpoint.context()).unwrap() {
            AuthenticatedBrokerMethodRequestAdmissionV1::New { request, next_traffic } => (request, next_traffic),
            _ => panic!("synthetic signed request unexpectedly replayed"),
        };
        let response = BrokerResponseEnvelope {
            method: method.into(), request_id: id.to_vec(), body: response(&request),
            // Sign the same exact disposition table as the real closed profile.
            // These fixtures retain historical DATA and never own native FDs.
            request_descriptor_dispositions: roles.iter()
                .zip(profile.request_descriptor_dispositions()).enumerate()
                .map(|(index, (role, disposition))| BrokerDescriptorDispositionEntry {
                    request_index: index as u32, role: (*role).into(),
                    disposition: (*disposition).into(), ..Default::default()
                }).collect(),
            ..Default::default()
        };
        let outcome_subject = BrokerOutcomeSubjectV1::new(transcript.session_binding(), [14; 16], sequence, id,
            request.signed_request_digest(), outcome_fields_digest_v1(&response).unwrap()).unwrap();
        let signed_outcome = sign_outcome_v1(method, outcome_subject, self.signed.signers[3].clone(), &self.signed.keys[3]).unwrap();
        let response_packet = encode_signed_response_packet_v1(response, &signed_outcome).unwrap();
        let outcome = match admit_client_received_authenticated_broker_method_outcome_v1(&pending, &request,
            &response_packet, None, 0, checkpoint.context()).unwrap() {
            AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. } => outcome,
            _ => panic!("synthetic signed outcome unexpectedly replayed"),
        };
        let bindings = BrokerSessionProtectedBindingsV1::new(checkpoint.context().protected_context_digest(), [35; 32], self.catalog).unwrap();
        let companion = BrokerSessionRequestCompanionV1::try_from_parts(checkpoint.context().protocol(), method,
            request.deadline_boottime_nanoseconds(), request.maximum_response_bytes(), signed_request).unwrap();
        let prepared = match self.records.last() {
            Some(prior) => prior.with_next_request(bindings, request.semantic_commitment(), id, companion, request_packet).unwrap(),
            None => BrokerSessionDurableRecordV1::new_request(1, [0; 32], BrokerSessionDurableEndpointV1::Client,
                transcript.session_binding(), BrokerSessionPeerBindingV1::new([34; 32]).unwrap(), bindings,
                request.semantic_commitment(), id, companion, request_packet).unwrap(),
        };
        let companion = BrokerSessionOutcomeCompanionV1::try_from_parts(checkpoint.context().protocol(), method, id,
            sequence, request.maximum_response_bytes(), request.signed_request_digest(), signed_outcome).unwrap();
        let terminal = prepared.with_terminal_outcome(prepared.revision() + 1, prepared.commitment().unwrap(), bindings,
            outcome.semantic_commitment(), companion, response_packet).unwrap();
        self.records.extend([prepared, terminal]);
        outcome
    }

    fn stored(&self) -> Vec<u8> {
        let history = BrokerSessionDurableHistoryV1::from_records(self.records.clone()).unwrap();
        StoredBrokerSessionHistoryV1 { protocol: self.signed.checkpoint.context().protocol(), endpoint: BrokerSessionDurableEndpointV1::Client,
            generation: 1, stable_endpoint_identity: [33; 32], endpoint_publication: [35; 32], current_catalog: self.catalog,
            current_head: history.head_commitment(), history: history.encode().unwrap(), checkpoint: Some(self.signed.checkpoint.clone()) }
            .encode().unwrap()
    }
}


fn grant(verb: BrokerVerb, target: BrokerGrantTarget, commitment: BrokerArgumentCommitment, descriptors: u16) -> BrokerGrant {
    BrokerGrant::new(verb, target, commitment, RESPONSE, descriptors).unwrap()
}

fn apply_body(id: [u8; 16], operation: OperationId, spec: &ExecutionSpecV1,
    action: HostExecutionActionV1, version: u32, content: HostExecutionSpecContentFieldsV1) -> Vec<u8>
{
    ApplyHostExecutionRequestV1 {
        header: Some(header(id)).into(), operation_id: operation.as_bytes().to_vec(),
        execution_id: spec.execution().as_bytes().to_vec(), source_operation_commitment: vec![4; 32],
        action: action.into(), spec_transfer_version: version, spec_content_bytes: content.bytes(),
        spec_content_digest: content.digest().to_vec(), spec_attempt_commitment: content.attempt_commitment().to_vec(),
        ..Default::default()
    }.encode_to_vec()
}

/// Builds valid signed59, Authorize and first-Observe DATA through the real codecs.
///
/// This synthetic fixture performs no native Host or Guest admission.
///
/// # Panics
/// Panics if any existing codec, signature, continuity or completion check fails.
#[must_use]
pub fn signed_observe_completion_fixture_v1() -> SignedObserveCompletionFixtureV1 {
    signed_observe_fixture_engine(None).0
}

fn signed_observe_fixture_engine(capture: Option<capture_fixture::CaptureFixtureData>) -> (SignedObserveCompletionFixtureV1, Option<Vec<u8>>) {
    let spec = if capture.is_some() { fixture_spec(257) } else {
        let key = ExecutionPublicKeyV1::new_ssh_ed25519(
            SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes()).unwrap();
        fixture_spec_for_io_v5(257, ExecutionIoV1::new(
            ExecutionTerminalModeV1::None, ExecutionOutputModeV1::Stream,
            ExecutionDisconnectPolicyV1::Cancel,
            ExecutionAccessRouteV1::open_ssh(key, vec![
                ExecutionEndpointCapabilityV1::StandardOutput,
                ExecutionEndpointCapabilityV1::StandardError,
            ]).unwrap(),
        ).unwrap())
    };
    let (logical_records, _, _, registration, logical_authority) = capture_fixture::logical_data_v5(&spec);
    let assignment = spec.resources().output_bytes().assignment().broker_assignment().unwrap();
    let execution = spec.execution();
    let create = OperationId::from_bytes([2; 16]);
    let source = argument_source(&spec, [3; 16]);
    let proposed = argument_source(&spec, [99; 16]);
    let signed = signed_checkpoint(1);
    let session = signed.checkpoint.verify().unwrap().session_binding();
    let preparation = crate::host_execution_argument::preparation::HostArgumentPreparationV2::from_observed_fields(
        &proposed, session, [7; 32], [12; 32], [14; 32], [15; 32], 1).unwrap();
    let semantic = crate::semantics::host_execution_argument_accept_grant_v2(assignment, [3; 16], &source, &preparation).unwrap();
    let authorization = authorization_artifacts_with_grant(assignment, grant(semantic.verb(), semantic.target(), semantic.commitment(), 0));
    let fresh = fresh_guest_receipt(&spec, source);
    let request = AcceptHostExecutionArgumentRequestV2 { header: Some(header([3; 16])).into(),
        canonical_attempt: source.to_vec(), canonical_preparation: preparation.canonical_bytes().to_vec(), ..Default::default() };
    let response = AcceptHostExecutionArgumentResponseV2 { canonical_receipt: fresh.canonical_bytes(), ..Default::default() };
    let mut history = HistoryFixture { signed, records: Vec::new(), catalog: [36; 32] };
    let accepted = history.append(BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2, [3; 16],
        request.encode_to_vec(), authorization, response.encode_to_vec());

    let mut caf = ControllerArgumentReceiptDataV1 { execution, create_operation: create,
        attempt_digest: ObjectDigest::from_bytes(source[304..].try_into().unwrap()),
        request_packet_digest: ObjectDigest::from_bytes(Sha256::digest(accepted.request().canonical_packet()).into()),
        outcome_packet_digest: ObjectDigest::from_bytes(Sha256::digest(accepted.canonical_packet()).into()),
        exact_host_receipt: fresh.canonical_bytes(), record_digest: ObjectDigest::from_bytes([0; 32]) };
    let caf_bytes = caf.encode().unwrap();
    caf.record_digest = crate::execution_argument_receipt::digest_record(&caf_bytes[..caf_bytes.len() - 32]);
    let argument_receipt = caf.encode().unwrap();
    let spec_bytes = encode_execution_spec_v1(&spec);
    let mut csi = ExecutionSpecAttemptFieldsV1 { execution, create_operation: create,
        accepted_request_digest: ObjectDigest::from_bytes([18; 32]),
        source_heads: ControllerExecutionSpecSourceHeadsV1 { assignment_digest: assignment.digest(), assignment_epoch: assignment.epoch().get(),
            parent_binding: ObjectDigest::from_bytes([19; 32]), parent_projection: ObjectDigest::from_bytes([20; 32]),
            sandbox_spec_record: ObjectDigest::from_bytes([21; 32]), environment_activation: ObjectDigest::from_bytes([22; 32]),
            environment_manifest: spec.environment_descriptor().digest(), environment_generation: spec.environment_generation().get(),
            output_claim: logical_records.host_locator().claim_digest(),
            output_settlement: crate::storage_capture_grant::ControllerOutputSettlementPreimageV1::from_canonical_bytes(
                logical_records.settlement()).unwrap().record_digest(),
            argument_receipt: caf.record_digest, host_argument_custody: ObjectDigest::from_bytes([15; 32]), host_argument_sequence: 16 },
        controller_sequence: 17, specification_digest: execution_spec_digest_v1(&spec), specification_bytes: &spec_bytes,
        record_digest: ObjectDigest::from_bytes([0; 32]) };
    csi.record_digest = crate::execution_spec_attempt::digest_record(&csi.encode_without_digest());
    let specification = csi.encode();

    let admission = match capture.as_ref() {
        Some(capture) => capture.content(&specification),
        None => {
            let digest = descriptor_for_bytes(MediaType::new(
                PortableMediaType::OwnershipLease.as_str().to_owned()).unwrap(),
                &logical_authority.ownership_lease).digest();
            let lifetime = capture_fixture::lifetime_data_v5(&spec, digest);
            crate::host_execution::admission_content::HostExecutionAdmissionContentV5::new_stream_v5(
                &specification, &registration, &lifetime).unwrap().encode().unwrap()
        }
    };
    let content = HostExecutionSpecContentFieldsV1::for_grant(&admission)
        .bind_lifetime_admission_attempt_v5([5; 16], *create.as_bytes(), execution, ObjectDigest::from_bytes([4; 32]));
    let semantic = crate::semantics::host_execution::host_execution_apply_lifetime_admission_grant_v5(
        assignment, *create.as_bytes(), execution, ObjectDigest::from_bytes([4; 32]), content).unwrap();
    let authorization = authorization_artifacts_with_grant(assignment, grant(semantic.verb(), semantic.target(), semantic.commitment(), 1));
    let (response, authorize_receipt) = successful_body(EffectOperationV1::AuthorizeExecution, create, &spec, 1);
    history.append(BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION, [5; 16],
        apply_body([5; 16], create, &spec, HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE, 5, content), authorization, response);
    let reservation = ControllerExecutionObserveReservationV1::new(execution, create, execution_spec_digest_v1(&spec), [4; 32], &authorize_receipt).unwrap();
    let observe = reservation.observe_operation();
    let content = HostExecutionSpecContentFieldsV1::for_grant(crate::host_execution::HOST_EXECUTION_CONTROL_CONTENT_V1)
        .bind_attempt([6; 16], *observe.as_bytes(), execution, ObjectDigest::from_bytes([4; 32]), EffectOperationV1::Observe);
    let semantic = crate::semantics::host_execution_apply_content_grant_v1(assignment, *observe.as_bytes(), execution,
        ObjectDigest::from_bytes([4; 32]), EffectOperationV1::Observe, content).unwrap();
    let authorization = authorization_artifacts_with_grant(assignment, grant(semantic.verb(), semantic.target(), semantic.commitment(), 1));
    let (response, receipt) = successful_body(EffectOperationV1::Observe, observe, &spec, 2);
    history.append(BrokerMethod::BROKER_METHOD_HOST_APPLY_EXECUTION, [6; 16],
        apply_body([6; 16], observe, &spec, HostExecutionActionV1::HOST_EXECUTION_ACTION_OBSERVE, 1, content), authorization, response);
    let sample = RawPairedClockSample::new_untrusted(RawClockProvenance::new_untrusted([1; 16]).unwrap(), [4; 16], 50, 50_000).unwrap();
    let anchor = capture.as_ref().map(|capture| capture.anchor.clone());
    let stored = history.stored();
    let completion_cutoff = capture.as_ref().map_or(CUTOFF, |capture| capture.effect_cutoff.min(CUTOFF));
    let completion = ObserveChildCompletionDataV1::new_lifetime_v5(
        &reservation, &specification, &argument_receipt, &stored, &admission, anchor.as_deref(),
        sample, completion_cutoff, &receipt).unwrap();
    (SignedObserveCompletionFixtureV1 { specification, argument_receipt, argument_attempt: source.to_vec(), reservation, completion, receipt }, anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::effect_history::{EffectLedgerRecord, EffectPlan, EffectState, EffectReceipt, decode_effect};
    use crate::domain_ledger::effect_history::observe_completion::{encode_completed_observe_effect_v1, decode_completed_observe_effect_v1};

    #[test]
    fn real_signed58_uses_actual_signed_request_in_preparation() {
        let spec = fixture_spec(257);
        let assignment = spec.resources().output_bytes().assignment().broker_assignment().unwrap();
        let proposed = argument_source(&spec, [99; 16]);
        let semantic = crate::semantics::host_execution_argument_prepare_grant_v2(assignment, [99; 16], &proposed).unwrap();
        let authorization = authorization_artifacts_with_grant(assignment,
            grant(semantic.verb(), semantic.target(), semantic.commitment(), 0));
        let request = PrepareHostExecutionArgumentRequestV2 { header: Some(header([99; 16])).into(),
            proposed_attempt: proposed.to_vec(), ..Default::default() };
        let mut history = HistoryFixture { signed: signed_checkpoint(3), records: Vec::new(), catalog: [36; 32] };
        let outcome = history.append_with_response(BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2,
            [99; 16], request.encode_to_vec(), authorization, |actual| {
                crate::host_execution_argument::preparation::HostArgumentPreparationV2::from_observed_fields(
                    &proposed, actual.session_binding(), [7; 32], [12; 32], actual.signed_request_digest(), [15; 32], 1)
                    .unwrap().canonical_bytes().to_vec()
            });
        let checkpoint = &history.signed.checkpoint;
        let historical = historical_terminal_outcome(&history.records, 1, checkpoint, &checkpoint.verify().unwrap()).unwrap();
        assert_eq!(historical.canonical_packet(), outcome.canonical_packet());
        assert_eq!(historical.request().canonical_packet(), outcome.request().canonical_packet());
    }

    #[test]
    fn real_signed_history_completes_exact_v7_and_rejects_changed_packet_and_expiry() {
        let fixture = signed_observe_completion_fixture_v1();
        let applied = EffectLedgerRecord::from_parts((EffectPlan::reserved_observe(&fixture.reservation),
            EffectState::Applied { attempt: 1, receipt: EffectReceipt::new(fixture.receipt.to_vec()).unwrap() }, None, None));
        let encoded = encode_completed_observe_effect_v1(&applied, &fixture.completion).unwrap();
        assert_eq!(decode_effect(&encoded).unwrap(), applied);
        assert_eq!(decode_completed_observe_effect_v1(&encoded).unwrap().1, fixture.completion);

        let (core, registration, selector) = super::admission::split(fixture.completion.bytes()).unwrap();
        let fields = split(core).unwrap();
        let admission = super::admission::reconstruct_content_v5(&fields, registration, selector).unwrap();
        let anchor = selector.capture_anchor_v5();
        let mut changed_session = fields.session.to_vec();
        let position = changed_session.windows(8).rposition(|window| window == b"AOSEEO01").unwrap();
        changed_session[position + 113] ^= 1;
        let sample = RawPairedClockSample::new_untrusted(RawClockProvenance::new_untrusted([1; 16]).unwrap(), [4; 16], 50, 50_000).unwrap();
        assert!(ObserveChildCompletionDataV1::new_lifetime_v5(&fixture.reservation, fields.specification, fields.argument_receipt,
            &changed_session, &admission, anchor, sample, CUTOFF, &fixture.receipt).is_err());
        let expired = RawPairedClockSample::new_untrusted(RawClockProvenance::new_untrusted([1; 16]).unwrap(), [4; 16], 200, 50_000).unwrap();
        assert!(ObserveChildCompletionDataV1::new_lifetime_v5(&fixture.reservation, fields.specification, fields.argument_receipt,
            fields.session, &admission, anchor, expired, CUTOFF, &fixture.receipt).is_err());
    }
}
