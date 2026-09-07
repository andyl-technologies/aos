//! Adversarial publication, recovery, and canonical-encoding tests.

use std::path::PathBuf;

use aos_proto::aos::sandbox::local::v1::{
    ApplyRuntimeRequest, AssignmentFence, Audience, BrokerDescriptorRole, BrokerMethod,
    RequestHeader, RuntimeAction,
};
use aos_sandbox_core::format::{encode_signature, encode_trust_policy};
use aos_sandbox_core::model::{
    AssignmentManifestV1, KeyReference, KeyUsage, SandboxAncestry, SignaturePurpose,
    SignatureStatement, StableKeyId, TrustPolicy,
};
use aos_sandbox_core::{
    AssignmentEpoch, BrokerArgumentCommitment, BrokerAssignment, BrokerAuthorizationPlan,
    BrokerGrant, BrokerGrantTarget, BrokerVerb, DesiredGeneration, FeatureRef, IncarnationId,
    LeaseAssignment, MediaType, NamespaceGeneration, NodeId, ObjectDescriptor, OwnershipLease,
    OwnershipLeaseTrustAnchor, PortableMediaType, ProjectId, ProtocolId, ProtocolVersion,
    RawClockProvenance, ResourceDimension, ResourceVector, RevocationScopeId, TrustScopeId,
    sign_statement,
};
use buffa::Message as _;
use ed25519_dalek::SigningKey;

use crate::{
    BrokerDispatchSemanticIdentityV1, BrokerPlanPreparation, OwnershipAuthorityVerifier,
    OwnershipClaimV1, OwnershipTransactionReceiptV1, ReturnedSignature, SignedBrokerPlan,
    SigningAuthority, UnverifiedOwnershipLeaseResponse,
};
use aos_sandbox_ownership_protocol::ExpectedOwnershipLease;

use super::*;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("aos-publication-{}", OperationId::new()));
        std::fs::create_dir(&path).unwrap_or_else(|error| panic!("test directory failed: {error}"));
        Self(path)
    }

    fn journal(&self) -> PathBuf {
        self.0.join("controller.journal")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
    ObjectDescriptor::new(
        MediaType::new(kind.as_str().to_owned())
            .unwrap_or_else(|error| panic!("test media type failed: {error}")),
        ObjectDigest::from_bytes([byte; 32]),
        u64::from(byte),
    )
}

fn manifest_with_node(node: u8) -> CanonicalAssignmentManifestV1 {
    manifest_with_generations(node, 7, 8)
}

fn manifest_with_generations(
    node: u8,
    desired: u64,
    namespace: u64,
) -> CanonicalAssignmentManifestV1 {
    let sandbox = SandboxId::from_bytes([1; 16]);
    let feature = FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0)
        .unwrap_or_else(|error| panic!("test feature failed: {error}"));
    let model = AssignmentManifestV1::new(
        sandbox,
        ProjectId::from_bytes([2; 16]),
        SandboxAncestry::new(sandbox, vec![SandboxId::from_bytes([3; 16])])
            .unwrap_or_else(|error| panic!("test ancestry failed: {error}")),
        IncarnationId::from_bytes([4; 16]),
        NodeId::from_bytes([node; 16]),
        AssignmentEpoch::new(6),
        DesiredGeneration::new(desired),
        NamespaceGeneration::new(namespace),
        descriptor(PortableMediaType::SandboxSpec, 9),
        descriptor(PortableMediaType::Policy, 10),
        descriptor(PortableMediaType::Environment, 11),
        descriptor(PortableMediaType::View, 12),
        vec![descriptor(PortableMediaType::Tree, 13)],
        ObjectDigest::from_bytes([14; 32]),
        ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 4096),
        vec![feature],
    )
    .unwrap_or_else(|error| panic!("test manifest failed: {error}"));
    CanonicalAssignmentManifestV1::new(model)
}

fn manifest() -> CanonicalAssignmentManifestV1 {
    manifest_with_node(5)
}

fn key_reference(name: &str, usage: KeyUsage, key: &SigningKey) -> KeyReference {
    KeyReference::new(
        StableKeyId::new(name.to_owned())
            .unwrap_or_else(|error| panic!("test key failed: {error}")),
        1,
        ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
        usage,
    )
}

fn authority(key: &SigningKey) -> SigningAuthority {
    let signer = key_reference("controller", KeyUsage::BrokerAuthorization, key);
    let scope = TrustScopeId::from_bytes([20; 16]);
    let policy = TrustPolicy::new(
        scope,
        SignaturePurpose::BrokerAuthorization,
        vec![signer.clone()],
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("test policy failed: {error}"));
    let bytes = encode_trust_policy(&policy);
    let descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
            .unwrap_or_else(|error| panic!("test policy media failed: {error}")),
        &bytes,
    );
    SigningAuthority::new(
        bytes,
        descriptor,
        scope,
        signer,
        key.verifying_key().to_bytes(),
        SignaturePurpose::BrokerAuthorization,
        DecodeLimits::default(),
    )
    .unwrap_or_else(|error| panic!("test authority failed: {error}"))
}

fn signed_plan(
    manifest: &CanonicalAssignmentManifestV1,
    lease_signer: KeyReference,
) -> (SignedBrokerPlan, BrokerDispatchSemanticIdentityV1) {
    let key = SigningKey::from_bytes(&[40; 32]);
    let semantics = BrokerDispatchSemanticIdentityV1::new(
        BrokerVerb::MountCreate,
        BrokerGrantTarget::Assignment,
        BrokerArgumentCommitment::for_canonical_bytes(b"mount-create"),
    );
    let assignment: BrokerAssignment = manifest
        .broker_assignment()
        .unwrap_or_else(|error| panic!("test broker assignment failed: {error}"));
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Mount,
        ProtocolId::MountBroker,
        ProtocolVersion::new(1, 0),
        assignment,
        manifest.manifest().node(),
        lease_signer,
        vec![
            BrokerGrant::new(
                semantics.verb(),
                semantics.target(),
                semantics.argument_commitment(),
                4096,
                1,
            )
            .unwrap_or_else(|error| panic!("test grant failed: {error}")),
        ],
        ObjectDigest::from_bytes([50; 32]),
        RevocationScopeId::from_bytes([51; 16]),
        100,
        200,
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("test plan failed: {error}"));
    let preparation = BrokerPlanPreparation::new(plan, authority(&key))
        .unwrap_or_else(|error| panic!("test plan preparation failed: {error}"));
    let signature = sign_statement(preparation.signing_request().statement().clone(), &key)
        .unwrap_or_else(|error| panic!("test signing failed: {error}"));
    let signed = preparation
        .complete(ReturnedSignature::Bytes(signature.signature()), 150)
        .unwrap_or_else(|error| panic!("test signed plan failed: {error}"));
    (signed, semantics)
}

fn signed_host_plan(
    manifest: &CanonicalAssignmentManifestV1,
    lease_signer: KeyReference,
) -> (SignedBrokerPlan, BrokerDispatchSemanticIdentityV1, Vec<u8>) {
    signed_host_control_plan(manifest, lease_signer, RuntimeAction::RUNTIME_ACTION_STOP)
}

fn signed_host_control_plan(
    manifest: &CanonicalAssignmentManifestV1,
    lease_signer: KeyReference,
    action: RuntimeAction,
) -> (SignedBrokerPlan, BrokerDispatchSemanticIdentityV1, Vec<u8>) {
    signed_host_control_plan_with_scope(manifest, lease_signer, action, false)
}

fn signed_host_control_plan_with_scope(
    manifest: &CanonicalAssignmentManifestV1,
    lease_signer: KeyReference,
    action: RuntimeAction,
    observe_scope: bool,
) -> (SignedBrokerPlan, BrokerDispatchSemanticIdentityV1, Vec<u8>) {
    let key = SigningKey::from_bytes(&[40; 32]);
    let assignment = manifest
        .broker_assignment()
        .unwrap_or_else(|error| panic!("test broker assignment failed: {error}"));
    let body = ApplyRuntimeRequest {
        header: Some(RequestHeader {
            protocol_major: 1,
            protocol_minor: if observe_scope { 2 } else { 1 },
            request_id: vec![0x44; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 0,
            maximum_response_bytes: 4096,
            ..Default::default()
        })
        .into(),
        fence: Some(AssignmentFence {
            sandbox_id: assignment.sandbox().as_bytes().to_vec(),
            incarnation_id: assignment.incarnation().as_bytes().to_vec(),
            assignment_epoch: assignment.epoch().get(),
            desired_generation: assignment.desired_generation().get(),
            assignment_digest: assignment.digest().as_bytes().to_vec(),
            ..Default::default()
        })
        .into(),
        action: action.into(),
        ..Default::default()
    }
    .encode_to_vec();
    let checked = aos_sandbox_protocol::decode_runtime_template_v1(&body)
        .unwrap_or_else(|error| panic!("test Host template failed: {error}"));
    let canonical =
        aos_sandbox_protocol::semantics::host::canonical_host_template_semantics_v1(&checked)
            .unwrap_or_else(|error| panic!("test Host semantics failed: {error}"));
    let semantics = BrokerDispatchSemanticIdentityV1::new(
        canonical.verb(),
        canonical.target(),
        canonical.commitment(),
    );
    let mut grants = vec![
        BrokerGrant::new(
            semantics.verb(),
            semantics.target(),
            semantics.argument_commitment(),
            4096,
            1,
        )
        .unwrap_or_else(|error| panic!("test Host grant failed: {error}")),
    ];
    if observe_scope {
        grants.push(payload_scope_grant(assignment));
        grants.sort_by_key(|grant| (grant.verb(), grant.target(), grant.argument_commitment()));
    }
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Host,
        ProtocolId::HostBroker,
        ProtocolVersion::new(1, 1),
        assignment,
        manifest.manifest().node(),
        lease_signer,
        grants,
        ObjectDigest::from_bytes([50; 32]),
        RevocationScopeId::from_bytes([51; 16]),
        100,
        200,
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("test Host plan failed: {error}"));
    let preparation = BrokerPlanPreparation::new(plan, authority(&key))
        .unwrap_or_else(|error| panic!("test Host plan preparation failed: {error}"));
    let signature = sign_statement(preparation.signing_request().statement().clone(), &key)
        .unwrap_or_else(|error| panic!("test Host signing failed: {error}"));
    let signed = preparation
        .complete(ReturnedSignature::Bytes(signature.signature()), 150)
        .unwrap_or_else(|error| panic!("test signed Host plan failed: {error}"));
    (signed, semantics, body)
}

fn payload_scope_grant(assignment: BrokerAssignment) -> BrokerGrant {
    use aos_proto::aos::sandbox::local::v1::ObservePayloadScopeRequest;
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
    let request = ObservePayloadScopeRequest {
        header: Some(RequestHeader {
            protocol_major: 1,
            protocol_minor: 2,
            request_id: vec![1; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 101,
            maximum_response_bytes: 16384,
            ..Default::default()
        })
        .into(),
        fence: Some(AssignmentFence {
            sandbox_id: assignment.sandbox().as_bytes().to_vec(),
            incarnation_id: assignment.incarnation().as_bytes().to_vec(),
            assignment_epoch: assignment.epoch().get(),
            desired_generation: assignment.desired_generation().get(),
            assignment_digest: assignment.digest().as_bytes().to_vec(),
            ..Default::default()
        })
        .into(),
        runtime_handle: aos_sandbox_protocol::semantics::host::runtime_handle_v1(
            assignment.incarnation().as_bytes(),
            assignment.epoch().get(),
            assignment.digest().as_bytes(),
        )
        .to_vec(),
        ..Default::default()
    };
    let checked = aos_sandbox_protocol::payload_scope::decode_payload_scope_request(
        &request.encode_to_vec(),
        PeerCredentials {
            uid: 1,
            gid: 1,
            pid: Some(1),
        },
        PeerPolicy {
            uid: 1,
            gid: Some(1),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        100,
    )
    .unwrap_or_else(|error| panic!("test scope request failed: {error}"));
    let semantics =
        aos_sandbox_protocol::semantics::payload_scope::canonical_payload_scope_semantics_v1(
            &checked,
        )
        .unwrap_or_else(|error| panic!("test scope semantics failed: {error}"));
    BrokerGrant::new(
        semantics.verb(),
        semantics.target(),
        semantics.commitment(),
        8192,
        0,
    )
    .unwrap_or_else(|error| panic!("test scope grant failed: {error}"))
}

fn signed_ownership_lease(
    assignment: BrokerAssignment,
    node: NodeId,
    generation: u64,
    expiry: i64,
    signing_key: &SigningKey,
    signer: KeyReference,
) -> SignedOwnershipLease {
    let lease_assignment = LeaseAssignment::new(
        assignment.sandbox(),
        assignment.incarnation(),
        assignment.epoch(),
        assignment.digest(),
    )
    .unwrap_or_else(|error| panic!("test lease assignment failed: {error}"));
    let lease = OwnershipLease::new(
        lease_assignment,
        node,
        generation,
        110,
        expiry,
        5,
        [u8::try_from(generation).unwrap_or(u8::MAX); 16],
    )
    .unwrap_or_else(|error| panic!("test lease failed: {error}"));
    let lease_bytes = aos_sandbox_core::format::encode_ownership_lease(&lease);
    let scope = TrustScopeId::from_bytes([61; 16]);
    let policy = TrustPolicy::new(
        scope,
        SignaturePurpose::OwnershipLease,
        vec![signer.clone()],
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("test lease policy failed: {error}"));
    let policy_bytes = encode_trust_policy(&policy);
    let policy_descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
            .unwrap_or_else(|error| panic!("test lease policy media failed: {error}")),
        &policy_bytes,
    );
    let lease_descriptor = descriptor_for_bytes(
        MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned())
            .unwrap_or_else(|error| panic!("test lease media failed: {error}")),
        &lease_bytes,
    );
    let lease_statement = SignatureStatement::new(
        lease_descriptor,
        scope,
        signer.clone(),
        SignaturePurpose::OwnershipLease,
        110,
        Some(expiry),
        policy_descriptor.clone(),
    )
    .unwrap_or_else(|error| panic!("test lease statement failed: {error}"));
    let lease_signature = sign_statement(lease_statement, signing_key)
        .unwrap_or_else(|error| panic!("test lease signature failed: {error}"));
    let claim = OwnershipClaimV1::acquire(
        [u8::try_from(generation).unwrap_or(u8::MAX).max(1); 16],
        lease_assignment,
        assignment.desired_generation(),
        node,
        100,
    )
    .unwrap_or_else(|error| panic!("test ownership claim failed: {error}"));
    let receipt = OwnershipTransactionReceiptV1::new(signer.clone(), &claim, &lease_bytes)
        .unwrap_or_else(|error| panic!("test ownership receipt failed: {error}"));
    let receipt_descriptor = descriptor_for_bytes(
        MediaType::new(
            PortableMediaType::OwnershipTransactionReceipt
                .as_str()
                .to_owned(),
        )
        .unwrap_or_else(|error| panic!("test receipt media failed: {error}")),
        receipt.canonical_bytes(),
    );
    let receipt_statement = SignatureStatement::new(
        receipt_descriptor,
        scope,
        signer.clone(),
        SignaturePurpose::OwnershipLease,
        110,
        Some(expiry),
        policy_descriptor.clone(),
    )
    .unwrap_or_else(|error| panic!("test receipt statement failed: {error}"));
    let receipt_signature = sign_statement(receipt_statement, signing_key)
        .unwrap_or_else(|error| panic!("test receipt signature failed: {error}"));
    let response = UnverifiedOwnershipLeaseResponse::from_transport(
        lease_bytes,
        encode_signature(&lease_signature),
        receipt.canonical_bytes().to_vec(),
        encode_signature(&receipt_signature),
    )
    .unwrap_or_else(|error| panic!("test ownership response failed: {error}"));
    let anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
        policy_bytes,
        policy_descriptor,
        scope,
        signer.clone(),
        signing_key.verifying_key().to_bytes(),
        DecodeLimits::default(),
    )
    .unwrap_or_else(|error| panic!("test lease anchor failed: {error}"));
    let verifier = OwnershipAuthorityVerifier::new(anchor, signer);
    let live_clock = RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([91; 16])
            .unwrap_or_else(|error| panic!("test provenance failed: {error}")),
        [92; 16],
        150,
        1_000,
    )
    .unwrap_or_else(|error| panic!("test clock failed: {error}"));
    verifier
        .verify_response(&claim, response, &live_clock)
        .unwrap_or_else(|error| panic!("test response verification failed: {error}"))
}

fn proposal(lease_generation: u64, expiry: i64) -> AuthorityPublicationProposalV1 {
    let manifest = manifest();
    let lease_key = SigningKey::from_bytes(&[41; 32]);
    let lease_signer = key_reference("lease", KeyUsage::OwnershipLease, &lease_key);
    let (plan, semantics) = signed_plan(&manifest, lease_signer.clone());
    let broker_assignment = manifest
        .broker_assignment()
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
    let signed_lease = signed_ownership_lease(
        broker_assignment,
        manifest.manifest().node(),
        lease_generation,
        expiry,
        &lease_key,
        lease_signer,
    );
    let template = BrokerDispatchTemplateV1::new(
        plan,
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
        vec![0x0a, 0x02, 0x08, 0x01, 0x12, 0x01, 0xaa],
        vec![BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT],
        semantics,
    )
    .unwrap_or_else(|error| panic!("test template failed: {error}"));
    AuthorityPublicationProposalV1::new(
        manifest,
        signed_lease,
        vec![BrokerAudience::Mount],
        vec![template],
    )
}

pub(crate) fn activation_fixture(
    lease_generation: u64,
) -> (AuthorityPublicationDraftV1, PreparedAuthorityPublicationV1) {
    let source = proposal(lease_generation, 190);
    let lease = source.lease.clone();
    let draft = AuthorityPublicationDraftV1::new(
        source.manifest,
        source.required_audiences,
        source.templates,
    )
    .unwrap_or_else(|error| panic!("test draft failed: {error}"));
    let claim = activation_claim(&draft, lease_generation);
    let prepared = draft
        .clone()
        .bind_lease(&claim, lease)
        .unwrap_or_else(|error| panic!("test bind failed: {error}"));
    (draft, prepared)
}

pub(crate) fn descriptor_free_activation_fixture(
    lease_generation: u64,
) -> (AuthorityPublicationDraftV1, PreparedAuthorityPublicationV1) {
    descriptor_free_control_activation_fixture(lease_generation, RuntimeAction::RUNTIME_ACTION_STOP)
}

pub(crate) fn descriptor_free_stop_draft_with_node(node: u8) -> AuthorityPublicationDraftV1 {
    descriptor_free_stop_draft(manifest_with_node(node))
}

pub(crate) fn descriptor_free_stop_draft_with_generations(
    desired: u64,
    namespace: u64,
) -> AuthorityPublicationDraftV1 {
    descriptor_free_stop_draft(manifest_with_generations(5, desired, namespace))
}

fn descriptor_free_stop_draft(
    manifest: CanonicalAssignmentManifestV1,
) -> AuthorityPublicationDraftV1 {
    let lease_key = SigningKey::from_bytes(&[41; 32]);
    let lease_signer = key_reference("lease", KeyUsage::OwnershipLease, &lease_key);
    let (plan, semantics, body) = signed_host_plan(&manifest, lease_signer);
    let template = BrokerDispatchTemplateV1::new(
        plan,
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
        body,
        Vec::new(),
        semantics,
    )
    .unwrap_or_else(|error| panic!("test Stop template failed: {error}"));
    AuthorityPublicationDraftV1::new(manifest, vec![BrokerAudience::Host], vec![template])
        .unwrap_or_else(|error| panic!("test Stop draft failed: {error}"))
}

pub(crate) fn descriptor_free_control_activation_fixture(
    lease_generation: u64,
    action: RuntimeAction,
) -> (AuthorityPublicationDraftV1, PreparedAuthorityPublicationV1) {
    control_activation_fixture(lease_generation, action, false)
}

pub(crate) fn runtime_scope_activation_fixture(
    lease_generation: u64,
) -> (AuthorityPublicationDraftV1, PreparedAuthorityPublicationV1) {
    control_activation_fixture(lease_generation, RuntimeAction::RUNTIME_ACTION_STOP, true)
}

fn control_activation_fixture(
    lease_generation: u64,
    action: RuntimeAction,
    observe_scope: bool,
) -> (AuthorityPublicationDraftV1, PreparedAuthorityPublicationV1) {
    let mut source = proposal(lease_generation, 190);
    let lease_signer = source.lease.signer().clone();
    let (plan, semantics, body) =
        signed_host_control_plan_with_scope(&source.manifest, lease_signer, action, observe_scope);
    source.templates = vec![
        BrokerDispatchTemplateV1::new(
            plan,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            body,
            Vec::new(),
            semantics,
        )
        .unwrap_or_else(|error| panic!("descriptor-free test template failed: {error}")),
    ];
    source.required_audiences = vec![BrokerAudience::Host];
    let lease = source.lease.clone();
    let draft = AuthorityPublicationDraftV1::new(
        source.manifest,
        source.required_audiences,
        source.templates,
    )
    .unwrap_or_else(|error| panic!("test draft failed: {error}"));
    let claim = activation_claim(&draft, lease_generation);
    let prepared = draft
        .clone()
        .bind_lease(&claim, lease)
        .unwrap_or_else(|error| panic!("test bind failed: {error}"));
    (draft, prepared)
}

pub(crate) fn descriptor_host_activation_fixture(
    lease_generation: u64,
) -> (AuthorityPublicationDraftV1, PreparedAuthorityPublicationV1) {
    let mut source = proposal(lease_generation, 190);
    let lease_signer = source.lease.signer().clone();
    let (plan, semantics, body) = signed_host_plan(&source.manifest, lease_signer);
    source.templates = vec![
        BrokerDispatchTemplateV1::new(
            plan,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            body,
            vec![BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT],
            semantics,
        )
        .unwrap_or_else(|error| panic!("descriptor Host test template failed: {error}")),
    ];
    source.required_audiences = vec![BrokerAudience::Host];
    let lease = source.lease.clone();
    let draft = AuthorityPublicationDraftV1::new(
        source.manifest,
        source.required_audiences,
        source.templates,
    )
    .unwrap_or_else(|error| panic!("descriptor Host draft failed: {error}"));
    let claim = activation_claim(&draft, lease_generation);
    let prepared = draft
        .clone()
        .bind_lease(&claim, lease)
        .unwrap_or_else(|error| panic!("descriptor Host bind failed: {error}"));
    (draft, prepared)
}

pub(crate) fn descriptor_free_mount_activation_fixture()
-> (AuthorityPublicationDraftV1, PreparedAuthorityPublicationV1) {
    let mut source = proposal(1, 190);
    let original = source.templates[0].clone();
    source.templates = vec![
        BrokerDispatchTemplateV1::new(
            original.signed_plan().clone(),
            original.method(),
            original.body_without_deadline().to_vec(),
            Vec::new(),
            original.semantics(),
        )
        .unwrap_or_else(|error| panic!("descriptor-free Mount template failed: {error}")),
    ];
    let lease = source.lease.clone();
    let draft = AuthorityPublicationDraftV1::new(
        source.manifest,
        source.required_audiences,
        source.templates,
    )
    .unwrap_or_else(|error| panic!("descriptor-free Mount draft failed: {error}"));
    let claim = activation_claim(&draft, 1);
    let prepared = draft
        .clone()
        .bind_lease(&claim, lease)
        .unwrap_or_else(|error| panic!("descriptor-free Mount bind failed: {error}"));
    (draft, prepared)
}

pub(crate) fn alternate_descriptor_free_activation_fixture()
-> (AuthorityPublicationDraftV1, PreparedAuthorityPublicationV1) {
    let mut source = proposal(1, 190);
    let lease_signer = source.lease.signer().clone();
    let (plan, semantics, body) = signed_host_plan(&source.manifest, lease_signer);
    let mut request = ApplyRuntimeRequest::decode_from_slice(&body)
        .unwrap_or_else(|error| panic!("alternate Host body decode failed: {error}"));
    let mut header = request
        .header
        .as_option()
        .unwrap_or_else(|| panic!("alternate Host header missing"))
        .clone();
    header.request_id = vec![0x45; 16];
    request.header = Some(header).into();
    let body = request.encode_to_vec();
    source.templates = vec![
        BrokerDispatchTemplateV1::new(
            plan,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            body,
            Vec::new(),
            semantics,
        )
        .unwrap_or_else(|error| panic!("alternate descriptor-free template failed: {error}")),
    ];
    source.required_audiences = vec![BrokerAudience::Host];
    let lease = source.lease.clone();
    let draft = AuthorityPublicationDraftV1::new(
        source.manifest,
        source.required_audiences,
        source.templates,
    )
    .unwrap_or_else(|error| panic!("alternate test draft failed: {error}"));
    let claim = activation_claim(&draft, 1);
    let prepared = draft
        .clone()
        .bind_lease(&claim, lease)
        .unwrap_or_else(|error| panic!("alternate test bind failed: {error}"));
    (draft, prepared)
}

pub(crate) fn activation_claim(
    draft: &AuthorityPublicationDraftV1,
    lease_generation: u64,
) -> OwnershipClaimV1 {
    let manifest = draft.manifest();
    let assignment = manifest
        .broker_assignment()
        .unwrap_or_else(|error| panic!("test assignment failed: {error}"));
    OwnershipClaimV1::acquire(
        [u8::try_from(lease_generation).unwrap_or(u8::MAX).max(1); 16],
        LeaseAssignment::new(
            assignment.sandbox(),
            assignment.incarnation(),
            assignment.epoch(),
            assignment.digest(),
        )
        .unwrap_or_else(|error| panic!("test lease assignment failed: {error}")),
        assignment.desired_generation(),
        draft.manifest().manifest().node(),
        100,
    )
    .unwrap_or_else(|error| panic!("test ownership claim failed: {error}"))
}

#[test]
fn draft_binding_rejects_receipt_claim_substitution() {
    let source = proposal(1, 190);
    let lease = source.lease.clone();
    let draft = AuthorityPublicationDraftV1::new(
        source.manifest,
        source.required_audiences,
        source.templates,
    )
    .unwrap_or_else(|error| panic!("test draft failed: {error}"));
    let claim = activation_claim(&draft, 1);
    let wrong_request = OwnershipClaimV1::acquire(
        [0x55; 16],
        claim.assignment(),
        claim.desired_generation(),
        claim.node(),
        claim.requested_maximum_seconds(),
    )
    .unwrap_or_else(|error| panic!("test wrong request claim failed: {error}"));
    let wrong_generation = OwnershipClaimV1::acquire(
        [1; 16],
        claim.assignment(),
        DesiredGeneration::new(claim.desired_generation().get() + 1),
        claim.node(),
        claim.requested_maximum_seconds(),
    )
    .unwrap_or_else(|error| panic!("test wrong generation claim failed: {error}"));
    let expected = ExpectedOwnershipLease::new(1, lease.digest())
        .unwrap_or_else(|error| panic!("test expected lease failed: {error}"));
    let wrong_action = OwnershipClaimV1::renew(
        [1; 16],
        claim.assignment(),
        claim.desired_generation(),
        claim.node(),
        expected,
        claim.requested_maximum_seconds(),
    )
    .unwrap_or_else(|error| panic!("test wrong action claim failed: {error}"));
    for wrong in [wrong_request, wrong_generation, wrong_action] {
        assert!(matches!(
            draft.clone().bind_lease(&wrong, lease.clone()),
            Err(AuthorityPublicationError::ContextMismatch)
        ));
    }
}

fn clock(wall: i64, boottime: u64) -> RawPairedClockSample {
    RawPairedClockSample::new_untrusted(
        aos_sandbox_core::RawClockProvenance::new_untrusted([91; 16])
            .unwrap_or_else(|error| panic!("test provenance failed: {error}")),
        [92; 16],
        wall,
        boottime,
    )
    .unwrap_or_else(|error| panic!("test clock failed: {error}"))
}

fn publication_artifact_range(bytes: &[u8], artifact: usize) -> std::ops::Range<usize> {
    let mut cursor = 10;
    for index in 0..=artifact {
        let length = u32::from_be_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .unwrap_or_else(|_| panic!("missing test artifact length")),
        ) as usize;
        cursor += 4;
        let range = cursor..cursor + length;
        if index == artifact {
            return range;
        }
        cursor = range.end;
    }
    panic!("missing test artifact")
}

fn replace_publication_artifact(bytes: &mut Vec<u8>, artifact: usize, replacement: &[u8]) {
    let range = publication_artifact_range(bytes, artifact);
    let encoded_length = u32::try_from(replacement.len())
        .unwrap_or_else(|_| panic!("test replacement is too large"))
        .to_be_bytes();
    bytes[range.start - 4..range.start].copy_from_slice(&encoded_length);
    bytes.splice(range, replacement.iter().copied());
}

#[test]
fn publication_is_atomic_idempotent_and_byte_exact_after_reopen() {
    let directory = TestDirectory::new();
    let prepared = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
    let idempotency = IdempotencyKey::new(b"publish-one".to_vec())
        .unwrap_or_else(|error| panic!("test idempotency failed: {error}"));
    let operation = OperationId::from_bytes([70; 16]);
    {
        let (mut journal, _) = Journal::open(directory.journal(), Default::default())
            .unwrap_or_else(|error| panic!("test journal failed: {error}"));
        let mut store = AuthorityPublicationStore::new(&mut journal);
        assert_eq!(
            store
                .publish(&prepared, &idempotency, operation, [71; 16])
                .unwrap_or_else(|error| panic!("test publish failed: {error}")),
            AuthorityPublicationOutcome::Published(operation)
        );
        assert_eq!(
            store
                .publish(&prepared, &idempotency, operation, [72; 16])
                .unwrap_or_else(|error| panic!("test replay failed: {error}")),
            AuthorityPublicationOutcome::Replay(operation)
        );
        let changed = proposal(2, 195)
            .prepare()
            .unwrap_or_else(|error| panic!("test changed prepare failed: {error}"));
        assert!(matches!(
            store.publish(&changed, &idempotency, operation, [73; 16]),
            Err(AuthorityPublicationError::IdempotencyConflict)
        ));
    }
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test reopen failed: {error}"));
    let store = AuthorityPublicationStore::new(&mut journal);
    let current = store
        .current(SandboxId::from_bytes([1; 16]))
        .unwrap_or_else(|error| panic!("test current failed: {error}"))
        .unwrap_or_else(|| panic!("missing current"));
    assert_eq!(current.canonical_bytes(), prepared.canonical_bytes());
    assert_eq!(current.digest(), prepared.digest());
    assert_eq!(current.manifest(), prepared.manifest());
    assert_eq!(current.manifest(), &manifest());
}

#[test]
fn preparation_and_recovery_retain_complete_manifest_and_source_draft() {
    let (draft, prepared) = activation_fixture(1);
    let recovered = decode_prepared(prepared.canonical_bytes(), prepared.digest())
        .unwrap_or_else(|error| panic!("test prepared recovery failed: {error}"));
    assert_eq!(prepared.manifest(), draft.manifest());
    assert_eq!(recovered.manifest(), draft.manifest());
    assert_eq!(prepared.source_draft_digest(), draft.digest());
    assert_eq!(recovered.source_draft_digest(), draft.digest());
    assert_eq!(recovered.canonical_bytes(), prepared.canonical_bytes());
}

#[test]
fn poisoned_publication_snapshot_cannot_be_read_or_replayed_through_a_new_facade() {
    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal failed: {error}"));
    let prepared = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
    let key = IdempotencyKey::new("poisoned-publication")
        .unwrap_or_else(|error| panic!("test key failed: {error}"));
    let operation = OperationId::new();
    AuthorityPublicationStore::new(&mut journal)
        .publish(&prepared, &key, operation, [0xe1; 16])
        .unwrap_or_else(|error| panic!("test publish failed: {error}"));

    // Exercise an actual I/O failure, not a synthetic flag. The old permanent
    // record remains diagnostic data, but cannot serve as current authority.
    std::fs::create_dir(directory.0.join("controller.journal.compact.tmp"))
        .unwrap_or_else(|error| panic!("test failure setup failed: {error}"));
    assert!(matches!(journal.compact(), Err(JournalError::Io(_))));
    assert!(
        journal
            .get(
                RecordNamespace::AuthorityPublication,
                &prepared_key(prepared.digest())
            )
            .is_some()
    );

    for _ in 0..2 {
        let mut store = AuthorityPublicationStore::new(&mut journal);
        assert!(matches!(
            store.current(prepared.sandbox),
            Err(AuthorityPublicationError::Journal(JournalError::Poisoned))
        ));
        assert!(matches!(
            store.prepared(prepared.digest()),
            Err(AuthorityPublicationError::Journal(JournalError::Poisoned))
        ));
        assert!(matches!(
            store.publish(&prepared, &key, operation, [0xe2; 16]),
            Err(AuthorityPublicationError::Journal(JournalError::Poisoned))
        ));
    }

    drop(journal);
    let (mut reopened, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test recovery failed: {error}"));
    assert!(
        AuthorityPublicationStore::new(&mut reopened)
            .current(prepared.sandbox)
            .unwrap_or_else(|error| panic!("test recovered current failed: {error}"))
            .is_some()
    );
}

#[test]
fn publication_replay_requires_its_permanent_record_but_not_current() {
    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal failed: {error}"));
    let first = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test first prepare failed: {error}"));
    let newer = proposal(2, 195)
        .prepare()
        .unwrap_or_else(|error| panic!("test newer prepare failed: {error}"));
    let key = IdempotencyKey::new("historical-publication")
        .unwrap_or_else(|error| panic!("test key failed: {error}"));
    let operation = OperationId::new();
    {
        let mut store = AuthorityPublicationStore::new(&mut journal);
        store
            .publish(&first, &key, operation, [0xd1; 16])
            .unwrap_or_else(|error| panic!("test first publish failed: {error}"));
        let newer_key = IdempotencyKey::new("newer-publication")
            .unwrap_or_else(|error| panic!("test newer key failed: {error}"));
        store
            .publish(&newer, &newer_key, OperationId::new(), [0xd2; 16])
            .unwrap_or_else(|error| panic!("test newer publish failed: {error}"));
        assert_eq!(
            store
                .publish(&first, &key, operation, [0xd3; 16])
                .unwrap_or_else(|error| panic!("test replay failed: {error}")),
            AuthorityPublicationOutcome::Replay(operation)
        );
    }
    journal
        .commit(
            &JournalTransaction::new(
                [0xd4; 16],
                vec![JournalRecord::delete(
                    RecordNamespace::AuthorityPublication,
                    prepared_key(first.digest()),
                )],
            )
            .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("test deletion failed: {error}"));
    assert!(matches!(
        AuthorityPublicationStore::new(&mut journal).publish(&first, &key, operation, [0xd5; 16]),
        Err(AuthorityPublicationError::CorruptCurrent)
    ));
}

#[test]
fn generic_desired_state_cannot_collide_with_publication_keys() {
    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal failed: {error}"));
    let prepared = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
    let key = IdempotencyKey::new("namespace-isolation")
        .unwrap_or_else(|error| panic!("test key failed: {error}"));
    AuthorityPublicationStore::new(&mut journal)
        .publish(&prepared, &key, OperationId::new(), [0xd6; 16])
        .unwrap_or_else(|error| panic!("test publish failed: {error}"));
    journal
        .commit(
            &JournalTransaction::new(
                [0xd7; 16],
                vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        current_key(prepared.sandbox),
                        b"generic-current-collision".to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        prepared_key(prepared.digest()),
                        b"generic-prepared-collision".to_vec(),
                    ),
                ],
            )
            .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("test collision commit failed: {error}"));
    assert_eq!(
        AuthorityPublicationStore::new(&mut journal)
            .current(prepared.sandbox)
            .unwrap_or_else(|error| panic!("test current failed: {error}"))
            .unwrap_or_else(|| panic!("missing test current"))
            .digest(),
        prepared.digest()
    );
}

#[test]
fn current_key_is_bound_to_its_exact_sandbox() {
    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal failed: {error}"));
    let prepared = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
    let key = IdempotencyKey::new("sandbox-key-binding")
        .unwrap_or_else(|error| panic!("test key failed: {error}"));
    AuthorityPublicationStore::new(&mut journal)
        .publish(&prepared, &key, OperationId::new(), [0xd8; 16])
        .unwrap_or_else(|error| panic!("test publish failed: {error}"));
    let current_bytes = journal
        .get(
            RecordNamespace::AuthorityPublication,
            &current_key(prepared.sandbox),
        )
        .unwrap_or_else(|| panic!("missing current bytes"))
        .to_vec();
    let wrong_sandbox = SandboxId::from_bytes([0xee; 16]);
    journal
        .commit(
            &JournalTransaction::new(
                [0xd9; 16],
                vec![JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    current_key(wrong_sandbox),
                    current_bytes,
                )],
            )
            .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("test substitution commit failed: {error}"));
    let store = AuthorityPublicationStore::new(&mut journal);
    assert!(matches!(
        store.current(wrong_sandbox),
        Err(AuthorityPublicationError::CorruptCurrent)
    ));
}

#[test]
fn current_requires_a_byte_exact_permanent_prepared_record() {
    for (case, replacement) in [(1_u8, None), (2_u8, Some(vec![0x55]))] {
        let directory = TestDirectory::new();
        let (mut journal, _) = Journal::open(directory.journal(), Default::default())
            .unwrap_or_else(|error| panic!("test journal open failed: {error}"));
        let prepared = proposal(1, 190)
            .prepare()
            .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
        {
            let mut store = AuthorityPublicationStore::new(&mut journal);
            store
                .publish(
                    &prepared,
                    &IdempotencyKey::new(format!("prepared-cross-link-{case}"))
                        .unwrap_or_else(|error| panic!("test key failed: {error}")),
                    OperationId::new(),
                    [case; 16],
                )
                .unwrap_or_else(|error| panic!("test publish failed: {error}"));
        }
        let record = match replacement {
            Some(bytes) => JournalRecord::put(
                RecordNamespace::AuthorityPublication,
                prepared_key(prepared.digest()),
                bytes,
            ),
            None => JournalRecord::delete(
                RecordNamespace::AuthorityPublication,
                prepared_key(prepared.digest()),
            ),
        };
        journal
            .commit(
                &JournalTransaction::new([case + 10; 16], vec![record])
                    .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("test corruption commit failed: {error}"));

        let store = AuthorityPublicationStore::new(&mut journal);
        assert!(matches!(
            store.current(SandboxId::from_bytes([1; 16])),
            Err(AuthorityPublicationError::CorruptCurrent)
        ));
    }
}

#[test]
fn prepared_lookup_derives_and_validates_self_contained_metadata() {
    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal open failed: {error}"));
    let prepared = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
    journal
        .commit(
            &JournalTransaction::new(
                [31; 16],
                vec![JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    prepared_key(prepared.digest()),
                    prepared.canonical_bytes().to_vec(),
                )],
            )
            .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("test commit failed: {error}"));
    let store = AuthorityPublicationStore::new(&mut journal);
    assert_eq!(
        store
            .prepared(prepared.digest())
            .unwrap_or_else(|error| panic!("test lookup failed: {error}")),
        Some(prepared)
    );
    assert!(
        store
            .prepared(ObjectDigest::from_bytes([0x99; 32]))
            .unwrap_or_else(|error| panic!("test absent lookup failed: {error}"))
            .is_none()
    );
}

#[test]
fn gate_activation_bridge_owns_exact_publication_records_and_facts() {
    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal open failed: {error}"));
    let (draft, prepared) = activation_fixture(1);
    let activation = AuthorityPublicationStore::new(&mut journal)
        .prepare_gate_activation(&draft, &prepared)
        .unwrap_or_else(|error| panic!("test activation preparation failed: {error}"));
    let AuthorityPublicationActivationPartsV1 {
        records,
        sandbox,
        assignment_digest: assignment,
        source_draft_digest: source_draft,
        ownership_authority: authority,
        publication_digest: publication,
        lease_generation,
        lease_digest: lease,
        receipt_action,
        receipt_request_id,
        receipt_claim_digest,
        prepared: recovered_prepared,
    } = activation.into_parts();
    assert!(
        records
            .iter()
            .all(|record| record.namespace() == RecordNamespace::AuthorityPublication)
    );
    assert_eq!(records[0].key(), prepared_key(prepared.digest()));
    assert_eq!(records[0].value(), Some(prepared.canonical_bytes()));
    assert_eq!(records[1].key(), current_key(sandbox));
    assert_eq!(sandbox, prepared.sandbox);
    assert_eq!(assignment, prepared.assignment_digest);
    assert_eq!(source_draft, draft.digest());
    assert_eq!(&authority, draft.ownership_authority());
    assert_eq!(publication, prepared.digest());
    assert_eq!(lease_generation, prepared.lease_generation);
    assert_eq!(lease, prepared.lease_digest);
    assert_eq!(receipt_action, prepared.receipt_action);
    assert_eq!(receipt_request_id, prepared.receipt_request_id);
    assert_eq!(receipt_claim_digest, prepared.receipt_claim_digest);
    assert_eq!(recovered_prepared, prepared);
}

#[test]
fn gate_activation_rejects_conflicting_permanent_digest_value() {
    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal open failed: {error}"));
    let (draft, prepared) = activation_fixture(1);
    journal
        .commit(
            &JournalTransaction::new(
                [37; 16],
                vec![JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    prepared_key(prepared.digest()),
                    vec![0x77],
                )],
            )
            .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("test commit failed: {error}"));
    assert!(matches!(
        AuthorityPublicationStore::new(&mut journal).prepare_gate_activation(&draft, &prepared),
        Err(AuthorityPublicationError::PreparedConflict)
    ));
}

#[test]
fn direct_publish_rejects_conflicting_permanent_digest_value() {
    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal failed: {error}"));
    let prepared = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
    journal
        .commit(
            &JournalTransaction::new(
                [0xdc; 16],
                vec![JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    prepared_key(prepared.digest()),
                    vec![0x77],
                )],
            )
            .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("test corruption commit failed: {error}"));
    let key = IdempotencyKey::new("direct-prepared-conflict")
        .unwrap_or_else(|error| panic!("test key failed: {error}"));

    assert!(matches!(
        AuthorityPublicationStore::new(&mut journal).publish(
            &prepared,
            &key,
            OperationId::new(),
            [0xdd; 16],
        ),
        Err(AuthorityPublicationError::PreparedConflict)
    ));
}

#[test]
fn authority_draft_is_golden_canonical_and_binds_checked_lease() {
    let source = proposal(1, 190);
    let lease = source.lease.clone();
    let draft = AuthorityPublicationDraftV1::new(
        source.manifest.clone(),
        source.required_audiences.clone(),
        source.templates.clone(),
    )
    .unwrap_or_else(|error| panic!("test draft failed: {error}"));
    assert_eq!(&draft.canonical_bytes()[..10], b"AOSCDRF1\0\x01");
    assert_eq!(draft.canonical_bytes().len(), 1_283);
    assert_eq!(
        draft.digest().to_string(),
        "sha256:418353f4a4aca13d2d2bd8b03aaa76a18904aee57c0381d992289ad8e1f79ff1"
    );
    assert_eq!(draft.manifest().digest(), source.manifest.digest());
    assert_eq!(draft.required_audiences(), source.required_audiences);
    assert_eq!(draft.templates().len(), source.templates.len());
    assert!(
        draft
            .templates()
            .iter()
            .zip(&source.templates)
            .all(
                |(recovered, checked)| recovered.digest() == checked.digest()
                    && recovered.canonical_plan() == checked.signed_plan().canonical_plan()
                    && recovered.canonical_plan_signature()
                        == checked.signed_plan().canonical_signature()
            )
    );
    assert_eq!(
        draft.ownership_authority(),
        source.templates[0]
            .signed_plan()
            .plan()
            .ownership_authority()
    );

    let draft_bytes = draft.canonical_bytes().to_vec();
    let claim = activation_claim(&draft, 1);
    let expected = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test proposal failed: {error}"));
    drop(source);
    drop(draft);

    let decoded = AuthorityPublicationDraftV1::from_canonical_bytes(&draft_bytes)
        .unwrap_or_else(|error| panic!("test draft decode failed: {error}"));
    assert_eq!(decoded.canonical_bytes(), draft_bytes);
    let prepared = decoded
        .bind_lease(&claim, lease)
        .unwrap_or_else(|error| panic!("test lease binding failed: {error}"));
    assert_eq!(prepared, expected);
}

#[test]
fn authority_draft_decoder_rejects_substitution_and_bounds() {
    let source = proposal(1, 190);
    let draft = AuthorityPublicationDraftV1::new(
        source.manifest.clone(),
        source.required_audiences.clone(),
        source.templates.clone(),
    )
    .unwrap_or_else(|error| panic!("test draft failed: {error}"));
    for offset in [0_usize, 9, 14, draft.canonical_bytes().len() - 1] {
        let mut bytes = draft.canonical_bytes().to_vec();
        bytes[offset] ^= 1;
        assert!(matches!(
            AuthorityPublicationDraftV1::from_canonical_bytes(&bytes),
            Err(AuthorityPublicationError::InvalidDraft)
        ));
    }
    assert!(matches!(
        AuthorityPublicationDraftV1::new(
            source.manifest,
            vec![BrokerAudience::Mount, BrokerAudience::Mount],
            source.templates,
        ),
        Err(AuthorityPublicationError::IncompleteAudienceSet)
    ));
    assert!(matches!(
        AuthorityPublicationDraftV1::from_canonical_bytes(&vec![
            0;
            MAXIMUM_PUBLICATION_DRAFT_BYTES + 1
        ]),
        Err(AuthorityPublicationError::InvalidDraft)
    ));
}

#[test]
fn draft_roundtrips_multiple_templates_for_one_audience() {
    let mut source = proposal(1, 190);
    let original = source.templates[0].clone();
    let second = BrokerDispatchTemplateV1::new(
        original.signed_plan().clone(),
        original.method(),
        vec![0x0a, 0x02, 0x08, 0x01, 0x12, 0x01, 0xab],
        original.descriptor_roles().to_vec(),
        original.semantics(),
    )
    .unwrap_or_else(|error| panic!("test second template failed: {error}"));
    source.templates.push(second);
    source
        .templates
        .sort_by_key(BrokerDispatchTemplateV1::digest);
    let lease = source.lease.clone();
    let draft = AuthorityPublicationDraftV1::new(
        source.manifest,
        source.required_audiences,
        source.templates,
    )
    .unwrap_or_else(|error| panic!("test draft failed: {error}"));
    assert_eq!(draft.templates().len(), 2);
    let first_binding = draft
        .bind_effect(draft.templates()[0].digest())
        .unwrap_or_else(|error| panic!("first effect binding failed: {error}"));
    let second_binding = draft
        .bind_effect(draft.templates()[1].digest())
        .unwrap_or_else(|error| panic!("second effect binding failed: {error}"));
    assert_eq!(first_binding.audience(), BrokerAudience::Mount);
    assert_ne!(
        first_binding.template_digest(),
        second_binding.template_digest()
    );
    assert_ne!(
        first_binding.body_without_deadline(),
        second_binding.body_without_deadline()
    );
    let decoded = AuthorityPublicationDraftV1::from_canonical_bytes(draft.canonical_bytes())
        .unwrap_or_else(|error| panic!("test draft decode failed: {error}"));
    assert_eq!(decoded, draft);
    let claim = activation_claim(&draft, 1);
    let prepared = draft
        .clone()
        .bind_lease(&claim, lease)
        .unwrap_or_else(|error| panic!("test lease binding failed: {error}"));

    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal failed: {error}"));
    let key = IdempotencyKey::new("multi-template")
        .unwrap_or_else(|error| panic!("test key failed: {error}"));
    AuthorityPublicationStore::new(&mut journal)
        .publish(&prepared, &key, OperationId::new(), [0xda; 16])
        .unwrap_or_else(|error| panic!("test publish failed: {error}"));
    assert_eq!(
        AuthorityPublicationStore::new(&mut journal)
            .current(prepared.sandbox)
            .unwrap_or_else(|error| panic!("test current failed: {error}"))
            .unwrap_or_else(|| panic!("missing test current"))
            .templates()
            .len(),
        2
    );
}

#[test]
fn v1_and_v2_namespaces_require_migration_on_read_and_write() {
    for (case, prefix) in [
        (1_u8, LEGACY_CURRENT_KEY_PREFIX),
        (2_u8, LEGACY_PREPARED_KEY_PREFIX),
        (3_u8, LEGACY_V2_CURRENT_KEY_PREFIX),
        (4_u8, LEGACY_V2_PREPARED_KEY_PREFIX),
    ] {
        let directory = TestDirectory::new();
        let (mut journal, _) = Journal::open(directory.journal(), Default::default())
            .unwrap_or_else(|error| panic!("test journal open failed: {error}"));
        let mut key = prefix.to_vec();
        key.extend_from_slice(&[case; 32]);
        journal
            .commit(
                &JournalTransaction::new(
                    [case; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        key,
                        vec![case],
                    )],
                )
                .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("test commit failed: {error}"));

        let prepared = proposal(1, 190)
            .prepare()
            .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
        let mut store = AuthorityPublicationStore::new(&mut journal);
        assert!(matches!(
            store.current(prepared.sandbox),
            Err(AuthorityPublicationError::MigrationRequired)
        ));
        assert!(matches!(
            store.publish(
                &prepared,
                &IdempotencyKey::new(vec![case])
                    .unwrap_or_else(|error| panic!("test idempotency key failed: {error}")),
                OperationId::from_bytes([case; 16]),
                [case + 10; 16],
            ),
            Err(AuthorityPublicationError::MigrationRequired)
        ));
    }
}

#[test]
fn legacy_magic_under_v3_keys_requires_migration() {
    for magic in [LEGACY_V1_MAGIC, LEGACY_V2_MAGIC] {
        let mut bytes = magic.to_vec();
        bytes.extend_from_slice(&[0; CURRENT_HEADER_BYTES]);
        assert!(matches!(
            decode_prepared(&bytes, ObjectDigest::from_bytes([1; 32])),
            Err(AuthorityPublicationError::MigrationRequired)
        ));
        assert!(matches!(
            decode_current(&bytes),
            Err(AuthorityPublicationError::MigrationRequired)
        ));
    }
}

#[test]
fn unknown_publication_namespace_record_fails_closed() {
    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal failed: {error}"));
    journal
        .commit(
            &JournalTransaction::new(
                [0xdb; 16],
                vec![JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    b"unknown-publication-record".to_vec(),
                    b"unknown".to_vec(),
                )],
            )
            .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("test corruption commit failed: {error}"));
    let prepared = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
    assert!(matches!(
        AuthorityPublicationStore::new(&mut journal).current(prepared.sandbox),
        Err(AuthorityPublicationError::CorruptCurrent)
    ));
}

#[test]
fn malformed_orphan_under_valid_prepared_key_fails_closed() {
    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal failed: {error}"));
    journal
        .commit(
            &JournalTransaction::new(
                [0xde; 16],
                vec![JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    prepared_key(ObjectDigest::from_bytes([0xdf; 32])),
                    vec![0x77],
                )],
            )
            .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("test corruption commit failed: {error}"));
    let prepared = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
    assert!(matches!(
        AuthorityPublicationStore::new(&mut journal).current(prepared.sandbox),
        Err(AuthorityPublicationError::CorruptCurrent)
    ));
}

#[test]
fn publication_record_bound_accounts_for_current_wrapper_and_journal_header() {
    assert_eq!(
        MAXIMUM_PUBLICATION_BYTES
            + CURRENT_HEADER_BYTES
            + JOURNAL_RECORD_HEADER_BYTES
            + CURRENT_KEY_PREFIX.len()
            + 16,
        JOURNAL_RECORD_BYTES
    );
}

#[test]
fn recovery_retains_exact_typed_lease_plan_and_template_bytes() {
    let directory = TestDirectory::new();
    let proposal = proposal(1, 190);
    let expected_lease = proposal.lease.canonical_lease().to_vec();
    let expected_lease_signature = proposal.lease.canonical_signature().to_vec();
    let expected_receipt = proposal.lease.canonical_receipt().to_vec();
    let expected_receipt_signature = proposal.lease.canonical_receipt_signature().to_vec();
    let expected_template = proposal.templates[0].clone();
    let prepared = proposal
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
    {
        let (mut journal, _) = Journal::open(directory.journal(), Default::default())
            .unwrap_or_else(|error| panic!("test journal failed: {error}"));
        AuthorityPublicationStore::new(&mut journal)
            .publish(
                &prepared,
                &IdempotencyKey::new(b"typed".to_vec())
                    .unwrap_or_else(|error| panic!("test key failed: {error}")),
                OperationId::from_bytes([93; 16]),
                [94; 16],
            )
            .unwrap_or_else(|error| panic!("test publish failed: {error}"));
    }

    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test reopen failed: {error}"));
    let current = AuthorityPublicationStore::new(&mut journal)
        .current(SandboxId::from_bytes([1; 16]))
        .unwrap_or_else(|error| panic!("test current failed: {error}"))
        .unwrap_or_else(|| panic!("missing current"));
    assert_eq!(current.lease().canonical_lease(), expected_lease);
    assert_eq!(
        current.lease().canonical_signature(),
        expected_lease_signature
    );
    assert_eq!(current.lease().canonical_receipt(), expected_receipt);
    assert_eq!(
        current.lease().canonical_receipt_signature(),
        expected_receipt_signature
    );
    assert_eq!(current.templates().len(), 1);
    let recovered = &current.templates()[0];
    assert_eq!(recovered.digest(), expected_template.digest());
    assert_eq!(
        recovered.canonical_plan(),
        expected_template.signed_plan().canonical_plan()
    );
    assert_eq!(
        recovered.canonical_plan_signature(),
        expected_template.signed_plan().canonical_signature()
    );
    assert_eq!(
        recovered.body_without_deadline(),
        expected_template.body_without_deadline()
    );
    assert_eq!(
        recovered.descriptor_roles(),
        expected_template.descriptor_roles()
    );
    assert_eq!(recovered.semantics(), expected_template.semantics());
}

#[test]
fn selection_rejects_substitution_wrong_audience_and_stale_publication() {
    let directory = TestDirectory::new();
    let first_proposal = proposal(1, 190);
    let template_digest = first_proposal.templates[0].digest();
    let first = first_proposal
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal failed: {error}"));
    let mut store = AuthorityPublicationStore::new(&mut journal);
    store
        .publish(
            &first,
            &IdempotencyKey::new(b"first-selection".to_vec())
                .unwrap_or_else(|error| panic!("test key failed: {error}")),
            OperationId::from_bytes([95; 16]),
            [96; 16],
        )
        .unwrap_or_else(|error| panic!("test publish failed: {error}"));

    let attempt = store
        .select_current_attempt(
            SandboxId::from_bytes([1; 16]),
            first.digest(),
            BrokerAudience::Mount,
            template_digest,
            2_000,
            clock(150, 1_000),
        )
        .unwrap_or_else(|error| panic!("test selection failed: {error}"));
    assert_eq!(attempt.template_digest(), template_digest);
    assert_eq!(attempt.lease_digest(), first.lease_digest);
    assert!(matches!(
        store.select_current_attempt(
            SandboxId::from_bytes([1; 16]),
            first.digest(),
            BrokerAudience::Host,
            template_digest,
            2_000,
            clock(150, 1_000),
        ),
        Err(AuthorityPublicationError::WrongAudience)
    ));
    assert!(matches!(
        store.select_current_attempt(
            SandboxId::from_bytes([1; 16]),
            first.digest(),
            BrokerAudience::Mount,
            ObjectDigest::from_bytes([97; 32]),
            2_000,
            clock(150, 1_000),
        ),
        Err(AuthorityPublicationError::TemplateAbsent)
    ));

    let renewed = proposal(2, 195)
        .prepare()
        .unwrap_or_else(|error| panic!("test renewal prepare failed: {error}"));
    store
        .publish(
            &renewed,
            &IdempotencyKey::new(b"renewed-selection".to_vec())
                .unwrap_or_else(|error| panic!("test key failed: {error}")),
            OperationId::from_bytes([98; 16]),
            [99; 16],
        )
        .unwrap_or_else(|error| panic!("test renewal publish failed: {error}"));
    assert!(matches!(
        store.select_current_attempt(
            SandboxId::from_bytes([1; 16]),
            first.digest(),
            BrokerAudience::Mount,
            template_digest,
            2_000,
            clock(150, 1_000),
        ),
        Err(AuthorityPublicationError::StaleCurrent)
    ));
}

#[test]
fn incomplete_substituted_and_noncanonical_audience_sets_fail_closed() {
    let mut missing = proposal(1, 190);
    missing.required_audiences = vec![BrokerAudience::Host, BrokerAudience::Mount];
    assert!(matches!(
        missing.prepare(),
        Err(AuthorityPublicationError::IncompleteAudienceSet)
    ));
    let mut duplicate = proposal(1, 190);
    duplicate.required_audiences = vec![BrokerAudience::Mount, BrokerAudience::Mount];
    assert!(matches!(
        duplicate.prepare(),
        Err(AuthorityPublicationError::IncompleteAudienceSet)
    ));
    let mut wrong_lease = proposal(1, 190);
    wrong_lease.manifest = manifest_with_node(99);
    assert!(matches!(
        wrong_lease.prepare(),
        Err(AuthorityPublicationError::ContextMismatch)
    ));
}

#[test]
fn renewal_advances_and_rollback_or_equal_generation_equivocation_fails() {
    let directory = TestDirectory::new();
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal failed: {error}"));
    let mut store = AuthorityPublicationStore::new(&mut journal);
    for (generation, expiry, key, operation, transaction) in [
        (1, 190, b"one".as_slice(), [1; 16], [11; 16]),
        (2, 195, b"two".as_slice(), [2; 16], [12; 16]),
    ] {
        let prepared = proposal(generation, expiry)
            .prepare()
            .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
        let idempotency = IdempotencyKey::new(key.to_vec())
            .unwrap_or_else(|error| panic!("test key failed: {error}"));
        store
            .publish(
                &prepared,
                &idempotency,
                OperationId::from_bytes(operation),
                transaction,
            )
            .unwrap_or_else(|error| panic!("test renewal failed: {error}"));
    }
    let rollback = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test rollback prepare failed: {error}"));
    let rollback_key = IdempotencyKey::new(b"rollback".to_vec())
        .unwrap_or_else(|error| panic!("test rollback key failed: {error}"));
    assert!(matches!(
        store.publish(
            &rollback,
            &rollback_key,
            OperationId::from_bytes([3; 16]),
            [13; 16],
        ),
        Err(AuthorityPublicationError::GenerationRollback)
    ));
    let equivocation = proposal(2, 196)
        .prepare()
        .unwrap_or_else(|error| panic!("test equivocation prepare failed: {error}"));
    let equivocation_key = IdempotencyKey::new(b"equivocation".to_vec())
        .unwrap_or_else(|error| panic!("test equivocation key failed: {error}"));
    assert!(matches!(
        store.publish(
            &equivocation,
            &equivocation_key,
            OperationId::from_bytes([4; 16]),
            [14; 16],
        ),
        Err(AuthorityPublicationError::GenerationEquivocation)
    ));
}

#[test]
fn successor_cannot_change_the_receipt_authority() {
    let current = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test current prepare failed: {error}"));
    let mut next = proposal(2, 195)
        .prepare()
        .unwrap_or_else(|error| panic!("test next prepare failed: {error}"));
    let other_key = SigningKey::from_bytes(&[42; 32]);
    next.receipt_authority = key_reference("other-lease", KeyUsage::OwnershipLease, &other_key);

    assert!(matches!(
        validate_successor(&current, &next),
        Err(AuthorityPublicationError::ContextMismatch)
    ));
}

#[test]
fn a_prepared_record_without_current_is_never_observed_as_current() {
    let directory = TestDirectory::new();
    let prepared = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
    let (mut journal, _) = Journal::open(directory.journal(), Default::default())
        .unwrap_or_else(|error| panic!("test journal failed: {error}"));
    journal
        .commit(
            &JournalTransaction::new(
                [80; 16],
                vec![JournalRecord::put(
                    RecordNamespace::AuthorityPublication,
                    prepared_key(prepared.digest()),
                    prepared.canonical_bytes().to_vec(),
                )],
            )
            .unwrap_or_else(|error| panic!("test transaction failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("test partial commit failed: {error}"));
    let store = AuthorityPublicationStore::new(&mut journal);
    assert!(
        store
            .current(SandboxId::from_bytes([1; 16]))
            .unwrap_or_else(|error| panic!("test current failed: {error}"))
            .is_none()
    );
}

#[test]
fn recomputed_outer_digests_do_not_hide_inner_substitution() {
    let prepared = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));

    let mut semantic_tamper = prepared.clone();
    let last = semantic_tamper
        .bytes
        .last_mut()
        .unwrap_or_else(|| panic!("empty publication"));
    *last ^= 1;
    semantic_tamper.digest = publication_digest(&semantic_tamper.bytes);
    assert!(matches!(
        decode_current(&encode_current(&semantic_tamper)),
        Err(AuthorityPublicationError::CorruptCurrent)
    ));

    let mut summary_tamper = prepared;
    summary_tamper.node = [99; 16];
    summary_tamper.digest = publication_digest(&summary_tamper.bytes);
    assert!(matches!(
        decode_current(&encode_current(&summary_tamper)),
        Err(AuthorityPublicationError::CorruptCurrent)
    ));
}

#[test]
fn recomputed_outer_digest_does_not_hide_receipt_substitution_or_truncation() {
    let original = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test prepare failed: {error}"));
    let substitute = proposal(2, 195);

    for (artifact, replacement) in [
        (3, substitute.lease.canonical_receipt()),
        (4, substitute.lease.canonical_receipt_signature()),
    ] {
        let mut substituted = original.clone();
        replace_publication_artifact(&mut substituted.bytes, artifact, replacement);
        substituted.digest = publication_digest(&substituted.bytes);
        assert!(matches!(
            decode_current(&encode_current(&substituted)),
            Err(AuthorityPublicationError::CorruptCurrent)
        ));

        let mut truncated = original.clone();
        let range = publication_artifact_range(&truncated.bytes, artifact);
        truncated.bytes.remove(range.end - 1);
        truncated.digest = publication_digest(&truncated.bytes);
        assert!(matches!(
            decode_current(&encode_current(&truncated)),
            Err(AuthorityPublicationError::CorruptCurrent)
        ));
    }
}
