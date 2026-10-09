//! Original passive canonical publication regressions and fixtures.

use std::path::PathBuf;

use aos_proto::aos::sandbox::local::v1::{
    ApplyRuntimeRequest, AssignmentFence, Audience, BrokerDescriptorRole, BrokerMethod, Feature,
    RequestHeader, ResourceLimit, RuntimeAction,
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

use aos_sandbox_ownership_protocol::{
    OwnershipAuthorityVerifier, OwnershipClaimV1, OwnershipTransactionReceiptV1,
    UnverifiedOwnershipLeaseResponse, ExpectedOwnershipLease,
};
use crate::dispatch_template::BrokerDispatchSemanticIdentityV1;
use crate::authorization_artifact::{
    BrokerPlanPreparation, ReturnedSignature, SignedBrokerPlan, SigningAuthority,
};

use crate::authorization_artifact::tests::{authority, key_reference};
use super::*;

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
    manifest_with_spec(
        node,
        desired,
        namespace,
        descriptor(PortableMediaType::SandboxSpec, 9),
    )
}

fn manifest_with_spec(
    node: u8,
    desired: u64,
    namespace: u64,
    spec: ObjectDescriptor,
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
        spec,
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
        ProtocolVersion::new(2, 0),
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
    let preparation = BrokerPlanPreparation::new(
        plan,
        authority(
            "controller",
            SignaturePurpose::BrokerAuthorization,
            &key,
            20,
        ),
    )
    .unwrap_or_else(|error| panic!("test plan preparation failed: {error}"));
    let signature = sign_statement(preparation.signing_request().statement().clone(), &key)
        .unwrap_or_else(|error| panic!("test signing failed: {error}"));
    let signed = preparation
        .complete(ReturnedSignature::Bytes(signature.signature()), 150)
        .unwrap_or_else(|error| panic!("test signed plan failed: {error}"));
    (signed, semantics)
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
    proposal_with_manifest(manifest(), lease_generation, expiry)
}

fn proposal_with_manifest(
    manifest: CanonicalAssignmentManifestV1,
    lease_generation: u64,
    expiry: i64,
) -> AuthorityPublicationProposalV1 {
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
) -> (AuthorityPublicationDraftV1, PublicationHistoryV1) {
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
        "sha256:017c70a0062fb357ea1a11fe6630d8280912c7cf1da35be10a9a2e5688fa57ae"
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
            Err(PublicationHistoryError::InvalidDraft)
        ));
    }
    assert!(matches!(
        AuthorityPublicationDraftV1::new(
            source.manifest,
            vec![BrokerAudience::Mount, BrokerAudience::Mount],
            source.templates,
        ),
        Err(PublicationHistoryError::IncompleteAudienceSet)
    ));
    assert!(matches!(
        AuthorityPublicationDraftV1::from_canonical_bytes(&vec![
            0;
            MAXIMUM_PUBLICATION_DRAFT_BYTES + 1
        ]),
        Err(PublicationHistoryError::InvalidDraft)
    ));
}
#[test]
fn rich_v1_codec_round_trips_and_rejects_non_v1_headers() {
    let prepared = proposal(1, 190)
        .prepare()
        .unwrap_or_else(|error| panic!("test preparation failed: {error}"));
    assert_eq!(&prepared.canonical_bytes()[..10], b"AOSCPUB1\0\x01");
    assert_eq!(
        decode_prepared(prepared.canonical_bytes(), prepared.digest())
            .unwrap_or_else(|error| panic!("test prepared decode failed: {error}")),
        prepared
    );

    let current = encode_current(&prepared);
    let (decoded, _, _) = decode_current(&current)
        .unwrap_or_else(|error| panic!("test current decode failed: {error}"))
        .into_parts();
    assert_eq!(decoded.canonical_bytes(), prepared.canonical_bytes());
    assert_eq!(decoded.digest(), prepared.digest());

    for version in [0_u16, 2] {
        let mut prepared_bytes = prepared.canonical_bytes().to_vec();
        prepared_bytes[8..10].copy_from_slice(&version.to_be_bytes());
        assert!(matches!(
            decode_prepared(&prepared_bytes, publication_digest(&prepared_bytes)),
            Err(PublicationHistoryError::CorruptCurrent)
        ));

        let mut current_bytes = current.clone();
        current_bytes[8..10].copy_from_slice(&version.to_be_bytes());
        assert!(matches!(
            decode_current(&current_bytes),
            Err(PublicationHistoryError::CorruptCurrent)
        ));
    }

    let mut wrong_magic = prepared.canonical_bytes().to_vec();
    wrong_magic[0] ^= 1;
    assert!(matches!(
        decode_prepared(&wrong_magic, publication_digest(&wrong_magic)),
        Err(PublicationHistoryError::CorruptCurrent)
    ));

    let mut wrong_current_magic = current;
    wrong_current_magic[0] ^= 1;
    assert!(matches!(
        decode_current(&wrong_current_magic),
        Err(PublicationHistoryError::CorruptCurrent)
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
fn incomplete_substituted_and_noncanonical_audience_sets_fail_closed() {
    let mut missing = proposal(1, 190);
    missing.required_audiences = vec![BrokerAudience::Host, BrokerAudience::Mount];
    assert!(matches!(
        missing.prepare(),
        Err(PublicationHistoryError::IncompleteAudienceSet)
    ));
    let mut duplicate = proposal(1, 190);
    duplicate.required_audiences = vec![BrokerAudience::Mount, BrokerAudience::Mount];
    assert!(matches!(
        duplicate.prepare(),
        Err(PublicationHistoryError::IncompleteAudienceSet)
    ));
    let mut dedicated_guardian = proposal(1, 190);
    dedicated_guardian.required_audiences = vec![BrokerAudience::Guardian];
    assert!(matches!(
        encode_draft(
            &dedicated_guardian.manifest,
            &dedicated_guardian.required_audiences,
            &dedicated_guardian.templates,
        ),
        Err(PublicationHistoryError::UnsupportedBrokerAudience)
    ));
    assert!(matches!(
        dedicated_guardian.prepare(),
        Err(PublicationHistoryError::UnsupportedBrokerAudience)
    ));
    for reserved in [0, 5] {
        assert!(matches!(
            audience_from_code(reserved),
            Err(PublicationHistoryError::CorruptCurrent)
        ));
    }
    let mut wrong_lease = proposal(1, 190);
    wrong_lease.manifest = manifest_with_node(99);
    assert!(matches!(
        wrong_lease.prepare(),
        Err(PublicationHistoryError::ContextMismatch)
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
        current.require_successor(&next),
        Err(PublicationHistoryError::ContextMismatch)
    ));
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
        Err(PublicationHistoryError::CorruptCurrent)
    ));

    let mut summary_tamper = prepared;
    summary_tamper.node = [99; 16];
    summary_tamper.digest = publication_digest(&summary_tamper.bytes);
    assert!(matches!(
        decode_current(&encode_current(&summary_tamper)),
        Err(PublicationHistoryError::CorruptCurrent)
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
            Err(PublicationHistoryError::CorruptCurrent)
        ));

        let mut truncated = original.clone();
        let range = publication_artifact_range(&truncated.bytes, artifact);
        truncated.bytes.remove(range.end - 1);
        truncated.digest = publication_digest(&truncated.bytes);
        assert!(matches!(
            decode_current(&encode_current(&truncated)),
            Err(PublicationHistoryError::CorruptCurrent)
        ));
    }
}
