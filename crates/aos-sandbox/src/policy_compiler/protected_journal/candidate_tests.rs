//! Candidate byte-consistency fixtures using the real pure policy compiler.
//!
//! Synthetic input verifiers exist only in this test module. These fixtures do
//! not establish installed owner custody, publication authority, or read grants.

use aos_sandbox_core::{
    CacheDomainId, ResourceDimension, ResourceId, Selector,
    model::{
        CacheDomain, CacheDomainKind, Optimization, OptimizationKind, OptimizationProfile,
        RevocationMode, RevocationPolicy,
    },
};

use super::*;
use crate::policy_compiler::{
    AuthenticatedCacheDomainV1, AuthenticatedEndpointCatalogV1, AuthenticatedNamespaceCatalogV1,
    AuthenticatedSandboxProjectRelationV1, BackendCapabilitiesV1, BackendEnforcementSetV1,
    CacheDomainBindingV1, CacheDomainInputV1, CacheDomainVerifierV1, EndpointCatalogVerifierV1,
    HardEnforcementV1, HardLimitRequestV1, HardLimitValueV1, HardResourceKeyV1,
    HardResourceProfileV1, NamespaceCatalogVerifierV1, NodePolicyInputV1,
    PORTABLE_LIMIT_DIMENSIONS, PolicyCompilerLimitsV1, PolicyCompilerV1, PolicyLayerV1,
    ProjectPolicyInputV1, RequestPolicyInputV1, RevocationInputV1,
    SandboxProjectRelationVerifierV1, SitePolicyInputV1,
};

struct SyntheticInputVerifier;

impl SandboxProjectRelationVerifierV1 for SyntheticInputVerifier {
    fn verify(&self, _: SandboxId, _: ProjectId, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

impl CacheDomainVerifierV1 for SyntheticInputVerifier {
    fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

impl EndpointCatalogVerifierV1 for SyntheticInputVerifier {
    fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

impl NamespaceCatalogVerifierV1 for SyntheticInputVerifier {
    fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

const ENFORCEMENT: [HardEnforcementV1; 7] = [
    HardEnforcementV1::CgroupV2,
    HardEnforcementV1::BrokerLedger,
    HardEnforcementV1::ZfsQuota,
    HardEnforcementV1::NodeBoundedSharedResidency,
    HardEnforcementV1::HardIsolatedResidency,
    HardEnforcementV1::CombinedFileDescriptor,
    HardEnforcementV1::CombinedMemoryAccounting,
];

fn resources(amount: Option<u64>) -> HardResourceProfileV1 {
    let entry = |key| {
        match amount {
            Some(amount) => HardLimitRequestV1::new(
                key,
                HardLimitValueV1::Bounded(amount),
                Some(
                    ENFORCEMENT
                        .into_iter()
                        .find(|mechanism| mechanism.supports(key))
                        .expect("registered enforcement"),
                ),
            ),
            None => HardLimitRequestV1::new(key, HardLimitValueV1::Inherit, None),
        }
        .expect("complete fixture limit")
    };

    HardResourceProfileV1::new(
        PORTABLE_LIMIT_DIMENSIONS
            .into_iter()
            .map(|dimension| entry(HardResourceKeyV1::Portable(dimension)))
            .collect(),
        ResourceDimension::ALL
            .into_iter()
            .map(|dimension| entry(HardResourceKeyV1::Accounting(dimension)))
            .collect(),
    )
    .expect("complete fixture resource profile")
}

pub(super) fn fixture(amount: u64) -> VerifiedPolicyPublicationV1 {
    let project = ProjectId::from_bytes([1; 16]);
    let sandbox = SandboxId::from_bytes([2; 16]);
    let verifier = SyntheticInputVerifier;
    let domain = AuthenticatedCacheDomainV1::authenticate(
        CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([3; 16])),
        CacheDomainBindingV1::Project(project),
        &verifier,
    )
    .expect("synthetic project domain");
    let ceiling = PolicyLayerV1::new(
        Vec::new(),
        resources(Some(amount)),
        Vec::new(),
        Vec::new(),
        CacheDomainInputV1::Exact(domain),
        RevocationInputV1::Exact(RevocationPolicy::new(RevocationMode::DenyNew, 0)),
    )
    .expect("explicit synthetic ceiling");
    let inherited = PolicyLayerV1::new(
        Vec::new(),
        resources(None),
        Vec::new(),
        Vec::new(),
        CacheDomainInputV1::Inherit,
        RevocationInputV1::Inherit,
    )
    .expect("inherited fixture layer");
    let input = PolicyCompilerInputV1::new(
        AuthenticatedSandboxProjectRelationV1::authenticate(sandbox, project, &verifier)
            .expect("synthetic relation"),
        NodePolicyInputV1::new(ceiling).expect("explicit node ceiling"),
        SitePolicyInputV1::new(inherited.clone()).expect("site fixture"),
        ProjectPolicyInputV1::new(project, inherited.clone()).expect("project fixture"),
        Vec::new(),
        RequestPolicyInputV1::new(inherited).expect("request fixture"),
        AuthenticatedEndpointCatalogV1::authenticate(Vec::new(), &verifier)
            .expect("empty fixture catalog"),
        AuthenticatedNamespaceCatalogV1::authenticate(Vec::new(), &verifier)
            .expect("empty fixture namespace"),
        BackendCapabilitiesV1::new(
            BackendEnforcementSetV1::new(ENFORCEMENT.to_vec()).expect("ordered fixture mechanisms"),
            Vec::new(),
            Vec::new(),
        )
        .expect("fixture backend"),
        PolicyCompilerLimitsV1::DEFAULT,
    )
    .expect("complete synthetic compiler input");
    let normalized_input = normalized_policy_input_digest_v1(&input).expect("normalized input");
    let candidate = PolicyCompilerV1::compile(input).expect("real pure compilation");
    let diagnostics =
        super::super::model::canonical_bytes(DIAGNOSTICS_DOMAIN, candidate.explanation())
            .expect("real compiler diagnostics");
    let prerequisites = PolicyPublicationPrerequisitesV1::new(
        ObjectDigest::from_bytes([4; 32]),
        ObjectDigest::from_bytes([5; 32]),
        ObjectDigest::from_bytes([6; 32]),
        ObjectDigest::from_bytes([7; 32]),
        11,
    )
    .expect("synthetic prerequisite claims");

    // The record encoder's input is assembled only inside this codec fixture;
    // no protected publication verifier or journal authority is manufactured.
    VerifiedPolicyPublicationV1 {
        project,
        sandbox,
        normalized_input,
        candidate,
        diagnostics,
        prerequisites,
    }
}

fn encoded_fixture(verified: &VerifiedPolicyPublicationV1) -> (Vec<u8>, Vec<u8>) {
    let diagnostics = digest_bytes(DIAGNOSTICS_DOMAIN, &verified.diagnostics);
    let candidate = encode_candidate_payload(13, verified, diagnostics).expect("V3 candidate");
    let current = encode_current_payload(
        verified.project,
        verified.sandbox,
        13,
        verified.candidate.commitment().digest(),
        verified.normalized_input,
        diagnostics,
        &verified.prerequisites,
    );
    (candidate, current)
}

fn legacy_v2(bytes: &[u8]) -> Vec<u8> {
    let mut legacy = bytes[..CANDIDATE_V2_FIXED_BYTES].to_vec();
    legacy[8..10].copy_from_slice(&2_u16.to_be_bytes());
    legacy.extend_from_slice(&bytes[CANDIDATE_V3_FIXED_BYTES..]);
    legacy
}

fn replace_output(bytes: &[u8], index: usize, replacement: &[u8]) -> Vec<u8> {
    let header = decode_candidate_header(bytes).expect("fixture header");
    let fields = candidate_output_bytes(bytes).expect("original canonical outputs");
    let mut changed = bytes[..header.output_offset].to_vec();
    let descriptor_offset = 314 + 41 * index;
    changed[descriptor_offset + 1..descriptor_offset + 33]
        .copy_from_slice(&Sha256::digest(replacement));
    changed[descriptor_offset + 33..descriptor_offset + 41]
        .copy_from_slice(&(replacement.len() as u64).to_be_bytes());
    for (position, field) in fields.into_iter().enumerate() {
        let field = if position == index {
            replacement
        } else {
            field
        };
        changed.extend_from_slice(&(field.len() as u32).to_be_bytes());
        changed.extend_from_slice(field);
    }
    changed
}

#[test]
fn candidate_v3_roundtrip_retains_exact_existing_compiler_preimage_and_outputs() {
    let verified = fixture(4096);
    let (bytes, current) = encoded_fixture(&verified);
    let header = validate_candidate_payload(&bytes).expect("complete candidate consistency");
    assert!(header.has_complete_preimage());
    assert!(header.matches_current(&decode_current_payload(&current).expect("Current")));
    assert_eq!(
        header.preimage,
        Some(verified.candidate.commitment_preimage())
    );

    let portable = verified.candidate.portable();
    assert_eq!(
        candidate_output_bytes(&bytes).expect("borrowed canonical outputs"),
        [
            portable.policy_bytes(),
            portable.optimization_bytes(),
            portable.namespace_graph_bytes(),
            portable.advisory_program_bytes()
        ]
    );
    let original_hash = super::super::model::digest(
        b"aos.sandbox.compiled-policy-candidate.v2",
        &(
            verified.candidate.authority().commitment(),
            verified.candidate.namespace().commitment(),
            verified.candidate.hard_resources().commitment(),
            verified.candidate.advisory().commitment(),
            portable.policy_descriptor(),
            portable.optimization_descriptor(),
            portable.namespace_graph_descriptor(),
            portable.advisory_program_descriptor(),
            verified.candidate.explanation().commitment(),
        ),
    )
    .expect("unchanged original commitment tuple");
    assert_eq!(header.candidate, original_hash);
}

#[test]
fn candidate_v2_is_observation_only_even_with_exact_current_claims() {
    let verified = fixture(4096);
    let (bytes, current) = encoded_fixture(&verified);
    let legacy = legacy_v2(&bytes);
    let header = validate_candidate_payload(&legacy).expect("legacy structural replay");
    assert!(!header.has_complete_preimage());
    assert!(header.matches_current(&decode_current_payload(&current).expect("Current")));
    assert_eq!(
        candidate_output_bytes(&legacy).unwrap(),
        candidate_output_bytes(&bytes).unwrap()
    );

    let mut relabeled = legacy;
    relabeled[8..10].copy_from_slice(&3_u16.to_be_bytes());
    assert!(validate_candidate_payload(&relabeled).is_err());
}

#[test]
fn candidate_v3_rejects_all_four_repaired_output_substitutions() {
    let (bytes, _) = encoded_fixture(&fixture(4096));
    let other = fixture(4097);
    let optimization = encode_optimization(
        &OptimizationProfile::new(vec![Optimization::new(
            OptimizationKind::Readahead,
            Selector::Resource {
                resource: ResourceId::from_bytes([8; 16]),
            },
            1,
        )])
        .expect("canonical unrelated optimization"),
    );
    let namespace = super::super::model::canonical_bytes(
        b"aos.sandbox.portable-namespace-graph.v1",
        &serde_json::json!({"substituted": true}),
    )
    .unwrap();
    let advisory = super::super::model::canonical_bytes(
        b"aos.sandbox.portable-advisory-program.v1",
        &serde_json::json!({"substituted": true}),
    )
    .unwrap();
    let replacements = [
        other.candidate.portable().policy_bytes(),
        optimization.as_slice(),
        namespace.as_slice(),
        advisory.as_slice(),
    ];

    for (index, replacement) in replacements.into_iter().enumerate() {
        let changed = replace_output(&bytes, index, replacement);
        assert!(
            validate_candidate_payload(&legacy_v2(&changed)).is_ok(),
            "substitution {index} has repaired canonical output descriptors"
        );
        assert!(
            validate_candidate_payload(&changed).is_err(),
            "V3 must reject substitution {index} against the original full preimage"
        );
    }
}

#[test]
fn candidate_v3_rejects_every_changed_or_zero_plan_commitment() {
    let (bytes, _) = encoded_fixture(&fixture(4096));
    for index in 0..5 {
        let offset = CANDIDATE_V2_FIXED_BYTES + index * 32;
        for replacement in [[9; 32], [0; 32]] {
            let mut changed = bytes.clone();
            changed[offset..offset + 32].copy_from_slice(&replacement);
            assert!(validate_candidate_payload(&changed).is_err());
        }
    }
}

#[test]
fn candidate_current_join_rejects_target_generation_and_tuple_substitution() {
    let (bytes, current) = encoded_fixture(&fixture(4096));
    let header = validate_candidate_payload(&bytes).unwrap();
    let current_header = decode_current_payload(&current).unwrap();

    for (offset, length) in [(10, 16), (26, 16), (306, 8), (74, 32), (106, 32)] {
        let mut changed = bytes.clone();
        changed[offset..offset + length].fill(9);
        let changed = validate_candidate_payload(&changed).expect("canonical changed claim");
        assert!(!changed.matches_current(&current_header));
    }

    // Independent claim mutations remain well-framed; none is a currentness proof.
    for (offset, length) in [(10, 16), (26, 16), (42, 8), (50, 32), (82, 32), (114, 32)] {
        let mut changed = current.clone();
        changed[offset..offset + length].fill(9);
        let changed = decode_current_payload(&changed).expect("canonical changed claim");
        assert!(!header.matches_current(&changed));
    }
    let changed_prerequisites = PolicyPublicationPrerequisitesV1::new(
        ObjectDigest::from_bytes([9; 32]),
        ObjectDigest::from_bytes([5; 32]),
        ObjectDigest::from_bytes([6; 32]),
        ObjectDigest::from_bytes([7; 32]),
        11,
    )
    .unwrap();
    let mut changed = decode_current_payload(&current).unwrap();
    changed.prerequisites = changed_prerequisites.digest();
    changed.prerequisite_tuple = changed_prerequisites;
    assert!(!header.matches_current(&changed));
}

#[test]
fn candidate_versions_require_exact_framing_and_nonzero_descriptors() {
    let (bytes, _) = encoded_fixture(&fixture(4096));
    let legacy = legacy_v2(&bytes);
    for valid in [&bytes, &legacy] {
        for length in [0, 8, 10, CANDIDATE_V2_FIXED_BYTES - 1, valid.len() - 1] {
            assert!(validate_candidate_payload(&valid[..length]).is_err());
        }
        let mut trailing = valid.as_slice().to_vec();
        trailing.push(0);
        assert!(validate_candidate_payload(&trailing).is_err());
        let mut unknown = valid.as_slice().to_vec();
        unknown[8..10].copy_from_slice(&4_u16.to_be_bytes());
        assert!(validate_candidate_payload(&unknown).is_err());
        let mut wrong_media = valid.as_slice().to_vec();
        wrong_media[314] = 4;
        assert!(validate_candidate_payload(&wrong_media).is_err());
        let mut zero_size = valid.as_slice().to_vec();
        zero_size[347..355].fill(0);
        assert!(validate_candidate_payload(&zero_size).is_err());
    }
}
