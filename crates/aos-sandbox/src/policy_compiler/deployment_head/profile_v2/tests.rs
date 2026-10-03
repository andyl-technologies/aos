//! Explicit-profile fixtures with real protected role/head writes.
//!
//! Temporary UID-owned journals exercise the same head reducer, not installed
//! Root custody. Synthetic verifiers appear only in the pure intersection test;
//! these tests confer no Source genesis, catalog currentness, or worker authority.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::{
    AttachmentSlotId, CacheDomainId, FeatureRef, Grant, GrantId, NetworkEndpointId, Operation,
    OperationSet, PathName, RelativePath, ResourceId, ResourceKind, SandboxId, Selector,
    model::{CacheDomain, CacheDomainKind, RevocationMode, RevocationPolicy},
};
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::journal::JournalLimits;
use crate::policy_compiler::{
    AdvisoryActionV1, AdvisoryDegradationV1, AdvisoryKindV1, AuthenticatedCacheDomainV1,
    AuthenticatedSandboxProjectRelationV1, CacheDomainBindingV1, CacheDomainInputV1,
    CacheDomainVerifierV1, EndpointCatalogVerifierV1, EndpointUseV1, LogicalSourceV1,
    NamespaceBackendFeatureV1, NamespaceCatalogVerifierV1, NamespaceRuleV1, NamespaceSourceClassV1,
    PolicyCompilerInputV1, PolicyCompilerLimitsV1, PolicyCompilerV1, PolicyLayerV1,
    ProjectPolicyInputV1, RequestPolicyInputV1, RevocationInputV1,
    SandboxProjectRelationVerifierV1, ViewExecutionV1,
};

fn input_views(bytes: &[Vec<u8>; 4]) -> PolicyDeploymentInputsV1<'_> {
    PolicyDeploymentInputsV1 {
        node: &bytes[0],
        site: &bytes[1],
        backend: &bytes[2],
        catalogs: &bytes[3],
    }
}

fn sign_head(generation: u64, inputs: &[Vec<u8>; 4], key: &SigningKey) -> Vec<u8> {
    let mut packet = MAGIC.to_vec();
    packet.extend_from_slice(&generation.to_be_bytes());
    packet.extend_from_slice(&10_i64.to_be_bytes());
    packet.extend_from_slice(&30_i64.to_be_bytes());
    for input in inputs {
        packet.extend_from_slice(&Sha256::digest(input));
    }
    let mut signed = SIGNING_DOMAIN.to_vec();
    signed.extend_from_slice(&packet);
    packet.extend_from_slice(&key.sign(&signed).to_bytes());
    packet
}

fn source_selector() -> Selector {
    Selector::Tree {
        tree: ObjectDescriptor::new(
            MediaType::new(PortableMediaType::Tree.as_str()).expect("tree media"),
            ObjectDigest::from_bytes([71; 32]),
            100,
        ),
    }
}

fn fixture_profile(generation: u64, signer_generation: u64) -> PolicyDeploymentInputProfileV2 {
    // Reuse the established complete hard-limit fixture rather than another
    // dimension-to-enforcement table. V2 grants/rules below are explicit.
    let key = SigningKey::from_bytes(&[72; 32]);
    let (legacy_packet, legacy_inputs) = super::super::tests::signed_deployment_fixture(&key);
    let views = input_views(&legacy_inputs);
    let legacy_head =
        verify_policy_deployment_head_v1(&legacy_packet, &views, &key.verifying_key(), 20)
            .expect("legacy resource fixture");
    let legacy = decode_policy_deployment_sources_v1(&views, legacy_head).expect("typed resources");
    let source = ResourceId::from_bytes([73; 16]);
    let selector = source_selector();
    let operations = OperationSet::one(Operation::Discover)
        .union(OperationSet::one(Operation::MetadataRead))
        .union(OperationSet::one(Operation::ContentRead));
    let layer = PolicyLayerV1::new(
        vec![
            Grant::new(
                GrantId::from_bytes([74; 16]),
                ResourceKind::Tree,
                operations,
                selector.clone(),
                false,
            )
            .expect("explicit data-only grant"),
        ],
        legacy.node().layer().resources().clone(),
        vec![
            NamespaceRuleV1::Source(
                LogicalSourceV1::new(
                    source,
                    ResourceKind::Tree,
                    selector.clone(),
                    NamespaceSourceClassV1::Immutable,
                    None,
                )
                .expect("immutable nonexecutable declaration"),
            ),
            NamespaceRuleV1::Include {
                source,
                prefix: RelativePath::new(vec![
                    PathName::new(b"data".to_vec()).expect("component"),
                ])
                .expect("relative view"),
                execution: ViewExecutionV1::NoExecute,
            },
        ],
        vec![AdvisoryActionV1::new(
            AdvisoryKindV1::Readahead,
            source,
            ResourceKind::Tree,
            selector,
            1024,
            1,
            AdvisoryDegradationV1::Omit,
        )],
        CacheDomainInputV1::Inherit,
        RevocationInputV1::Inherit,
    )
    .expect("complete constructor-normalized layer");
    let backend = BackendCapabilitiesV1::new(
        legacy.backend().enforcement().clone(),
        vec![
            NamespaceBackendFeatureV1::Immutable,
            NamespaceBackendFeatureV1::NoExecute,
        ],
        vec![AdvisoryKindV1::Readahead],
    )
    .expect("full typed backend declaration");
    let catalogs = PolicyDeploymentCatalogDeclarationsV2::new(
        vec![EndpointCatalogEntryV1::new(
            NetworkEndpointId::from_bytes([75; 16]),
            ResourceId::from_bytes([76; 16]),
            ObjectDigest::from_bytes([77; 32]),
            EndpointUseV1::Discover,
        )],
        vec![NamespaceDestinationV1::new(
            AttachmentSlotId::from_bytes([78; 16]),
            ResourceId::from_bytes([79; 16]),
        )],
    )
    .expect("plain nonempty catalog declarations");

    PolicyDeploymentInputProfileV2::new(
        generation,
        signer_generation,
        NodePolicyInputV1::new(layer.clone()).expect("node ceiling"),
        SitePolicyInputV1::new(layer).expect("site ceiling"),
        backend,
        catalogs,
    )
    .expect("explicit V2 profile")
}

fn open_journal(directory: &Path) -> Journal {
    let uid = fs::metadata(directory).expect("fixture directory").uid();
    let journal = Journal::open_protected_at_uid(
        directory,
        "authority.journal",
        JournalLimits::default(),
        uid,
    )
    .expect("protected owner fixture")
    .0;
    journal
        .validate_held_protected_at_uid_for_test(directory, "authority.journal", uid)
        .expect("actual held fixed fixture names");
    journal
}

fn pinned_journal(directory: &Path, key: &VerifyingKey, generation: u64) -> Journal {
    let mut journal = open_journal(directory);
    let project_key = SigningKey::from_bytes(&[80; 32]);
    admit_policy_signer_pins_in_journal_v1(
        &mut journal,
        generation,
        key,
        5,
        &project_key.verifying_key(),
    )
    .expect("independent protected role pins");
    journal
}

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("private owner fixture");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("owner-only fixture directory");
    directory
}

#[test]
fn explicit_deployment_profile_v2_retains_all_typed_inputs_and_current_owner_head() {
    let key = SigningKey::from_bytes(&[81; 32]);
    let profile = fixture_profile(1, 3);
    let inputs = profile.canonical_inputs().expect("canonical full inputs");
    let packet = sign_head(1, &inputs, &key);
    assert_eq!(packet.len(), PACKET_BYTES);
    assert_eq!(&packet[..8], b"AOSPDH01");
    assert_eq!(profile.node().layer().grants().len(), 1);
    assert_eq!(profile.node().layer().namespace_rules().len(), 2);
    assert_eq!(profile.site().layer().advisory_actions().len(), 1);
    assert_eq!(profile.backend().namespace().len(), 2);
    assert_eq!(profile.backend().advisory(), &[AdvisoryKindV1::Readahead]);
    let (endpoint, _) = canonical_endpoint_catalog_v1(profile.catalogs().endpoints())
        .expect("same existing endpoint codec");
    let (destination, _) = canonical_namespace_catalog_v1(profile.catalogs().destinations())
        .expect("same existing destination codec");
    assert_eq!(*profile.catalogs().endpoint_descriptor(), endpoint);
    assert_eq!(*profile.catalogs().destination_descriptor(), destination);

    let directory = private_directory();
    let mut journal = pinned_journal(directory.path(), &key.verifying_key(), 3);
    let views = input_views(&inputs);
    let head = verify_signed_profile(&packet, &views, &profile, &key.verifying_key(), 20)
        .expect("exact signed declaration");
    admit_deployment_head_in_journal(&mut journal, &packet, head, &key.verifying_key())
        .expect("existing protected head CAS");
    let sequence = journal.snapshot_sequence();
    assert_eq!(
        verify_current_profile(&mut journal, &packet, &views, &profile, 20)
            .expect("actual role pin and exact current head")
            .packet_digest(),
        head.packet_digest()
    );
    assert_eq!(journal.snapshot_sequence(), sequence);
    drop(journal);

    let mut reopened = open_journal(directory.path());
    assert!(verify_current_profile(&mut reopened, &packet, &views, &profile, 20).is_ok());
    assert_eq!(reopened.snapshot_sequence(), sequence);
}

#[test]
fn explicit_deployment_profile_v2_never_upgrades_legacy_or_substituted_signed_inputs() {
    let key = SigningKey::from_bytes(&[81; 32]);
    let profile = fixture_profile(1, 3);
    let inputs = profile.canonical_inputs().expect("typed profile bytes");
    let packet = sign_head(1, &inputs, &key);
    let views = input_views(&inputs);
    assert!(verify_policy_deployment_head_v1(&packet, &views, &key.verifying_key(), 20).is_err());
    let (legacy, legacy_inputs) = super::super::tests::signed_deployment_fixture(&key);
    assert!(
        verify_signed_profile(
            &legacy,
            &input_views(&legacy_inputs),
            &profile,
            &key.verifying_key(),
            20,
        )
        .is_err()
    );

    // Every component substitution is signed correctly by the deployment
    // role. Signature validity cannot substitute a different typed profile.
    for index in 0..4 {
        let mut changed = inputs.clone();
        changed[index].push(b' ');
        let signed = sign_head(1, &changed, &key);
        assert!(verify_historical_packet(&signed, &key.verifying_key()).is_ok());
        assert!(
            verify_signed_profile(
                &signed,
                &input_views(&changed),
                &profile,
                &key.verifying_key(),
                20,
            )
            .is_err()
        );
        assert!(
            verify_signed_profile(
                &packet,
                &input_views(&changed),
                &profile,
                &key.verifying_key(),
                20,
            )
            .is_err()
        );
    }

    let payload_offset = 16 + INPUT_DOMAINS[0].len();
    let original_node: serde_json::Value =
        serde_json::from_slice(&inputs[0][payload_offset..]).expect("typed node JSON fixture");
    for missing in [true, false] {
        let mut raw = original_node.clone();
        let fields = raw[1].as_object_mut().expect("typed layer fields");
        if missing {
            fields.remove("grants");
        } else {
            fields.insert("unknown-grant-default".to_owned(), serde_json::json!(true));
        }
        let mut changed = inputs.clone();
        changed[0] = canonical_bytes(INPUT_DOMAINS[0], &raw).expect("untrusted shaped bytes");
        let signed = sign_head(1, &changed, &key);
        assert!(verify_historical_packet(&signed, &key.verifying_key()).is_ok());
        assert!(
            verify_signed_profile(
                &signed,
                &input_views(&changed),
                &profile,
                &key.verifying_key(),
                20,
            )
            .is_err()
        );
    }

    let original = profile.node().layer();
    let changed_layer = PolicyLayerV1::new(
        original.grants().to_vec(),
        original.resources().clone(),
        original.namespace_rules().to_vec(),
        original.advisory_actions().to_vec(),
        CacheDomainInputV1::Inherit,
        RevocationInputV1::Exact(RevocationPolicy::new(RevocationMode::DenyNew, 1)),
    )
    .expect("semantically different complete layer");
    let changed_backend = BackendCapabilitiesV1::new(
        profile.backend().enforcement().clone(),
        Vec::new(),
        Vec::new(),
    )
    .expect("different explicit backend declaration");
    let empty_catalogs = PolicyDeploymentCatalogDeclarationsV2::new(Vec::new(), Vec::new())
        .expect("different explicit catalog declaration");
    for index in 0..4 {
        let changed = PolicyDeploymentInputProfileV2::new(
            1,
            3,
            if index == 0 {
                NodePolicyInputV1::new(changed_layer.clone()).expect("changed node")
            } else {
                profile.node().clone()
            },
            if index == 1 {
                SitePolicyInputV1::new(changed_layer.clone()).expect("changed site")
            } else {
                profile.site().clone()
            },
            if index == 2 {
                changed_backend.clone()
            } else {
                profile.backend().clone()
            },
            if index == 3 {
                empty_catalogs.clone()
            } else {
                profile.catalogs().clone()
            },
        )
        .expect("well-formed but different typed profile");
        let changed_inputs = changed
            .canonical_inputs()
            .expect("authentic typed serialization");
        for component in 0..4 {
            assert_eq!(
                changed_inputs[component] == inputs[component],
                component != index
            );
        }
        let changed_packet = sign_head(1, &changed_inputs, &key);
        assert!(
            verify_signed_profile(
                &changed_packet,
                &input_views(&changed_inputs),
                &changed,
                &key.verifying_key(),
                20,
            )
            .is_ok()
        );
        assert!(
            verify_signed_profile(
                &changed_packet,
                &input_views(&changed_inputs),
                &profile,
                &key.verifying_key(),
                20,
            )
            .is_err()
        );
    }
    let changed_generation = fixture_profile(2, 3);
    let changed_signer = fixture_profile(1, 4);
    for changed in [&changed_generation, &changed_signer] {
        assert!(verify_signed_profile(&packet, &views, changed, &key.verifying_key(), 20).is_err());
    }
    for instant in [9, 30] {
        assert!(
            verify_signed_profile(&packet, &views, &profile, &key.verifying_key(), instant)
                .is_err()
        );
    }

    let mut invalid_signature = packet.clone();
    invalid_signature[PACKET_BYTES - 1] ^= 1;
    assert!(matches!(
        admit_fixed_policy_deployment_profile_v2(
            &invalid_signature,
            &views,
            &profile,
            &key.verifying_key(),
            20
        ),
        Err(PolicyDeploymentHeadErrorV1::InvalidSignature)
    ));
}

#[test]
fn explicit_deployment_profile_v2_pins_role_generation_and_rejects_head_equivocation() {
    let key = SigningKey::from_bytes(&[81; 32]);
    let project_key = SigningKey::from_bytes(&[80; 32]);
    let profile = fixture_profile(1, 3);
    let inputs = profile.canonical_inputs().expect("typed inputs");
    let packet = sign_head(1, &inputs, &key);
    let views = input_views(&inputs);

    let directory = private_directory();
    let mut journal = pinned_journal(directory.path(), &key.verifying_key(), 3);
    let head = verify_signed_profile(&packet, &views, &profile, &key.verifying_key(), 20)
        .expect("correct role signature");
    admit_deployment_head_in_journal(&mut journal, &packet, head, &key.verifying_key())
        .expect("initial current head");
    let sequence = journal.snapshot_sequence();
    assert!(verify_current_profile(&mut journal, &packet, &views, &profile, 30).is_err());
    let project_signed = sign_head(1, &inputs, &project_key);
    assert!(
        verify_signed_profile(
            &project_signed,
            &views,
            &profile,
            &project_key.verifying_key(),
            20,
        )
        .is_ok()
    );
    assert!(verify_current_profile(&mut journal, &project_signed, &views, &profile, 20).is_err());
    assert!(
        admit_policy_signer_pins_in_journal_v1(
            &mut journal,
            4,
            &key.verifying_key(),
            5,
            &project_key.verifying_key(),
        )
        .is_err()
    );
    assert_eq!(journal.snapshot_sequence(), sequence);

    // Independently pinned generation/key mismatches are rejected even when
    // the caller supplies a self-consistent, correctly signed current packet.
    for (pin, generation) in [(&key.verifying_key(), 4), (&project_key.verifying_key(), 3)] {
        let other = private_directory();
        let mut pinned = pinned_journal(other.path(), pin, generation);
        let (actual_key, actual_generation) =
            read_deployment_role(&mut pinned).expect("actual pins");
        assert!(
            actual_key != key.verifying_key() || actual_generation != profile.signer_generation()
        );
        // A deliberately wrong-role historical head does not lend authority
        // to the supplied key, even with exact current-head byte equality.
        let transaction = JournalTransaction::new(
            [85; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                HEAD_KEY.to_vec(),
                packet.clone(),
            )],
        )
        .expect("wrong-role fixture record");
        pinned
            .commit(&transaction)
            .expect("protected wrong-role history fixture");
        let before = pinned.snapshot_sequence();
        assert!(verify_current_profile(&mut pinned, &packet, &views, &profile, 20).is_err());
        assert_eq!(pinned.snapshot_sequence(), before);
    }
}

#[test]
fn explicit_deployment_profile_v2_reuses_exact_head_cas_and_cold_replay() {
    let key = SigningKey::from_bytes(&[81; 32]);
    let directory = private_directory();
    let mut journal = pinned_journal(directory.path(), &key.verifying_key(), 3);
    let mut retained = None;
    for generation in [1, 2] {
        let profile = fixture_profile(generation, 3);
        let inputs = profile.canonical_inputs().expect("successor inputs");
        let packet = sign_head(generation, &inputs, &key);
        let head = verify_signed_profile(
            &packet,
            &input_views(&inputs),
            &profile,
            &key.verifying_key(),
            20,
        )
        .expect("signed successor");
        admit_deployment_head_in_journal(&mut journal, &packet, head, &key.verifying_key())
            .expect("one-generation shared CAS");
        let sequence = journal.snapshot_sequence();
        admit_deployment_head_in_journal(&mut journal, &packet, head, &key.verifying_key())
            .expect("lost-reply exact retry");
        assert_eq!(journal.snapshot_sequence(), sequence);

        let mut conflict = inputs.clone();
        conflict[0].push(b' ');
        let equivocated = sign_head(generation, &conflict, &key);
        let mut conflicting_head = head;
        conflicting_head.packet_digest =
            ObjectDigest::from_bytes(Sha256::digest(&equivocated).into());
        assert!(
            admit_deployment_head_in_journal(
                &mut journal,
                &equivocated,
                conflicting_head,
                &key.verifying_key()
            )
            .is_err()
        );
        assert_eq!(journal.snapshot_sequence(), sequence);
        retained = Some((profile, inputs, packet, sequence));
    }
    let (profile, inputs, packet, sequence) = retained.expect("last successor");
    let gap = fixture_profile(4, 3);
    let gap_inputs = gap.canonical_inputs().expect("gap input");
    let gap_packet = sign_head(4, &gap_inputs, &key);
    let gap_head = verify_signed_profile(
        &gap_packet,
        &input_views(&gap_inputs),
        &gap,
        &key.verifying_key(),
        20,
    )
    .expect("correctly signed but skipped generation");
    assert!(
        admit_deployment_head_in_journal(&mut journal, &gap_packet, gap_head, &key.verifying_key())
            .is_err()
    );
    assert_eq!(journal.snapshot_sequence(), sequence);
    drop(journal);

    let mut reopened = open_journal(directory.path());
    assert!(
        verify_current_profile(&mut reopened, &packet, &input_views(&inputs), &profile, 20).is_ok()
    );
    assert_eq!(reopened.snapshot_sequence(), sequence);
}

#[test]
fn explicit_deployment_profile_v2_catalog_shapes_and_generations_are_closed() {
    let profile = fixture_profile(1, 3);
    let endpoint = profile.catalogs().endpoints()[0];
    let destination = profile.catalogs().destinations()[0];
    assert!(
        PolicyDeploymentCatalogDeclarationsV2::new(vec![endpoint, endpoint], Vec::new()).is_err()
    );
    assert!(
        PolicyDeploymentCatalogDeclarationsV2::new(Vec::new(), vec![destination, destination])
            .is_err()
    );
    let sentinel = EndpointCatalogEntryV1::new(
        NetworkEndpointId::from_bytes([0; 16]),
        ResourceId::from_bytes([1; 16]),
        ObjectDigest::from_bytes([2; 32]),
        EndpointUseV1::Discover,
    );
    assert!(PolicyDeploymentCatalogDeclarationsV2::new(vec![sentinel], Vec::new()).is_err());
    for (generation, signer_generation) in [(0, 3), (1, 0)] {
        assert!(
            PolicyDeploymentInputProfileV2::new(
                generation,
                signer_generation,
                profile.node().clone(),
                profile.site().clone(),
                profile.backend().clone(),
                profile.catalogs().clone(),
            )
            .is_err()
        );
    }

    let many = (1_u128..=1024)
        .map(|value| {
            NamespaceDestinationV1::new(
                AttachmentSlotId::from_bytes(value.to_be_bytes()),
                ResourceId::from_bytes([1; 16]),
            )
        })
        .collect();
    let catalogs = PolicyDeploymentCatalogDeclarationsV2::new(Vec::new(), many)
        .expect("ordered catalog within shape bound");
    assert!(
        PolicyDeploymentInputProfileV2::new(
            1,
            3,
            profile.node().clone(),
            profile.site().clone(),
            profile.backend().clone(),
            catalogs,
        )
        .is_err()
    );

    let unknown = Grant::new(
        GrantId::from_bytes([86; 16]),
        ResourceKind::Tree,
        OperationSet::one(Operation::ContentRead),
        Selector::Profile {
            feature: FeatureRef::new("unregistered.policy-selector", 1, 0)
                .expect("syntactic feature"),
            body: profile.catalogs().endpoint_descriptor().clone(),
        },
        false,
    )
    .expect("syntactic grant is not registered policy semantics");
    assert!(
        PolicyLayerV1::new(
            vec![unknown],
            profile.node().layer().resources().clone(),
            Vec::new(),
            Vec::new(),
            CacheDomainInputV1::Inherit,
            RevocationInputV1::Inherit,
        )
        .is_err()
    );
}

struct SyntheticCompilerVerifier;

impl SandboxProjectRelationVerifierV1 for SyntheticCompilerVerifier {
    fn verify(&self, _: SandboxId, _: ProjectId, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

impl CacheDomainVerifierV1 for SyntheticCompilerVerifier {
    fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

impl EndpointCatalogVerifierV1 for SyntheticCompilerVerifier {
    fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

impl NamespaceCatalogVerifierV1 for SyntheticCompilerVerifier {
    fn verify(&self, _: &ObjectDescriptor, _: &[u8]) -> bool {
        true
    }
}

#[test]
fn explicit_deployment_profile_v2_keeps_content_and_live_kernel_read_intersected() {
    let profile = fixture_profile(1, 3);
    let verifier = SyntheticCompilerVerifier;
    let project = ProjectId::from_bytes([82; 16]);
    let selector = source_selector();
    let domain = AuthenticatedCacheDomainV1::authenticate(
        CacheDomain::new(
            CacheDomainKind::Project,
            CacheDomainId::from_bytes(*project.as_bytes()),
        ),
        CacheDomainBindingV1::Project(project),
        &verifier,
    )
    .expect("synthetic compile-only domain");
    let original = profile.node().layer();
    let project_layer = PolicyLayerV1::new(
        original.grants().to_vec(),
        original.resources().clone(),
        original.namespace_rules().to_vec(),
        original.advisory_actions().to_vec(),
        CacheDomainInputV1::Exact(domain),
        RevocationInputV1::Exact(RevocationPolicy::new(RevocationMode::DenyNew, 0)),
    )
    .expect("explicit synthetic project ceiling");
    let requested = Grant::new(
        GrantId::from_bytes([84; 16]),
        ResourceKind::Tree,
        original.grants()[0]
            .operations()
            .union(OperationSet::one(Operation::LiveKernelCoupledRead)),
        selector.clone(),
        false,
    )
    .expect("request attempts separate live-kernel operation");
    let request = PolicyLayerV1::new(
        vec![requested],
        original.resources().clone(),
        original.namespace_rules().to_vec(),
        original.advisory_actions().to_vec(),
        CacheDomainInputV1::Inherit,
        RevocationInputV1::Inherit,
    )
    .expect("explicit request, no mapping from public Create");
    let inputs = PolicyCompilerInputV1::new(
        AuthenticatedSandboxProjectRelationV1::authenticate(
            SandboxId::from_bytes([85; 16]),
            project,
            &verifier,
        )
        .expect("synthetic relationship"),
        profile.node().clone(),
        profile.site().clone(),
        ProjectPolicyInputV1::new(project, project_layer).expect("project input"),
        Vec::new(),
        RequestPolicyInputV1::new(request).expect("request input"),
        AuthenticatedEndpointCatalogV1::authenticate(Vec::new(), &verifier)
            .expect("empty compile catalog"),
        AuthenticatedNamespaceCatalogV1::authenticate(Vec::new(), &verifier)
            .expect("empty compile destinations"),
        profile.backend().clone(),
        PolicyCompilerLimitsV1::DEFAULT,
    )
    .expect("existing pure compiler input");

    let candidate = PolicyCompilerV1::compile(inputs).expect("existing intersection semantics");
    assert!(candidate.authority().admits(
        ResourceKind::Tree,
        OperationSet::one(Operation::ContentRead),
        &selector
    ));
    assert!(!candidate.authority().admits(
        ResourceKind::Tree,
        OperationSet::one(Operation::LiveKernelCoupledRead),
        &selector
    ));
    assert!(!candidate.authority().admits(
        ResourceKind::Tree,
        OperationSet::one(Operation::Execute),
        &selector
    ));
}
