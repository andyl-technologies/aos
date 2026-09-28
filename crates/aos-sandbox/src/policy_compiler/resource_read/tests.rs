//! Exercises derivation comparisons under real fixture journal custody.
//!
//! Input and assignment verifiers are synthetic, explicitly nonauthorizing.
//! These tests cannot qualify Source floors, Root history or worker disclosure.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::model::{CacheDomainKind, SandboxAncestry};
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, Grant, GrantId, IncarnationId, MediaType,
    NamespaceGeneration, NodeId, ObjectDescriptor, ObjectDigest, PortableMediaType, ResourceId,
    ResourceVector,
};

use super::*;
use crate::Journal;
use crate::policy_compiler::protected_journal::resolved_policy_fixture as fixture;
use crate::policy_compiler::protected_owner::{POLICY_STATE_JOURNAL, policy_state_journal_limits};
use crate::policy_compiler::resolved_policy::tests::{commit_fixture, open};
use crate::policy_compiler::{CandidateAuthorityV1, PolicyCompilerLimitsV1};

fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
    ObjectDescriptor::new(
        MediaType::new(kind.as_str()).unwrap(),
        ObjectDigest::from_bytes([byte; 32]),
        8,
    )
}

fn assignment(input: &PolicyCompilerInputV1, policy: ObjectDescriptor) -> AssignmentManifestV1 {
    assignment_for_target(input, input.sandbox(), policy)
}

fn assignment_for_target(
    input: &PolicyCompilerInputV1,
    sandbox: aos_sandbox_core::SandboxId,
    policy: ObjectDescriptor,
) -> AssignmentManifestV1 {
    AssignmentManifestV1::new(
        sandbox,
        input.project().project(),
        SandboxAncestry::new(sandbox, Vec::new()).unwrap(),
        IncarnationId::from_bytes([21; 16]),
        NodeId::from_bytes([22; 16]),
        AssignmentEpoch::new(1),
        DesiredGeneration::new(1),
        NamespaceGeneration::new(1),
        descriptor(PortableMediaType::SandboxSpec, 23),
        policy,
        descriptor(PortableMediaType::Environment, 24),
        descriptor(PortableMediaType::View, 25),
        Vec::new(),
        ObjectDigest::from_bytes([26; 32]),
        ResourceVector::ZERO,
        Vec::new(),
    )
    .unwrap()
}

fn root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn selectors() -> (Selector, Selector) {
    (
        Selector::Tree {
            tree: descriptor(PortableMediaType::Tree, 31),
        },
        Selector::Resource {
            resource: ResourceId::from_bytes([32; 16]),
        },
    )
}

fn grants(tree: bool, cache: bool) -> Vec<Grant> {
    let (tree_selector, cache_selector) = selectors();
    let mut grants = Vec::new();
    for (enabled, id, kind, selector) in [
        (tree, 33, ResourceKind::Tree, tree_selector),
        (cache, 34, ResourceKind::CacheRead, cache_selector),
    ] {
        if enabled {
            grants.push(
                Grant::new(
                    GrantId::from_bytes([id; 16]),
                    kind,
                    OperationSet::one(Operation::ContentRead),
                    selector,
                    false,
                )
                .unwrap(),
            );
        }
    }
    grants
}

#[test]
fn resource_read_retained_compile_preserves_complete_input_candidate_and_preimage() {
    let input = fixture::compiler_input(4096, CacheDomainKind::TrustDomain, grants(true, true));
    let before = input.clone();
    let borrowed = PolicyCompilerV1::compile_retained(&input).unwrap();
    let consuming = PolicyCompilerV1::compile(input.clone()).unwrap();

    assert_eq!(input, before);
    assert_eq!(borrowed, consuming);
    assert_eq!(
        borrowed.commitment_preimage(),
        consuming.commitment_preimage()
    );
    assert_eq!(
        borrowed.authority_status(),
        CandidateAuthorityV1::NonAuthoritativeAncestry
    );
}

#[test]
fn resource_read_retained_compile_keeps_work_admission_first() {
    let input = fixture::compiler_input(4096, CacheDomainKind::Project, grants(true, true));
    let limited = PolicyCompilerInputV1::new(
        input.relation().clone(),
        input.node().clone(),
        input.site().clone(),
        input.project().clone(),
        input
            .ancestors()
            .iter()
            .map(|ancestor| (ancestor.sandbox(), ancestor.layer().clone()))
            .collect(),
        input.request().clone(),
        input.endpoints().clone(),
        input.destinations().clone(),
        input.backend().clone(),
        PolicyCompilerLimitsV1::new(1, input.limits().dag_depth(), input.limits().rules()).unwrap(),
    )
    .unwrap();

    // The shared borrowed implementation performs work admission before its
    // first output stage and contains no clone of the complete input model.
    assert!(matches!(
        PolicyCompilerV1::compile_retained(&limited),
        Err(PolicyCompilationError::WorkLimitExceeded)
    ));
    assert!(matches!(
        PolicyCompilerV1::compile(limited),
        Err(PolicyCompilationError::WorkLimitExceeded)
    ));
}

#[test]
fn resource_read_same_target_origin_reuses_exact_borrowed_derivation() {
    let original_input = super::super::project_source_v3::tests::original_input;
    let input = original_input(aos_sandbox_core::SandboxId::from_bytes([2; 16]), None);
    let prepared = super::super::compile_publisher_policy_revision_v2(&input, 1, 1, 30)
        .expect("actual original compiler producer");
    let origin = prepared
        .revision()
        .compiler_origin()
        .expect("retained original provenance");
    let foreign_input = original_input(aos_sandbox_core::SandboxId::from_bytes([71; 16]), None);
    let foreign = super::super::compile_publisher_policy_revision_v2(&foreign_input, 1, 1, 30)
        .expect("explicit different original target");
    let mut untrusted_bytes = origin.to_record_bytes().unwrap();
    untrusted_bytes[268] ^= 1;
    let untrusted = RetainedPublisherCompilerOriginV3::from_record_bytes(&untrusted_bytes)
        .expect("cold input bytes remain data, not reconstructed authenticated input");
    let publication = fixture::compiled_publication_from_input(input.clone());
    let root = root();
    let mut owner = open(root.path());
    let sequence = commit_fixture(&mut owner, &publication);

    for cold in [false, true] {
        if cold {
            drop(owner);
            owner = open(root.path());
        }
        owner
            .with_current_policy_claim(publication.project, publication.sandbox, |state| {
                let assignment = assignment(&input, state.policy_descriptor().clone());
                let compared = compare_held_resource_read_policy_v1(
                    state,
                    &input,
                    &assignment,
                    1,
                    &publication.prerequisites,
                )
                .unwrap();
                compared
                    .compare_same_target_publisher_origin(origin)
                    .unwrap();
                assert!(matches!(
                    compared.compare_same_target_publisher_origin(
                        foreign.revision().compiler_origin().unwrap()
                    ),
                    Err(ResourceReadPolicyComparisonErrorV1::OriginalTargetMismatch)
                ));
                assert!(matches!(
                    compared.compare_same_target_publisher_origin(&untrusted),
                    Err(ResourceReadPolicyComparisonErrorV1::PublisherOrigin(_))
                ));
                // Origin data cannot replace the exact input retained by the
                // comparison. The same fresh candidate and held cut remain intact.
                assert_eq!(
                    compared.candidate().commitment().digest(),
                    origin.candidate()
                );
                compared.recheck().unwrap();
            })
            .unwrap();
    }
    drop(owner);
    let (journal, _) = Journal::open_protected_at_uid(
        root.path(),
        POLICY_STATE_JOURNAL,
        policy_state_journal_limits(),
        fs::metadata(root.path()).unwrap().uid(),
    )
    .unwrap();
    assert_eq!(journal.snapshot_sequence(), sequence);
}

#[test]
fn resource_read_derivation_all_four_domains_retain_exact_cold_state() {
    for domain in [
        CacheDomainKind::Private,
        CacheDomainKind::TrustDomain,
        CacheDomainKind::Public,
        CacheDomainKind::Project,
    ] {
        let root = root();
        let input = fixture::compiler_input(4096, domain, grants(true, true));
        let publication = fixture::compiled_publication_from_input(input.clone());
        let mut owner = open(root.path());
        let sequence = commit_fixture(&mut owner, &publication);

        for cold in [false, true] {
            if cold {
                drop(owner);
                owner = open(root.path());
            }
            owner
                .with_current_policy_claim(publication.project, publication.sandbox, |state| {
                    let assignment = assignment(&input, state.policy_descriptor().clone());
                    let compared = compare_held_resource_read_policy_v1(
                        state,
                        &input,
                        &assignment,
                        1,
                        &publication.prerequisites,
                    )
                    .unwrap();

                    compared.recheck().unwrap();
                    assert_eq!(compared.cache_domain().kind(), domain);
                    assert_eq!(
                        compared.candidate().commitment().digest(),
                        publication.candidate
                    );
                    assert_eq!(
                        compared.candidate().portable().policy_bytes(),
                        publication.policy
                    );
                    let (tree, cache) = selectors();
                    assert!(compared.content_read_grants_cover(&tree, &cache));
                    assert_eq!(state.prerequisites(), &publication.prerequisites);
                    // The comparison retains the actual named writer, not an
                    // independently reopenable snapshot or serialized grant.
                    assert!(
                        Journal::open_protected_at_uid(
                            root.path(),
                            POLICY_STATE_JOURNAL,
                            policy_state_journal_limits(),
                            fs::metadata(root.path()).unwrap().uid(),
                        )
                        .is_err()
                    );
                })
                .unwrap();
        }
        // Readback/compilation does not mutate or manufacture an owner head.
        assert_eq!(sequence, 5);
    }
}

#[test]
fn resource_read_derivation_refuses_legacy_without_full_preimage() {
    let root = root();
    let publication = fixture::publication(CacheDomainKind::Public);
    let input = fixture::compiler_input(4096, CacheDomainKind::Public, Vec::new());
    let mut owner = open(root.path());
    commit_fixture(&mut owner, &publication);

    owner
        .with_current_policy_claim(publication.project, publication.sandbox, |state| {
            assert!(!state.has_complete_preimage());
            let assignment = assignment(&input, state.policy_descriptor().clone());
            assert!(
                compare_held_resource_read_policy_v1(
                    state,
                    &input,
                    &assignment,
                    1,
                    &publication.prerequisites,
                )
                .is_err()
            );
        })
        .unwrap();
}

#[test]
fn resource_read_derivation_refuses_false_input_claim_despite_valid_v3_outputs() {
    let root = root();
    let input = fixture::compiler_input(4096, CacheDomainKind::Project, Vec::new());
    let other = fixture::compiler_input(8192, CacheDomainKind::Project, Vec::new());
    let mut publication = fixture::compiled_publication_from_input(other);
    publication.input = super::super::normalized_policy_input_digest_v1(&input).unwrap();
    // Candidate identity commits outputs/plans, not independently authentic
    // normalized input. Retain a structurally valid counterclaim to prove the
    // complete typed recompile, not scalar equality, supplies this comparison.
    publication.body[74..106].copy_from_slice(publication.input.as_bytes());
    let mut owner = open(root.path());
    commit_fixture(&mut owner, &publication);

    owner
        .with_current_policy_claim(publication.project, publication.sandbox, |state| {
            assert!(state.has_complete_preimage());
            assert_eq!(state.normalized_input(), publication.input);
            let assignment = assignment(&input, state.policy_descriptor().clone());
            assert!(
                compare_held_resource_read_policy_v1(
                    state,
                    &input,
                    &assignment,
                    1,
                    &publication.prerequisites,
                )
                .is_err()
            );
        })
        .unwrap();
}

#[test]
fn resource_read_derivation_binds_full_publication_tuple_and_assignment_descriptor() {
    let root = root();
    let input = fixture::compiler_input(4096, CacheDomainKind::Private, Vec::new());
    let publication = fixture::compiled_publication_from_input(input.clone());
    let mut owner = open(root.path());
    commit_fixture(&mut owner, &publication);

    owner
        .with_current_policy_claim(publication.project, publication.sandbox, |state| {
            let good = assignment(&input, state.policy_descriptor().clone());
            let wrong_tuple = PolicyPublicationPrerequisitesV1::new(
                ObjectDigest::from_bytes([51; 32]),
                publication.prerequisites.compiler_authority_head(),
                publication.prerequisites.cache_domain_head(),
                publication.prerequisites.revocation_head(),
                publication.prerequisites.generation(),
            )
            .unwrap();
            for (generation, prerequisites) in [(2, &publication.prerequisites), (1, &wrong_tuple)]
            {
                assert!(
                    compare_held_resource_read_policy_v1(
                        state,
                        &input,
                        &good,
                        generation,
                        prerequisites,
                    )
                    .is_err()
                );
            }
            let policy = state.policy_descriptor();
            let foreign = assignment_for_target(
                &input,
                aos_sandbox_core::SandboxId::from_bytes([53; 16]),
                policy.clone(),
            );
            assert!(matches!(
                compare_held_resource_read_policy_v1(
                    state,
                    &input,
                    &foreign,
                    1,
                    &publication.prerequisites,
                ),
                Err(ResourceReadPolicyComparisonErrorV1::AssignmentMismatch)
            ));

            for changed in [
                ObjectDescriptor::new(
                    policy.media_type().clone(),
                    ObjectDigest::from_bytes([52; 32]),
                    policy.encoded_size(),
                ),
                ObjectDescriptor::new(
                    policy.media_type().clone(),
                    policy.digest(),
                    policy.encoded_size() + 1,
                ),
            ] {
                let wrong = assignment(&input, changed);
                assert!(matches!(
                    compare_held_resource_read_policy_v1(
                        state,
                        &input,
                        &wrong,
                        1,
                        &publication.prerequisites
                    ),
                    Err(ResourceReadPolicyComparisonErrorV1::AssignmentMismatch)
                ));
            }
        })
        .unwrap();
}

#[test]
fn resource_read_derivation_requires_both_exact_content_read_grants() {
    for (tree_allowed, cache_allowed) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let root = root();
        let input = fixture::compiler_input(
            4096,
            CacheDomainKind::Public,
            grants(tree_allowed, cache_allowed),
        );
        let publication = fixture::compiled_publication_from_input(input.clone());
        let mut owner = open(root.path());
        commit_fixture(&mut owner, &publication);

        owner
            .with_current_policy_claim(publication.project, publication.sandbox, |state| {
                let assignment = assignment(&input, state.policy_descriptor().clone());
                let compared = compare_held_resource_read_policy_v1(
                    state,
                    &input,
                    &assignment,
                    1,
                    &publication.prerequisites,
                )
                .unwrap();
                let (tree, cache) = selectors();
                assert_eq!(
                    compared.content_read_grants_cover(&tree, &cache),
                    tree_allowed && cache_allowed
                );
                assert!(!compared.content_read_grants_cover(
                    &tree,
                    &Selector::Resource {
                        resource: ResourceId::from_bytes([61; 16])
                    }
                ));
                assert!(!compared.content_read_grants_cover(
                    &Selector::Tree {
                        tree: descriptor(PortableMediaType::Tree, 62)
                    },
                    &cache
                ));
            })
            .unwrap();
    }
}

#[test]
fn resource_read_derivation_metadata_read_cannot_substitute_for_either_content_grant() {
    for wrong_kind in [ResourceKind::Tree, ResourceKind::CacheRead] {
        let root = root();
        let grants = grants(true, true)
            .into_iter()
            .map(|grant| {
                let operations = if grant.resource_kind() == wrong_kind {
                    OperationSet::one(Operation::MetadataRead)
                } else {
                    grant.operations()
                };
                Grant::new(
                    grant.id(),
                    grant.resource_kind(),
                    operations,
                    grant.selector().clone(),
                    false,
                )
                .unwrap()
            })
            .collect();
        let input = fixture::compiler_input(4096, CacheDomainKind::Public, grants);
        let publication = fixture::compiled_publication_from_input(input.clone());
        let mut owner = open(root.path());
        commit_fixture(&mut owner, &publication);

        owner
            .with_current_policy_claim(publication.project, publication.sandbox, |state| {
                let assignment = assignment(&input, state.policy_descriptor().clone());
                let compared = compare_held_resource_read_policy_v1(
                    state,
                    &input,
                    &assignment,
                    1,
                    &publication.prerequisites,
                )
                .unwrap();
                let (tree, cache) = selectors();
                assert!(!compared.content_read_grants_cover(&tree, &cache));
            })
            .unwrap();
    }
}

#[test]
fn resource_read_derivation_does_not_survive_changed_held_policy_names() {
    let root = root();
    let input = fixture::compiler_input(4096, CacheDomainKind::Project, Vec::new());
    let publication = fixture::compiled_publication_from_input(input.clone());
    let mut owner = open(root.path());
    commit_fixture(&mut owner, &publication);

    assert!(
        owner
            .with_current_policy_claim(publication.project, publication.sandbox, |state| {
                let assignment = assignment(&input, state.policy_descriptor().clone());
                let compared = compare_held_resource_read_policy_v1(
                    state,
                    &input,
                    &assignment,
                    1,
                    &publication.prerequisites,
                )
                .unwrap();
                fs::rename(
                    root.path().join("state.journal"),
                    root.path().join("moved.journal"),
                )
                .unwrap();
                assert!(compared.recheck().is_err());
            })
            .is_err()
    );
}
