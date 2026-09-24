//! Protected first-issuance and retained handle custody regressions.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::format::encode_policy;
use aos_sandbox_core::model::{
    CacheDomain, CacheDomainKind, Policy, ResourceProfile, RevocationMode, RevocationPolicy,
};
use aos_sandbox_core::{
    CacheDomainId, DecodeLimits, GrantId, Operation, OperationSet, ResourceId, ResourceVector,
    RevocationScopeId, Selector,
};

use super::*;
use crate::publisher_policy::{
    PreparedPublisherPolicyRevisionV1, PublisherControllerHeadV1, PublisherRevocationHeadV1,
};
use crate::{JournalLimits, RecordNamespace};

fn grant(operation: Operation) -> Grant {
    Grant::new(
        GrantId::from_bytes([4; 16]),
        ResourceKind::Sandbox,
        OperationSet::one(operation),
        Selector::Resource {
            resource: ResourceId::from_bytes([5; 16]),
        },
        false,
    )
    .unwrap()
}

fn holder() -> AuthenticatedHolderV1 {
    AuthenticatedHolderV1 {
        principal: PrincipalId::from_bytes([6; 16]),
        project: ProjectId::from_bytes([7; 16]),
        key_binding: ChannelBinding::new([8; 32]),
    }
}

fn approval(operation: Operation) -> InitialPublicCapabilityApprovalV1 {
    InitialPublicCapabilityApprovalV1::new(
        vec![grant(operation)],
        DelegationLimits::new(0, 0, ResourceVector::ZERO),
        100,
    )
    .unwrap()
}

fn protected_journal(directory: &tempfile::TempDir) -> Journal {
    let uid = std::fs::metadata(directory.path()).unwrap().uid();
    Journal::open_protected_at_uid(
        directory.path(),
        "initial-capability.journal",
        JournalLimits::default(),
        uid,
    )
    .unwrap()
    .0
}

fn policy() -> PreparedPublisherPolicyRevisionV1 {
    let domain = CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([9; 16]));
    let policy = Policy::new(
        Vec::new(),
        Vec::new(),
        vec![grant(Operation::Create)],
        Vec::new(),
        ResourceProfile::new(Vec::new()).unwrap(),
        Vec::new(),
        domain,
        RevocationPolicy::new(RevocationMode::DenyNew, 0),
        None,
        Vec::new(),
    )
    .unwrap();
    PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        holder().project,
        1,
        100,
        1_000,
        &encode_policy(&policy),
        DecodeLimits::default(),
    )
    .unwrap()
}

fn install_current_heads(journal: &mut Journal, bind_revocation: bool) {
    let scope = RevocationScopeId::from_bytes([10; 16]);
    let mut store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default()).unwrap();
    store
        .publish_policy_from_trusted_controller([1; 16], None, &policy())
        .unwrap();
    store
        .advance_controller_from_trusted_controller(
            [2; 16],
            None,
            PublisherControllerHeadV1 {
                principal: PrincipalId::from_bytes([11; 16]),
                generation: 1,
            },
        )
        .unwrap();
    store
        .advance_revocation_from_trusted_controller(
            [3; 16],
            None,
            PublisherRevocationHeadV1 {
                scope,
                generation: 1,
            },
        )
        .unwrap();
    if bind_revocation {
        store
            .bind_project_revocation_scope_from_trusted_controller([4; 16], holder().project, scope)
            .unwrap();
    }
}

#[test]
fn first_issuance_retains_a_random_holder_bound_handle_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = protected_journal(&directory);
    install_current_heads(&mut journal, true);

    let issued = issue_checked(&mut journal, holder(), approval(Operation::Create), 200).unwrap();
    assert_ne!(issued.holder_handle(), &[0; 32]);
    assert_ne!(issued.holder_handle()[..16], issued.id().as_bytes()[..]);
    drop(journal);

    let mut journal = protected_journal(&directory);
    let registry =
        PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default())
            .unwrap();
    assert_eq!(
        registry
            .resolve_holder_handle(
                issued.holder_handle(),
                holder().principal,
                holder().key_binding
            )
            .unwrap(),
        issued.id()
    );
    assert!(
        registry
            .resolve_holder_handle(
                issued.holder_handle(),
                PrincipalId::from_bytes([12; 16]),
                holder().key_binding,
            )
            .is_err()
    );
    assert!(
        registry
            .resolve_holder_handle(
                issued.holder_handle(),
                holder().principal,
                ChannelBinding::new([12; 32]),
            )
            .is_err()
    );
    assert_eq!(
        registry
            .resolve_current(issued.id())
            .unwrap()
            .claims()
            .policy_digest,
        policy().descriptor().digest()
    );
}

#[test]
fn first_issuance_requires_exact_current_authority_and_policy_coverage() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = protected_journal(&directory);
    install_current_heads(&mut journal, false);

    assert!(issue_checked(&mut journal, holder(), approval(Operation::Create), 200).is_err());
    PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default())
        .unwrap()
        .bind_project_revocation_scope_from_trusted_controller(
            [4; 16],
            holder().project,
            RevocationScopeId::from_bytes([10; 16]),
        )
        .unwrap();
    assert!(issue_checked(&mut journal, holder(), approval(Operation::Remove), 200).is_err());
    assert!(issue_checked(&mut journal, holder(), approval(Operation::Create), 950).is_err());

    let mut wrong_project = holder();
    wrong_project.project = ProjectId::from_bytes([13; 16]);
    assert!(
        issue_checked(
            &mut journal,
            wrong_project,
            approval(Operation::Create),
            200
        )
        .is_err()
    );
    let mut missing_key = holder();
    missing_key.key_binding = ChannelBinding::new([0; 32]);
    assert!(issue_checked(&mut journal, missing_key, approval(Operation::Create), 200).is_err());
    assert!(
        journal
            .records(RecordNamespace::PublisherAuthority)
            .next()
            .is_none()
    );
}
