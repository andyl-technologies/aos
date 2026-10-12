//! Verifies that a genuine failed audit publication cannot erase source data.

mod fs;

use std::collections::BTreeMap;

use super::{
    AUDIT, DomainDeletionAudit, DomainReadRequest, Fixture, LocalAuthorityIdentity,
    LocalRepositoryLocation, MAIN, MetadataValidator, Repository, RoutedDomainStore, TARGET,
    TokioClock, TokioLocalFs, policy, selection,
};
use crate::bucket::{FileBucket, held::SingleHeld};
use crate::store::RefStore;

use fs::AuditFaultFs;

type FaultRepository =
    Repository<FileBucket<AuditFaultFs, TokioClock, MetadataValidator>, TokioClock, AuditFaultFs>;

#[tokio::test]
async fn domain_deletion_native_failed_audit_intent_preserves_source_and_active_route() {
    let fixture = Fixture::new(31, false).await;
    let expected = b"source remains readable after actual failed audit publication";
    let commit = fixture.commit(expected).await;
    let (content, size) = selection(&fixture, commit).await;
    let source_before: BTreeMap<_, _> = fixture
        .payloads()
        .into_iter()
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    assert!(!source_before.is_empty());

    let fs = AuditFaultFs::default();
    let identity = LocalAuthorityIdentity {
        issuer: "domain-fixture".into(),
        key_id: "initial".into(),
        owner_uid: fixture.owner,
    };
    let target_location = LocalRepositoryLocation {
        bucket: fixture.route.target().root.clone(),
        authority: fixture.directory.join("target-authority"),
    };
    let (target, target_authority): (FaultRepository, _) = Repository::open_local(
        &target_location,
        &identity,
        policy(TARGET, MAIN, false),
        MAIN,
        fs.clone(),
        TokioClock,
    )
    .await
    .unwrap();
    let (audit_repository, audit_authority): (FaultRepository, _) = Repository::open_local(
        &fixture.audit_location,
        &identity,
        policy(AUDIT, fixture.route.control_ref(), true),
        fixture.route.control_ref(),
        fs.clone(),
        TokioClock,
    )
    .await
    .unwrap();
    let audit = audit_repository
        .domain_audit(&fixture.route, &audit_authority)
        .await
        .unwrap();
    let audit_before = audit_repository
        .coordinator()
        .guard()
        .store()
        .ref_get(fixture.route.control_ref())
        .await
        .unwrap();
    let control = {
        let held = SingleHeld::acquire(audit_repository.coordinator().guard().store())
            .await
            .unwrap();
        let source = held.source();
        let observed = source.observe_publication_retained().await.unwrap();
        observed
            .physical_reads()
            .iter()
            .find(|read| {
                read.path()
                    .file_name()
                    .is_some_and(|name| name == "backend-registration.cbor")
            })
            .unwrap()
            .path()
            .parent()
            .unwrap()
            .to_owned()
    };
    fs.arm(control, fixture.route.control_ref());

    let result = target
        .delete_domain(&fixture.route, &target_authority, &audit)
        .await;

    assert!(result.is_err());
    assert!(!fs.rejected_slot().exists());
    assert_eq!(
        audit_repository
            .coordinator()
            .guard()
            .store()
            .ref_get(fixture.route.control_ref())
            .await
            .unwrap(),
        audit_before
    );
    assert_eq!(
        fixture.payloads(),
        source_before.keys().cloned().collect::<Vec<_>>()
    );
    for (path, bytes) in &source_before {
        assert_eq!(&std::fs::read(path).unwrap(), bytes);
    }
    assert!(!audit.domain_deleted(TARGET).await.unwrap());

    // Independent production reopening proves the failed intent left an active
    // route and genuine readable source, rather than only surviving filenames.
    let (reopened_target, reopened_target_authority) = Repository::open_local(
        &target_location,
        &identity,
        policy(TARGET, MAIN, false),
        MAIN,
        TokioLocalFs,
        TokioClock,
    )
    .await
    .unwrap();
    let (reopened_audit, reopened_audit_authority) = Repository::open_local(
        &fixture.audit_location,
        &identity,
        policy(AUDIT, fixture.route.control_ref(), true),
        fixture.route.control_ref(),
        TokioLocalFs,
        TokioClock,
    )
    .await
    .unwrap();
    let reopened_registration = reopened_audit
        .domain_audit(&fixture.route, &reopened_audit_authority)
        .await
        .unwrap();
    assert!(!reopened_registration.domain_deleted(TARGET).await.unwrap());
    let route = RoutedDomainStore::new(&reopened_target, &reopened_registration)
        .await
        .unwrap();
    assert_eq!(
        route
            .read_content(&DomainReadRequest {
                reference: MAIN,
                token: reopened_target_authority.token(),
                commit,
                path: b"/file",
                content,
                size,
                surface: "sdk",
            })
            .await
            .unwrap(),
        expected
    );
}
