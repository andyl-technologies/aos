//! Real SQL writer-lifetime substitution refusal after original discovery.

use super::super::ExternalOciStagePreparation;
use crate::{
    backend::Statement,
    db::{
        BeginOciUpload, Database, NewBindingWriteRevision, NewSurfacePlacementSpec, SurfaceTarget,
    },
    direct_upload::{DirectActorKind, DirectActorSlot, WireInteger},
    domain::{Permission, Principal},
    storage_authority::external_object::oci::{
        OciActorOriginal, OciUploadOriginal, OciWriterOriginal,
    },
    value::ToValue as _,
};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

async fn fixture() -> (Arc<Database>, crate::db::SurfacePlacementRecord) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db
        .create_org("connected-copy", "Connected copy")
        .await
        .unwrap();
    let owner = db.org_by_id(org).await.unwrap().unwrap();
    let registry = db
        .create_managed_registry(org, "", "system", "public", &[], false)
        .await
        .unwrap();
    let binding = db
        .create_topology_binding(
            Some(org),
            "connected-copy-binding",
            &owner.stable_id,
            "Copy fixture",
            "s3",
            None,
            Some("fixture-bucket"),
            Some("managed/binding"),
            Some("https"),
            Some("dns"),
            Some(b"s3.fleet.test"),
            Some(443),
            Some("fixture-region"),
            Some("private"),
        )
        .await
        .unwrap();
    for purpose in ["read", "write", "list"] {
        let revision = db
            .set_binding_credential_revision(
                binding,
                purpose,
                &format!("secret://connected-copy/{purpose}/v1"),
                0,
                &hex::encode(Sha256::digest(
                    b"fixture-access:fixture-secret:fixture-region",
                )),
                "fixture",
            )
            .await
            .unwrap();
        db.validate_binding_credential_revision(
            binding,
            purpose,
            revision.generation,
            "valid",
            None,
            revision.head_resource_version,
        )
        .await
        .unwrap();
    }
    let revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id: binding,
            write_credential_generation: 1,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "fixture-writer".into(),
            capability_fingerprint: "fixture-copy".into(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding, revision.revision, "valid", None, None)
        .await
        .unwrap();

    let write_state = db.binding_write_state(binding).await.unwrap().unwrap();
    db.set_current_binding_write_revision(binding, revision.revision, write_state.resource_version)
        .await
        .unwrap();

    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry),
            name: "oci-primary".into(),
            binding_id: binding,
            prefix: "reserved-oci-test/registry".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: true,
        })
        .await
        .unwrap();
    let placement = db
        .observe_surface_placement(
            placement.id,
            "ready",
            "complete",
            placement.observation_version.unwrap(),
        )
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(placement.id, revision.revision)
        .await
        .unwrap();
    let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
    db.create_surface_write_authority(
        SurfaceTarget::Registry(registry),
        "oci-actual-authority",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        revision.revision,
    )
    .await
    .unwrap();
    let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
    (db, placement)
}

#[tokio::test]
async fn stage_current_writer_rejects_real_authority_delete_recreate_before_effect() {
    let (db, placement) = fixture().await;
    let registry = placement.registry_id.unwrap();
    let now = crate::clock::now_unix_secs();
    let repository = db
        .ensure_oci_repository(
            registry,
            &aos_oci_types::RepositoryName::parse("aos").unwrap(),
            now,
        )
        .await
        .unwrap();
    let user = db
        .create_user("oci-lifetime-writer@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (token, _) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    let upload = db
        .begin_oci_upload(&BeginOciUpload {
            registry_id: registry,
            repository_id: repository.id,
            publication_id: None,
            writer_id: token.clone(),
            token_id: token.clone(),
            idempotency_key: "actual-stage-lifetime".into(),
            expected_digest: None,
            expected_size: Some(16),
            maximum_size: 16,
            now,
            expires_at: now + 600,
        })
        .await
        .unwrap();
    let authority = db
        .surface_write_authority(SurfaceTarget::Registry(registry))
        .await
        .unwrap()
        .unwrap();
    let binding = db.binding(placement.binding_id).await.unwrap().unwrap();
    let revision = db
        .placement_publication_write_revision(placement.id)
        .await
        .unwrap()
        .unwrap();
    let writer = OciWriterOriginal::from_records(
        &OciUploadOriginal::from_record(&upload).unwrap(),
        &placement,
        &binding,
        &revision,
        &authority,
    )
    .unwrap();
    // This fixture uses a genuine unrevoked Publish token. Production staging
    // passes the resolver's complete checked IAM statements, not this test fence.
    let iam = vec![
        Statement::new(
            "UPDATE tokens SET last_used_at = last_used_at
        WHERE id = ?1 AND owner_kind = 'user' AND owner_id = ?2
          AND scope_key = 'instance' AND revoked_at IS NULL AND rotated_at IS NULL",
            vec![token.to_value(), user.to_value()],
        )
        .expecting(1),
    ];
    let upload = db
        .reserve_external_oci_staging(&upload, &placement, &writer, iam, now + 600, now)
        .await
        .unwrap();
    let selected = ExternalOciStagePreparation {
        upload: upload.clone(),
        actor: OciActorOriginal::from_authenticated(
            DirectActorSlot {
                kind: DirectActorKind::User,
                numeric_id: WireInteger::new(user as u64),
                incarnation: db
                    .principal_incarnation(Principal::user(user))
                    .await
                    .unwrap()
                    .unwrap(),
            },
            token.clone(),
            now + 600,
        )
        .unwrap(),
        writer,
        staging_key: ExternalOciStagePreparation::chunk_key(&upload, 0).unwrap(),
        ordinal: 0,
        offset: 0,
        prior_sha256: upload.sha256.clone(),
        maximum_bytes: 16,
        expected: None,
    };
    selected.check_current_writer(&db).await.unwrap();

    assert!(
        db.remove_surface_write_authority(
            authority.id,
            &authority.incarnation_id,
            authority.resource_version,
            authority.desired_generation
        )
        .await
        .unwrap()
    );
    let replacement = db
        .create_surface_write_authority(
            SurfaceTarget::Registry(registry),
            "actual-recreated-authority",
            placement.id,
            placement.resource_version,
            placement.write_spec_version,
            revision.revision,
        )
        .await
        .unwrap();
    let replacement_writer = OciWriterOriginal::from_records(
        &OciUploadOriginal::from_record(&upload).unwrap(),
        &placement,
        &binding,
        &revision,
        &replacement,
    )
    .unwrap();
    assert_ne!(replacement_writer, selected.writer);
    // Actual authority deletion/recreation may not redirect an unresolved
    // business position to a fresh private guard, even with a new grant.
    assert_eq!(
        ExternalOciStagePreparation::chunk_key(&upload, 0).unwrap(),
        selected.staging_key
    );
    assert_ne!(
        ExternalOciStagePreparation::chunk_key(&upload, 1).unwrap(),
        selected.staging_key
    );
    assert_ne!(replacement.incarnation_id, authority.incarnation_id);
    assert!(selected.check_current_writer(&db).await.is_err());
    assert_eq!(
        db.oci_upload(&upload.id, &upload.writer_id, &upload.token_id, now)
            .await
            .unwrap()
            .unwrap(),
        upload
    );
}
