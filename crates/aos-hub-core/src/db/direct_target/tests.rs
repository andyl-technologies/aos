//! Transactional authorization races using actual cache and publication accounting.

use super::*;
use crate::{
    auth::jwt::{Claims, AUTHORIZATION_CLAIMS_VERSION},
    domain::{Permission, Principal},
};

async fn authorization(db: &Database) -> Claims {
    let user = db
        .create_user("target-fence@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (token, _) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::RegistryConfigure, Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    Claims {
        sub: token,
        owner_kind: "user".into(),
        owner_id: user,
        owner_incarnation: db
            .principal_incarnation(Principal::user(user))
            .await
            .unwrap(),
        browser_session_id_hash: None,
        scope: "instance".into(),
        perms: vec!["registry.configure".into(), "publish".into()],
        authz_version: AUTHORIZATION_CLAIMS_VERSION.into(),
        iat: 1,
        exp: 1000,
    }
}

async fn atomic_target_contract(db: Database) {
    db.install_write_failure_test_tickets().await.unwrap();
    let claims = authorization(&db).await;
    let scope = "cache:00000000000000000000000000000001";
    let iam = db
        .direct_iam_fence(&claims, scope, Permission::RegistryConfigure, 12)
        .await
        .unwrap();
    db.backend
        .execute(
            "UPDATE cache_write_tickets SET quota_org_id = 1, quota_state = 'pending'
             WHERE ticket_id = 'cache-single-pre'",
            &[],
        )
        .await
        .unwrap();
    let activation = Database::activate_cache_write_ticket_statements(
        "cache-single-pre",
        1,
        Some(1),
        1,
        1,
        None,
        Some(&"c".repeat(64)),
        12,
    )
    .unwrap();
    db.backend.checked_batch(&activation).await.unwrap();
    let mut finish =
        Database::complete_cache_write_ticket_statements("cache-single-pre", 2, 14).unwrap();
    finish.push(iam);

    // A grant may disappear while Native awaits the independently signed guard.
    db.backend
        .execute(
            "DELETE FROM memberships WHERE principal_kind = 'user' AND principal_id = ?1",
            &vals![claims.owner_id],
        )
        .await
        .unwrap();
    assert!(db.backend.checked_batch(&finish).await.is_err());
    let ticket = db
        .cache_write_ticket("cache-single-pre")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ticket.state, "active");
    assert_eq!(ticket.resource_version, 2);
    let before = db
        .backend
        .query_opt("SELECT epoch FROM cache_gc_state WHERE cache_id = 1", &[])
        .await
        .unwrap()
        .unwrap();
    let epoch: i64 = before.get(0).unwrap();

    db.grant_membership("user", claims.owner_id, "instance", "owner")
        .await
        .unwrap();
    let iam = db
        .direct_iam_fence(&claims, scope, Permission::RegistryConfigure, 14)
        .await
        .unwrap();
    db.backend
        .execute(
            "UPDATE tokens SET permissions = ?2 WHERE id = ?1",
            &vals![claims.sub, "[\"publish\"]"],
        )
        .await
        .unwrap();
    let mut finish =
        Database::complete_cache_write_ticket_statements("cache-single-pre", 2, 14).unwrap();
    finish.push(iam);
    assert!(db.backend.checked_batch(&finish).await.is_err());
    assert!(db
        .direct_iam_fence(&claims, scope, Permission::RegistryConfigure, 14)
        .await
        .is_err());
    assert_eq!(
        db.cache_write_ticket("cache-single-pre")
            .await
            .unwrap()
            .unwrap()
            .state,
        "active"
    );
    let after = db
        .backend
        .query_opt("SELECT epoch FROM cache_gc_state WHERE cache_id = 1", &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.get::<i64>(0).unwrap(), epoch);

    db.backend
        .execute(
            "UPDATE tokens SET permissions = ?2 WHERE id = ?1",
            &vals![claims.sub, "[\"registry.configure\",\"publish\"]"],
        )
        .await
        .unwrap();
    db.backend.checked_batch(&finish).await.unwrap();
    assert_eq!(
        db.cache_write_ticket("cache-single-pre")
            .await
            .unwrap()
            .unwrap()
            .state,
        "completed"
    );
    let after = db
        .backend
        .query_opt("SELECT epoch FROM cache_gc_state WHERE cache_id = 1", &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.get::<i64>(0).unwrap(), epoch + 1);

    let dependency = db
        .create_surface_object(&super::super::SetSurfaceObject {
            surface: super::super::SurfaceTarget::BinaryCache(1),
            object_key: "nar/dependency.nar".into(),
            content_hash: Some("e".repeat(64)),
            size: Some(64),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    db.backend.execute(
        "INSERT INTO object_placements(surface_object_id,cache_id,registry_id,placement_id,state,observed_hash,observed_size,
           etag,observed_inventory_generation,observed_at,catalog_object_resource_version)
         VALUES(?1,1,NULL,1,'present',?2,64,'source-etag',1,14,1)",
        &vals![dependency.id, "e".repeat(64)]).await.unwrap();
    let dependency_fence =
        Database::direct_cache_metadata_fence(1, "nar/dependency.nar", &"e".repeat(64), 64, None)
            .unwrap();
    db.backend
        .checked_batch(&[dependency_fence.clone()])
        .await
        .unwrap();
    db.backend
        .execute(
            "UPDATE object_placements SET state = 'missing' WHERE surface_object_id = ?1",
            &vals![dependency.id],
        )
        .await
        .unwrap();
    let mut metadata_plan =
        Database::complete_cache_write_ticket_statements("cache-single-post", 1, 15).unwrap();
    metadata_plan.push(dependency_fence);
    assert!(db.backend.checked_batch(&metadata_plan).await.is_err());
    assert_eq!(
        db.cache_write_ticket("cache-single-post")
            .await
            .unwrap()
            .unwrap()
            .state,
        "active"
    );
    db.backend
        .execute(
            "UPDATE object_placements SET state = 'present' WHERE surface_object_id = ?1",
            &vals![dependency.id],
        )
        .await
        .unwrap();
    db.backend.checked_batch(&metadata_plan).await.unwrap();

    let publication = "atomic-target-publication";
    db.create_registry_publication(&super::super::NewRegistryPublication {
        publication_id: publication.into(),
        registry_id: 1,
        generation: "target-generation".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: None,
        parent_publication_id: None,
    })
    .await
    .unwrap();
    let object = db
        .create_surface_object(&super::super::SetSurfaceObject {
            surface: super::super::SurfaceTarget::Registry(1),
            object_key: "images/source.bin".into(),
            content_hash: Some("d".repeat(64)),
            size: Some(91),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    db.set_registry_publication_object(&super::super::SetRegistryPublicationObject {
        publication_id: publication.into(),
        surface_object_id: object.id,
        object_kind: "immutable".into(),
        expected_hash: "d".repeat(64),
        expected_size: 91,
    })
    .await
    .unwrap();
    db.set_registry_publication_placement(&super::super::SetRegistryPublicationPlacement {
        publication_id: publication.into(),
        placement_id: 2,
        required: true,
        state: "preparing".into(),
        observed_at: 15,
    })
    .await
    .unwrap();
    let mut publication_plan = Database::registry_publication_object_presence_statements(
        publication,
        object.id,
        2,
        &"d".repeat(64),
        91,
        Some("strong-final"),
        16,
        Some((1, 1)),
    )
    .unwrap();
    publication_plan.push(
        db.direct_iam_fence(
            &claims,
            "registry:00000000000000000000000000000001",
            Permission::Publish,
            16,
        )
        .await
        .unwrap(),
    );
    db.backend
        .execute(
            "UPDATE tokens SET revoked_at = 16 WHERE id = ?1",
            &vals![claims.sub],
        )
        .await
        .unwrap();
    assert!(db.backend.checked_batch(&publication_plan).await.is_err());
    assert!(!db
        .registry_publication_class_is_complete(publication, "immutable")
        .await
        .unwrap());
    let rows = db
        .backend
        .query(
            "SELECT 1 FROM registry_publication_object_evidence WHERE publication_id = ?1",
            &vals![publication],
        )
        .await
        .unwrap();
    assert!(rows.is_empty());
    db.backend
        .execute(
            "UPDATE tokens SET revoked_at = NULL WHERE id = ?1",
            &vals![claims.sub],
        )
        .await
        .unwrap();
    db.backend.checked_batch(&publication_plan).await.unwrap();
    assert!(db
        .registry_publication_class_is_complete(publication, "immutable")
        .await
        .unwrap());
}

#[tokio::test]
async fn direct_target_sqlite_atomic_authorization_races() {
    atomic_target_contract(Database::open_in_memory().await.unwrap()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn direct_target_postgres_atomic_authorization_races() {
    let Ok(url) = std::env::var("AOS_HUB_DIRECT_TEST_PG_URL") else {
        return;
    };
    atomic_target_contract(Database::connect(&url).await.unwrap()).await;
}
