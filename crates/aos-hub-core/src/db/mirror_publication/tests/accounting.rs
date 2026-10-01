//! Ordinary publication and mirror completion share one durable logical charge.

use super::*;

async fn ordinary_plans(
    db: &Database,
    original: &MirrorOriginal,
    publication_id: &str,
    paths: &[&str],
) -> Vec<Vec<CheckedStatement>> {
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.into(),
        registry_id: original.registry_id,
        generation: publication_id.into(),
        manifest_digest: hex::encode(Sha256::digest(publication_id.as_bytes())),
        refs_digest: "b".repeat(64),
        default_commit: None,
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.admit_registry_publication_manifest_objects(
        original.registry_id,
        publication_id,
        &paths
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|path| RegistryPublicationManifestObject {
                object_key: path.into(),
                expected_hash: "1".repeat(64),
                expected_size: 11,
                object_kind: "immutable".into(),
            })
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
        publication_id: publication_id.into(),
        placement_id: original.placement_id,
        required: true,
        state: "preparing".into(),
        observed_at: 102,
    })
    .await
    .unwrap();

    let mut plans = Vec::new();
    for path in paths {
        let object = db
            .surface_object_named(SurfaceTarget::Registry(original.registry_id), path)
            .await
            .unwrap()
            .unwrap();
        plans.push(
            db.verified_registry_publication_presence_statements(
                publication_id,
                object.id,
                original.placement_id,
                &"1".repeat(64),
                11,
                Some("\"verified-copy\""),
                103,
                Some((
                    original.placement_resource_version,
                    original.binding_resource_version,
                )),
            )
            .await
            .unwrap(),
        );
    }
    plans
}

async fn concurrent_accounting_contract(db: &Database) {
    let (original, org) = owned_original(db).await;
    db.set_org_quota(
        org,
        &OrgQuota {
            max_bytes: Some(22),
            max_objects: Some(2),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Both complete plans are built against the same initial totals, before
    // either transaction executes. Different logical objects must both succeed.
    let plans = ordinary_plans(
        db,
        &original,
        "parallel-fit",
        &["nar/one.nar", "nar/two.nar"],
    )
    .await;
    let (first, second) = tokio::join!(
        db.backend.checked_batch(&plans[0]),
        db.backend.checked_batch(&plans[1]),
    );
    first.unwrap();
    second.unwrap();
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (22, 2));

    db.set_org_quota(
        org,
        &OrgQuota {
            max_bytes: Some(33),
            max_objects: Some(3),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let plans = ordinary_plans(
        db,
        &original,
        "parallel-cap",
        &["nar/three.nar", "nar/four.nar"],
    )
    .await;
    let (first, second) = tokio::join!(
        db.backend.checked_batch(&plans[0]),
        db.backend.checked_batch(&plans[1]),
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (33, 3));
    let count: i64 = db.backend.query_opt(
        "SELECT COUNT(*) FROM surface_object_usage charge JOIN surface_objects object ON object.id=charge.surface_object_id
          WHERE object.registry_id=?1 AND object.object_key IN ('nar/three.nar','nar/four.nar')",
        &vals![original.registry_id],
    ).await.unwrap().unwrap().get(0).unwrap();
    assert_eq!(count, 1);
    let copies: i64 = db.backend.query_opt(
        "SELECT COUNT(*) FROM object_placements presence JOIN surface_objects object ON object.id=presence.surface_object_id
          WHERE object.registry_id=?1 AND object.object_key IN ('nar/three.nar','nar/four.nar')",
        &vals![original.registry_id],
    ).await.unwrap().unwrap().get(0).unwrap();
    assert_eq!(copies, 1);

    // The cap permits two additions; the object's unique ledger, rather than
    // the global cap, must reject the losing same-object first-charge race.
    db.set_org_quota(
        org,
        &OrgQuota {
            max_bytes: Some(55),
            max_objects: Some(5),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let plans = ordinary_plans(
        db,
        &original,
        "parallel-same-new",
        &["nar/shared.nar", "nar/shared.nar"],
    )
    .await;
    let (first, second) = tokio::join!(
        db.backend.checked_batch(&plans[0]),
        db.backend.checked_batch(&plans[1]),
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (44, 4));

    // Once charged, two plans capture the same exact ledger revision. Only
    // one may advance that revision; its duplicate batch rolls back completely.
    let plans = ordinary_plans(
        db,
        &original,
        "parallel-same-existing",
        &["nar/shared.nar", "nar/shared.nar"],
    )
    .await;
    let (first, second) = tokio::join!(
        db.backend.checked_batch(&plans[0]),
        db.backend.checked_batch(&plans[1]),
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let object = db
        .surface_object_named(
            SurfaceTarget::Registry(original.registry_id),
            "nar/shared.nar",
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        db.surface_object_usage(object.id)
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        2
    );
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (44, 4));

    db.set_org_quota(org, &OrgQuota::default()).await.unwrap();
    let plans = ordinary_plans(db, &original, "parallel-overflow", &["nar/overflow.nar"]).await;
    for (bytes, objects) in [(i64::MAX, 4), (44, i64::MAX)] {
        db.backend
            .execute(
                "UPDATE org_usage SET used_bytes=?2,object_count=?3 WHERE org_id=?1",
                &vals![org, bytes, objects],
            )
            .await
            .unwrap();
        assert!(db.backend.checked_batch(&plans[0]).await.is_err());
        let usage = db.org_usage(org).await.unwrap();
        assert_eq!((usage.used_bytes, usage.object_count), (bytes, objects));
    }
    let overflow = db
        .surface_object_named(
            SurfaceTarget::Registry(original.registry_id),
            "nar/overflow.nar",
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        db.surface_object_usage(overflow.id)
            .await
            .unwrap()
            .is_none()
    );
    let plans = ordinary_plans(db, &original, "parallel-underflow", &["nar/shared.nar"]).await;
    db.backend
        .execute(
            "UPDATE org_usage SET used_bytes=0,object_count=4 WHERE org_id=?1",
            &vals![org],
        )
        .await
        .unwrap();
    assert!(db.backend.checked_batch(&plans[0]).await.is_err());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 0);
    assert_eq!(
        db.surface_object_usage(object.id)
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        2
    );
    db.backend
        .execute(
            "UPDATE org_usage SET used_bytes=44,object_count=4 WHERE org_id=?1",
            &vals![org],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn parallel_prebuilt_plans_add_independent_charges_and_reject_duplicate_or_overcap_sqlite() {
    concurrent_accounting_contract(&Database::open_in_memory().await.unwrap()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn parallel_prebuilt_plans_add_independent_charges_and_reject_duplicate_or_overcap_postgres()
{
    let Ok(url) = std::env::var("AOS_MIRROR_PUBLICATION_PARALLEL_LEDGER_TEST_DATABASE_URL") else {
        return;
    };
    concurrent_accounting_contract(&Database::connect(&url).await.unwrap()).await;
}

async fn ordinary_then_mirror_contract(db: &Database) {
    let (original, org) = owned_original(db).await;
    let mut pointer = original.clone();
    pointer.path = "state.json".into();
    pointer.copy_operation_id = Some("8".repeat(32));
    pointer.job_id = pointer.identity().unwrap();
    publication(db, &original, &pointer).await;
    let object = db
        .surface_object_named(
            SurfaceTarget::Registry(original.registry_id),
            &original.path,
        )
        .await
        .unwrap()
        .unwrap();
    let origin: Option<i64> = db
        .backend
        .query_opt(
            "SELECT accounting_origin_version FROM surface_objects WHERE id=?1",
            &vals![object.id],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(origin, Some(7));

    db.set_org_quota(
        org,
        &OrgQuota {
            max_bytes: Some(10),
            max_objects: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        db.record_registry_publication_object_presence_fenced(
            "mirror-atomic-publication",
            object.id,
            original.placement_id,
            &"1".repeat(64),
            11,
            Some("\"ordinary-final\""),
            103,
            original.placement_resource_version,
            original.binding_resource_version,
        )
        .await
        .is_err()
    );
    assert!(db.surface_object_usage(object.id).await.unwrap().is_none());
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 0);
    let copies: i64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM object_placements WHERE surface_object_id=?1",
            &vals![object.id],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(copies, 0);

    db.set_org_quota(
        org,
        &OrgQuota {
            max_bytes: Some(11),
            max_objects: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    db.record_registry_publication_object_presence_fenced(
        "mirror-atomic-publication",
        object.id,
        original.placement_id,
        &"1".repeat(64),
        11,
        Some("\"ordinary-final\""),
        104,
        original.placement_resource_version,
        original.binding_resource_version,
    )
    .await
    .unwrap();
    let first = db.surface_object_usage(object.id).await.unwrap().unwrap();
    assert_eq!((first.accounted_bytes, first.resource_version), (11, 1));

    // A distinct independently guarded copy adopts the same logical ledger;
    // neither physical replacement nor its exact replay adds a second charge.
    let progress = build_progress(&original);
    retain(db, &original, &progress, 104).await;
    db.commit_mirror_import(
        &original,
        &progress,
        &proof(&original, &progress, 105),
        Some("mirror-atomic-publication"),
        105,
    )
    .await
    .unwrap();
    db.commit_mirror_import(
        &original,
        &progress,
        &proof(&original, &progress, 105),
        Some("mirror-atomic-publication"),
        1000,
    )
    .await
    .unwrap();
    let charge = db.surface_object_usage(object.id).await.unwrap().unwrap();
    assert_eq!((charge.accounted_bytes, charge.resource_version), (11, 2));
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (11, 1));
}

#[tokio::test]
async fn ordinary_publication_then_mirror_bills_once_and_quota_refusal_rolls_back_sqlite() {
    ordinary_then_mirror_contract(&Database::open_in_memory().await.unwrap()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn ordinary_publication_then_mirror_bills_once_and_quota_refusal_rolls_back_postgres() {
    let Ok(url) = std::env::var("AOS_MIRROR_PUBLICATION_SHARED_LEDGER_TEST_DATABASE_URL") else {
        return;
    };
    ordinary_then_mirror_contract(&Database::connect(&url).await.unwrap()).await;
}

#[tokio::test]
async fn manifest_conflict_preserves_unknown_legacy_origin_and_refuses_new_charge() {
    let db = Database::open_in_memory().await.unwrap();
    let (original, org) = owned_original(&db).await;
    let object_id = db
        .create_surface_object(&crate::db::SetSurfaceObject {
            surface: SurfaceTarget::Registry(original.registry_id),
            object_key: original.path.clone(),
            content_hash: Some("1".repeat(64)),
            size: Some(11),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap()
        .id;
    let mut pointer = original.clone();
    pointer.path = "state.json".into();
    pointer.copy_operation_id = Some("8".repeat(32));
    pointer.job_id = pointer.identity().unwrap();
    publication(&db, &original, &pointer).await;
    let origin: Option<i64> = db
        .backend
        .query_opt(
            "SELECT accounting_origin_version FROM surface_objects WHERE id=?1",
            &vals![object_id],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(origin, None);
    assert!(
        db.verified_registry_object_accounting_eligibility(object_id)
            .await
            .is_err()
    );
    assert!(
        db.record_registry_publication_object_presence(
            "mirror-atomic-publication",
            object_id,
            original.placement_id,
            &"1".repeat(64),
            11,
            Some("\"legacy-final\""),
            103,
        )
        .await
        .is_err()
    );
    let progress = build_progress(&original);
    retain(&db, &original, &progress, 104).await;
    assert!(
        db.validate_mirror_publication_dispatch(
            &original,
            &progress,
            Some("mirror-atomic-publication"),
            105
        )
        .await
        .is_err()
    );
    assert!(
        db.commit_mirror_import(
            &original,
            &progress,
            &proof(&original, &progress, 105),
            Some("mirror-atomic-publication"),
            105
        )
        .await
        .is_err()
    );
    assert!(db.surface_object_usage(object_id).await.unwrap().is_none());
    let usage = db.org_usage(org).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (0, 0));
    assert_eq!(
        db.surface_object(object_id)
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        1
    );
    assert_eq!(
        db.mirror_import(&original.job_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "published"
    );
}
