//! Caches regression cases and contract checks.

use super::*;

#[tokio::test]
async fn release_ability_graph_authorizes_before_lookup() {
    let (service, db, _lease, underprivileged_auth) = injected_service(vec![], vec![]).await;
    let org_id = db
        .create_org("ability-graph-auth", "Ability graph auth")
        .await
        .unwrap();
    db.create_managed_registry(org_id, "", "packages", "private", &[], true)
        .await
        .unwrap();
    let request = pb::GetReleaseAbilityGraphRequest {
        registry: "ability-graph-auth/packages".into(),
        release: String::new(),
        platform: String::new(),
    };

    assert!(matches!(
        service
            .get_release_ability_graph(None, request.clone())
            .await,
        Err(RpcError::Unauthenticated(_))
    ));
    assert!(matches!(
        service
            .get_release_ability_graph(Some(&underprivileged_auth), request)
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
}

#[tokio::test]
async fn commit_advances_a_fully_reused_publication_without_uploads() {
    let (service, db, _lease, auth) = injected_service(vec![], vec![]).await;
    let org_id = db.create_org("reuse-only", "Reuse only").await.unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "main", "private", &[], false)
        .await
        .unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            "binding-reuse-only",
            &org.stable_id,
            "registry",
            "r2",
            None,
            Some("reuse-only"),
            Some("registry"),
            Some("https"),
            Some("dns"),
            Some(b"storage.example.invalid"),
            Some(443),
            Some("auto"),
            Some("private"),
        )
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".into(),
            binding_id: binding_id,
            prefix: "main".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let placement = db
        .observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();

    let publication_id = "reuseonlypublication00000000000001";
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: publication_id.into(),
        registry_id,
        generation: "reuse-only-generation".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: Some("c".repeat(64)),
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
        publication_id: publication_id.into(),
        placement_id: placement.id,
        required: true,
        state: "preparing".into(),
        observed_at: 2,
    })
    .await
    .unwrap();

    for (path, kind, hash, size) in [
        ("nar/reused.nar.zst", "immutable", "d".repeat(64), 7),
        ("info/refs", "mutable_pointer", "e".repeat(64), 9),
    ] {
        let object = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(registry_id),
                object_key: path.into(),
                content_hash: Some(hash.clone()),
                size: Some(size),
                object_kind: kind.into(),
                mutable_publication_id: (kind == "mutable_pointer").then(|| publication_id.into()),
            })
            .await
            .unwrap();
        db.set_registry_publication_object(&SetRegistryPublicationObject {
            publication_id: publication_id.into(),
            surface_object_id: object.id,
            object_kind: kind.into(),
            expected_hash: hash.clone(),
            expected_size: size,
        })
        .await
        .unwrap();
        db.record_registry_publication_object_presence(
            publication_id,
            object.id,
            placement.id,
            &hash,
            size,
            Some("reused"),
            3,
        )
        .await
        .unwrap();
    }

    let committed = service
        .commit_registry_publication(
            Some(&auth),
            pb::CommitRegistryPublicationRequest {
                publication_id: publication_id.into(),
            },
        )
        .await
        .unwrap();

    assert_eq!(committed.state, "ready");
    assert_eq!(committed.placements[0].state, "ready");
    assert_eq!(committed.objects.len(), 2);

    let listed = service
        .list_registry_publications(
            Some(&auth),
            pb::ListRegistryPublicationsRequest {
                registry: "reuse-only/main".into(),
                state: "ready".into(),
                page_size: 1,
                page_token: String::new(),
            },
        )
        .await
        .unwrap();
    assert_eq!(listed.publications.len(), 1);
    assert!(listed.publications[0].objects.is_empty());

    let shown = service
        .get_registry_publication(
            Some(&auth),
            pb::GetRegistryPublicationRequest {
                publication_id: publication_id.into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(shown.objects.len(), 2);
    assert_eq!(
        db.registry_publication_state(registry_id)
            .await
            .unwrap()
            .unwrap()
            .current_publication_id
            .as_deref(),
        Some(publication_id)
    );
}

#[tokio::test]
async fn cache_upload_batch_returns_replayable_proxy_tickets_in_input_order() {
    let (service, db, _lease, auth) = injected_service(vec![], vec![]).await;
    let cache = db
        .binary_cache_by_slug("failure/cache")
        .await
        .unwrap()
        .unwrap();
    let request = pb::CreateCacheObjectUploadsRequest {
        cache_id: cache.stable_id,
        paths: vec!["nar/bulk-one.nar".into(), "nar/bulk-two.nar".into()],
        sizes: vec![11, 22],
        ..Default::default()
    };

    let first = service
        .create_cache_object_uploads(Some(&auth), request.clone())
        .await
        .unwrap();
    let replay = service
        .create_cache_object_uploads(Some(&auth), request)
        .await
        .unwrap();

    assert_eq!(first.uploads.len(), 2);
    assert_eq!(first.uploads[0].path, "nar/bulk-one.nar");
    assert_eq!(first.uploads[1].path, "nar/bulk-two.nar");
    assert!(first
        .uploads
        .iter()
        .all(|upload| upload.expires_at == 0 && !upload.upload_url.is_empty()));
    assert_eq!(
        first
            .uploads
            .iter()
            .map(|upload| upload.upload_ticket_id.as_str())
            .collect::<Vec<_>>(),
        replay
            .uploads
            .iter()
            .map(|upload| upload.upload_ticket_id.as_str())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn narinfo_batch_rejects_duplicate_identities_before_writing() {
    let (service, db, _lease, _auth) = injected_service(vec![], vec![]).await;
    let cache = db
        .binary_cache_by_slug("failure/cache")
        .await
        .unwrap()
        .unwrap();
    let duplicate = pb::CacheNarinfo {
        store_hash: "duplicate".into(),
        narinfo: "invalid but never parsed".into(),
        nar_upload_ticket_id: String::new(),
    };

    let error = service
        .register_cache_narinfos_authorized(&cache, &[duplicate.clone(), duplicate])
        .await
        .unwrap_err();

    assert!(matches!(error, RpcError::InvalidArgument(_)));
}

#[tokio::test]
async fn presigned_preflight_failure_never_creates_a_ticket() {
    let (service, db, _lease, _auth) =
        injected_service_with_sealer(vec![], vec![], vec![SealerBehavior::Failure]).await;
    let cache = db
        .binary_cache_by_slug("failure/cache")
        .await
        .unwrap()
        .unwrap();
    assert!(service
        .mint_presigned_cache_write(&cache, "nar/direct-preflight.nar", 4, 9)
        .await
        .unwrap()
        .is_none());
    assert!(db
        .test_cache_write_ticket_for_key("nar/direct-preflight.nar")
        .await
        .unwrap()
        .is_none());
}

#[test]
fn multipart_completion_requires_exact_confirmed_part_identities() {
    let mut durable = vec![WriteTicketPartRecord {
        part_number: 1,
        admitted_size: 4,
        body_digest: "0".repeat(64),
        state: "ambiguous".into(),
        etag: None,
    }];
    let requested = vec![PartTag {
        part_number: 1,
        etag: "etag-1".into(),
    }];
    assert!(!multipart_completion_matches(&durable, &requested, 4));
    durable[0].state = "confirmed".into();
    durable[0].etag = Some("etag-1".into());
    assert!(multipart_completion_matches(&durable, &requested, 4));
    assert!(!multipart_completion_matches(&durable, &requested, 5));

    durable.push(WriteTicketPartRecord {
        part_number: 3,
        admitted_size: 4,
        body_digest: "1".repeat(64),
        state: "confirmed".into(),
        etag: Some("etag-3".into()),
    });
    let requested_with_gap = vec![
        PartTag {
            part_number: 1,
            etag: "etag-1".into(),
        },
        PartTag {
            part_number: 3,
            etag: "etag-3".into(),
        },
    ];
    assert!(!multipart_completion_matches(
        &durable,
        &requested_with_gap,
        8
    ));
}

#[test]
fn nix_cache_info_shape() {
    let s = render_nix_cache_info(true, 40);
    assert!(s.contains("StoreDir: /nix/store"), "{s}");
    assert!(s.contains("WantMassQuery: 1"), "{s}");
    assert!(s.contains("Priority: 40"), "{s}");
    assert!(render_nix_cache_info(false, 7).contains("WantMassQuery: 0"));
}

#[test]
fn retention_selector_canonicalization_is_server_owned() {
    let mut spec = pb::RetentionSubscriptionSpec {
        selector: Some(pb::RetentionSelector {
            current_catalog: false,
            channel_targets: Some(pb::ChannelTargetSelector {
                all: false,
                names: vec!["stable".into(), "beta".into(), "stable".into()],
            }),
            recent_releases: None,
            release_tags: vec!["2.0.0".into(), "1.0.0".into(), "2.0.0".into()],
            semver: Some(pb::SemverRetentionSelector {
                requirement: " >=2.0.0 , <3.0.0 || =1.0.0 ".into(),
                include_prereleases: false,
            }),
            all_releases: false,
        }),
        removal_grace_seconds: 0,
    };
    RpcService::canonicalize_retention_spec(&mut spec).unwrap();
    let selector = spec.selector.unwrap();
    assert_eq!(selector.channel_targets.unwrap().names, ["beta", "stable"]);
    assert_eq!(selector.release_tags, ["1.0.0", "2.0.0"]);
    assert_eq!(
        selector.semver.unwrap().requirement,
        "<3.0.0,>=2.0.0||=1.0.0"
    );
}

#[test]
fn retention_selector_storage_json_is_canonical_object_order() {
    let selector = pb::RetentionSelector {
        current_catalog: true,
        channel_targets: Some(pb::ChannelTargetSelector {
            all: false,
            names: vec!["stable".into()],
        }),
        recent_releases: None,
        release_tags: vec!["1.0.0".into()],
        semver: None,
        all_releases: false,
    };

    let value = serde_json::to_value(&selector).unwrap();
    let stored = serde_json::to_string(&value).unwrap();
    let reparsed: serde_json::Value = serde_json::from_str(&stored).unwrap();

    assert!(reparsed.is_object());
    assert_eq!(serde_json::to_string(&reparsed).unwrap(), stored);
}
