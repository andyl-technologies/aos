//! Caches regression cases and contract checks.

use super::*;
use aos_hub_db::hybrid_ingress::HybridCacheUploadAdmissionRequest;

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
    let (mut service, db, lease, auth) = injected_service(vec![], vec![]).await;
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
        db.admit_registry_publication_manifest_objects(
            registry_id,
            publication_id,
            &[aos_hub_db::db::RegistryPublicationManifestObject {
                object_key: path.into(),
                expected_hash: hash.clone(),
                expected_size: size,
                object_kind: kind.into(),
            }],
        )
        .await
        .unwrap();
        if path == "nar/reused.nar.zst" {
            let request = pb::CommitRegistryPublicationRequest {
                publication_id: publication_id.into(),
            };
            let (refused, sql, summary) =
                aos_hub_db::application_body_observation::observe_with_publication_phases(
                    service.commit_registry_publication(Some(&auth), request.clone()),
                )
                .await;
            assert!(matches!(refused, Err(RpcError::FailedPrecondition(_))));
            assert!(sql.is_none());
            let summary = summary.unwrap();
            summary.validate_original(&request).unwrap();
            assert_eq!(summary.terminal_outcome(),
                    aos_hub_db::application_body_observation::publication::TerminalOutcome::ReturnedError);
            let encoded = serde_json::to_value(summary).unwrap();
            assert_eq!(encoded["phases"].as_array().unwrap().len(), 1);
            assert_eq!(encoded["phases"][0]["phase"], "authorized");
            assert!(
                db.registry_publication(publication_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .state
                    == "preparing"
            );
        }

        let object = db
            .surface_object_named(SurfaceTarget::Registry(registry_id), path)
            .await
            .unwrap()
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

    service.lease = Arc::new(UnavailablePublishLease);
    let unavailable = service
        .commit_registry_publication(
            Some(&auth),
            pb::CommitRegistryPublicationRequest {
                publication_id: publication_id.into(),
            },
        )
        .await;
    assert!(matches!(unavailable, Err(RpcError::Unavailable(_))));
    assert_eq!(
        db.registry_publication(publication_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "preparing"
    );
    assert_eq!(
        db.registry_publication_state(registry_id)
            .await
            .unwrap()
            .unwrap()
            .current_publication_id,
        None
    );

    service.lease = lease;

    let request = pb::CommitRegistryPublicationRequest {
        publication_id: publication_id.into(),
    };
    let (committed, sql, summary) =
        aos_hub_db::application_body_observation::observe_with_publication_phases(
            service.commit_registry_publication(Some(&auth), request.clone()),
        )
        .await;
    let committed = committed.unwrap();
    assert!(sql.is_none());
    let summary = summary.unwrap();
    summary.validate_original(&request).unwrap();
    assert_eq!(
        summary.terminal_outcome(),
        aos_hub_db::application_body_observation::publication::TerminalOutcome::ReturnedSuccess
    );
    let encoded = serde_json::to_value(summary).unwrap();
    let phases = encoded["phases"].as_array().unwrap();
    assert!(phases.iter().any(
        |phase| phase["phase"] == "mutable_objects_promoted" && phase["completedItems"] == "1"
    ));
    assert!(phases
        .iter()
        .any(|phase| phase["phase"] == "response_materialized"));

    let usage = db.org_usage(org_id).await.unwrap();
    assert_eq!((usage.used_bytes, usage.object_count), (16, 2));

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

    let request = pb::GetRegistryPublicationRequest {
        publication_id: publication_id.into(),
    };
    let raw = serde_json::to_vec(&request).unwrap();
    let (shown, projection) =
        aos_hub_db::application_body_observation::observe_with_sql_projection(async {
            let encoder = aos_hub_db::application_body_observation::rpc::request::<
                pb::GetRegistryPublicationRequest,
                pb::RegistryPublication,
            >(&request, &raw);
            let shown = service
                .get_registry_publication(Some(&auth), request.clone())
                .await
                .unwrap();
            let evidence =
                aos_hub_db::application_body_observation::rpc::reply(encoder, &shown).unwrap();
            assert_eq!(evidence.constructor, "publication_get");
            shown
        })
        .await;
    let projection = serde_json::to_value(projection.unwrap()).unwrap();
    let checkpoints = projection["checkpoints"].as_array().unwrap();
    assert_eq!(checkpoints.len(), 1);
    let observed = &checkpoints[0]["observation"];
    assert_eq!(observed["operation"], "publication_get");
    assert_eq!(observed["publicationId"], publication_id);
    assert_eq!(observed["state"], "ready");
    assert_eq!(
        observed["reply"]["sha256"],
        aos_hub_db::application_body_observation::image(&serde_json::to_vec(&shown).unwrap())
            .sha256
    );

    let (refused, refused_projection) =
        aos_hub_db::application_body_observation::observe_with_sql_projection(async {
            service.get_registry_publication(None, request).await
        })
        .await;
    assert!(refused.is_err());
    assert!(refused_projection.is_none());
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

#[tokio::test]
async fn authenticated_public_cache_info_disables_shared_caching() {
    use crate::service::ReadAuthorization;

    let (service, db, _lease, _auth) = injected_service(vec![], vec![]).await;
    let org_id = db.create_org("public-info", "Public info").await.unwrap();
    let cache_id = db
        .create_binary_cache(
            Some(org_id),
            "public-info/cache",
            "Public cache",
            "public",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
    let cache = db.binary_cache_by_id(cache_id).await.unwrap().unwrap();

    let anonymous = service
        .cache_serve(
            ReadAuthorization::AuthorizationHeader(None),
            &cache,
            "nix-cache-info",
            None,
        )
        .await
        .unwrap()
        .unwrap();
    let authenticated = service
        .cache_serve(
            ReadAuthorization::PreauthorizedSession,
            &cache,
            "nix-cache-info",
            None,
        )
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        anonymous.headers()[axum::http::header::CACHE_CONTROL],
        "private, no-store"
    );
    assert_eq!(
        authenticated.headers()[axum::http::header::CACHE_CONTROL],
        "private, no-store"
    );
}

#[tokio::test]
async fn hybrid_cache_upload_refuses_an_external_binding_before_put() {
    let (service, db, _lease, auth) = injected_service(vec![], vec![]).await;
    let cache = db
        .binary_cache_by_slug("failure/cache")
        .await
        .unwrap()
        .unwrap();
    let path = "nar/hybrid-example.nar";
    let body = b"cache bytes";
    let upload = service
        .create_cache_object_uploads(
            Some(&auth),
            pb::CreateCacheObjectUploadsRequest {
                cache_id: cache.stable_id.clone(),
                path: path.into(),
                size: body.len() as u64,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let encoded_path = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(path);

    let error = service
        .admit_hybrid_cache_upload(
            Some(&auth),
            &cache.stable_id,
            &upload.upload_ticket_id,
            &encoded_path,
            HybridCacheUploadAdmissionRequest {
                size: body.len() as u64,
                sha256: hex::encode(Sha256::digest(body)),
                projection: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, RpcError::FailedPrecondition(_)));
}

#[tokio::test]
async fn hybrid_cache_preflight_authorizes_the_exact_ticket_before_body_read() {
    let (service, db, _lease, auth) = injected_service(vec![], vec![]).await;
    let cache = db
        .binary_cache_by_slug("failure/cache")
        .await
        .unwrap()
        .unwrap();
    let path = "nar/preflight.nar";
    let upload = service
        .create_cache_object_uploads(
            Some(&auth),
            pb::CreateCacheObjectUploadsRequest {
                cache_id: cache.stable_id.clone(),
                path: path.into(),
                size: 11,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let encoded_path = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(path);

    assert!(matches!(
        service
            .preflight_hybrid_cache_upload(
                None,
                &cache.stable_id,
                &upload.upload_ticket_id,
                &encoded_path,
            )
            .await,
        Err(RpcError::Unauthenticated(_))
    ));
    assert!(matches!(
        service
            .preflight_hybrid_cache_upload(
                Some(&auth),
                &cache.stable_id,
                "wrong-ticket",
                &encoded_path,
            )
            .await,
        Err(RpcError::NotFound(_))
    ));
    assert!(matches!(
        service
            .preflight_hybrid_cache_upload(
                Some(&auth),
                &cache.stable_id,
                &upload.upload_ticket_id,
                &encoded_path,
            )
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
}

#[tokio::test]
async fn completed_cache_ticket_admits_identical_hybrid_retry_without_put() {
    let body = b"cache bytes";
    let (service, db, _lease, auth) = injected_service(
        vec![
            FetchBehavior::Missing,
            FetchBehavior::Missing,
            FetchBehavior::Evidence {
                bytes: body.to_vec(),
                strong_etag: "\"stored\"".into(),
            },
        ],
        vec![WriteBehavior::Success],
    )
    .await;
    let cache = db
        .binary_cache_by_slug("failure/cache")
        .await
        .unwrap()
        .unwrap();
    let path = "nar/hybrid-retry.nar";
    let upload = service
        .create_cache_object_uploads(
            Some(&auth),
            pb::CreateCacheObjectUploadsRequest {
                cache_id: cache.stable_id.clone(),
                path: path.into(),
                size: body.len() as u64,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let encoded_path = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(path);
    service
        .upload_cache_object(
            Some(&auth),
            &cache.stable_id,
            &upload.upload_ticket_id,
            &encoded_path,
            body,
        )
        .await
        .unwrap();

    let admission = service
        .admit_hybrid_cache_upload(
            Some(&auth),
            &cache.stable_id,
            &upload.upload_ticket_id,
            &encoded_path,
            HybridCacheUploadAdmissionRequest {
                size: body.len() as u64,
                sha256: hex::encode(Sha256::digest(body)),
                projection: None,
            },
        )
        .await
        .unwrap();
    assert!(admission.completed);
    assert!(admission.object_key.is_none());
}

#[tokio::test]
async fn narinfo_batch_rejects_uninspectable_hash_before_writing() {
    let (service, db, _lease, _auth) = injected_service(vec![], vec![]).await;
    let cache = db
        .binary_cache_by_slug("failure/cache")
        .await
        .unwrap()
        .unwrap();
    let narinfo = pb::CacheNarinfo {
        store_hash: "fleetgc".into(),
        narinfo: "StorePath: /nix/store/fleetgc-payload\nURL: nar/payload.nar\n".into(),
        nar_upload_ticket_id: String::new(),
    };

    let error = service
        .register_cache_narinfos_authorized(&cache, &[narinfo])
        .await
        .unwrap_err();

    assert!(matches!(error, RpcError::InvalidArgument(_)));
    assert!(db
        .surface_object_named(SurfaceTarget::BinaryCache(cache.id), "fleetgc.narinfo")
        .await
        .unwrap()
        .is_none());
}
