//! Database dialect contract tests (RFC-0004 phase 4c "Database abstraction").
//!
//! The same exercise — build the full schema, then drive a representative
//! cross-section of [`Database`](aos_hub::db::Database) methods — is
//! run against every backend the build supports:
//!
//! - **sqlite** always, in-memory and hermetic.
//! - **postgres** when `AOS_HUB_TEST_PG_URL` is set and the crate is built
//!   with `--features postgres`.
//! - **mysql** when `AOS_HUB_TEST_MYSQL_URL` is set and the crate is built
//!   with `--features mysql`.
//!
//! Developer runs may omit either live server. The hermetic package gate builds
//! with `required-live-dialects`, which makes a missing feature or URL a hard
//! failure. The pg/mysql cases drop and recreate a clean schema before
//! connecting, so repeated runs against long-lived servers are idempotent. The
//! mysql case also creates a physical v19 schema and reopens it through the
//! production migration path to cover the v19-to-v20 catalog upgrade.
//!
//! Run the live cases with, e.g.:
//!
//! ```text
//! AOS_HUB_TEST_PG_URL=postgresql://postgres:hub@localhost:55432/hubtest \
//! AOS_HUB_TEST_MYSQL_URL=mysql://root:hub@localhost:55306/hubtest \
//!   cargo test -p aos-hub --features postgres,mysql --test dialect -- --nocapture
//! ```

#[cfg(all(
    feature = "required-live-dialects",
    not(all(feature = "postgres", feature = "mysql"))
))]
compile_error!("required-live-dialects requires both postgres and mysql features");

use aos_hub::db::Database;
use aos_hub::domain::{Permission, Principal};
use aos_hub_core::db::{
    BeginCacheGcGeneration, CacheGcCoverageError, CacheInventoryNarinfoCandidate,
    CacheObjectPresenceObservation, NewBindingWriteRevision, SurfacePlacementRecord, SurfaceTarget,
};

mod common;

/// Stages one complete NAR/narinfo candidate for a placement inventory scan.
async fn stage_dialect_inventory_candidate(
    db: &Database,
    cache_id: i64,
    generation: i64,
    placement_id: i64,
    owner_token: &str,
    identity_digest: &str,
) {
    let narinfo_key = "deadbeef.narinfo";
    let nar_key = "nar/dialect.nar.zst";
    let narinfo_hash = "a".repeat(64);
    let nar_hash = "b".repeat(64);
    for (object_key, content_hash, size) in [
        (narinfo_key, narinfo_hash.as_str(), 96),
        (nar_key, nar_hash.as_str(), 3),
    ] {
        db.stage_cache_surface_object_identity(
            cache_id,
            generation,
            placement_id,
            owner_token,
            object_key,
            content_hash,
            size,
        )
        .await
        .unwrap();
        db.stage_cache_object_presence(
            owner_token,
            &CacheObjectPresenceObservation {
                cache_id,
                object_key: object_key.to_string(),
                placement_id,
                state: "present".to_string(),
                observed_hash: Some(content_hash.to_string()),
                observed_size: Some(size),
                etag: Some(format!("dialect-{placement_id}-{object_key}")),
                inventory_generation: generation,
                observed_at: 20,
            },
        )
        .await
        .unwrap();
    }
    db.stage_cache_inventory_narinfo_candidate(
        owner_token,
        &CacheInventoryNarinfoCandidate {
            cache_id,
            generation,
            placement_id,
            store_hash: "deadbeef".to_string(),
            store_name: "deadbeef-dialect-1.0".to_string(),
            identity_digest: identity_digest.to_string(),
            narinfo_object_key: narinfo_key.to_string(),
            nar_object_key: nar_key.to_string(),
            nar_hash: "sha256:nar-dialect".to_string(),
            nar_size: 5,
            file_hash: nar_hash,
            file_size: 3,
            compression: "zstd".to_string(),
            deriver: None,
            signature: None,
            content_address: None,
            references: Vec::new(),
            published_at: 20,
        },
    )
    .await
    .unwrap();
    db.stage_cache_inventory_manifest(
        cache_id,
        generation,
        placement_id,
        owner_token,
        &format!("dialect-placement-{placement_id}"),
        2,
        20,
    )
    .await
    .unwrap();
}

/// Exercises atomic multi-placement inventory publication and fail-closed GC.
async fn exercise_topology_inventory_and_gc(
    db: &Database,
    cache_id: i64,
    placements: &[SurfacePlacementRecord],
) {
    assert_eq!(placements.len(), 2);
    let owner_token = "dialect-inventory-owner";
    db.begin_cache_inventory_topology(cache_id, 2, 0, owner_token, 10, 100)
        .await
        .unwrap();
    assert!(db
        .begin_cache_inventory_topology(cache_id, 2, 0, "dialect-inventory-rival", 11, 130)
        .await
        .is_err());
    db.heartbeat_cache_inventory_topology(cache_id, 2, owner_token, 12, 140)
        .await
        .unwrap();
    stage_dialect_inventory_candidate(
        db,
        cache_id,
        2,
        placements[0].id,
        owner_token,
        &"c".repeat(64),
    )
    .await;
    stage_dialect_inventory_candidate(
        db,
        cache_id,
        2,
        placements[1].id,
        owner_token,
        &"d".repeat(64),
    )
    .await;
    assert!(
        db.publish_cache_inventory_topology(
            cache_id,
            2,
            owner_token,
            "dialect-conflicting-inventory",
            0,
            "dialect-conflicting-publication",
            21,
        )
        .await
        .is_err(),
        "cross-placement metadata drift must roll the publication back"
    );
    assert!(db
        .normalized_cache_object(cache_id, "deadbeef")
        .await
        .unwrap()
        .is_none());
    db.fail_cache_inventory_topology(cache_id, 2, owner_token)
        .await
        .unwrap();

    db.begin_cache_inventory_topology(cache_id, 2, 0, owner_token, 30, 120)
        .await
        .unwrap();
    for placement in placements {
        stage_dialect_inventory_candidate(
            db,
            cache_id,
            2,
            placement.id,
            owner_token,
            &"e".repeat(64),
        )
        .await;
    }
    db.publish_cache_inventory_topology(
        cache_id,
        2,
        owner_token,
        "dialect-corrected-inventory",
        0,
        "dialect-corrected-publication",
        40,
    )
    .await
    .unwrap();
    let object = db
        .normalized_cache_object(cache_id, "deadbeef")
        .await
        .unwrap()
        .expect("corrected inventory publishes one normalized object");
    let state = db.cache_gc_topology_state(cache_id).await.unwrap().unwrap();
    assert_eq!(state.inventory_generation, 2);
    assert_eq!(state.epoch, 1);
    assert!(!state.destructive_enabled);

    db.begin_cache_gc_generation(&BeginCacheGcGeneration {
        generation_id: "dialect-gc-incomplete".to_string(),
        cache_id,
        cutoff_at: 50,
        expected_epoch: state.epoch,
        created_at: 50,
    })
    .await
    .unwrap();
    db.stage_cache_gc_coverage_error(
        cache_id,
        "dialect-gc-incomplete",
        &CacheGcCoverageError {
            error_id: "dialect-missing-reference".to_string(),
            kind: "missing_reference".to_string(),
            store_hash: Some("deadbeef".to_string()),
            referenced_store_hash: Some("feedface".to_string()),
            detail: "dialect fixture deliberately omits one referenced object".to_string(),
        },
    )
    .await
    .unwrap();
    assert!(
        db.complete_cache_gc_generation(cache_id, "dialect-gc-incomplete", 51)
            .await
            .is_err(),
        "coverage failure must prevent a GC mark generation from publishing"
    );
    db.fail_cache_gc_generation(
        cache_id,
        "dialect-gc-incomplete",
        "expected coverage failure",
        52,
    )
    .await
    .unwrap();

    db.begin_cache_gc_generation(&BeginCacheGcGeneration {
        generation_id: "dialect-gc-complete".to_string(),
        cache_id,
        cutoff_at: 60,
        expected_epoch: state.epoch,
        created_at: 60,
    })
    .await
    .unwrap();
    db.stage_cache_gc_mark(cache_id, "dialect-gc-complete", object.id)
        .await
        .unwrap();
    db.complete_cache_gc_generation(cache_id, "dialect-gc-complete", 61)
        .await
        .unwrap();
}

/// Configures one shared binding revision as the writer for both surfaces.
async fn configure_dialect_writers(
    db: &Database,
    binding_id: i64,
    registry_id: i64,
    registry_placement: &SurfacePlacementRecord,
    cache_id: i64,
    cache_placement: &SurfacePlacementRecord,
) -> (i64, i64) {
    let credential_generation =
        common::create_valid_write_credential(db, binding_id, "secret://dialect/write/v1").await;
    let revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id: binding_id,
            write_credential_generation: credential_generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "dialect-write-revision-v1".to_string(),
            capability_fingerprint: "dialect-writes-and-cas".to_string(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding_id, revision.revision, "valid", None, None)
        .await
        .unwrap();
    let binding_state = db.binding_write_state(binding_id).await.unwrap().unwrap();
    db.set_current_binding_write_revision(
        binding_id,
        revision.revision,
        binding_state.resource_version,
    )
    .await
    .unwrap();
    for (surface, placement, incarnation) in [
        (
            SurfaceTarget::Registry(registry_id),
            registry_placement,
            "dialect-registry-writer",
        ),
        (
            SurfaceTarget::BinaryCache(cache_id),
            cache_placement,
            "dialect-cache-writer",
        ),
    ] {
        db.bind_surface_placement_write_capability(placement.id, revision.revision)
            .await
            .unwrap();
        db.create_surface_write_authority(
            surface,
            incarnation,
            placement.id,
            placement.resource_version,
            placement.write_spec_version,
            revision.revision,
        )
        .await
        .unwrap();
        assert!(
            db.surface_placement(placement.id)
                .await
                .unwrap()
                .unwrap()
                .effective_write_enabled
        );
    }
    (revision.revision, credential_generation)
}

/// Exercises durable multipart admission, replay, conflict, and completion.
async fn exercise_topology_multipart(
    db: &Database,
    org_id: i64,
    cache_id: i64,
    cache_placement: &SurfacePlacementRecord,
    binding_revision: i64,
    credential_generation: i64,
) {
    let body_digest = "1".repeat(64);
    let other_digest = "2".repeat(64);
    let intended_hash = "3".repeat(64);

    let observing = db
        .begin_cache_write_ticket(
            "dialect-cache-multipart",
            cache_id,
            cache_placement.id,
            cache_placement.resource_version,
            binding_revision,
            credential_generation,
            "nar/multipart.nar.zst",
            3,
            "multipart",
            Some(org_id),
            0,
            0,
            1_000,
            100,
            None,
            None,
        )
        .await
        .unwrap();
    let active = db
        .activate_cache_write_ticket(
            &observing.ticket_id,
            observing.resource_version,
            Some(org_id),
            3,
            1,
            None,
            Some(&intended_hash),
            101,
        )
        .await
        .unwrap();
    let active = db
        .claim_cache_write_backend_creation(
            &active.ticket_id,
            active.resource_version,
            "dialect-cache-create-token",
            200,
            102,
        )
        .await
        .unwrap();
    let active = db
        .attach_cache_write_backend_upload(
            &active.ticket_id,
            active.resource_version,
            "dialect-cache-create-token",
            "dialect-cache-backend-upload",
            103,
        )
        .await
        .unwrap();
    let admitted = db
        .admit_cache_write_part(
            &active.ticket_id,
            active.resource_version,
            1,
            3,
            &body_digest,
        )
        .await
        .unwrap();
    let replay = db
        .admit_cache_write_part(
            &admitted.ticket_id,
            admitted.resource_version,
            1,
            3,
            &body_digest,
        )
        .await
        .unwrap();
    assert_eq!(replay.uploaded_size, 3, "exact replay cannot double-charge");
    assert!(db
        .admit_cache_write_part(
            &replay.ticket_id,
            replay.resource_version,
            1,
            3,
            &other_digest,
        )
        .await
        .is_err());
    db.confirm_cache_write_part(
        &replay.ticket_id,
        replay.resource_version,
        1,
        "cache-part-etag",
    )
    .await
    .unwrap();
    let active = db
        .cache_write_ticket(&replay.ticket_id)
        .await
        .unwrap()
        .unwrap();
    let completing = db
        .begin_cache_multipart_completion(&active.ticket_id, active.resource_version, 103)
        .await
        .unwrap();
    let completing = db
        .reconcile_cache_write_ticket_size(
            &completing.ticket_id,
            completing.resource_version,
            3,
            104,
        )
        .await
        .unwrap();
    db.complete_cache_write_ticket(&completing.ticket_id, completing.resource_version, 105)
        .await
        .unwrap();
}

/// Drives the representative cross-section of the `Database` surface against an
/// already-migrated handle, asserting the parity invariants that must hold on
/// every dialect.
///
/// Covers: org/user/service-account creation, membership grants and effective
/// scope resolution, token mint + validation, managed-registry creation,
/// multi-placement cache inventory publication + fail-closed GC, durable cache
/// multipart cache writes, a config change-set apply, audit record +
/// scoped list, and the webhook enqueue/list path.
async fn exercise(db: &Database) {
    // Mirror creation SSRF-validates its target; these
    // contract assertions use placeholder hosts, so opt out of the
    // local/internal-address rejection (the non-HTTP scheme rejection still
    // applies). Production never sets this.
    std::env::set_var("AOS_HUB_ALLOW_LOCAL_REMOTES", "1");

    // -- orgs, projects, users -------------------------------------------------
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    assert_eq!(db.org_by_slug("acme").await.unwrap().unwrap().id, org);
    db.create_project(org, "infra", "Infrastructure")
        .await
        .unwrap();
    assert_eq!(db.list_projects(org).await.unwrap().len(), 1);

    let alice = db
        .create_user("alice@acme.com", Some("Alice"))
        .await
        .unwrap();
    assert_eq!(
        db.user_by_email("alice@acme.com").await.unwrap(),
        Some(alice)
    );
    assert_eq!(
        db.user_email(alice).await.unwrap().as_deref(),
        Some("alice@acme.com")
    );

    let ci = db.create_service_account(org, "ci").await.unwrap();
    assert_eq!(
        db.service_account_by_name(org, "ci").await.unwrap(),
        Some(ci)
    );

    // -- memberships + effective scopes ---------------------------------------
    let principal = Principal::user(alice);
    let org_scope = common::org_scope(db, "acme").await;
    let project_scope = common::project_scope(db, "acme", "infra").await;
    db.grant_membership(principal.kind.as_str(), principal.id, &org_scope, "admin")
        .await
        .unwrap();
    db.grant_membership(
        principal.kind.as_str(),
        principal.id,
        &project_scope,
        "maintainer",
    )
    .await
    .unwrap();
    let scopes = db.effective_scopes(principal).await.unwrap();
    assert_eq!(scopes.len(), 2, "two grants resolve");
    assert_eq!(
        db.list_memberships_for("user", alice).await.unwrap().len(),
        2
    );
    assert_eq!(db.list_members_of_scope(&org_scope).await.unwrap().len(), 1);

    // -- tokens ----------------------------------------------------------------
    let (token_id, secret) = db
        .create_token(
            principal,
            &project_scope,
            &[Permission::Read, Permission::Publish],
            Some("ci token"),
            None,
        )
        .await
        .unwrap();
    let auth = db
        .validate_token(&secret)
        .await
        .unwrap()
        .expect("freshly minted token validates");
    assert_eq!(auth.token_id, token_id);
    assert_eq!(auth.owner, principal);
    assert_eq!(auth.scope.as_str(), project_scope);
    assert_eq!(
        auth.permissions,
        vec![Permission::Read, Permission::Publish]
    );
    assert!(
        db.validate_token("aos_not_a_real_secret")
            .await
            .unwrap()
            .is_none(),
        "unknown secret rejected"
    );

    // -- binding + managed registry -----------------------------------
    let binding = common::create_local_binding(&db, org, "primary", "/srv/aos-hub").await;
    db.create_project(org, "infra/prod", "Production")
        .await
        .unwrap();
    let reg = db
        .create_managed_registry(
            org,
            "infra/prod",
            "cdn",
            "private",
            &["cdn:Ed25519:AAAA".to_string()],
            true,
        )
        .await
        .unwrap();
    let record = db
        .registry_by_scope("acme", "infra/prod", "cdn")
        .await
        .unwrap()
        .expect("managed registry resolves by scope");
    assert_eq!(record.id, reg);
    assert_eq!(record.visibility, "private");
    let registry_scope = db.registry_authorization_scope(reg).await.unwrap();
    let registry_placement = common::create_ready_placement(
        db,
        aos_hub::db::SurfaceTarget::Registry(reg),
        binding,
        "primary",
        "infra/prod/cdn",
    )
    .await;

    // -- managed caches (v22+) -------------------------------------------------
    // Exercise the final cache topology on every dialect: two simultaneous
    // placements, atomic inventory publication, fail-closed GC, and the same
    // durable multipart protocol used by both cache and registry writes.
    let cache = db
        .create_binary_cache(
            Some(org),
            "acme-cache",
            "Acme Cache",
            "public",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        db.binary_cache_by_slug("acme-cache")
            .await
            .unwrap()
            .unwrap()
            .id,
        cache
    );
    let cache_primary = common::create_ready_placement(
        db,
        SurfaceTarget::BinaryCache(cache),
        binding,
        "cache-primary",
        "cache/primary",
    )
    .await;
    let cache_replica = common::create_ready_placement(
        db,
        SurfaceTarget::BinaryCache(cache),
        binding,
        "cache-replica",
        "cache/replica",
    )
    .await;
    exercise_topology_inventory_and_gc(db, cache, &[cache_primary.clone(), cache_replica]).await;
    let usage = db.cache_usage(cache).await.unwrap();
    assert_eq!(usage.object_count, 1);
    assert_eq!(usage.used_bytes, 3);
    assert_eq!(
        db.search_normalized_cache_objects(cache, "dialect", 10)
            .await
            .unwrap()
            .len(),
        1
    );
    let (binding_revision, credential_generation) =
        configure_dialect_writers(db, binding, reg, &registry_placement, cache, &cache_primary)
            .await;
    db.add_org_usage(org, 0, 0).await.unwrap();
    exercise_topology_multipart(
        db,
        org,
        cache,
        &cache_primary,
        binding_revision,
        credential_generation,
    )
    .await;
    // -- configuration change-set ---------------------------------------------
    let change_id = "00000000-0000-4000-8000-000000000001";
    db.create_changeset(
        change_id,
        "user",
        Some(alice),
        "alice@acme.com",
        &registry_scope,
        Some("make cdn public"),
    )
    .await
    .unwrap();
    db.add_revision(
        change_id,
        "registry",
        &registry_scope,
        "update",
        Some(r#"{"visibility":"private"}"#),
        Some(r#"{"visibility":"public"}"#),
    )
    .await
    .unwrap();
    // Collect the object types touched by the changeset, then apply the live
    // mutation outside the closure: the closure passed to `apply_changeset`
    // returns a `'static`-friendly boxed future, so it must not borrow `db`.
    let touched = std::sync::Arc::new(std::sync::Mutex::new(Vec::<bool>::new()));
    let touched_in = std::sync::Arc::clone(&touched);
    db.apply_changeset(change_id, move |rev| {
        let is_registry = rev.object_type == "registry";
        let touched_in = std::sync::Arc::clone(&touched_in);
        Box::pin(async move {
            touched_in.lock().unwrap().push(is_registry);
            Ok(())
        })
    })
    .await
    .unwrap();
    if touched.lock().unwrap().iter().any(|&r| r) {
        let current = db.registry_by_id(reg).await.unwrap().unwrap();
        assert!(db
            .seed_registry_configuration_for_test(
                reg,
                current.resource_version,
                "public",
                &current.crawl_policy,
                current.llms_txt_body.as_deref(),
                &current.trust_keys,
                "00000000-0000-4000-8000-000000000002",
                "user",
                Some(alice),
                "alice@acme.com",
            )
            .await
            .unwrap());
    }
    assert_eq!(
        db.registry_by_slug("acme/infra/prod/cdn")
            .await
            .unwrap()
            .unwrap()
            .visibility,
        "public",
        "change-set applied the visibility flip"
    );
    assert_eq!(
        db.changeset(change_id).await.unwrap().unwrap().status,
        "applied"
    );
    assert_eq!(db.list_revisions(change_id).await.unwrap().len(), 1);

    // -- audit -----------------------------------------------------------------
    db.record_audit(
        "user",
        Some(alice),
        "alice@acme.com",
        "registry.visibility",
        &registry_scope,
        Some(change_id),
        None,
        None,
        Some(r#"{"old":"private","new":"public"}"#),
    )
    .await
    .unwrap();
    let org_audit = db.list_audit(&org_scope).await.unwrap();
    assert_eq!(
        org_audit
            .iter()
            .filter(|row| row.action == "registry.visibility")
            .count(),
        1,
        "org-scoped query surfaces the registry action"
    );
    assert!(
        db.list_audit("other").await.unwrap().is_empty(),
        "an unrelated scope sees nothing"
    );

    // -- webhooks --------------------------------------------------------------
    let hook = db
        .seed_webhook_for_test(
            org,
            "https://ci.acme/hook",
            "native://acme/webhook/v1",
            "043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(db.list_webhooks(org).await.unwrap().len(), 1);
    db.seed_topology_event_for_test(
        "webhook.created",
        &org_scope,
        "webhook",
        &format!("webhook:{hook}"),
    )
    .await
    .unwrap();
    db.seed_topology_event_for_test(
        "webhook.deleted",
        &org_scope,
        "webhook",
        &format!("webhook:{hook}"),
    )
    .await
    .unwrap();
    assert_eq!(db.materialize_topology_events().await.unwrap(), 2);
    let delivery = db
        .seed_delivery_for_test(
            hook,
            "index.completed",
            r#"{"registry":"acme/infra/prod/cdn"}"#,
        )
        .await
        .unwrap();
    let due = db.claim_due_deliveries(i64::MAX, 100, 30).await.unwrap();
    assert_eq!(due.len(), 3);
    assert!(due.iter().any(|row| row.id == delivery));
    assert!(due.iter().all(|row| row.url == "https://ci.acme/hook"));
    let (pending, delivered, failed) = db.delivery_status_counts().await.unwrap();
    assert_eq!((pending, delivered, failed), (3, 0, 0));

    // -- validation findings + repair jobs (v14) ------------------------------
    // Record a deep run with one missing and one corrupt finding, then assert
    // they round-trip distinctly on every dialect.
    let run_id = db
        .record_validation_run_with_findings(
            reg,
            "file:///srv/cache",
            "deep",
            5,
            &[
                aos_hub::db::ValidationFinding {
                    store_hash: "absent01".into(),
                    status: aos_hub::db::FindingStatus::Missing,
                },
                aos_hub::db::ValidationFinding {
                    store_hash: "tampered1".into(),
                    status: aos_hub::db::FindingStatus::Corrupt,
                },
            ],
            true,
            0,
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        db.validation_missing(run_id).await.unwrap(),
        vec!["absent01"]
    );
    assert_eq!(
        db.validation_corrupt(run_id).await.unwrap(),
        vec!["tampered1"]
    );

    // Record a repair job and read it back.
    db.record_repair_job(
        reg,
        "file:///srv/cache",
        "absent01",
        "file:///srv/good",
        "done",
        None,
        0,
        Some(1),
    )
    .await
    .unwrap();
    let jobs = db.list_repair_jobs(reg, 10).await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, "done");
    assert_eq!(jobs[0].store_hash, "absent01");
    assert_eq!(jobs[0].source_cache_url, "file:///srv/good");

    // -- mirror sources -------------------------------------------------------
    // A mirror source round-trips and `is_mirror` flips; the last-sync record
    // updates without clobbering the frontier on a later failure.
    assert!(!db.is_mirror(reg).await.unwrap());
    db.create_mirror_source(reg, "https://upstream.example/", "full", true, 1800)
        .await
        .unwrap();
    assert!(db.is_mirror(reg).await.unwrap());
    let source = db.mirror_source(reg).await.unwrap().expect("mirror source");
    assert_eq!(source.upstream_url, "https://upstream.example/");
    assert_eq!(source.mode, "full");
    assert!(source.verify);
    assert_eq!(source.schedule_secs, 1800);
    db.update_mirror_sync(reg, 100, "ok", None, Some("2.0.0"))
        .await
        .unwrap();
    db.update_mirror_sync(reg, 200, "failed", Some("upstream tampered"), None)
        .await
        .unwrap();
    let source = db.mirror_source(reg).await.unwrap().unwrap();
    assert_eq!(source.last_sync_status.as_deref(), Some("failed"));
    assert_eq!(source.last_sync_error.as_deref(), Some("upstream tampered"));
    // The frontier from the prior OK sync survives the later failure.
    assert_eq!(source.upstream_frontier.as_deref(), Some("2.0.0"));
    assert_eq!(db.list_mirror_sources().await.unwrap().len(), 1);
}

#[tokio::test]
async fn sqlite_contract() {
    let db = Database::open_in_memory().await.unwrap();
    exercise(&db).await;
    println!("dialect contract: sqlite OK");
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_contract() {
    let Ok(url) = std::env::var("AOS_HUB_TEST_PG_URL") else {
        #[cfg(feature = "required-live-dialects")]
        panic!("AOS_HUB_TEST_PG_URL is required by the live dialect gate");
        #[cfg(not(feature = "required-live-dialects"))]
        println!("dialect contract: postgres SKIPPED (AOS_HUB_TEST_PG_URL unset)");
        #[cfg(not(feature = "required-live-dialects"))]
        return;
    };
    reset_pg_schema(&url).await;
    let db = Database::connect(&url)
        .await
        .expect("connect + migrate postgres");
    exercise(&db).await;
    println!("dialect contract: postgres OK ({url})");
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn mysql_contract() {
    let Ok(url) = std::env::var("AOS_HUB_TEST_MYSQL_URL") else {
        #[cfg(feature = "required-live-dialects")]
        panic!("AOS_HUB_TEST_MYSQL_URL is required by the live dialect gate");
        #[cfg(not(feature = "required-live-dialects"))]
        println!("dialect contract: mysql SKIPPED (AOS_HUB_TEST_MYSQL_URL unset)");
        #[cfg(not(feature = "required-live-dialects"))]
        return;
    };
    reset_mysql_schema(&url).await;
    let db = Database::connect(&url)
        .await
        .expect("connect + migrate mysql");
    exercise(&db).await;
    drop(db);

    reset_mysql_schema(&url).await;
    seed_legacy_mysql_v19(&url).await;
    let upgraded = Database::connect(&url)
        .await
        .expect("upgrade a physical mysql v19 schema to v20");
    assert_mysql_v19_catalog_upgrade(&url).await;
    drop(upgraded);

    println!("dialect contract: mysql fresh + v19 upgrade OK ({url})");
}

/// Drops every table in the target postgres database, so the subsequent
/// connect re-runs all migrations from scratch and the run is idempotent.
#[cfg(feature = "postgres")]
async fn reset_pg_schema(url: &str) {
    use sqlx::{Executor as _, PgPool};

    let pool = PgPool::connect(url)
        .await
        .expect("connecting to postgres for schema reset");
    // The public schema cascade is the cleanest full reset for a test database.
    pool.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("dropping public schema");
}

/// Drops every table in the target mysql database, so the subsequent connect
/// re-runs all migrations from scratch and the run is idempotent.
#[cfg(feature = "mysql")]
async fn reset_mysql_schema(url: &str) {
    use sqlx::{Connection as _, MySqlConnection};

    let db_name = url.rsplit_once('/').map(|(_, name)| name.to_string());
    let mut connection = MySqlConnection::connect(url)
        .await
        .expect("connecting to mysql for reset");
    if let Some(db) = db_name {
        // Drop and recreate the whole database — the simplest idempotent reset.
        sqlx::query(&format!("DROP DATABASE IF EXISTS `{db}`"))
            .execute(&mut connection)
            .await
            .expect("dropping mysql database");
        sqlx::query(&format!("CREATE DATABASE `{db}`"))
            .execute(&mut connection)
            .await
            .expect("creating mysql database");
        sqlx::query(&format!("USE `{db}`"))
            .execute(&mut connection)
            .await
            .expect("selecting mysql database");
    }
}

/// Creates a pre-catalog schema with the shipped v19 release-key representation.
///
/// This intentionally stops at v19 and stamps the legacy marker instead of
/// using [`Database::connect`], which would immediately apply v20 and hide an
/// incompatible foreign key in the catalog migration. Unrelated v19 tables use
/// the current fresh-schema translation, while the v1 source is rewritten to
/// the exact historical release-key declarations before it is translated.
#[cfg(feature = "mysql")]
async fn seed_legacy_mysql_v19(url: &str) {
    use aos_hub_core::backend::split_statements;
    use aos_hub_core::db::MIGRATIONS;
    use aos_hub_core::dialect::Dialect;
    use sqlx::{Connection as _, MySqlConnection, Row as _};

    const LEGACY_VERSION: usize = 19;
    assert_eq!(
        MIGRATIONS.len(),
        LEGACY_VERSION + 1,
        "the OCI catalog must remain migration v20"
    );

    let mut connection = MySqlConnection::connect(url)
        .await
        .expect("connecting to mysql to seed v19");
    sqlx::query("CREATE TABLE schema_version (version BIGINT NOT NULL)")
        .execute(&mut connection)
        .await
        .expect("creating the legacy version marker");

    for (offset, migration) in MIGRATIONS[..LEGACY_VERSION].iter().enumerate() {
        let migration = if offset == 0 {
            migration
                .replace("semver KEYTEXT255 NOT NULL", "semver TEXT NOT NULL")
                .replace("release KEYTEXT255 NOT NULL", "release TEXT NOT NULL")
        } else {
            (*migration).to_string()
        };
        for statement in split_statements(&migration) {
            let translated = Dialect::Mysql
                .translate(&statement)
                .expect("translating a legacy mysql migration");
            sqlx::query(&translated.sql)
                .execute(&mut connection)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "applying legacy mysql migration v{} failed: {error}; SQL: {}",
                        offset + 1,
                        translated.sql
                    )
                });
        }
    }
    sqlx::query("INSERT INTO schema_version(version) VALUES (?)")
        .bind(LEGACY_VERSION as i64)
        .execute(&mut connection)
        .await
        .expect("stamping mysql schema v19");

    let releases_semver = sqlx::query(
        "SELECT DATA_TYPE, CAST(CHARACTER_MAXIMUM_LENGTH AS SIGNED)
         FROM information_schema.columns
         WHERE table_schema = DATABASE()
           AND table_name = 'releases' AND column_name = 'semver'",
    )
    .fetch_one(&mut connection)
    .await
    .expect("reading the physical v19 release key");
    assert_eq!(
        releases_semver
            .try_get::<String, _>(0)
            .expect("releases.semver data type"),
        "varchar"
    );
    assert_eq!(
        releases_semver
            .try_get::<i64, _>(1)
            .expect("releases.semver capacity"),
        255
    );
}

/// Verifies that production migration v20 links roots without changing v19.
#[cfg(feature = "mysql")]
async fn assert_mysql_v19_catalog_upgrade(url: &str) {
    use sqlx::{Connection as _, MySqlConnection};

    let mut connection = MySqlConnection::connect(url)
        .await
        .expect("connecting to mysql after v20 upgrade");
    let version: i64 = sqlx::query_scalar("SELECT version FROM hub_schema_version WHERE id = 1")
        .fetch_one(&mut connection)
        .await
        .expect("reading the upgraded mysql schema version");
    assert_eq!(version, 20);

    let numeric_release_fk: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM information_schema.key_column_usage
         WHERE table_schema = DATABASE()
           AND table_name = 'oci_release_roots'
           AND column_name = 'release_id'
           AND referenced_table_name = 'releases'
           AND referenced_column_name = 'id'",
    )
    .fetch_one(&mut connection)
    .await
    .expect("reading the v20 release-root foreign key");
    assert_eq!(numeric_release_fk, 1);

    let incompatible_tag_fk: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM information_schema.key_column_usage
         WHERE table_schema = DATABASE()
           AND table_name = 'oci_release_roots'
           AND column_name = 'release_tag'
           AND referenced_table_name = 'releases'
           AND referenced_column_name = 'semver'",
    )
    .fetch_one(&mut connection)
    .await
    .expect("checking for an incompatible v20 release-tag foreign key");
    assert_eq!(incompatible_tag_fk, 0);
}
