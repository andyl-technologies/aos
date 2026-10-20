//! Webhooks regression cases and contract checks.

use super::*;

#[tokio::test]
async fn webhook_limit_is_serialized_inside_the_create_transaction() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db.create_org("webhook-cap", "Webhook Cap").await.unwrap();
    let fingerprint = "0".repeat(64);
    for ordinal in 0..(MAX_WEBHOOKS_PER_ORG - 1) {
        db.create_webhook_from_plan(
            org_id,
            "https://hooks.example.test/aos",
            "native://webhook-cap/signing/v1",
            &fingerprint,
            &[],
            &format!("cap-seed-{ordinal}"),
            "system",
            None,
            "webhook limit test",
        )
        .await
        .unwrap();
    }

    let fingerprint = fingerprint.as_str();
    let create = |plan_id: &'static str| {
        let db = Arc::clone(&db);
        async move {
            db.create_webhook_from_plan(
                org_id,
                "https://hooks.example.test/aos",
                "native://webhook-cap/signing/v1",
                fingerprint,
                &[],
                plan_id,
                "system",
                None,
                "webhook limit test",
            )
            .await
        }
    };
    let (left, right) = tokio::join!(create("cap-race-left"), create("cap-race-right"));
    assert_ne!(
        left.is_ok(),
        right.is_ok(),
        "exactly one contender wins the last slot"
    );
    assert_eq!(
        db.list_webhooks(org_id).await.unwrap().len(),
        MAX_WEBHOOKS_PER_ORG
    );
}

#[tokio::test]
async fn registry_configuration_cas_commits_head_history_audit_and_outbox_once() {
    let db = Database::open_in_memory().await.unwrap();
    db.register_registry("demo", &[], false).await.unwrap();
    let before = db.registry_by_slug("demo").await.unwrap().unwrap();
    let change_id = uuid::Uuid::new_v4().to_string();

    assert!(db
        .apply_registry_configuration_change(
            before.id,
            before.resource_version,
            "private",
            "deny_all",
            Some("# private registry\n"),
            &before.trust_keys,
            &change_id,
            "user",
            Some(42),
            "operator@example.test",
        )
        .await
        .unwrap());

    let after = db.registry_by_slug("demo").await.unwrap().unwrap();
    assert_eq!(after.resource_version, before.resource_version + 1);
    assert_eq!(after.visibility, "private");
    let changeset = db.changeset(&change_id).await.unwrap().unwrap();
    assert_eq!(changeset.status, "applied");
    assert_eq!(changeset.actor_label, "operator@example.test");
    let revisions = db.list_revisions(&change_id).await.unwrap();
    assert_eq!(revisions.len(), 1);
    assert_eq!(revisions[0].object_id, before.stable_id.as_str());
    assert_eq!(revisions[0].op, "update");

    assert!(db
        .apply_registry_configuration_change(
            before.id,
            before.resource_version,
            "private",
            "deny_all",
            Some("# private registry\n"),
            &before.trust_keys,
            &change_id,
            "user",
            Some(42),
            "operator@example.test",
        )
        .await
        .unwrap());
    assert_eq!(db.list_revisions(&change_id).await.unwrap().len(), 1);

    assert_eq!(db.materialize_topology_events().await.unwrap(), 1);
    assert_eq!(db.materialize_topology_events().await.unwrap(), 0);
    let audit = db.list_audit(&before.scope_key).await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].change_id.as_deref(), Some(change_id.as_str()));
    assert_eq!(audit[0].action, "registry.configuration.updated");

    let stale_change_id = uuid::Uuid::new_v4().to_string();
    assert!(!db
        .apply_registry_configuration_change(
            before.id,
            before.resource_version,
            "public",
            "allow_all",
            None,
            &[],
            &stale_change_id,
            "user",
            Some(42),
            "operator@example.test",
        )
        .await
        .unwrap());
    assert!(db.changeset(&stale_change_id).await.unwrap().is_none());
    assert_eq!(
        db.registry_by_slug("demo")
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        after.resource_version
    );
}

#[tokio::test]
async fn registry_delete_cas_commits_history_audit_and_outbox_once() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("retired", "Retired").await.unwrap();
    let id = db
        .create_managed_registry(org_id, "", "registry", "private", &[], false)
        .await
        .unwrap();
    let registry = db.registry_by_id(id).await.unwrap().unwrap();
    let binding_id = create_test_binding(&db, org_id, "retired", "/tmp/retired").await;
    let mut placement = topology_placement(SurfaceTarget::Registry(id), "primary", "retired", 0);
    placement.binding_id = binding_id;
    let placement = db.create_surface_placement(&placement).await.unwrap();
    let placement = db
        .observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    let write_generation =
        create_valid_write_credential(&db, binding_id, "secret://binding/retired/v1").await;
    let write_revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id: binding_id,
            write_credential_generation: write_generation,
            writes_supported: true,
            conditional_writes_supported: false,
            revision_fingerprint: "retired-write-v1".into(),
            capability_fingerprint: "retired-writes".into(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding_id, write_revision.revision, "valid", None, None)
        .await
        .unwrap();
    let write_state = db.binding_write_state(binding_id).await.unwrap().unwrap();
    db.set_current_binding_write_revision(
        binding_id,
        write_revision.revision,
        write_state.resource_version,
    )
    .await
    .unwrap();
    db.bind_surface_placement_write_capability(placement.id, write_revision.revision)
        .await
        .unwrap();
    db.create_surface_write_authority(
        SurfaceTarget::Registry(id),
        "retired-authority-v1",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        write_revision.revision,
    )
    .await
    .unwrap();
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: "retired-publication".into(),
        registry_id: id,
        generation: "retired-generation".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: None,
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.fail_registry_publication("retired-publication", unix_now())
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO registry_publications
                 (publication_id, registry_id, ordinal, generation,
                  manifest_digest, refs_digest, parent_publication_id, state,
                  created_at, completed_at)
                 VALUES ('retired-publication-child', ?1, 2,
                   'retired-generation-child', ?2, ?3,
                   'retired-publication', 'failed', ?4, ?4)",
            &vals![id, "5".repeat(64), "6".repeat(64), unix_now()],
        )
        .await
        .unwrap();
    let cache_id = db
        .create_binary_cache(
            Some(org_id),
            "retired-cache",
            "Retired cache",
            "private",
            10,
            "zstd",
            true,
        )
        .await
        .unwrap();
    db.backend
        .batch(&[
            Statement::new(
                "INSERT INTO releases
                     (id, registry_id, semver, tag_oid, commit_oid, pack_present)
                     VALUES (9001, ?1, '1.0.0', ?2, ?3, 1)",
                vals![id, "e".repeat(64), "f".repeat(64)],
            ),
            Statement::new(
                "INSERT INTO release_artifact_snapshots
                     (snapshot_id, release_id, registry_id, source_commit,
                      verified_tag_oid, verification_record_id, manifest_digest,
                      state, complete_slot, expected_artifact_count,
                      actual_artifact_count, started_at, completed_at)
                     VALUES ('retired-snapshot', 9001, ?1, ?2, ?3,
                       'retired-verification', ?4, 'complete', 1, 1, 1, ?5, ?5)",
                vals![
                    id,
                    "f".repeat(64),
                    "e".repeat(64),
                    "1".repeat(64),
                    unix_now()
                ],
            ),
            Statement::new(
                "INSERT INTO release_artifacts
                     (snapshot_id, release_id, registry_id, package_name,
                      package_version, platform, artifact_kind, store_path,
                      store_hash, metadata_digest)
                     VALUES ('retired-snapshot', 9001, ?1, 'demo', '1.0.0',
                       'x86_64-linux', 'output', '/nix/store/demo', 'demo', ?2)",
                vals![id, "2".repeat(64)],
            ),
            Statement::new(
                "INSERT INTO release_artifact_snapshot_heads
                     (release_id, registry_id, complete_artifact_snapshot_id,
                      updated_at)
                     VALUES (9001, ?1, 'retired-snapshot', ?2)",
                vals![id, unix_now()],
            ),
            Statement::new(
                "INSERT INTO cache_retention_subscriptions
                     (id, cache_id, registry_id, selector_json, selector_digest,
                      created_at, updated_at)
                     VALUES (9001, ?1, ?2, '{}', ?3, ?4, ?4)",
                vals![cache_id, id, "3".repeat(64), unix_now()],
            ),
            Statement::new(
                "INSERT INTO cache_retention_refreshes
                     (refresh_id, subscription_id, cache_id, registry_id,
                      expected_subscription_version, expected_cache_epoch,
                      selector_digest, registry_source_revision,
                      registry_index_generation, registry_index_digest, state,
                      started_at, activated_at, parent_grace_until, finished_at,
                      expected_reason_count, actual_reason_count)
                     VALUES ('retired-refresh', 9001, ?1, ?2, 1, 0, ?3, ?4,
                       1, ?5, 'complete', ?6, ?6, ?6, ?6, 0, 0)",
                vals![
                    cache_id,
                    id,
                    "3".repeat(64),
                    "retired-source",
                    "4".repeat(64),
                    unix_now()
                ],
            ),
        ])
        .await
        .unwrap();
    db.backend
        .batch(&[
            Statement::new(
                "INSERT INTO cache_retention_refreshes
                     (refresh_id, subscription_id, cache_id, registry_id,
                      parent_refresh_id, expected_parent_refresh_id,
                      expected_subscription_version, expected_cache_epoch,
                      selector_digest, registry_source_revision,
                      registry_index_generation, registry_index_digest, state,
                      started_at, activated_at, parent_grace_until, finished_at,
                      expected_reason_count, actual_reason_count)
                     VALUES ('retired-refresh-child', 9001, ?1, ?2,
                       'retired-refresh', 'retired-refresh', 1, 0, ?3, ?4,
                       2, ?5, 'complete', ?6, ?6, ?6, ?6, 0, 0)",
                vals![
                    cache_id,
                    id,
                    "3".repeat(64),
                    "retired-source-child",
                    "7".repeat(64),
                    unix_now()
                ],
            ),
            Statement::new(
                "INSERT INTO cache_retention_refresh_heads
                     (subscription_id, cache_id, registry_id, current_refresh_id,
                      updated_at)
                     VALUES (9001, ?1, ?2, 'retired-refresh-child', ?3)",
                vals![cache_id, id, unix_now()],
            ),
        ])
        .await
        .unwrap();
    db.materialize_topology_events().await.unwrap();
    let purge_now = unix_now();
    let purge_plan = db
        .plan_oci_registry_purge_fence(&PlanOciRegistryPurgeFence {
            registry_id: id,
            action: OciRegistryPurgeFenceAction::Begin,
            actor_id: "release-controller".to_string(),
            idempotency_key: "retired-purge-plan".to_string(),
            expected_resource_version: registry.resource_version,
            now: purge_now,
        })
        .await
        .unwrap();
    db.apply_oci_registry_purge_fence(&ApplyOciRegistryPurgeFence {
        plan_id: purge_plan.id,
        actor_id: "release-controller".to_string(),
        idempotency_key: "retired-purge-apply".to_string(),
        confirmation_hash: purge_plan.confirmation_hash,
        expected_resource_version: purge_plan.resource_version,
        now: purge_now + 1,
    })
    .await
    .unwrap();

    let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
    let inventory = db
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id: id,
            placement_id: placement.id,
            expected_placement_resource_version: placement.resource_version,
            expected_placement_observation_version: placement.observation_version.unwrap(),
            collector_id: "retired-purge-collector".to_string(),
            collector_claim_token: "retired-purge-claim".to_string(),
            collector_lease_seconds: 100,
            idempotency_key: "retired-purge-inventory".to_string(),
            now: purge_now + 2,
        })
        .await
        .unwrap();
    db.append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
        generation_id: inventory.id.clone(),
        collector_id: "retired-purge-collector".to_string(),
        collector_claim_token: "retired-purge-claim".to_string(),
        expected_checkpoint_ordinal: 0,
        expected_provider_cursor: None,
        next_provider_cursor: None,
        last_listed_key: None,
        entries: Vec::new(),
        now: purge_now + 3,
        lease_seconds: 100,
    })
    .await
    .unwrap();
    db.complete_oci_provider_inventory(&CompleteOciProviderInventory {
        generation_id: inventory.id,
        collector_id: "retired-purge-collector".to_string(),
        collector_claim_token: "retired-purge-claim".to_string(),
        expected_checkpoint_ordinal: 1,
        observed_at: purge_now + 3,
        now: purge_now + 4,
    })
    .await
    .unwrap();
    assert!(!db
        .oci_registry_purge_blockers(id, purge_now + 4)
        .await
        .unwrap()
        .any());

    let change_id = uuid::Uuid::new_v4().to_string();

    assert!(db
        .delete_registry_at_version(
            id,
            registry.resource_version,
            &change_id,
            "service_account",
            Some(9),
            "release-controller",
        )
        .await
        .unwrap());
    assert!(db.registry_by_id(id).await.unwrap().is_none());
    let changeset = db.changeset(&change_id).await.unwrap().unwrap();
    assert_eq!(changeset.status, "applied");
    let revisions = db.list_revisions(&change_id).await.unwrap();
    assert_eq!(revisions.len(), 1);
    assert_eq!(revisions[0].op, "delete");
    assert!(revisions[0].new_json.is_none());

    assert_eq!(db.materialize_topology_events().await.unwrap(), 1);
    assert_eq!(db.materialize_topology_events().await.unwrap(), 0);
    let audit = db.list_audit(&registry.scope_key).await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "registry.deleted");
    assert_eq!(audit[0].change_id.as_deref(), Some(change_id.as_str()));
}
