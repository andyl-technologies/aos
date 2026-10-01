//! Live SQL coverage for upload-version inventory and reviewed deletion grants.

use super::*;
use aos_hub_core::db::{
    AppendOciProviderInventoryPage, ApplyOciGc, BeginOciProviderInventory,
    CompleteOciProviderInventory, OciImageConfigProjection, OciLayerProjection,
    OciProviderInventoryEntryInput, PlanOciGc, RecordOciConditionalDeleteCapability,
};

pub(super) async fn exercise(db: &Database, org_id: i64, binding_id: i64) {
    let registry_id = db
        .create_managed_registry(org_id, "", "incarnation-gc", "private", &[], false)
        .await
        .unwrap();
    let placement = common::create_ready_placement(
        db,
        SurfaceTarget::Registry(registry_id),
        binding_id,
        "incarnation-primary",
        "incarnation-gc",
    )
    .await;
    let binding = db.binding(binding_id).await.unwrap().unwrap();
    let revision = db
        .binding_write_state(binding_id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    db.bind_surface_placement_write_capability(placement.id, revision)
        .await
        .unwrap();
    db.create_surface_write_authority(
        SurfaceTarget::Registry(registry_id),
        "incarnation-gc-writer",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        revision,
    )
    .await
    .unwrap();

    let layer_bytes = b"incarnation-layer";
    let layer = oci_descriptor(MediaType::OciLayerGzip, layer_bytes);
    let diff_id = Sha256Digest::digest(layer_bytes);
    let config_json = format!(
        "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"{diff_id}\"]}}}}"
    );
    let config = oci_descriptor(MediaType::OciImageConfig, config_json.as_bytes());
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: Some(MediaType::OciImageManifest),
        artifact_type: None,
        config: config.clone(),
        layers: vec![layer.clone()],
        subject: None,
        annotations: Annotations::new(),
    };
    let manifest_bytes = aos_oci_types::to_canonical_json(&manifest).unwrap();
    let root = oci_descriptor(MediaType::OciImageManifest, &manifest_bytes);
    let catalog = IndexOciRepositoryCatalog {
        registry_id,
        placement_id: placement.id,
        repository: RepositoryName::parse("unreferenced").unwrap(),
        objects: vec![
            OciCatalogObject {
                descriptor: root.clone(),
                projection: Some(OciCatalogProjection::Manifest {
                    document: manifest,
                    platform: Some(Platform::linux_amd64()),
                    image_config: Some(OciImageConfigProjection {
                        config_json,
                        aos_system: "x86_64-linux".into(),
                        layers: vec![OciLayerProjection {
                            unpacked_byte_size: layer_bytes.len() as u64,
                            diff_id,
                            closure_group: String::new(),
                        }],
                    }),
                }),
            },
            OciCatalogObject {
                descriptor: config,
                projection: None,
            },
            OciCatalogObject {
                descriptor: layer,
                projection: None,
            },
        ],
        root_digest: root.digest,
        tag: None,
        source_kind: "manual".into(),
        actor_id: "test:incarnation-gc".into(),
        observed_at: 10,
    };
    for object in &catalog.objects {
        db.record_oci_uploaded_object(
            registry_id,
            placement.id,
            object.descriptor.digest,
            object.descriptor.size,
            "uploaded-etag",
            catalog.observed_at,
        )
        .await
        .unwrap();
    }
    db.index_oci_repository_catalog(&catalog).await.unwrap();

    // The nullable identity remains supported for local providers. Supplying a
    // real opaque identity exercises the same SQL as deployment-R2 on all engines.
    let now = 2_000_000;
    db.record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
        binding_id,
        binding_write_revision: revision,
        binding_resource_version: binding.resource_version,
        delete_credential_purpose: None,
        delete_credential_generation: None,
        capability_fingerprint: "incarnation-guard-v1".into(),
        state: "valid".into(),
        expected_resource_version: None,
        observed_at: now,
    })
    .await
    .unwrap();
    let generation = db
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id,
            placement_id: placement.id,
            expected_placement_resource_version: placement.resource_version,
            expected_placement_observation_version: placement.observation_version.unwrap(),
            collector_id: "incarnation-collector".into(),
            collector_claim_token: "incarnation-claim".into(),
            collector_lease_seconds: 100,
            idempotency_key: "incarnation-inventory".into(),
            now,
        })
        .await
        .unwrap();
    let mut entries = catalog
        .objects
        .iter()
        .map(|object| OciProviderInventoryEntryInput {
            object_key: aos_hub_core::db::oci_blob_object_key(object.descriptor.digest),
            object_digest: object.descriptor.digest,
            observed_hash: object.descriptor.digest,
            byte_size: object.descriptor.size,
            strong_etag: "\"same-content-etag\"".into(),
            provider_version: Some(format!("upload:{}", object.descriptor.digest.encoded())),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.object_key.cmp(&right.object_key));
    let page = AppendOciProviderInventoryPage {
        generation_id: generation.id.clone(),
        collector_id: "incarnation-collector".into(),
        collector_claim_token: "incarnation-claim".into(),
        expected_checkpoint_ordinal: 0,
        expected_provider_cursor: None,
        next_provider_cursor: None,
        last_listed_key: entries.last().map(|entry| entry.object_key.clone()),
        entries,
        now: now + 1,
        lease_seconds: 100,
    };
    let persisted = db.append_oci_provider_inventory_page(&page).await.unwrap();
    assert_eq!(
        db.append_oci_provider_inventory_page(&page).await.unwrap(),
        persisted
    );
    let mut replacement = page.clone();
    replacement.entries[0].provider_version = Some("replacement-upload".into());
    assert!(db
        .append_oci_provider_inventory_page(&replacement)
        .await
        .is_err());

    let sealed = db
        .complete_oci_provider_inventory(&CompleteOciProviderInventory {
            generation_id: generation.id,
            collector_id: "incarnation-collector".into(),
            collector_claim_token: "incarnation-claim".into(),
            expected_checkpoint_ordinal: 1,
            observed_at: now + 1,
            now: now + 2,
        })
        .await
        .unwrap();
    assert_eq!(
        sealed.inventory_digest,
        Some(Sha256Digest::digest(
            &serde_json::to_vec(&page.entries).unwrap()
        ))
    );
    // Head replacement must be portable and monotonic. An older observation
    // cannot roll back the complete generation or its checkpoint; equal-time
    // observations use the exact generation ID ordering on every engine.
    let next = db
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id,
            placement_id: placement.id,
            expected_placement_resource_version: placement.resource_version,
            expected_placement_observation_version: placement.observation_version.unwrap(),
            collector_id: "incarnation-collector-next".into(),
            collector_claim_token: "incarnation-claim-next".into(),
            collector_lease_seconds: 100,
            idempotency_key: "incarnation-inventory-next".into(),
            now: now + 3,
        })
        .await
        .unwrap();
    let mut next_page = page.clone();
    next_page.generation_id = next.id.clone();
    next_page.collector_id = "incarnation-collector-next".into();
    next_page.collector_claim_token = "incarnation-claim-next".into();
    next_page.now = now + 3;
    db.append_oci_provider_inventory_page(&next_page)
        .await
        .unwrap();
    let mut completion = CompleteOciProviderInventory {
        generation_id: next.id.clone(),
        collector_id: "incarnation-collector-next".into(),
        collector_claim_token: "incarnation-claim-next".into(),
        expected_checkpoint_ordinal: 1,
        observed_at: now,
        now: now + 4,
    };
    assert!(db
        .complete_oci_provider_inventory(&completion)
        .await
        .is_err());
    assert_eq!(
        db.oci_provider_inventory_head(placement.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        sealed.id
    );
    assert_eq!(
        db.oci_provider_inventory_generation(&next.id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "sealing"
    );
    completion.observed_at = sealed.observed_at.unwrap();
    let equal_time = db.complete_oci_provider_inventory(&completion).await;
    assert_eq!(equal_time.is_ok(), next.id > sealed.id);
    if equal_time.is_err() {
        completion.observed_at += 1;
        db.complete_oci_provider_inventory(&completion)
            .await
            .unwrap();
    }
    assert_eq!(
        db.oci_provider_inventory_head(placement.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        next.id
    );
    // Exact terminal replay keeps the published head and row-count contract.
    db.complete_oci_provider_inventory(&completion)
        .await
        .unwrap();

    let plan = db
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "test:incarnation-gc".into(),
            idempotency_key: "incarnation-plan".into(),
            expected_resource_version: 0,
            now: now + 5,
        })
        .await
        .unwrap();
    let blockers = db.list_oci_gc_blockers(&plan.id).await.unwrap();
    assert!(blockers.is_empty(), "GC blockers: {blockers:?}");
    // The first reviewed frontier contains the unreferenced manifest. Its
    // config and layer remain protected until that manifest is removed.
    assert_eq!(plan.planned_objects, 1);
    assert_eq!(plan.planned_bytes, root.size);
    let actions = db
        .list_oci_gc_placement_actions(&plan.id, None, 10, None)
        .await
        .unwrap();
    assert_eq!(actions.items.len(), 1);
    assert_eq!(actions.items[0].digest, root.digest);
    for action in &actions.items {
        let inventoried = page
            .entries
            .iter()
            .find(|entry| entry.object_key == action.object_key)
            .unwrap();
        assert_eq!(
            action.expected_provider_version,
            inventoried.provider_version
        );
    }
    db.apply_oci_gc(&ApplyOciGc {
        generation_id: plan.id,
        actor_id: "test:incarnation-gc".into(),
        idempotency_key: "incarnation-apply".into(),
        confirmation_hash: plan.confirmation_hash,
        now: now + 6,
    })
    .await
    .unwrap();
    let claim = db
        .claim_oci_gc_placement_action(
            "incarnation-worker",
            "incarnation-action-claim",
            now + 7,
            100,
        )
        .await
        .unwrap()
        .unwrap();
    let inventoried = page
        .entries
        .iter()
        .find(|entry| entry.object_key == claim.object_key)
        .unwrap();
    assert_eq!(
        claim.expected_provider_version,
        inventoried.provider_version
    );
}
