//! Exact frozen-placement adapter regressions.

use std::collections::BTreeMap;
use std::sync::Arc;

use aos_hub_core::db::{
    Database, NewBindingWriteRevision, NewSurfacePlacementSpec,
    RecordOciConditionalDeleteCapability, SurfaceTarget,
};
use aos_hub_core::fetch::SurfaceProvider as _;
use aos_hub_core::secret_version::{ResolvedSecretVersion, SecretVersionResolver};
use aos_hub_core::surface_write::{self as core_sw, SurfaceWriteProvider as _};
use sha2::{Digest as _, Sha256};

use super::{HubSurfaceProvider, HubSurfaceWriteProvider};

struct TestSecretVersions(BTreeMap<String, Vec<u8>>);

#[async_trait::async_trait]
impl SecretVersionResolver for TestSecretVersions {
    async fn resolve(&self, version_ref: &str) -> anyhow::Result<ResolvedSecretVersion> {
        self.0
            .get(version_ref)
            .cloned()
            .map(ResolvedSecretVersion::from_bytes)
            .ok_or_else(|| anyhow::anyhow!("missing test secret version"))
    }
}

async fn validated_credential(
    db: &Database,
    binding_id: i64,
    purpose: &str,
    version_ref: &str,
    secret: &[u8],
) -> i64 {
    let current = db
        .current_binding_credential(binding_id, purpose)
        .await
        .unwrap();
    let revision = db
        .set_binding_credential_revision(
            binding_id,
            purpose,
            version_ref,
            current.as_ref().map_or(0, |row| row.generation),
            &hex::encode(Sha256::digest(secret)),
            "test",
        )
        .await
        .unwrap();
    db.validate_binding_credential_revision(
        binding_id,
        purpose,
        revision.generation,
        "valid",
        None,
        revision.head_resource_version,
    )
    .await
    .unwrap()
    .generation
}

#[tokio::test]
async fn frozen_local_access_never_reselects_a_current_placement_address() {
    let directory = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let registry_id = db
        .register_registry("frozen-access", &[], false)
        .await
        .unwrap();
    let binding = db
        .ensure_instance_default_binding("local_fs", Some(directory.path().to_str().unwrap()), None)
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "current".into(),
            binding_id: binding.id,
            prefix: "current".into(),
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
    let revision = db
        .binding_write_state(binding.id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    let capability = db
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            binding_id: binding.id,
            binding_write_revision: revision,
            binding_resource_version: binding.resource_version,
            delete_credential_purpose: None,
            delete_credential_generation: None,
            capability_fingerprint: "native-localfs-noreplace-v1".into(),
            state: "valid".into(),
            expected_resource_version: None,
            observed_at: 10,
        })
        .await
        .unwrap();
    let access = core_sw::FrozenSurfaceAccess {
        registry_id,
        placement_id: placement.id,
        placement_name: placement.name.clone(),
        // Simulate a durable claim retaining the old address after the current
        // row moved. The adapter must never select the new address.
        placement_prefix: "frozen".into(),
        placement_resource_version: placement.resource_version,
        placement_write_spec_version: placement.write_spec_version,
        placement_observation_version: placement.observation_version.unwrap(),
        binding_id: binding.id,
        binding_resource_version: binding.resource_version,
        binding_write_revision: revision,
        delete_credential_purpose: None,
        delete_credential_generation: None,
        delete_capability_fingerprint: capability.capability_fingerprint.clone(),
        delete_capability_resource_version: capability.resource_version,
    };

    let bytes = b"frozen bytes";
    let digest = hex::encode(Sha256::digest(bytes));
    let object_key = format!("oci/blobs/sha256/{digest}");
    let frozen_path = directory.path().join("frozen").join(&object_key);
    let current_path = directory.path().join("current").join(&object_key);
    tokio::fs::create_dir_all(frozen_path.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::create_dir_all(current_path.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&frozen_path, bytes).await.unwrap();
    tokio::fs::write(&current_path, b"current bytes")
        .await
        .unwrap();

    // A semantically identical refresh receives a newer resource version and
    // must not wedge an already-frozen action.
    db.record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
        binding_id: binding.id,
        binding_write_revision: revision,
        binding_resource_version: binding.resource_version,
        delete_credential_purpose: None,
        delete_credential_generation: None,
        capability_fingerprint: capability.capability_fingerprint.clone(),
        state: "valid".into(),
        expected_resource_version: Some(capability.resource_version),
        observed_at: 11,
    })
    .await
    .unwrap();

    let reads = HubSurfaceProvider::new(
        Arc::clone(&db),
        reqwest::Client::builder().build().unwrap(),
        None,
    );
    let fetch = reads.frozen_placement_fetcher(&access).await.unwrap();
    assert_eq!(fetch.fetch(&object_key).await.unwrap().unwrap(), bytes);

    let writes =
        HubSurfaceWriteProvider::new(Arc::clone(&db), reqwest::Client::builder().build().unwrap());
    let deleter = writes.frozen_placement_deleter(&access).await.unwrap();
    assert!(matches!(
        deleter
            .delete_if_matches(
                &object_key,
                &core_sw::SurfaceDeletePrecondition {
                    etag: Some(format!("\"snapshot-sha256-{digest}\"")),
                    content_hash: Some(format!("sha256:{digest}")),
                    size: Some(bytes.len() as i64),
                },
            )
            .await
            .unwrap(),
        core_sw::SurfaceDeleteOutcome::Deleted { .. }
    ));
    assert!(!tokio::fs::try_exists(frozen_path).await.unwrap());
    assert_eq!(
        tokio::fs::read(current_path).await.unwrap(),
        b"current bytes"
    );
}

#[tokio::test]
async fn frozen_local_access_rejects_binding_drift_before_io() {
    let directory = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let binding = db
        .ensure_instance_default_binding("local_fs", Some(directory.path().to_str().unwrap()), None)
        .await
        .unwrap();
    let revision = db
        .binding_write_state(binding.id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    let access = core_sw::FrozenSurfaceAccess {
        registry_id: 1,
        placement_id: 1,
        placement_name: "stale".into(),
        placement_prefix: "must-not-delete".into(),
        placement_resource_version: 1,
        placement_write_spec_version: 1,
        placement_observation_version: 1,
        binding_id: binding.id,
        binding_resource_version: binding.resource_version + 1,
        binding_write_revision: revision,
        delete_credential_purpose: None,
        delete_credential_generation: None,
        delete_capability_fingerprint: "native-localfs-noreplace-v1".into(),
        delete_capability_resource_version: 1,
    };
    let path = directory.path().join("must-not-delete/object");
    tokio::fs::create_dir_all(path.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&path, b"retained").await.unwrap();

    let writes = HubSurfaceWriteProvider::new(db, reqwest::Client::builder().build().unwrap());
    assert!(writes.frozen_placement_deleter(&access).await.is_err());
    assert_eq!(tokio::fs::read(path).await.unwrap(), b"retained");
}

#[tokio::test]
async fn frozen_external_access_retains_gen_one_after_current_capability_moves_to_gen_two() {
    const WRITE_REF: &str = "native://frozen/write/v1";
    const DELETE_V1_REF: &str = "native://frozen/delete/v1";
    const DELETE_V2_REF: &str = "native://frozen/delete/v2";
    const WRITE_SECRET: &[u8] = b"write-access:write-secret:auto";
    const DELETE_V1_SECRET: &[u8] = b"delete-one:delete-secret-one:auto";
    const DELETE_V2_SECRET: &[u8] = b"delete-two:delete-secret-two:auto";

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db
        .create_org("frozen-rotation", "Frozen rotation")
        .await
        .unwrap();
    let owner = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            "frozen-rotation-binding",
            &owner.stable_id,
            "frozen-rotation",
            "s3",
            None,
            Some("frozen-bucket"),
            Some("objects"),
            Some("https"),
            Some("dns"),
            Some(b"storage.example.invalid"),
            Some(443),
            Some("auto"),
            Some("private"),
        )
        .await
        .unwrap();
    let binding = db.binding(binding_id).await.unwrap().unwrap();
    let write_generation =
        validated_credential(&db, binding_id, "write", WRITE_REF, WRITE_SECRET).await;
    let write_revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id,
            write_credential_generation: write_generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "frozen-rotation-write-v1".into(),
            capability_fingerprint: "frozen-rotation-conditional-v1".into(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding_id, write_revision.revision, "valid", None, None)
        .await
        .unwrap();

    let delete_generation =
        validated_credential(&db, binding_id, "delete", DELETE_V1_REF, DELETE_V1_SECRET).await;
    let capability = db
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            binding_id,
            binding_write_revision: write_revision.revision,
            binding_resource_version: binding.resource_version,
            delete_credential_purpose: Some("delete".into()),
            delete_credential_generation: Some(delete_generation),
            capability_fingerprint: "frozen-rotation-conditional-v1".into(),
            state: "valid".into(),
            expected_resource_version: None,
            observed_at: 10,
        })
        .await
        .unwrap();
    let access = core_sw::FrozenSurfaceAccess {
        registry_id: 1,
        placement_id: 1,
        placement_name: "frozen".into(),
        placement_prefix: "frozen".into(),
        placement_resource_version: 1,
        placement_write_spec_version: 1,
        placement_observation_version: 1,
        binding_id,
        binding_resource_version: binding.resource_version,
        binding_write_revision: write_revision.revision,
        delete_credential_purpose: Some("delete".into()),
        delete_credential_generation: Some(delete_generation),
        delete_capability_fingerprint: capability.capability_fingerprint.clone(),
        delete_capability_resource_version: capability.resource_version,
    };

    let delete_generation_two =
        validated_credential(&db, binding_id, "delete", DELETE_V2_REF, DELETE_V2_SECRET).await;
    let refreshed = db
        .record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
            binding_id,
            binding_write_revision: write_revision.revision,
            binding_resource_version: binding.resource_version,
            delete_credential_purpose: Some("delete".into()),
            delete_credential_generation: Some(delete_generation_two),
            capability_fingerprint: capability.capability_fingerprint,
            state: "valid".into(),
            expected_resource_version: Some(capability.resource_version),
            observed_at: 11,
        })
        .await
        .unwrap();
    assert_eq!(refreshed.delete_credential_generation, Some(2));
    assert_eq!(access.delete_credential_generation, Some(1));

    let secrets = Arc::new(TestSecretVersions(BTreeMap::from([
        (WRITE_REF.to_string(), WRITE_SECRET.to_vec()),
        (DELETE_V1_REF.to_string(), DELETE_V1_SECRET.to_vec()),
        (DELETE_V2_REF.to_string(), DELETE_V2_SECRET.to_vec()),
    ])));
    let writes =
        HubSurfaceWriteProvider::new(Arc::clone(&db), reqwest::Client::builder().build().unwrap())
            .with_credentials(secrets);
    writes.frozen_placement_deleter(&access).await.unwrap();
}
