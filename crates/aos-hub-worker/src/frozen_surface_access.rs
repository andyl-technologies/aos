//! Frozen Worker provider access resolved after a durable OCI GC claim.
//!
//! The database claim owns capability/head validation and retains any old
//! credential generation needed by an applying run. This module reopens only
//! that DB-authored physical address and exact credential; it never consults a
//! mutable capability or credential head that may advance after Apply.

use anyhow::{Context as _, Result};
use aos_hub_core::db::Database;
use aos_hub_core::storage_credential::StorageCredentialResolver;
use aos_hub_core::surface_write::FrozenSurfaceAccess;

/// Reopens the exact frozen binding and immutable write revision.
pub(crate) async fn binding(
    db: &Database,
    access: &FrozenSurfaceAccess,
) -> Result<aos_hub_core::db::BindingRecord> {
    access.validate()?;
    let binding = db
        .binding(access.binding_id)
        .await?
        .context("frozen placement references a missing binding")?;
    anyhow::ensure!(
        binding.resource_version == access.binding_resource_version,
        "frozen placement binding resource version changed"
    );
    db.binding_write_revision(access.binding_id, access.binding_write_revision)
        .await?
        .context("frozen placement binding revision disappeared")?;
    Ok(binding)
}

/// Resolves the exact frozen delete credential without selecting its head.
pub(crate) async fn delete_credential(
    resolver: &dyn StorageCredentialResolver,
    access: &FrozenSurfaceAccess,
) -> Result<Option<aos_hub_core::storage_credential::ResolvedStorageCredential>> {
    match (
        access.delete_credential_purpose.as_deref(),
        access.delete_credential_generation,
    ) {
        (Some(purpose), Some(generation)) => Ok(Some(
            resolver
                .resolve_exact(access.binding_id, purpose, generation)
                .await?,
        )),
        (None, None) => Ok(None),
        _ => anyhow::bail!("frozen placement carries an incomplete credential fence"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use aos_hub_core::db::{
        Database, NewBindingWriteRevision, RecordOciConditionalDeleteCapability,
    };
    use aos_hub_core::secret_version::{ResolvedSecretVersion, SecretVersionResolver};
    use aos_hub_core::storage_credential::DatabaseStorageCredentialResolver;
    use aos_hub_core::surface_write::FrozenSurfaceAccess;
    use sha2::{Digest as _, Sha256};

    use super::{binding, delete_credential};

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
    async fn frozen_gen_one_resolves_after_current_capability_moves_to_gen_two() {
        const WRITE_REF: &str = "worker://frozen/write/v1";
        const DELETE_V1_REF: &str = "worker://frozen/delete/v1";
        const DELETE_V2_REF: &str = "worker://frozen/delete/v2";
        const WRITE_SECRET: &[u8] = b"write-access:write-secret:auto";
        const DELETE_V1_SECRET: &[u8] = b"delete-one:delete-secret-one:auto";
        const DELETE_V2_SECRET: &[u8] = b"delete-two:delete-secret-two:auto";

        let db = Arc::new(Database::open_in_memory().await.unwrap());
        let org_id = db
            .create_org("worker-frozen", "Worker frozen")
            .await
            .unwrap();
        let owner = db.org_by_id(org_id).await.unwrap().unwrap();
        let binding_id = db
            .create_topology_binding(
                Some(org_id),
                "worker-frozen-binding",
                &owner.stable_id,
                "worker-frozen",
                "r2",
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
        let binding_record = db.binding(binding_id).await.unwrap().unwrap();
        let write_generation =
            validated_credential(&db, binding_id, "write", WRITE_REF, WRITE_SECRET).await;
        let write_revision = db
            .create_binding_write_revision(&NewBindingWriteRevision {
                binding_id,
                write_credential_generation: write_generation,
                writes_supported: true,
                conditional_writes_supported: true,
                revision_fingerprint: "worker-frozen-write-v1".into(),
                capability_fingerprint: "worker-frozen-conditional-v1".into(),
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
                binding_resource_version: binding_record.resource_version,
                delete_credential_purpose: Some("delete".into()),
                delete_credential_generation: Some(delete_generation),
                capability_fingerprint: "worker-frozen-conditional-v1".into(),
                state: "valid".into(),
                expected_resource_version: None,
                observed_at: 10,
            })
            .await
            .unwrap();
        let access = FrozenSurfaceAccess {
            registry_id: 1,
            placement_id: 1,
            placement_name: "frozen".into(),
            placement_prefix: "frozen".into(),
            placement_resource_version: 1,
            placement_write_spec_version: 1,
            placement_observation_version: 1,
            binding_id,
            binding_resource_version: binding_record.resource_version,
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
                binding_resource_version: binding_record.resource_version,
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
        let resolver = DatabaseStorageCredentialResolver::new(Arc::clone(&db), secrets);
        binding(&db, &access).await.unwrap();
        let credential = delete_credential(&resolver, &access)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(credential.generation(), 1);
    }
}
