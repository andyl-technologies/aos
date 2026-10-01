//! Original trust configuration and destination pins selected before discovery.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::db::{
    BindingRecord, Database, RegistryMirrorRecord, RegistryRecord, SurfacePlacementRecord,
    SurfaceTarget,
};

use crate::storage_work::RemoteStorageWorkClient;

pub(super) struct Selection {
    pub(super) source: RegistryMirrorRecord,
    pub(super) placement: SurfacePlacementRecord,
    pub(super) binding: BindingRecord,
    pub(super) profile_digest: String,
    registry_resource_version: i64,
}

impl Selection {
    pub(super) async fn capture(
        db: &Database,
        work: &RemoteStorageWorkClient,
        registry: &RegistryRecord,
        source: RegistryMirrorRecord,
    ) -> Result<Self> {
        validate_supported_semantics(&source)?;
        let placement = db
            .reconciled_surface_writer(SurfaceTarget::Registry(registry.id))
            .await?;
        let binding = db
            .binding(placement.binding_id)
            .await?
            .context("selected mirror binding disappeared")?;
        ensure!(
            binding.kind == "deployment_r2" && binding.is_instance_default,
            "hybrid mirror requires the managed deployment R2 writer"
        );
        let selected = Self {
            source,
            placement,
            binding,
            profile_digest: work.mirror_managed_profile_digest()?,
            registry_resource_version: registry.resource_version,
        };
        selected.validate_current(db, work, registry).await?;
        Ok(selected)
    }

    pub(super) async fn validate_current(
        &self,
        db: &Database,
        work: &RemoteStorageWorkClient,
        registry: &RegistryRecord,
    ) -> Result<()> {
        let current_registry = db
            .registry_by_id(registry.id)
            .await?
            .context("selected mirror registry disappeared")?;
        let source = db
            .registry_mirror(registry.id)
            .await?
            .context("selected mirror configuration disappeared")?;
        let placement = db
            .reconciled_surface_writer(SurfaceTarget::Registry(registry.id))
            .await?;
        let binding = db
            .binding(placement.binding_id)
            .await?
            .context("selected mirror binding disappeared")?;
        ensure!(
            self.source.registry_id == registry.id
                && registry.resource_version == self.registry_resource_version
                && current_registry.resource_version == self.registry_resource_version
                && source.resource_version == self.source.resource_version
                && source.source_url == self.source.source_url
                && source.signature_policy == self.source.signature_policy
                && source.mode == self.source.mode
                && source.refspec == self.source.refspec
                && source.auth_secret_ref == self.source.auth_secret_ref
                && placement.id == self.placement.id
                && placement.resource_version == self.placement.resource_version
                && placement.write_spec_version == self.placement.write_spec_version
                && placement.prefix == self.placement.prefix
                && binding.id == self.binding.id
                && binding.resource_version == self.binding.resource_version
                && binding.kind == self.binding.kind
                && binding.is_instance_default
                && work.mirror_managed_profile_digest()? == self.profile_digest,
            "mirror discovery configuration or destination changed; restart verification"
        );
        Ok(())
    }
}

/// Credential references and filtered ref selection require a separate executor.
/// Pinning their strings does not apply authentication or filtering upstream.
fn validate_supported_semantics(source: &RegistryMirrorRecord) -> Result<()> {
    ensure!(
        source.auth_secret_ref.is_empty(),
        "hybrid mirror upstream credentials are not supported"
    );
    ensure!(
        source.refspec == "refs/*",
        "hybrid mirror supports only the default refs/* selection"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_mirror_refuses_unapplied_credential_and_refspec_semantics() {
        let mut source = RegistryMirrorRecord {
            registry_id: 1,
            source_url: "https://upstream.example.com/root".into(),
            refspec: "refs/*".into(),
            auth_secret_ref: String::new(),
            mode: "pull_through".into(),
            signature_policy: "required".into(),
            interval_seconds: 0,
            state: "ready".into(),
            observed_commit: None,
            error: None,
            last_sync_at: None,
            resource_version: 1,
        };
        assert!(validate_supported_semantics(&source).is_ok());

        source.auth_secret_ref = "secret/version/1".into();
        assert!(validate_supported_semantics(&source).is_err());
        source.auth_secret_ref.clear();
        source.refspec = "refs/heads/*".into();
        assert!(validate_supported_semantics(&source).is_err());
    }
}
