//! Fresh Native authority for bounded storage-local catalogue membership.
//!
//! Every exchange is selected from current SQL and rechecks the exact source,
//! placement, binding and qualified profile after the reply. Encoded Git source
//! bodies have no Native transport or generic fallback here.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::db::{Database, RegistryRecord};
use aos_hub_core::mirror_inspection::MirrorPackInspection;
use aos_hub_core::mirror_membership::{MirrorMembershipProjection, MirrorMembershipQuery};
use aos_hub_core::storage_work::{StorageWorkOperation, StorageWorkOutcome};

use super::RemoteStorageWorkClient;

impl RemoteStorageWorkClient {
    pub(crate) async fn inspect_mirror_membership(
        &self,
        db: &Database,
        registry: &RegistryRecord,
        index_path: &str,
        oids: Vec<String>,
        expected_source: Option<String>,
    ) -> Result<MirrorMembershipProjection> {
        let source = db
            .registry_mirror(registry.id)
            .await?
            .context("membership registry has no upstream source")?;
        let placement = db
            .reconciled_surface_writer(aos_hub_core::db::SurfaceTarget::Registry(registry.id))
            .await?;
        let binding = db
            .binding(placement.binding_id)
            .await?
            .context("membership binding disappeared")?;
        ensure!(
            binding.kind == "deployment_r2",
            "membership requires managed R2"
        );
        let profile = self.mirror_managed_profile_digest()?;
        let query = MirrorMembershipQuery {
            inspection: MirrorPackInspection {
                registry_id: registry.id,
                registry_resource_version: registry.resource_version,
                mirror_resource_version: source.resource_version,
                upstream_base: source.source_url.clone(),
                index_path: index_path.into(),
                protected_profile_digest: profile.clone(),
                selections: Vec::new(),
            },
            oids,
            expected_source,
        };
        query.validate()?;
        let plan = self.plan_for_placement(
            &placement,
            &binding,
            StorageWorkOperation::InspectMirrorMembership { query },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;

        let current_registry = db
            .registry_by_id(registry.id)
            .await?
            .context("membership registry disappeared")?;
        let current_source = db
            .registry_mirror(registry.id)
            .await?
            .context("membership upstream disappeared")?;
        let current_placement = db
            .surface_placement(placement.id)
            .await?
            .context("membership placement disappeared")?;
        let current_binding = db
            .binding(binding.id)
            .await?
            .context("membership binding disappeared")?;
        ensure!(
            current_registry.resource_version == registry.resource_version
                && current_source.resource_version == source.resource_version
                && current_source.source_url == source.source_url
                && current_placement.resource_version == placement.resource_version
                && current_placement.binding_id == placement.binding_id
                && current_placement.prefix == placement.prefix
                && current_binding.resource_version == binding.resource_version
                && current_binding.kind == binding.kind
                && self.mirror_managed_profile_digest()? == profile,
            "membership SQL authority changed during execution"
        );
        let StorageWorkOutcome::MirrorMembership { projection } = result.outcome else {
            anyhow::bail!("membership returned another result");
        };
        Ok(projection)
    }
}
