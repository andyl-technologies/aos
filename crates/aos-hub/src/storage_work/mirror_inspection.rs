//! Native source selection and bounded decoded pack inspection consumers.
//!
//! The catalogue supplies candidate names, never proof of provider presence.
//! Worker authenticates the source, verifies the entire pair, and returns only
//! selected decoded fields. Native rechecks the actual SQL placement/source
//! generations after each exchange; encoded bodies have no fallback transport.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::db::{Database, RegistryRecord};
use aos_hub_core::mirror_inspection::{
    MirrorPackInspection, MirrorPackProjection, MirrorPackSelection,
};
use aos_hub_core::storage_work::{StorageWorkOperation, StorageWorkOutcome};

use super::{HybridSurfaceFetch, RemoteStorageWorkClient};

impl RemoteStorageWorkClient {
    /// Reads one source-bound page from an approved upstream tree inventory.
    ///
    /// # Errors
    /// Returns an error for changed SQL authority, source, parser qualification
    /// or continuation. No pack, index or raw tree body is fetched by Native.
    pub(crate) async fn inspect_mirror_tree_inventory(
        &self,
        db: &Database,
        registry: &RegistryRecord,
        index_path: Option<&str>,
        tree_oid: &str,
        cursor: Option<aos_hub_core::mirror_tree_inventory::MirrorTreeInventoryCursor>,
    ) -> Result<Option<aos_hub_core::mirror_tree_inventory::MirrorTreeInventoryProjection>> {
        let source = db
            .registry_mirror(registry.id)
            .await?
            .context("inventory registry has no upstream")?;
        let placement = db
            .reconciled_surface_writer(aos_hub_core::db::SurfaceTarget::Registry(registry.id))
            .await?;
        let binding = db
            .binding(placement.binding_id)
            .await?
            .context("inventory binding disappeared")?;
        ensure!(
            binding.kind == "deployment_r2",
            "inventory requires managed R2"
        );
        let profile = self.mirror_managed_profile_digest()?;
        use aos_hub_core::mirror_tree_inventory::MirrorTreeInventorySource;
        let selected_source = match index_path {
            Some(index_path) => MirrorTreeInventorySource::Pack {
                inspection: MirrorPackInspection {
                    registry_id: registry.id,
                    registry_resource_version: registry.resource_version,
                    mirror_resource_version: source.resource_version,
                    upstream_base: source.source_url.clone(),
                    index_path: index_path.into(),
                    protected_profile_digest: profile.clone(),
                    selections: Vec::new(),
                },
            },
            None => MirrorTreeInventorySource::Loose {
                registry_id: registry.id,
                registry_resource_version: registry.resource_version,
                mirror_resource_version: source.resource_version,
                upstream_base: source.source_url.clone(),
                protected_profile_digest: profile.clone(),
            },
        };
        let query = aos_hub_core::mirror_tree_inventory::MirrorTreeInventoryQuery {
            source: selected_source,
            tree_oid: tree_oid.into(),
            cursor,
        };
        query.validate()?;
        let plan = self.plan_for_placement(
            &placement,
            &binding,
            StorageWorkOperation::InspectMirrorTreeInventory { query },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;
        let current_registry = db
            .registry_by_id(registry.id)
            .await?
            .context("inventory registry disappeared")?;
        let current_source = db
            .registry_mirror(registry.id)
            .await?
            .context("inventory upstream disappeared")?;
        let current_placement = db
            .surface_placement(placement.id)
            .await?
            .context("inventory placement disappeared")?;
        let current_binding = db
            .binding(binding.id)
            .await?
            .context("inventory binding disappeared")?;
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
            "inventory SQL authority changed during execution"
        );
        match result.outcome {
            StorageWorkOutcome::MirrorTreeInventory { projection } => Ok(Some(projection)),
            StorageWorkOutcome::NotFound => Ok(None),
            _ => anyhow::bail!("inventory returned another result"),
        }
    }

    /// Inspects one approved immutable upstream pair without receiving its bytes.
    ///
    /// # Errors
    /// Returns an error for changed source/configuration, missing qualification,
    /// unsupported provider, invalid pair or an oversized decoded result.
    pub(crate) async fn inspect_mirror_pack(
        &self,
        db: &Database,
        registry: &RegistryRecord,
        index_path: &str,
        selections: Vec<MirrorPackSelection>,
    ) -> Result<MirrorPackProjection> {
        let source = db
            .registry_mirror(registry.id)
            .await?
            .context("pack inspection registry has no upstream source")?;
        let placement = db
            .reconciled_surface_writer(aos_hub_core::db::SurfaceTarget::Registry(registry.id))
            .await?;
        let binding = db
            .binding(placement.binding_id)
            .await?
            .context("pack inspection binding disappeared")?;
        ensure!(
            binding.kind == "deployment_r2",
            "pack inspection requires managed R2"
        );
        let profile_digest = self.mirror_managed_profile_digest()?;
        let inspection = MirrorPackInspection {
            registry_id: registry.id,
            registry_resource_version: registry.resource_version,
            mirror_resource_version: source.resource_version,
            upstream_base: source.source_url.clone(),
            index_path: index_path.into(),
            protected_profile_digest: profile_digest.clone(),
            selections,
        };
        inspection.validate()?;
        let plan = self.plan_for_placement(
            &placement,
            &binding,
            StorageWorkOperation::InspectMirrorPack { inspection },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;
        let current_registry = db
            .registry_by_id(registry.id)
            .await?
            .context("pack inspection registry disappeared")?;
        let current_source = db
            .registry_mirror(registry.id)
            .await?
            .context("pack inspection upstream disappeared")?;
        let current_placement = db
            .surface_placement(placement.id)
            .await?
            .context("pack inspection placement disappeared")?;
        let current_binding = db
            .binding(binding.id)
            .await?
            .context("pack inspection binding disappeared")?;
        ensure!(
            current_registry.resource_version == registry.resource_version
                && current_source.resource_version == source.resource_version
                && current_source.source_url == source.source_url
                && current_placement.resource_version == placement.resource_version
                && current_placement.binding_id == placement.binding_id
                && current_placement.prefix == placement.prefix
                && current_binding.resource_version == binding.resource_version
                && current_binding.kind == binding.kind
                && self.mirror_managed_profile_digest()? == profile_digest,
            "pack inspection SQL authority changed during execution"
        );
        let StorageWorkOutcome::GitPackProjection { projection } = result.outcome else {
            anyhow::bail!("pack inspection returned another result");
        };
        Ok(projection)
    }
}

impl HybridSurfaceFetch {
    pub(super) async fn inspect_packed_tree(
        &self,
        oid: aos_registry_surface::object::Oid,
        names: &[String],
        cursor: Option<&aos_hub_core::tree_projection::GitTreeCursor>,
    ) -> Result<Option<aos_hub_core::tree_projection::GitTreeEntriesPage>> {
        aos_hub_core::tree_projection::validate_request(&oid.to_hex(), names, cursor)?;
        let surface = match (self.placement.registry_id, self.placement.cache_id) {
            (Some(id), None) => aos_hub_core::db::SurfaceTarget::Registry(id),
            (None, Some(id)) => aos_hub_core::db::SurfaceTarget::BinaryCache(id),
            _ => anyhow::bail!("pack tree lookup has no exact surface"),
        };
        for index_path in self.db.mirror_git_pack_candidates(surface).await? {
            let profile_digest = self.work.mirror_managed_profile_digest()?;
            let query = aos_hub_core::mirror_inspection::MirrorPackTreeQuery {
                index_path,
                oid: oid.to_hex(),
                names: names.to_vec(),
                cursor: cursor.cloned(),
                protected_profile_digest: profile_digest.clone(),
            };
            let plan = self.work.plan_for_placement(
                &self.placement,
                &self.binding,
                StorageWorkOperation::FilterStoredGitPackTree { query },
                aos_hub_core::clock::now_unix_secs(),
            )?;
            let result = self.execute(&plan).await?;
            ensure!(
                self.work.mirror_managed_profile_digest()? == profile_digest,
                "pack tree profile changed during execution"
            );
            let StorageWorkOutcome::GitPackTreeProjection { projection } = result.outcome else {
                anyhow::bail!("pack tree lookup returned another result");
            };
            if let Some(page) = projection.page {
                return Ok(Some(page));
            }
        }
        Ok(None)
    }

    pub(super) async fn inspect_packed_git(
        &self,
        oids: &[aos_registry_surface::object::Oid],
    ) -> Result<
        std::collections::BTreeMap<
            aos_registry_surface::object::Oid,
            Option<(aos_registry_surface::object::ObjectKind, Vec<u8>)>,
        >,
    > {
        use aos_registry_surface::object::{ObjectKind, Oid};
        use base64::Engine as _;

        let surface = match (self.placement.registry_id, self.placement.cache_id) {
            (Some(id), None) => aos_hub_core::db::SurfaceTarget::Registry(id),
            (None, Some(id)) => aos_hub_core::db::SurfaceTarget::BinaryCache(id),
            _ => anyhow::bail!("pack lookup has no exact surface"),
        };
        let candidates = self.db.mirror_git_pack_candidates(surface).await?;
        let mut remaining = oids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let mut found = oids
            .iter()
            .copied()
            .map(|oid| (oid, None))
            .collect::<std::collections::BTreeMap<_, _>>();
        for index_path in candidates {
            let requested = remaining.iter().copied().collect::<Vec<_>>();
            for batch in requested.chunks(8) {
                let selections = batch
                    .iter()
                    .map(|oid| MirrorPackSelection {
                        oid: oid.to_hex(),
                        range: None,
                    })
                    .collect();
                let profile = self.work.mirror_managed_profile_digest()?;
                let plan = self.work.plan_for_placement(
                    &self.placement,
                    &self.binding,
                    StorageWorkOperation::InspectStoredGitPack {
                        index_path: index_path.clone(),
                        selections,
                        protected_profile_digest: profile.clone(),
                    },
                    aos_hub_core::clock::now_unix_secs(),
                )?;
                let result = self.execute(&plan).await?;
                ensure!(
                    self.work.mirror_managed_profile_digest()? == profile,
                    "pack lookup profile changed during execution"
                );
                let StorageWorkOutcome::GitPackProjection { projection } = result.outcome else {
                    anyhow::bail!("stored pack lookup returned another result");
                };
                for object in projection.objects {
                    let oid = Oid::from_hex(&object.oid)?;
                    let kind = ObjectKind::parse(&object.kind)?;
                    let content =
                        base64::engine::general_purpose::STANDARD.decode(object.content_base64)?;
                    ensure!(
                        remaining.remove(&oid),
                        "pack lookup repeats an unrequested OID"
                    );
                    found.insert(oid, Some((kind, content)));
                }
            }
            if remaining.is_empty() {
                break;
            }
        }
        Ok(found)
    }
}
