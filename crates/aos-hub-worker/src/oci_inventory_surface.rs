//! Inventory-only placement readers over current Worker binding publications.
//!
//! Protected listings use their configured List lease. Head and bounded hash
//! ranges use the same typed guarded inspection path as authenticated storage
//! work; neither listing nor persisted progress grants source authority.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    db::{Database, OciSha256State, SurfacePlacementRecord},
    fetch::{
        SurfaceFetch, SurfaceInventoryHashChunk, SurfaceInventoryHead, SurfaceListPage,
        SurfaceListedEvidence, SurfaceProvider,
    },
    storage_work::{
        protected_inspection::ProtectedInspectionSource, StorageBindingSnapshot,
        StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult,
    },
};
use async_trait::async_trait;
use worker::Env;

use crate::external_object::InventoryDomainMode;

/// Connects only inventory jobs to installed protected source domains.
pub(crate) struct InventorySurfaceProvider {
    env: Env,
    db: Arc<Database>,
    legacy: crate::surface::R2SurfaceProvider,
}

impl InventorySurfaceProvider {
    /// Retains the invocation environment and the unchanged legacy placement adapter.
    pub(crate) fn new(
        env: Env,
        db: Arc<Database>,
        legacy: crate::surface::R2SurfaceProvider,
    ) -> Self {
        Self { env, db, legacy }
    }
}

#[async_trait(?Send)]
impl SurfaceProvider for InventorySurfaceProvider {
    async fn placement_fetcher(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceFetch>> {
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("inventory binding disappeared")?;
        if binding.kind == "deployment_r2" || binding.is_instance_default {
            return self.legacy.placement_fetcher(placement).await;
        }
        let now = aos_hub_core::clock::now_unix_secs();
        let deployment = self.env.var("HUB_DEPLOYMENT_ID")?.to_string();
        // Applicability uses retained physical identity, independently of
        // credential acceptance. It cannot make a stale protected member fall
        // back to the legacy reader or constrain unrelated legacy credentials.
        let coordinates = StorageBindingSnapshot::from_binding(
            deployment.clone(),
            &binding,
            &[],
            now,
            now.checked_add(30).context("inventory cutoff overflow")?,
        )?;
        let mode = crate::external_object::installed_inventory_mode(&self.env, &coordinates)?;
        if mode == InventoryDomainMode::Unconfigured {
            return self.legacy.placement_fetcher(placement).await;
        }
        let credentials = self.db.list_current_binding_credentials(binding.id).await?;
        let snapshot = StorageBindingSnapshot::from_binding(
            deployment,
            &binding,
            &credentials,
            now,
            now.checked_add(30).context("inventory cutoff overflow")?,
        )?;
        let write = self
            .db
            .binding_write_state(binding.id)
            .await?
            .context("inventory binding write state disappeared")?;
        let fetch = InventoryFetch {
            mode,
            env: self.env.clone(),
            db: Arc::clone(&self.db),
            placement: placement.clone(),
            snapshot,
            write_revision: write
                .current_write_revision
                .context("inventory binding has no current write revision")?,
        };
        fetch.check_current().await?;
        Ok(Box::new(fetch))
    }
}

struct InventoryFetch {
    mode: InventoryDomainMode,
    env: Env,
    db: Arc<Database>,
    placement: SurfacePlacementRecord,
    snapshot: StorageBindingSnapshot,
    write_revision: i64,
}

impl InventoryFetch {
    async fn check_current(&self) -> Result<()> {
        let placement = self
            .db
            .surface_placement(self.placement.id)
            .await?
            .context("inventory placement disappeared")?;
        ensure!(
            placement.resource_version == self.placement.resource_version
                && placement.binding_id == self.placement.binding_id
                && placement.prefix == self.placement.prefix
                && placement.write_spec_version == self.placement.write_spec_version
                && placement.observation_version == self.placement.observation_version
                && placement.registry_id == self.placement.registry_id
                && placement.state == "ready"
                && placement.completeness == "complete",
            "inventory placement changed during protected work"
        );
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("inventory binding disappeared")?;
        let write = self
            .db
            .binding_write_state(binding.id)
            .await?
            .context("inventory binding state disappeared")?;
        ensure!(
            write.current_write_revision == Some(self.write_revision),
            "inventory binding write revision changed"
        );
        let credentials = self.db.list_current_binding_credentials(binding.id).await?;
        let now = aos_hub_core::clock::now_unix_secs();
        let current = StorageBindingSnapshot::from_binding(
            self.snapshot.deployment_id.clone(),
            &binding,
            &credentials,
            now,
            now.checked_add(30).context("inventory cutoff overflow")?,
        )?;
        ensure!(
            current.binding_resource_version == self.snapshot.binding_resource_version
                && current.binding_spec_revision()? == self.snapshot.binding_spec_revision()?
                && current.credentials == self.snapshot.credentials,
            "inventory binding coordinates or credentials changed"
        );
        Ok(())
    }

    async fn execute(
        &self,
        operation: StorageWorkOperation,
    ) -> Result<(StorageWorkPlan, StorageWorkResult)> {
        self.check_current().await?;
        let publication = crate::hybrid_binding::resolve_for_delivery(
            &self.env,
            self.snapshot.binding_id,
            self.snapshot.binding_resource_version,
        )
        .await?;
        ensure!(
            publication.snapshot.binding_spec_revision()?
                == self.snapshot.binding_spec_revision()?
                && publication.snapshot.credentials == self.snapshot.credentials,
            "inventory publication differs from current SQL"
        );
        self.check_current().await?;
        let now = aos_hub_core::clock::now_unix_secs();
        let plan = crate::oci_inventory_plan::build(
            &publication.snapshot,
            self.placement.id,
            self.placement.resource_version,
            &self.placement.prefix,
            operation,
            now,
        )?;
        let abort = AbortOnDrop(
            worker::web_sys::AbortController::new()
                .map_err(|_| anyhow::anyhow!("inventory cancellation owner unavailable"))?,
        );
        let result = crate::surface::execute_external_storage_work(
            &self.env,
            &plan,
            &publication,
            &abort.0.signal(),
        )
        .await?
        .context("protected inventory operation is unsupported")?;
        self.check_current().await?;
        plan.validate(&plan.deployment_id, aos_hub_core::clock::now_unix_secs())?;
        ensure!(
            result.plan_id == plan.plan_id
                && result.placement_id == plan.placement_id
                && result.placement_resource_version == plan.placement_resource_version
                && result.binding_id == plan.binding_id
                && result.binding_resource_version == plan.binding_resource_version,
            "inventory result correlation differs"
        );
        Ok((plan, result))
    }
}

struct AbortOnDrop(worker::web_sys::AbortController);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[async_trait(?Send)]
impl SurfaceFetch for InventoryFetch {
    async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
        anyhow::bail!("protected inventory does not expose whole object bodies")
    }

    async fn list_page(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<SurfaceListPage> {
        let (plan, result) = self
            .execute(StorageWorkOperation::ListPage {
                prefix: prefix.into(),
                cursor: cursor.map(str::to_owned),
                limit,
            })
            .await?;
        ensure!(
            result.source_bytes == 0,
            "inventory listing returned object bytes"
        );
        let StorageWorkOutcome::ListPage {
            objects,
            cursor: next_cursor,
        } = result.outcome
        else {
            anyhow::bail!("inventory listing result differs")
        };
        let mut paths = Vec::with_capacity(objects.len());
        let mut evidence = BTreeMap::new();
        for object in objects {
            let relative = aos_hub_core::keymap::relative_key(&plan.placement_prefix, &object.key)
                .context("inventory listing escaped placement")?;
            ensure!(
                plan.object_key(&relative)? == object.key,
                "inventory listing key differs"
            );
            paths.push(relative.to_owned());
            evidence.insert(
                relative.to_owned(),
                SurfaceListedEvidence {
                    size: i64::try_from(object.size)?,
                    strong_etag: object.etag,
                    provider_version: object.provider_version,
                },
            );
        }
        let page = SurfaceListPage {
            paths,
            evidence,
            next_cursor,
        };
        page.validate(limit, prefix, cursor)?;
        Ok(page)
    }

    async fn inventory_head(&self, path: &str) -> Result<Option<SurfaceInventoryHead>> {
        let (plan, result) = self
            .execute(StorageWorkOperation::Head { path: path.into() })
            .await?;
        ensure!(
            result.source_bytes == 0,
            "inventory HEAD returned object bytes"
        );
        match result.outcome {
            StorageWorkOutcome::NotFound => Ok(None),
            StorageWorkOutcome::Head {
                object,
                guarded_source,
            } => {
                crate::oci_inventory_plan::validate_source(
                    self.mode,
                    &plan,
                    path,
                    &self.snapshot.object_prefix,
                    &object,
                    guarded_source.as_ref(),
                )?;
                Ok(Some(SurfaceInventoryHead {
                    size: i64::try_from(object.size)?,
                    strong_etag: Some(object.etag),
                    provider_version: object.provider_version,
                    guarded_source,
                }))
            }
            _ => anyhow::bail!("installed inventory HEAD source differs"),
        }
    }

    async fn inventory_hash_chunk_guarded_bounded(
        &self,
        path: &str,
        offset: u64,
        expected_total: u64,
        maximum_bytes: u64,
        strong_etag: &str,
        expected_provider_version: Option<&str>,
        guarded_source: Option<&ProtectedInspectionSource>,
        sha256_state: OciSha256State,
    ) -> Result<Option<SurfaceInventoryHashChunk>> {
        ensure!(
            maximum_bytes > 0
                && maximum_bytes <= aos_hub_core::storage_work::MAX_OCI_HASH_RANGE_BYTES as u64
                && offset < expected_total,
            "protected inventory hash interval differs"
        );
        let bytes = maximum_bytes.min(expected_total - offset);
        let end = offset
            .checked_add(bytes - 1)
            .context("inventory hash interval overflow")?;
        let (plan, result) = self
            .execute(StorageWorkOperation::HashOciRange {
                path: path.into(),
                start: offset,
                end,
                total: expected_total,
                strong_etag: strong_etag.into(),
                expected_provider_version: expected_provider_version.map(str::to_owned),
                sha256_state,
                guarded_source: guarded_source.cloned(),
            })
            .await?;
        let StorageWorkOutcome::OciRangeHashed {
            source: identity,
            start,
            end: actual_end,
            sha256_state,
            guarded_source: accepted_source,
        } = result.outcome
        else {
            anyhow::bail!("protected inventory hash result differs")
        };
        ensure!(
            start == offset
                && actual_end == end
                && result.source_bytes == bytes
                && identity.size == expected_total
                && identity.etag == strong_etag
                && identity.provider_version.as_deref() == expected_provider_version
                && accepted_source.as_ref() == guarded_source
                && sha256_state.total_bytes == end + 1,
            "protected inventory hash source or count differs"
        );
        crate::oci_inventory_plan::validate_source(
            self.mode,
            &plan,
            path,
            &self.snapshot.object_prefix,
            &identity,
            accepted_source.as_ref(),
        )?;
        sha256_state.validate()?;
        Ok(Some(SurfaceInventoryHashChunk {
            total: identity.size,
            range: (start, actual_end),
            strong_etag: identity.etag,
            provider_version: identity.provider_version,
            sha256_state,
            guarded_source: accepted_source,
        }))
    }

    fn describe(&self) -> String {
        "installed Worker OCI inventory placement".into()
    }
}
