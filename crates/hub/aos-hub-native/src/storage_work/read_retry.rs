//! Fresh deployment-owned point reads after a lost reply exhausts its plan.

use super::*;

/// Identifies an expired retry while retaining its original failed attempt.
#[derive(Debug, thiserror::Error)]
#[error("read-only storage transport exhausted its original plan")]
pub(super) struct ExpiredReadPlan {
    /// Retains the transport or HTTP failure that consumed the dispatch window.
    #[source]
    pub(super) failure: anyhow::Error,
}

impl HybridSurfaceFetch {
    /// Reissues an eligible deployment-owned point read under current SQL fences.
    ///
    /// # Errors
    ///
    /// Returns an error if SQL state is unavailable, the placement or binding
    /// changed, or a fresh plan cannot be issued.
    pub(super) async fn reissue_expired_managed_read(
        &self,
        original: &StorageWorkPlan,
        error: &anyhow::Error,
    ) -> Result<Option<StorageWorkPlan>> {
        if !error.is::<ExpiredReadPlan>()
            || original.binding_kind != "deployment_r2"
            || !self.binding.is_instance_default
            || !matches!(
                original.operation,
                StorageWorkOperation::Head { .. }
                    | StorageWorkOperation::InspectMetadata { .. }
                    | StorageWorkOperation::InspectSha256 { .. }
            )
        {
            return Ok(None);
        }

        // A lost reply can consume the original dispatch window. A fresh read
        // needs the current SQL fences; the original signed plan stays intact.
        let placement = self
            .db
            .surface_placement(self.placement.id)
            .await?
            .context("storage placement disappeared before read retry")?;
        let binding = self
            .db
            .binding(self.binding.id)
            .await?
            .context("storage binding disappeared before read retry")?;
        anyhow::ensure!(
            placement.id == original.placement_id
                && placement.resource_version == original.placement_resource_version
                && placement.binding_id == original.binding_id
                && placement.prefix == original.placement_prefix
                && placement.effective_read_enabled
                && binding.id == original.binding_id
                && binding.resource_version == original.binding_resource_version
                && binding.kind == original.binding_kind
                && binding.is_instance_default,
            "storage placement or binding changed before read retry"
        );
        self.work
            .plan_for_placement(
                &placement,
                &binding,
                original.operation.clone(),
                aos_hub_model::clock::now_unix_secs(),
            )
            .map(Some)
    }
}
