//! Explicit component repository and checkpoint storage fixtures.

use super::*;
use crucible_campaign::DebuggerAuthorityKey;
use crucible_cas::content_store::DirectoryBlobBackend;

#[cfg(any(test, feature = "test-support"))]
pub(super) fn default_run_repository<E>(
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
) -> Result<(CampaignRepository, PlannerAuthorityKey), GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    let planner_authority = PlannerAuthorityKey::from_bytes([0x31; 32])
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let debugger_authority = DebuggerAuthorityKey::from_bytes([0x47; 32])
        .map_err(GuardedDefaultCampaignRunError::Codec)?;
    let repository = CampaignRepository::with_component_authorities(
        blobs,
        refs,
        planner_authority.clone(),
        debugger_authority,
    )
    .map_err(GuardedDefaultCampaignRunError::Repository)?;
    Ok((repository, planner_authority))
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn campaign_run_exact_checkpoint_store<E>(
    request: &GuardedDefaultCampaignRunRequest,
    repository: &CampaignRepository,
) -> Result<Arc<ExactCheckpointStore>, GuardedDefaultCampaignRunError<E>>
where
    E: Error + 'static,
{
    request
        .capture_reached_stop
        .as_ref()
        .or_else(|| {
            request
                .resume_source
                .as_ref()
                .map(|source| &source.checkpoints)
        })
        .cloned()
        .map_or_else(
            || {
                let root = request
                    .lifecycle
                    .run_state_root()
                    .join("campaign-finding-exact-checkpoints");
                ExactCheckpointStore::new(
                    Arc::new(DirectoryBlobBackend::new(
                        "guarded-campaign-run-exact-checkpoints",
                        root,
                    )),
                    request.resources.maximum_disk_bytes(),
                    repository.ram_retention_authority(),
                )
                .and_then(|checkpoints| {
                    let resources =
                        crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
                            .map_err(|_| {
                            ExactCheckpointStoreError::Store(
                                crucible_cas::content_store::StoreError::Quota,
                            )
                        })?;
                    Ok(Arc::new(checkpoints.with_ram_root_resources(resources)))
                })
                .map_err(GuardedDefaultCampaignRunError::ExactCheckpoint)
            },
            Ok,
        )
}
