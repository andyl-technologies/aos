//! Deferred immutable catalog and promotion-worker construction.
//!
//! The enclosing plan admits all new payloads before invoking this builder.
//! Existing captured checkpoint bodies move once; every worker shares the map.

use super::*;

type PromotionWorker<H> = ProductionCheckpointPromotionWorker<Catalog<H>>;
pub(super) type Catalog<H> = ProductionBakedGenesisReplayCatalogFactory<
    ComposedQemuAttemptResourceGuardFactory<SharedQemuAttemptHostResourceFactory<H>>,
>;

pub(super) fn builder<H>(
    baked: BTreeMap<ScenarioArtifactId, ProductionBakedGenesisCheckpoint>,
    replay_config: Arc<ProductionVmLifecycleConfig>,
    replay_services: RetainedTemplateServiceFactory,
) -> impl FnOnce(
    &CampaignExecutorStore,
    &Arc<ExactCheckpointStore>,
    &SharedQemuAttemptHostResourceFactory<H>,
    &Path,
    usize,
    PromotionControlPayer<'_>,
) -> Result<(Vec<PromotionWorker<H>>, Catalog<H>), PackagedQemuExecutorError> {
    move |store, checkpoints, shared, root, count, payer| {
        let catalog_count = baked.len();
        let catalog = ProductionBakedGenesisReplayCatalogFactory::from_paid_catalog(
            baked.into_values(),
            ComposedQemuAttemptResourceGuardFactory::new(shared.clone()),
            catalog_count,
            payer.catalog_payment(),
        )?
        .with_savepoint_replay_config(replay_config)
        .with_replay_services(replay_services);
        let mut workers = Vec::with_capacity(count);
        for slot in 0..count {
            workers.push(ProductionCheckpointPromotionWorker::new(
                store.clone(),
                Arc::clone(checkpoints),
                crate::packaged_qemu_executor::promotion_plan::worker_path(root, slot)?,
                catalog.clone(),
            ));
        }
        Ok((workers, catalog))
    }
}
