//! Protected six-domain boot-inventory joins and lifecycle root publication.
//!
//! The dormant composition rechecks the concrete domain owners around source
//! derivation. The node controller commits bootstrap or refresh roots and joins
//! fresh post-publication observations before returning current boot authority.
//! Each path retains its own boot comparisons and owner-recheck bookends; these
//! implementations borrow the parent controller's sole reconciler and Journal.

use aos_sandbox_core::RawPairedClockSample;

use super::{
    ActivatedOperationCompiler, ControllerProtectedClockV1, DormantControllerCompositionV1,
    NodeController,
};
use crate::SingleNodeEffectExecutor;

impl<C, E, T> DormantControllerCompositionV1<C, E, T>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Rechecks every protected owner after first-root commit and returns the root.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecyclePhase6ErrorV1`] unless the newly
    /// committed root exactly matches a fresh all-domain join under one boot.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_lifecycle_boot_inventory_bootstrap<'current>(
        &mut self,
        lifecycle: &'current crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        runtime: &crate::lifecycle::LifecycleAuthenticatedRuntimeInventorySuccessorV1,
        mounts: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventorySuccessorV1,
        storage: &crate::DurableStorageResourceInventorySnapshotV1,
        storage_inventory: &crate::lifecycle::LifecycleAuthenticatedStorageInventorySuccessorV1,
        network: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventorySuccessorV1,
        cache: &mut crate::cache_residency::CacheResidencyProtectedOwnerV1,
        transfer: &mut crate::local_inventory::ProtectedMultiNodeAuthorityOwnerV1,
        transfer_inventory: &crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1,
    ) -> Result<
        crate::lifecycle::CurrentLifecycleBootInventoryV1<'current>,
        crate::lifecycle::LifecyclePhase6ErrorV1,
    > {
        let checked = self.controller.current_lifecycle_boot_domains(
            lifecycle,
            operation_key,
            boot_inventory_key,
            runtime,
            mounts,
            storage,
            storage_inventory,
            network,
            cache,
            transfer,
            transfer_inventory,
        )?;
        drop(checked);
        lifecycle
            .current_boot_inventory(boot_inventory_key)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .ok_or(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)
    }

    // Both publication paths must recheck the same owners around derivation
    // before either can commit a boot-inventory root.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    fn checked_lifecycle_boot_inventory_source(
        &mut self,
        challenge: crate::lifecycle::LifecycleBootInventoryBootstrapChallengeV1,
        runtime: &crate::lifecycle::LifecycleAuthenticatedRuntimeInventoryBootstrapV1,
        mounts: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        storage: &crate::DurableStorageResourceInventorySnapshotV1,
        storage_inventory: &crate::lifecycle::LifecycleAuthenticatedStorageInventoryBootstrapV1,
        network: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        cache: &mut crate::cache_residency::CacheResidencyProtectedOwnerV1,
        transfer: &mut crate::local_inventory::ProtectedMultiNodeAuthorityOwnerV1,
        transfer_inventory: &crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1,
    ) -> Result<
        crate::lifecycle::LifecycleBootInventoryBootstrapSourceV1,
        crate::lifecycle::LifecyclePhase6ErrorV1,
    > {
        use crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority;

        let boot_before = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| StaleAuthority)?
            .into_bytes();
        if boot_before != challenge.host_boot() {
            return Err(StaleAuthority);
        }
        storage
            .recheck(self.controller.reconciler.journal_mut())
            .map_err(|_| StaleAuthority)?;
        let cache_inventory = cache
            .lifecycle_boot_inventory()
            .map_err(|_| StaleAuthority)?;
        transfer
            .recheck_lifecycle_transfer_inventory(transfer_inventory)
            .map_err(|_| StaleAuthority)?;
        let source =
            crate::lifecycle::LifecycleBootInventoryBootstrapSourceV1::from_protected_join(
                challenge,
                runtime,
                mounts,
                storage_inventory,
                storage,
                network,
                &cache_inventory,
                transfer_inventory,
            )?;
        storage
            .recheck(self.controller.reconciler.journal_mut())
            .map_err(|_| StaleAuthority)?;
        if cache
            .lifecycle_boot_inventory()
            .map_err(|_| StaleAuthority)?
            != cache_inventory
        {
            return Err(StaleAuthority);
        }
        transfer
            .recheck_lifecycle_transfer_inventory(transfer_inventory)
            .map_err(|_| StaleAuthority)?;
        let boot_after = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| StaleAuthority)?
            .into_bytes();
        if boot_before != boot_after {
            return Err(StaleAuthority);
        }
        Ok(source)
    }

    /// Publishes the absent first lifecycle boot root from protected owners.
    ///
    /// Host, Mount, Storage, and Network must be challenge-authenticated by
    /// their fixed BSA sessions. Cache and Transfer are reread through their
    /// concrete protected owners around derivation. On an applied commit,
    /// callers must issue four new broker pairs and run the standard joined
    /// boot-domain query before using any recovery observation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecyclePhase6ErrorV1`] for a stale
    /// challenge, an existing root, changed owner state, boot rollover, or a
    /// protected append failure. Indeterminate commits retain their recovery
    /// token in the returned progress value.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn publish_lifecycle_boot_inventory_bootstrap(
        &mut self,
        lifecycle: &mut crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        challenge: crate::lifecycle::LifecycleBootInventoryBootstrapChallengeV1,
        runtime: &crate::lifecycle::LifecycleAuthenticatedRuntimeInventoryBootstrapV1,
        mounts: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        storage: &crate::DurableStorageResourceInventorySnapshotV1,
        storage_inventory: &crate::lifecycle::LifecycleAuthenticatedStorageInventoryBootstrapV1,
        network: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        cache: &mut crate::cache_residency::CacheResidencyProtectedOwnerV1,
        transfer: &mut crate::local_inventory::ProtectedMultiNodeAuthorityOwnerV1,
        transfer_inventory: &crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1,
        transaction_id: [u8; 16],
        atomic_join: aos_sandbox_core::ResourceId,
        operation_lineage: aos_sandbox_core::ResourceId,
        inventory_lineage: aos_sandbox_core::ResourceId,
    ) -> Result<
        crate::lifecycle::LifecycleProgressCommitOutcomeV1,
        crate::lifecycle::LifecyclePhase6ErrorV1,
    > {
        let source = self.checked_lifecycle_boot_inventory_source(
            challenge,
            runtime,
            mounts,
            storage,
            storage_inventory,
            network,
            cache,
            transfer,
            transfer_inventory,
        )?;
        self.controller
            .commit_lifecycle_boot_inventory_bootstrap(
                lifecycle,
                operation_key,
                boot_inventory_key,
                source,
                transaction_id,
                atomic_join,
                operation_lineage,
                inventory_lineage,
            )
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)
    }

    /// Publishes a refreshed lifecycle boot root from all protected domain owners.
    ///
    /// This dormant callsite performs the first phase only: it joins and
    /// rechecks every owner, consumes that capability internally, and commits
    /// the derived root. The caller must then obtain fresh Host and Storage
    /// successors and perform the ordinary boot-domain join; pre-publication
    /// observations cannot be reused as post-publication currentness.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecyclePhase6ErrorV1`] when any domain is
    /// stale or incomplete, the protected clock rolls over, or root preparation
    /// fails. An indeterminate commit is returned with its recovery token.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn publish_lifecycle_boot_inventory_refresh(
        &mut self,
        lifecycle: &mut crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        challenge: crate::lifecycle::LifecycleBootInventoryBootstrapChallengeV1,
        runtime: &crate::lifecycle::LifecycleAuthenticatedRuntimeInventoryBootstrapV1,
        mounts: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        storage: &crate::DurableStorageResourceInventorySnapshotV1,
        storage_inventory: &crate::lifecycle::LifecycleAuthenticatedStorageInventoryBootstrapV1,
        network: &crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
        cache: &mut crate::cache_residency::CacheResidencyProtectedOwnerV1,
        transfer: &mut crate::local_inventory::ProtectedMultiNodeAuthorityOwnerV1,
        transfer_inventory: &crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1,
        transaction_id: [u8; 16],
        atomic_join: aos_sandbox_core::ResourceId,
        operation_lineage: aos_sandbox_core::ResourceId,
        inventory_lineage: aos_sandbox_core::ResourceId,
    ) -> Result<
        crate::lifecycle::LifecycleProgressCommitOutcomeV1,
        crate::lifecycle::LifecyclePhase6ErrorV1,
    > {
        let source = self
            .checked_lifecycle_boot_inventory_source(
                challenge,
                runtime,
                mounts,
                storage,
                storage_inventory,
                network,
                cache,
                transfer,
                transfer_inventory,
            )?
            .into_refresh_source();
        self.controller
            .commit_lifecycle_boot_inventory_refresh(
                lifecycle,
                operation_key,
                boot_inventory_key,
                source,
                transaction_id,
                atomic_join,
                operation_lineage,
                inventory_lineage,
            )
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)
    }
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Joins all six protected current inventories for LIFE-06 planning.
    ///
    /// Runtime, Mount, Storage, and Network arrive as opaque adjacent outcome
    /// pairs minted from their fixed protected broker-session exchanges. Each
    /// pair preserves complete state and advances both traffic sequences by
    /// exactly one; retained historical or no-op rechecks are rejected.
    /// Storage's signed body includes its complete
    /// dataset/snapshot/clone/hold/quota projection. Cache and the complete
    /// zero-or-many transfer set are replayed by their fixed protected owners.
    /// The fixed kernel boot is sampled around the join and every commitment
    /// must match the lifecycle boot record.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecyclePhase6ErrorV1`] when any inventory
    /// is incomplete, stale, foreign to the current boot, replaced during the
    /// join, or mismatched with the operation-bound lifecycle aggregate.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn current_lifecycle_boot_domains<'current>(
        &'current mut self,
        lifecycle: &'current crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        runtime: &'current crate::lifecycle::LifecycleAuthenticatedRuntimeInventorySuccessorV1,
        mounts: &'current crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventorySuccessorV1,
        storage: &'current crate::DurableStorageResourceInventorySnapshotV1,
        storage_inventory: &'current crate::lifecycle::LifecycleAuthenticatedStorageInventorySuccessorV1,
        network: &'current crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventorySuccessorV1,
        cache: &'current mut crate::cache_residency::CacheResidencyProtectedOwnerV1,
        transfer: &'current mut crate::local_inventory::ProtectedMultiNodeAuthorityOwnerV1,
        transfer_inventory: &'current crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1,
    ) -> Result<
        crate::lifecycle::CurrentLifecycleBootDomainInventoriesV1<'current>,
        crate::lifecycle::LifecyclePhase6ErrorV1,
    > {
        let boot_before = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        let runtime_inventory = runtime.initial();
        let runtime_inventory_after = runtime.current();
        if runtime.boot_binding() != storage_inventory.boot_binding()
            || runtime.boot_binding() != mounts.boot_binding()
            || runtime.boot_binding() != network.boot_binding()
            || mounts.initial().endpoint()
                != crate::lifecycle::LifecycleBootBootstrapEndpointV1::Mount
            || network.initial().endpoint()
                != crate::lifecycle::LifecycleBootBootstrapEndpointV1::Network
        {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        runtime_inventory.recheck_boot(boot_before)?;
        runtime_inventory_after.recheck_boot(boot_before)?;
        storage
            .recheck(self.reconciler.journal_mut())
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let storage_inventory_after = storage_inventory.current();
        let storage_inventory = storage_inventory.initial();
        storage_inventory.recheck_launch_snapshot(storage)?;
        storage_inventory_after.recheck_launch_snapshot(storage)?;
        if storage.inventory().kernel_boot_id() != &boot_before {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }

        let cache_inventory = cache
            .lifecycle_boot_inventory()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        transfer
            .recheck_lifecycle_transfer_inventory(transfer_inventory)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        storage
            .recheck(self.reconciler.journal_mut())
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        storage_inventory_after.recheck_launch_snapshot(storage)?;
        let cache_after = cache
            .lifecycle_boot_inventory()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        transfer
            .recheck_lifecycle_transfer_inventory(transfer_inventory)
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        let boot_after = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        let boot_final = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        runtime_inventory.recheck_boot(boot_final)?;
        runtime_inventory_after.recheck_boot(boot_final)?;
        if boot_before != boot_after || boot_after != boot_final || cache_after != cache_inventory {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let commitments = [
            runtime_inventory.commitment(),
            mounts.initial().commitment(),
            storage_inventory.commitment(),
            network.initial().commitment(),
            cache_after.root(),
            transfer_inventory.commitment(),
        ];
        let physical = crate::lifecycle::fresh_physical_inventory(
            &runtime_inventory,
            mounts.initial(),
            &storage_inventory,
            network.initial(),
            &cache_after,
            transfer_inventory,
        )?;
        let current = lifecycle
            .bind_current_boot_domains(
                operation_key,
                boot_inventory_key,
                boot_final,
                commitments,
                physical,
            )
            .map_err(|_| crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority)?;
        if current.boot_binding() != runtime.boot_binding() {
            return Err(crate::lifecycle::LifecyclePhase6ErrorV1::StaleAuthority);
        }
        Ok(current)
    }

    /// Commits a new boot inventory root from a consumed protected six-domain join.
    ///
    /// This is the publication half of the dormant two-phase boot protocol.
    /// Callers first consume the current joined inventories into `source`; this
    /// method then derives every domain commitment from that opaque value and
    /// derives time and boot identity from the controller-owned kernel clock.
    /// After commit, callers must query Host and Storage again and run the
    /// ordinary current-domain join before using the new boot capability.
    ///
    /// # Errors
    ///
    /// Returns [`crate::lifecycle::LifecycleProtectedJournalErrorV1`] for a
    /// stale operation/root, clock or boot rollover, malformed lineage, or a
    /// protected commit failure. Outcome-unknown retains its exact recovery
    /// token in the returned progress value.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_lifecycle_boot_inventory_refresh(
        &mut self,
        lifecycle: &mut crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        source: crate::lifecycle::LifecycleBootInventoryRefreshSourceV1,
        transaction_id: [u8; 16],
        atomic_join: aos_sandbox_core::ResourceId,
        operation_lineage: aos_sandbox_core::ResourceId,
        inventory_lineage: aos_sandbox_core::ResourceId,
    ) -> Result<
        crate::lifecycle::LifecycleProgressCommitOutcomeV1,
        crate::lifecycle::LifecycleProtectedJournalErrorV1,
    > {
        let mut clock = ControllerProtectedClockV1::open_fixed()
            .map_err(|_| crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let sample = clock
            .sample()
            .map_err(|_| crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let current_boot = aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?
            .into_bytes();
        if sample.host_boot_id() != current_boot || sample.wall_seconds() <= 0 {
            return Err(crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let observed_at = lifecycle_observation_time(sample)?;
        let prepared = lifecycle.prepare_boot_inventory_refresh(
            operation_key,
            boot_inventory_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            inventory_lineage,
            current_boot,
            source,
            observed_at,
        )?;
        lifecycle.commit_auxiliary_append(prepared)
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_lifecycle_boot_inventory_bootstrap(
        &mut self,
        lifecycle: &mut crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>,
        operation_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        boot_inventory_key: &crate::lifecycle::LifecycleProtectedJournalKeyV1,
        source: crate::lifecycle::LifecycleBootInventoryBootstrapSourceV1,
        transaction_id: [u8; 16],
        atomic_join: aos_sandbox_core::ResourceId,
        operation_lineage: aos_sandbox_core::ResourceId,
        inventory_lineage: aos_sandbox_core::ResourceId,
    ) -> Result<
        crate::lifecycle::LifecycleProgressCommitOutcomeV1,
        crate::lifecycle::LifecycleProtectedJournalErrorV1,
    > {
        let mut clock = ControllerProtectedClockV1::open_fixed()
            .map_err(|_| crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let sample = clock
            .sample()
            .map_err(|_| crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        if sample.host_boot_id() != source.challenge().host_boot() || sample.wall_seconds() <= 0 {
            return Err(crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let observed_at = lifecycle_observation_time(sample)?;
        let prepared = lifecycle.prepare_boot_inventory_bootstrap(
            operation_key,
            boot_inventory_key,
            transaction_id,
            atomic_join,
            operation_lineage,
            inventory_lineage,
            source,
            observed_at,
        )?;
        lifecycle.commit_auxiliary_append(prepared)
    }
}

// Preserve the existing lifecycle encoding: checked wall-clock seconds and the
// BOOTTIME subsecond fraction. Boot currentness is checked by each effect path.
fn lifecycle_observation_time(
    sample: RawPairedClockSample,
) -> Result<crate::lifecycle::LifecycleTimeV1, crate::lifecycle::LifecycleProtectedJournalErrorV1> {
    u64::try_from(sample.wall_seconds())
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|value| value.checked_add(sample.boottime_nanoseconds() % 1_000_000_000))
        .and_then(|value| crate::lifecycle::LifecycleTimeV1::new(value).ok())
        .ok_or(crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord)
}
