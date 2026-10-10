//! Binds the shared RAM provider to the existing original catalog authority.
//!
//! The external catalog owner retains constructor credit after every provider
//! alias. Cache, descriptor and retirement loans use this same budget and quota;
//! no provider allocator, service reservation or replacement supervisor is made.

use crucible_api::vm_lifecycle::ProductionRamCatalogProvider;
use crucible_linux_resource::host_supervision::HostOperationClass;
use std::path::{Component, Path};

use super::*;
use crucible_cas::content_store::StorePhysicalQuotaGuard;

/// Retains the existing original catalog supervisor without another account.
#[derive(Clone)]
pub(crate) struct OriginalCatalogBinding(Arc<CatalogSupervisor>);

/// Shares the provider whose external original owner retains constructor credit.
#[derive(Clone)]
pub(crate) struct OriginalRamCatalogBinding {
    service: Arc<crate::packaged_qemu_executor::ram_catalog::provider::CatalogService>,
}

impl OriginalActorCatalogOwner {
    /// Constructs the shared provider from this physically bound original catalog.
    ///
    /// # Errors
    /// Refuses missing or foreign custody, original admission or the actual quota boundary.
    pub(crate) fn prepare_ram_provider(
        &mut self,
        heap: &crucible_cas::content_store::SqliteProcessHeap,
    ) -> Result<(), StoreError> {
        if self.provider.is_some() || self.provider_credit.is_some() {
            return Err(StoreError::Unauthorized);
        }
        let supervisor = self.supervisor.as_ref().ok_or(StoreError::Unavailable)?;
        StorePhysicalQuotaGuard::verify(supervisor.as_ref())?;
        heap.verify_live()?;
        let binding = OriginalCatalogBinding(Arc::clone(supervisor));
        let bytes = crate::packaged_qemu_executor::ram_catalog::provider::CatalogService::original_constructor_bytes()?;
        self.provider_credit = Some(
            supervisor
                .0
                .budget
                .reserve_scratch_bytes(bytes)
                .map_err(|source| supervisor.0.decode_error(source))?,
        );
        let service =
            crate::packaged_qemu_executor::ram_catalog::provider::CatalogService::new_original(
                binding, heap,
            )?;
        // Both owners are published before the independent original postcut.
        self.provider = Some(Arc::new(service));
        supervisor.0.check()
    }

    /// Shares the same published provider without a new service reservation.
    ///
    /// # Errors
    /// Refuses missing or foreign custody, original admission or the actual quota boundary.
    pub(crate) fn ram_provider_binding(&self) -> Result<OriginalRamCatalogBinding, StoreError> {
        let supervisor = self.supervisor.as_ref().ok_or(StoreError::Unavailable)?;
        StorePhysicalQuotaGuard::verify(supervisor.as_ref())?;
        Ok(OriginalRamCatalogBinding {
            service: Arc::clone(self.provider.as_ref().ok_or(StoreError::Unavailable)?),
        })
    }
}

impl OriginalRamCatalogBinding {
    /// Shares the same provider as the lifecycle interface.
    pub(crate) fn provider(&self) -> Arc<dyn ProductionRamCatalogProvider> {
        Arc::clone(&self.service) as Arc<dyn ProductionRamCatalogProvider>
    }

    /// Checks the actual retained original and installed project quota.
    ///
    /// # Errors
    /// Refuses missing or foreign custody, original admission or the actual quota boundary.
    pub(crate) fn verify(&self) -> Result<(), StoreError> {
        self.service.verify_original_binding()
    }

    /// Checks that the factory preparation is the same retained original.
    ///
    /// # Errors
    /// Refuses missing or foreign custody, original admission or the actual quota boundary.
    pub(crate) fn verify_preparation(
        &self,
        preparation: &crate::private_original_capture::OriginalPreparation,
    ) -> Result<(), StoreError> {
        self.service.verify_original_preparation(preparation)
    }

    /// Returns the fixed descendant used by this original catalog deployment.
    pub(crate) fn root(&self) -> &'static Path {
        Path::new("/var/lib/crucible/measurement/catalog/worlds")
    }
}

impl OriginalCatalogBinding {
    /// Checks the actual retained original and installed project quota.
    ///
    /// # Errors
    /// Refuses missing or foreign custody, original admission or the actual quota boundary.
    pub(crate) fn verify(&self) -> Result<(), StoreError> {
        StorePhysicalQuotaGuard::verify(self.0.as_ref())
    }

    /// Starts a fixed provider class in the existing original roster.
    ///
    /// # Errors
    /// Refuses missing or foreign custody, original admission or the actual quota boundary.
    pub(crate) fn begin(
        &self,
        class: HostOperationClass,
    ) -> Result<HostOperationGuard, StoreError> {
        self.verify()?;
        let guard = self
            .0
            .0
            .reconcile(self.0.0.accounts.begin_provider(class))?;
        self.0.0.check()?;
        Ok(guard)
    }

    /// Borrows actual metadata credit from the existing catalog budget.
    ///
    /// # Errors
    /// Refuses missing or foreign custody, original admission or the actual quota boundary.
    pub(crate) fn reserve_metadata(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        SqliteCatalogSupervisor::reserve_resident_bytes(self.0.as_ref(), bytes)
    }

    /// Borrows descriptor credit inside the same catalog purpose.
    ///
    /// # Errors
    /// Refuses missing or foreign custody, original admission or the actual quota boundary.
    pub(crate) fn reserve_descriptors(&self, descriptors: u64) -> Result<ResourceLoan, StoreError> {
        StorePhysicalQuotaGuard::reserve_resources(self.0.as_ref(), descriptors, 0)
    }

    /// Retains the first actual allocation refusal in prepaid catalog storage.
    pub(crate) fn retain_allocation_error(
        &self,
        source: std::collections::TryReserveError,
    ) -> StoreError {
        let original_after = self.0.0.accounts.check().err();
        self.0.0.remember(CatalogCause::Allocation {
            source,
            original_after,
        })
    }

    /// Returns the fixed supported metadata extent after original verification.
    ///
    /// # Errors
    /// Refuses missing or foreign custody, original admission or the actual quota boundary.
    pub(crate) fn metadata_limit(&self) -> Result<u64, StoreError> {
        StorePhysicalQuotaGuard::decoded_metadata_limit(self.0.as_ref())
    }

    /// Checks that the factory preparation is the same retained original.
    ///
    /// # Errors
    /// Refuses missing or foreign custody, original admission or the actual quota boundary.
    pub(crate) fn verify_preparation(
        &self,
        preparation: &crate::private_original_capture::OriginalPreparation,
    ) -> Result<(), StoreError> {
        self.verify()?;
        match &self.0.0.accounts {
            CatalogAccounts::Original(accounts) => self
                .0
                .0
                .reconcile_account(preparation.verify_catalog_accounts(accounts)),
            #[cfg(test)]
            CatalogAccounts::Fixture(_) => Err(StoreError::Unauthorized),
        }
    }

    /// Prepares a bounded descendant under the existing installed catalog quota.
    ///
    /// # Errors
    /// Refuses missing or foreign custody, original admission or the actual quota boundary.
    pub(crate) fn prepare(&self, directory: &Path) -> Result<(), StoreError> {
        let relative = directory
            .strip_prefix(Path::new("/var/lib/crucible/measurement/catalog"))
            .map_err(|_| StoreError::Unauthorized)?;
        if relative.components().count() > 16
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(StoreError::Unauthorized);
        }
        let operation = self.begin(HostOperationClass::Preparation)?;
        let slot = self
            .0
            .0
            .physical
            .try_lock()
            .map_err(|_| StoreError::Unavailable)?;
        let binding = slot
            .as_ref()
            .and_then(|physical| physical.binding.as_ref())
            .ok_or(StoreError::Unavailable)?;
        super::physical::reconcile_quota(
            &self.0.0,
            binding.prepare_descendant_directory(directory),
        )?;
        self.0.0.reconcile(operation.complete().map(|_| ()))
    }
}

impl std::fmt::Debug for OriginalRamCatalogBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginalRamCatalogBinding")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    //! These controls certify original custody and closed admission, not quotas.

    use super::*;
    use crucible_linux_resource::test_support::TestAllocationObserver;

    #[test]
    fn unbound_original_refuses_before_provider_constructor_credit_or_cache_birth()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, decoder, mut owner) = super::super::tests::fixture();
        let heap = crucible_cas::content_store::fixture_sqlite_heap()?;

        let (result, counts) = TestAllocationObserver::count(|| owner.prepare_ram_provider(&heap));

        assert!(matches!(result, Err(StoreError::Unavailable)));
        assert!(owner.provider.is_none());
        assert!(owner.provider_credit.is_none());
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        drop(heap);
        owner
            .try_close()
            .map_err(|_| "original owner close refused")?;
        decoder.try_close().map_err(|_| "decoder close refused")?;
        Ok(())
    }

    #[test]
    fn cancellation_preserves_same_original_before_provider_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let (supervisor, decoder, mut owner) = super::super::tests::fixture();
        let heap = crucible_cas::content_store::fixture_sqlite_heap()?;
        supervisor.cancel()?;

        let failure = owner
            .prepare_ram_provider(&heap)
            .err()
            .ok_or("cancelled original accepted")?;

        assert!(matches!(failure, StoreError::DecodeAdmission { .. }));
        assert!(owner.provider.is_none());
        assert!(owner.provider_credit.is_none());
        drop(failure);
        drop(heap);
        // The failed original remains terminal; no retry or healthy close is claimed.
        drop(owner);
        drop(decoder);
        Ok(())
    }

    #[test]
    fn provider_binding_alias_keeps_original_controls_until_actual_alias_free()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, decoder, owner) = super::super::tests::fixture();
        let binding = OriginalCatalogBinding(Arc::clone(
            owner.supervisor.as_ref().ok_or("supervisor missing")?,
        ));

        let owner = owner
            .try_close()
            .err()
            .ok_or("live provider binding permitted closure")?;

        assert!(owner.supervisor.is_some());
        assert!(owner.controls.is_some());
        drop(binding);
        owner
            .try_close()
            .map_err(|_| "original close refused after alias free")?;
        decoder.try_close().map_err(|_| "decoder close refused")?;
        Ok(())
    }
}
