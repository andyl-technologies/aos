//! Binds the authenticated catalog purpose to its installed kernel project.
//!
//! The same catalog control retains the actual namespace lease and original
//! audit loans. No path, scalar quota, allocator or replacement supervisor can
//! construct a catalog purpose through this module.

use crucible::owned_decode::{DecodeDescriptorLoan, DecodeScratch};
use crucible_cas::content_store::StorePhysicalQuotaGuard;
use crucible_linux_resource::LinuxProjectQuotaBinding;

use super::*;
use crucible_qemu::{
    OriginalActorCatalogPurpose, OriginalCatalogAuditError, OriginalCatalogPhysicalAudit,
};

const CATALOG_ROOT: &str = "/var/lib/crucible/measurement/catalog";

pub(super) struct CatalogPhysical {
    binding: Option<LinuxProjectQuotaBinding>,
    audit: OriginalCatalogPhysicalAudit,
    _descriptors: DecodeDescriptorLoan,
    _scratch: DecodeScratch,
}

impl OriginalActorCatalogOwner {
    /// Binds the one workflow purpose to the installed catalog project.
    ///
    /// The same actor's descriptor and byte loans precede the first root open.
    /// The original root roster supplies the bounded audit operation; its class
    /// and private absolute end are unchanged. Failed audit custody stays held.
    ///
    /// # Errors
    /// Refuses a different original, repeated binding, original credit or
    /// supervision, missing project quota, unsafe descendants or quota drift.
    pub fn bind_physical_catalog(
        &mut self,
        purpose: OriginalActorCatalogPurpose,
    ) -> Result<(), StoreError> {
        let authority = self.authority.as_ref().ok_or(StoreError::Unavailable)?;
        authority.check()?;
        let audit = authority.reconcile_account(authority.accounts.prepare_audit(purpose))?;
        let mut slot = authority
            .physical
            .try_lock()
            .map_err(|_| StoreError::Unavailable)?;
        if slot.is_some() {
            return Err(StoreError::Unavailable);
        }
        let descriptors = authority
            .budget
            .reserve_descriptors(LinuxProjectQuotaBinding::maximum_audit_file_descriptors())
            .map_err(|source| authority.decode_error(source))?;
        let scratch = authority
            .budget
            .reserve_scratch_bytes(LinuxProjectQuotaBinding::maximum_audit_scratch_bytes())
            .map_err(|source| authority.decode_error(source))?;
        // The binding keeps one path; a raw lower error can retain another.
        // Both names precede kernel I/O and its possible diagnostic allocation.
        authority
            .budget
            .charge_bytes(2 * CATALOG_ROOT.len() as u64)
            .map_err(|source| authority.decode_error(source))?;
        *slot = Some(CatalogPhysical {
            binding: None,
            audit,
            _descriptors: descriptors,
            _scratch: scratch,
        });
        let physical = slot.as_mut().ok_or(StoreError::Unavailable)?;
        authority.reconcile_account(physical.audit.start())?;
        authority.reconcile(Ok(()))?;
        let bound = physical.audit.bind_existing();
        let primary = match bound {
            Ok(binding) => {
                physical.binding = Some(binding);
                Ok(())
            }
            Err(OriginalCatalogAuditError::Quota(source)) => Err(source),
            Err(OriginalCatalogAuditError::Account(source)) => {
                return authority.reconcile_account(Err(source));
            }
        };
        reconcile_quota(authority, primary)?;
        authority.reconcile_account(physical.audit.complete())?;
        authority.reconcile(Ok(()))?;
        Ok(())
    }

    /// Shares the same physically bound catalog control with the real store.
    ///
    /// # Errors
    /// Refuses missing physical binding, original refusal or changed quota.
    pub fn physical_quota(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        let supervisor = self.supervisor.as_ref().ok_or(StoreError::Unavailable)?;
        StorePhysicalQuotaGuard::verify(supervisor.as_ref())?;
        Ok(Arc::clone(supervisor) as Arc<dyn StorePhysicalQuotaGuard>)
    }
}

impl StorePhysicalQuotaGuard for CatalogSupervisor {
    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        StorePhysicalQuotaGuard::verify(self)?;
        let metadata = self
            .0
            .budget
            .reserve_scratch_bytes(
                bytes
                    .checked_add(ResourceLoan::allocation_bytes::<PhysicalCredit>())
                    .ok_or(StoreError::Quota)?,
            )
            .map_err(|source| self.0.decode_error(source))?;
        let descriptors = if descriptors == 0 {
            None
        } else {
            Some(
                self.0
                    .budget
                    .reserve_descriptors(descriptors)
                    .map_err(|source| self.0.decode_error(source))?,
            )
        };
        let loan = ResourceLoan::new(PhysicalCredit {
            _descriptors: descriptors,
            _metadata: metadata,
            _authority: Arc::clone(&self.0),
        });
        self.0.check()?;
        Ok(loan)
    }

    fn verify(&self) -> Result<(), StoreError> {
        self.0.check()?;
        let slot = self
            .0
            .physical
            .try_lock()
            .map_err(|_| StoreError::Unavailable)?;
        let physical = slot.as_ref().ok_or(StoreError::Unavailable)?;
        let binding = physical.binding.as_ref().ok_or(StoreError::Unavailable)?;
        reconcile_quota(&self.0, binding.verify())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        StorePhysicalQuotaGuard::verify(self)?;
        Ok(256 << 20)
    }
}

struct PhysicalCredit {
    _descriptors: Option<DecodeDescriptorLoan>,
    _metadata: DecodeScratch,
    _authority: Arc<CatalogAuthority>,
}

fn reconcile_quota<T>(
    authority: &CatalogAuthority,
    primary: Result<T, crucible_linux_resource::LinuxProjectQuotaError>,
) -> Result<T, StoreError> {
    let after = authority.accounts.check();
    match (primary, after) {
        (Ok(value), Ok(_)) => Ok(value),
        (Err(source), after) => Err(authority.remember(CatalogCause::Quota {
            source,
            original_after: after.err(),
        })),
        (Ok(_), Err(source)) => Err(authority.remember(CatalogCause::Supervision {
            source,
            original_after: None,
        })),
    }
}
