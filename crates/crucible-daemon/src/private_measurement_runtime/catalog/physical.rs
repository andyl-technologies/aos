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

// The workflow's fixed catalog descriptor purpose is a subset of the existing
// actor bank. This inline census covers its audit, graph, refs and RAM caches;
// every admitted purpose still takes real descriptor credit from that bank.
const CATALOG_DESCRIPTOR_LIMIT: u64 = 128;

struct CatalogDescriptorCredit {
    loan: Option<DecodeDescriptorLoan>,
    authority: Arc<CatalogAuthority>,
    descriptors: u64,
}

impl CatalogAuthority {
    // The audit loan lives inside this authority, so its permanent census has
    // no self-owning Arc. External per-backend purposes retain their own Arc.
    fn reserve_catalog_audit_descriptors(&self) -> Result<DecodeDescriptorLoan, StoreError> {
        self.check()?;
        let mut held = self
            .descriptor_purposes
            .try_lock()
            .map_err(|_| StoreError::Unavailable)?;
        if *held != 0 {
            return Err(StoreError::Unauthorized);
        }
        let descriptors = LinuxProjectQuotaBinding::maximum_audit_file_descriptors();
        if descriptors > CATALOG_DESCRIPTOR_LIMIT {
            return Err(self.remember(CatalogCause::DescriptorPurpose));
        }
        let loan = self
            .budget
            .reserve_descriptors(descriptors)
            .map_err(|source| self.decode_error(source))?;
        *held = descriptors;
        Ok(loan)
    }

    fn reserve_catalog_descriptors(
        self: &Arc<Self>,
        descriptors: u64,
    ) -> Result<CatalogDescriptorCredit, StoreError> {
        self.check()?;
        let mut held = self
            .descriptor_purposes
            .try_lock()
            .map_err(|_| StoreError::Unavailable)?;
        let next = held
            .checked_add(descriptors)
            .filter(|value| *value <= CATALOG_DESCRIPTOR_LIMIT);
        let Some(next) = next else {
            return Err(self.remember(CatalogCause::DescriptorPurpose));
        };
        let loan = self
            .budget
            .reserve_descriptors(descriptors)
            .map_err(|source| self.decode_error(source))?;
        *held = next;
        drop(held);
        let credit = CatalogDescriptorCredit {
            loan: Some(loan),
            authority: Arc::clone(self),
            descriptors,
        };
        self.check()?;
        Ok(credit)
    }
}

impl Drop for CatalogDescriptorCredit {
    fn drop(&mut self) {
        // The caller's descriptors precede this credit. The actual original
        // descriptor loan closes before this subset becomes available again.
        drop(self.loan.take());
        // Contention or poison retains this conservative subset assignment
        // until the whole authority retires; Drop never waits for another user.
        if let Ok(mut held) = self.authority.descriptor_purposes.try_lock() {
            *held -= self.descriptors;
        }
    }
}

pub(super) struct CatalogPhysical {
    pub(super) binding: Option<LinuxProjectQuotaBinding>,
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
        let descriptors = authority.reserve_catalog_audit_descriptors()?;
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
            Some(self.0.reserve_catalog_descriptors(descriptors)?)
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
    _descriptors: Option<CatalogDescriptorCredit>,
    _metadata: DecodeScratch,
    _authority: Arc<CatalogAuthority>,
}

pub(super) fn reconcile_quota<T>(
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

#[cfg(test)]
mod descriptor_tests {
    //! Uses real same-budget loans to exercise the fixed catalog subset.

    use super::*;

    #[test]
    fn audit_and_backend_loans_share_one_catalog_descriptor_extent()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, decoder, owner, controls) = super::super::tests::campaign_creation_fixture();
        let authority = owner.authority.as_ref().ok_or("authority missing")?;
        let audit = authority.reserve_catalog_audit_descriptors()?;
        let remaining =
            CATALOG_DESCRIPTOR_LIMIT - LinuxProjectQuotaBinding::maximum_audit_file_descriptors();
        let backend = authority.reserve_catalog_descriptors(remaining)?;
        assert_eq!(
            *authority
                .descriptor_purposes
                .lock()
                .map_err(|_| "census poisoned")?,
            CATALOG_DESCRIPTOR_LIMIT
        );

        let refusal = authority
            .reserve_catalog_descriptors(1)
            .err()
            .ok_or("catalog subset overflow accepted")?;

        assert!(matches!(refusal, StoreError::DecodeAdmission { .. }));
        assert_eq!(
            *authority
                .descriptor_purposes
                .lock()
                .map_err(|_| "census poisoned")?,
            CATALOG_DESCRIPTOR_LIMIT
        );
        drop(refusal);
        drop(backend);
        drop(audit);
        // The original is terminal; releasing physical loans does not retry it.
        drop(owner);
        drop(decoder);
        std::mem::forget(controls);
        Ok(())
    }

    #[test]
    fn descriptor_credit_retains_original_until_real_loan_closure()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, decoder, owner, controls) = super::super::tests::campaign_creation_fixture();
        let loan = owner
            .authority
            .as_ref()
            .ok_or("authority missing")?
            .reserve_catalog_descriptors(CATALOG_DESCRIPTOR_LIMIT)?;

        let owner = owner
            .try_close()
            .err()
            .ok_or("live descriptor purpose permitted close")?;
        assert_eq!(
            *owner
                .authority
                .as_ref()
                .ok_or("authority missing")?
                .descriptor_purposes
                .lock()
                .map_err(|_| "census poisoned")?,
            CATALOG_DESCRIPTOR_LIMIT
        );
        drop(loan);
        assert_eq!(
            *owner
                .authority
                .as_ref()
                .ok_or("authority missing")?
                .descriptor_purposes
                .lock()
                .map_err(|_| "census poisoned")?,
            0
        );

        owner
            .try_close()
            .map_err(|_| "original close refused after actual loan free")?;
        decoder.try_close().map_err(|_| "decoder close refused")?;
        drop(controls);
        Ok(())
    }
}
