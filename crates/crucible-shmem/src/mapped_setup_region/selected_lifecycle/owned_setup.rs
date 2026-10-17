//! Same-field ownership of an ordinary or selected setup mapping.
//!
//! The original setup allocation keeps one physical mapping owner across
//! selection. It publishes selected custody before validation, retains failed
//! adoption, and keeps ordinary aliases fenced through the backing domain.

use super::{
    Arc, Domain, MappedSetupRegion, Ordering, RetainedWholeMapping, WholeMappingCustodyError,
    registered_domain, try_lock,
};

enum MappingOwner {
    Ordinary(Arc<MappedSetupRegion>),
    Selected(RetainedWholeMapping),
}

/// Owns the same setup mapping before and after whole-controller selection.
///
/// No process-private owner is written into shared memory. Selection preserves
/// this allocation and all existing typed views; it grants no native authority.
pub struct OwnedSetupMapping {
    owner: MappingOwner,
    intent: bool,
    intent_refused: bool,
    retention_slot: Arc<super::RetentionSlot>,
}

impl OwnedSetupMapping {
    /// Wraps the original mapped owner before any callback registration.
    #[must_use]
    pub fn new(mapping: MappedSetupRegion) -> Self {
        Self {
            owner: MappingOwner::Ordinary(Arc::new(mapping)),
            intent: false,
            intent_refused: false,
            retention_slot: Arc::new(super::RetentionSlot::default()),
        }
    }

    /// Borrows the same physical mapping in either lifecycle disposition.
    #[must_use]
    pub fn mapping(&self) -> &MappedSetupRegion {
        match &self.owner {
            MappingOwner::Ordinary(mapping) => mapping.as_ref(),
            MappingOwner::Selected(selected) => selected.mapping.as_ref(),
        }
    }

    /// Borrows the unique ordinary owner for initial typed view construction.
    ///
    /// # Errors
    ///
    /// Refuses selected custody or an unexpected additional strong owner.
    /// Selected service uses its separately authenticated paired loan instead.
    pub fn ordinary_mapping_mut(
        &mut self,
    ) -> Result<&mut MappedSetupRegion, WholeMappingCustodyError> {
        if self.intent || self.intent_refused {
            return Err(WholeMappingCustodyError::Selected);
        }
        match &mut self.owner {
            MappingOwner::Ordinary(mapping) => {
                Arc::get_mut(mapping).ok_or(WholeMappingCustodyError::Busy)
            }
            MappingOwner::Selected(_) => Err(WholeMappingCustodyError::Selected),
        }
    }

    /// Reserves bounded owning retention before any native source HOLD.
    ///
    /// Constructor preparation calls this before native HOLD, registration or
    /// getter effects. It allocates only process-private retention storage and
    /// neither fences aliases nor inspects mapped headers. Once successful,
    /// the same original allocation can remain owned through every failed
    /// intent and selected adoption without another retention allocation.
    ///
    /// # Errors
    ///
    /// Refuses foreign, previously failed, busy, poisoned or exhausted
    /// retention. Failure must stop construction before native source effects.
    pub fn prepare_whole_intent_retention(&mut self) -> Result<(), WholeMappingCustodyError> {
        if self.intent_refused {
            return Err(WholeMappingCustodyError::Selected);
        }
        self.reserve_retention()
    }

    /// Fences this original owner's ordinary aliases before native observation.
    ///
    /// Preparation first reserves retention, then the authentic source
    /// establishes its real HOLD barrier. This method publishes only a sticky
    /// lifetime fence and ends its ordinary
    /// mutation loan before returning; it assigns no epoch or native grant.
    ///
    /// # Errors
    ///
    /// Refuses foreign, mismatched, unavailable, busy, poisoned or previously
    /// failed original ownership. Failure retains the same actual allocation.
    pub fn begin_whole_intent(&mut self) -> Result<(), WholeMappingCustodyError> {
        if self.intent_refused {
            return Err(WholeMappingCustodyError::Selected);
        }
        if !self.retention_slot.armed() {
            self.intent_refused = true;
            return Err(WholeMappingCustodyError::ResourceLimit);
        }
        self.intent = true;
        let result = (|| {
            let mapping = self.mapping();
            let owner = mapping.mapping_owner_key();
            if owner.process != std::process::id() {
                return Err(WholeMappingCustodyError::Unregistered);
            }
            let registration = mapping
                .mapping_registration
                .as_ref()
                .ok_or(WholeMappingCustodyError::Unregistered)?;
            if registration.owner.address != owner.address
                || registration.owner.length != owner.length
                || registration.owner.identity != owner.identity
                || registration.owner.process != owner.process
            {
                return Err(WholeMappingCustodyError::Unregistered);
            }
            registration.domain.selected.store(true, Ordering::Release);
            let current = registered_domain(owner)?;
            if !Arc::ptr_eq(&registration.domain, &current) {
                return Err(WholeMappingCustodyError::Unregistered);
            }
            let _ordinary_loan = try_lock(&current.selection)?;
            Ok(())
        })();
        if result.is_err() {
            self.intent_refused = true;
            self.refuse_whole_control();
        }
        result
    }

    /// Refuses original whole custody and revokes its exact local permit.
    ///
    /// The provider calls this before returning any native currentness, body
    /// or stopped-journal failure. It reads only private owner registration,
    /// and preserves actual mapping ownership and HELD state without inferring
    /// native retirement, ACK consumption, release or replacement authority.
    pub fn refuse_whole_control(&mut self) {
        self.intent |= self.retention_slot.armed();
        self.intent_refused = true;
        match &mut self.owner {
            MappingOwner::Ordinary(mapping) => {
                if let Some(registration) = &mapping.mapping_registration {
                    if self.retention_slot.armed() {
                        registration.domain.selected.store(true, Ordering::Release);
                    }
                    registration
                        .cell
                        .lease_alive
                        .store(false, Ordering::Release);
                    super::paired_service::revoke_cell(&registration.cell);
                }
            }
            MappingOwner::Selected(selected) => selected.refuse_paired_control(),
        }
    }

    /// Selects whole custody in this same field before fallible validation.
    ///
    /// # Errors
    ///
    /// Returns the original selection or held-ring refusal. Failed selection
    /// remains selected; neither retry nor ordinary mutation is enabled.
    pub fn select_whole(&mut self, epoch: u64) -> Result<(), WholeMappingCustodyError> {
        self.select_whole_bounded(epoch, 16)
    }

    /// Selects the constructor's finite operation capacity in the same owner.
    ///
    /// The capacity is immutable after selection and must be in `1..=65_536`.
    /// The native constructor separately authenticates this bound and epoch.
    ///
    /// # Errors
    ///
    /// Returns sticky custody refusal for invalid bounds, prior selection,
    /// exhausted retention storage, or rings that are not held and drained.
    pub fn select_whole_bounded(
        &mut self,
        epoch: u64,
        operation_capacity: u64,
    ) -> Result<(), WholeMappingCustodyError> {
        self.select_whole_inner(epoch, operation_capacity, None)
    }

    /// Adopts the original constructor's exact roster before returning custody.
    ///
    /// The provider authenticates the original native constructor, mapping,
    /// epoch, operation capacity and header offsets before calling this method.
    /// Selection and one-time roster restriction complete in the same owner.
    /// This local adoption supplies no native readiness or grant authority.
    ///
    /// # Errors
    ///
    /// Returns sticky selection refusal or an empty, oversized, duplicate,
    /// unavailable or foreign original-header roster refusal.
    pub fn select_whole_roster_bounded(
        &mut self,
        epoch: u64,
        operation_capacity: u64,
        header_offsets: &[u64],
    ) -> Result<(), WholeMappingCustodyError> {
        self.select_whole_bounded(epoch, operation_capacity)?;
        self.selected_mut()?
            .restrict_paired_header_offsets(header_offsets)
    }

    /// Adopts the same owner after its shared wrapper published selection.
    ///
    /// # Errors
    ///
    /// Refuses a foreign original domain or the original adoption failure.
    pub(super) fn select_whole_preselected(
        &mut self,
        epoch: u64,
        operation_capacity: u64,
        domain: &Arc<Domain>,
    ) -> Result<(), WholeMappingCustodyError> {
        self.select_whole_inner(epoch, operation_capacity, Some(domain))
    }

    fn select_whole_inner(
        &mut self,
        epoch: u64,
        operation_capacity: u64,
        preselected: Option<&Arc<Domain>>,
    ) -> Result<(), WholeMappingCustodyError> {
        if self.intent_refused {
            return Err(WholeMappingCustodyError::Selected);
        }
        self.reserve_retention()?;
        self.intent = true;
        let mut selected = match &self.owner {
            MappingOwner::Ordinary(mapping) => {
                RetainedWholeMapping::unvalidated(Arc::clone(mapping), epoch)
            }
            MappingOwner::Selected(_) => return Err(WholeMappingCustodyError::Selected),
        };
        selected.operation_capacity = operation_capacity;
        selected.retention_slot = Some(Arc::clone(&self.retention_slot));
        self.owner = MappingOwner::Selected(selected);

        match &mut self.owner {
            MappingOwner::Selected(selected) => {
                selected.select_original_mapping_preselected(preselected);
                selected.selection_status()
            }
            MappingOwner::Ordinary(_) => Err(WholeMappingCustodyError::Selected),
        }
    }

    pub(super) fn retention_slot(&self) -> Arc<super::RetentionSlot> {
        Arc::clone(&self.retention_slot)
    }

    fn reserve_retention(&mut self) -> Result<(), WholeMappingCustodyError> {
        let result = if self.mapping().mapping_owner_key().process != std::process::id() {
            Err(WholeMappingCustodyError::Unregistered)
        } else {
            self.retention_slot.reserve()
        };
        if result.is_err() {
            self.intent_refused = true;
        }
        result
    }

    /// Transfers the actual allocation into its already-reserved owning slot.
    pub(super) fn retain_failed_selection_owner(&mut self) {
        if let MappingOwner::Ordinary(mapping) = &self.owner {
            self.retention_slot.retain(Arc::clone(mapping));
        }
    }

    /// Borrows retained selected custody without transferring its mapping.
    ///
    /// # Errors
    ///
    /// Refuses an ordinary mapping. This loan supplies no native current-cut
    /// proof and does not clear a failed selection or pending paired loan.
    pub fn selected_mut(&mut self) -> Result<&mut RetainedWholeMapping, WholeMappingCustodyError> {
        match &mut self.owner {
            MappingOwner::Selected(selected) => Ok(selected),
            MappingOwner::Ordinary(_) => Err(WholeMappingCustodyError::Unregistered),
        }
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_abi = "",
    target_endian = "little",
    target_pointer_width = "64"
))]
#[path = "owned_setup_tests.rs"]
mod tests;

impl Drop for OwnedSetupMapping {
    fn drop(&mut self) {
        if self.intent {
            // An intent may fail before constructing retained epoch custody.
            // Keep the original Arc allocation, rather than only its VMA.
            self.retain_failed_selection_owner();
        }
    }
}
