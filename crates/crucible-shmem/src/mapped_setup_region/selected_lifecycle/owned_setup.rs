//! Same-field ownership of an ordinary or selected setup mapping.
//!
//! The original setup allocation keeps one physical mapping owner across
//! selection. It publishes selected custody before validation, retains failed
//! adoption, and keeps ordinary aliases fenced through the backing domain.

use super::{Arc, Domain, MappedSetupRegion, RetainedWholeMapping, WholeMappingCustodyError};

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
}

impl OwnedSetupMapping {
    /// Wraps the original mapped owner before any callback registration.
    #[must_use]
    pub fn new(mapping: MappedSetupRegion) -> Self {
        Self {
            owner: MappingOwner::Ordinary(Arc::new(mapping)),
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
        match &mut self.owner {
            MappingOwner::Ordinary(mapping) => {
                Arc::get_mut(mapping).ok_or(WholeMappingCustodyError::Busy)
            }
            MappingOwner::Selected(_) => Err(WholeMappingCustodyError::Selected),
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
        let mut selected = match &self.owner {
            MappingOwner::Ordinary(mapping) => {
                RetainedWholeMapping::unvalidated(Arc::clone(mapping), epoch)
            }
            MappingOwner::Selected(_) => return Err(WholeMappingCustodyError::Selected),
        };
        selected.operation_capacity = operation_capacity;
        self.owner = MappingOwner::Selected(selected);

        match &mut self.owner {
            MappingOwner::Selected(selected) => {
                selected.select_original_mapping_preselected(preselected);
                selected.selection_status()
            }
            MappingOwner::Ordinary(_) => Err(WholeMappingCustodyError::Selected),
        }
    }

    /// Retains the original allocation after failed shared-owner adoption.
    pub(super) fn retain_failed_selection_owner(&mut self) {
        if let MappingOwner::Ordinary(mapping) = &self.owner {
            std::mem::forget(Arc::clone(mapping));
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
