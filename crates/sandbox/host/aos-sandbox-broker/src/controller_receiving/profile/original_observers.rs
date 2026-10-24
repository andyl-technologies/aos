//! Retains genuine P/I/Q/J observer origins and their exclusive native archives.
//!
//! Each named attachment consumes an origin created by the actual Controller
//! writer or J ledger. A lifetime/capacity pair cannot install an archive.
//! Closed and failed rows remain in their original slot; later observations
//! use the same native row engine without reopening a financial interval.

use std::sync::{Mutex, MutexGuard};

use aos_sandbox_model::ResourceVector;
use crate::controller_receiving::bank_launch::{
    ControllerCreateContinuationLedgerOriginalV1 as ContinuationOriginal,
    ControllerCreateStorageUseReceivingOriginalV1 as StorageUseOriginal,
};
use crate::receiving::RootObservationErrorV1;

use super::{ControllerProfileErrorV1 as Error, ControllerSelfProfileOriginalV1};
use crate::controller_receiving::bank_launch::{
    ControllerReservedObserverOriginalV1 as Origin, OriginalObserverPurposeV1 as Purpose,
};
use crate::profile_data::property_values::PropertyPairV1;
use crate::receiving::{
    FixedPropertyArchiveGrowthErrorV1, FixedPropertyArchiveV1, ObservationLifetimeV1,
};

struct ArchiveSlot {
    original: Origin,
    archive: FixedPropertyArchiveV1,
    capacity: usize,
}

type Slot = Mutex<Option<ArchiveSlot>>;

/// Preserves the original geometry refusal separately from retained J/U debt.
#[derive(Debug, thiserror::Error)]
pub enum ControllerCreateIntakeObserverGrowthPreparationErrorV1 {
    /// The unchanged complete row supplier rejected its native geometry.
    #[error(transparent)]
    Geometry(#[from] RootObservationErrorV1),
    /// A count or all-dimension product is unrepresentable.
    #[error("original observer row geometry conflicts")]
    Arithmetic,
    /// The actual J/U owner retains its earlier accounting or affinity cause.
    #[error("original observer funding is closed")]
    Funding,
}

// Both variants borrow the existing real owner. No paid vector, detached
// receipt or lifetime/capacity pair can construct this private union.
enum GrowthFunding<'funding> {
    Continuation(&'funding mut ContinuationOriginal),
    StorageUse(&'funding mut StorageUseOriginal),
}

/// Holds the genuine debited J/U through growth of its same native archive.
///
/// Dropping the loan releases only this borrow. Its debit and the original
/// archive remain resident; it never refunds, resets or finishes an interval.
#[must_use]
pub struct ControllerCreateIntakeObserverGrowthLoanV1<'funding, 'profile> {
    funding: GrowthFunding<'funding>,
    profile: &'profile ControllerSelfProfileOriginalV1,
    lifetime: ObservationLifetimeV1,
    previous: usize,
    additional: usize,
}

impl ControllerCreateIntakeObserverGrowthLoanV1<'_, '_> {
    /// Prices actual preparation, return, borrowed-guard and arithmetic controls.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(std::mem::size_of::<
                Result<Self, ControllerCreateIntakeObserverGrowthPreparationErrorV1>,
            >())?
            .checked_add(std::mem::size_of::<(
                MutexGuard<'_, Option<ArchiveSlot>>,
                ResourceVector,
                ResourceVector,
                usize,
                usize,
                Result<(), FixedPropertyArchiveGrowthErrorV1>,
                Result<ResourceVector, RootObservationErrorV1>,
                Result<
                    (),
                    crate::controller_receiving::bank_launch::ControllerCreateContinuationClosedV1,
                >,
                Result<
                    (),
                    crate::controller_receiving::bank_launch::ControllerCreateStorageUseClosedV1,
                >,
                Result<(), Error>,
            )>())
    }

    /// Grows the same archive after its actual financial debit and upper checks.
    ///
    /// # Errors
    /// Retains original archive allocation failure; rejects changed native
    /// origin, lifetime, cached capacity or the still-borrowed J/U's closure.
    pub fn grow_once_v1(self) -> Result<(), FixedPropertyArchiveGrowthErrorV1> {
        use FixedPropertyArchiveGrowthErrorV1 as Closed;
        // The loan retains exclusive custody of the same already-debited
        // ledger. This check borrows its sticky cause without latching a new
        // classification ahead of the upper independently owed posts.
        let healthy = match &self.funding {
            GrowthFunding::Continuation(owner) => owner.failure_v1().is_none(),
            GrowthFunding::StorageUse(owner) => owner.failure_v1().is_none(),
        };
        if !healthy {
            return Err(Closed::Closed);
        }
        let mut slot = self
            .profile
            .original_observers
            .create_intake
            .try_lock()
            .map_err(|_| Closed::Closed)?;
        let slot = slot.as_mut().ok_or(Closed::Closed)?;
        if slot.capacity != self.previous
            || !slot.original.same_lifetime_v1(&self.lifetime)
            || !slot.original.lifetime_is_open_v1()
        {
            return Err(Closed::Closed);
        }
        slot.original
            .require_attachment_profile_v1(self.profile, Purpose::CreateIntake)
            .map_err(|_| Closed::Closed)?;
        let maximum = slot
            .capacity
            .checked_add(self.additional)
            .ok_or(Closed::Closed)?;
        slot.archive.grow_rows(maximum)?;
        slot.capacity = maximum;
        Ok(())
    }
}

pub(super) struct OriginalObserverRegistryV1 {
    first_global: Slot,
    nix_intake: Slot,
    q04_intake: Slot,
    create_intake: Slot,
}

impl OriginalObserverRegistryV1 {
    pub(super) const fn new() -> Self {
        Self {
            first_global: Mutex::new(None),
            nix_intake: Mutex::new(None),
            q04_intake: Mutex::new(None),
            create_intake: Mutex::new(None),
        }
    }

    fn slot(&self, purpose: Purpose) -> &Slot {
        match purpose {
            Purpose::FirstGlobal => &self.first_global,
            Purpose::NixIntake => &self.nix_intake,
            Purpose::Q04Intake => &self.q04_intake,
            Purpose::CreateIntake => &self.create_intake,
        }
    }

    fn attach(
        &self,
        profile: &ControllerSelfProfileOriginalV1,
        purpose: Purpose,
        origin: Origin,
    ) -> Result<(), Error> {
        let predecessors = match purpose {
            Purpose::FirstGlobal => [
                Purpose::Q04Intake,
                Purpose::NixIntake,
                Purpose::CreateIntake,
            ],
            Purpose::NixIntake => [
                Purpose::CreateIntake,
                Purpose::Q04Intake,
                Purpose::FirstGlobal,
            ],
            Purpose::Q04Intake => [
                Purpose::FirstGlobal,
                Purpose::NixIntake,
                Purpose::CreateIntake,
            ],
            Purpose::CreateIntake => [Purpose::FirstGlobal, Purpose::NixIntake, Purpose::Q04Intake],
        };
        for predecessor in predecessors {
            let slot = self
                .slot(predecessor)
                .try_lock()
                .map_err(|_| Error::Service)?;
            let actual = slot.as_ref().map(|slot| &slot.original);
            if actual.is_some_and(Origin::lifetime_is_open_v1)
                || matches!(
                    (purpose, predecessor),
                    (Purpose::NixIntake, Purpose::FirstGlobal)
                ) && actual.is_none()
            {
                return Err(Error::Service);
            }
        }
        let mut slot = self.slot(purpose).try_lock().map_err(|_| Error::Service)?;
        if slot.is_some() {
            return Err(Error::Service);
        }
        origin.require_attachment_profile_v1(profile, purpose)?;
        let archive = if matches!(purpose, Purpose::CreateIntake) {
            FixedPropertyArchiveV1::with_materialization_limit(
                origin.capacity_data_v1(),
                origin.lifetime_v1(),
                64 * 1024,
            )
        } else {
            FixedPropertyArchiveV1::new(origin.capacity_data_v1(), origin.lifetime_v1())
        };
        let capacity = origin.capacity_data_v1();
        *slot = Some(ArchiveSlot { original: origin, archive, capacity });
        slot.as_mut()
            .ok_or(Error::Service)?
            .archive
            .prepare()
            .map_err(|_| Error::Service)
    }

    fn require_original(
        &self,
        purpose: Purpose,
        lifetime: &ObservationLifetimeV1,
    ) -> Result<(), Error> {
        let slot = self.slot(purpose).try_lock().map_err(|_| Error::Service)?;
        let actual = &slot.as_ref().ok_or(Error::Service)?.original;
        if !actual.lifetime_is_open_v1() || !actual.same_lifetime_v1(lifetime) {
            return Err(Error::Service);
        }
        Ok(())
    }

    fn require_recheck_entry(&self, purpose: Purpose) -> Result<(), Error> {
        let slot = self.slot(purpose).try_lock().map_err(|_| Error::Service)?;
        let actual = &slot.as_ref().ok_or(Error::Service)?.original;
        if matches!(purpose, Purpose::Q04Intake | Purpose::CreateIntake)
            && !actual.lifetime_is_open_v1()
        {
            return Err(Error::Service);
        }
        Ok(())
    }

    // Preserve the original Q/I/P presence rule, including closed slots.
    pub(super) fn has_piq_slot(&self) -> Result<bool, Error> {
        for slot in [&self.q04_intake, &self.nix_intake, &self.first_global] {
            if slot.try_lock().map_err(|_| Error::Service)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn read(
        &self,
        unit_name: &'static str,
        pid: u32,
        properties: &'static [&'static str],
    ) -> Result<PropertyPairV1, Error> {
        let mut create = self.create_intake.try_lock().map_err(|_| Error::Service)?;
        let mut q04 = self.q04_intake.try_lock().map_err(|_| Error::Service)?;
        let mut intake = self.nix_intake.try_lock().map_err(|_| Error::Service)?;
        let mut prefix = self.first_global.try_lock().map_err(|_| Error::Service)?;
        let active = [&*create, &*q04, &*intake, &*prefix]
            .into_iter()
            .filter(|slot| {
                slot.as_ref()
                    .is_some_and(|slot| slot.original.lifetime_is_open_v1())
            })
            .count();
        if active > 1 {
            return Err(Error::Service);
        }
        for slot in [&mut *create, &mut *q04, &mut *intake, &mut *prefix] {
            if let Some(slot) = slot.as_mut() {
                if slot.original.lifetime_is_open_v1() {
                    return slot.archive
                        .read(unit_name, pid, properties)
                        .map_err(|_| Error::Service);
                }
            }
        }
        Err(Error::Service)
    }
}

impl ControllerSelfProfileOriginalV1 {
    /// Reports the actual native original/archive slot header as comparison DATA.
    #[must_use]
    pub const fn original_observer_slot_bytes_v1() -> usize {
        std::mem::size_of::<Slot>()
    }

    /// Reports the actual native original/archive slot alignment as comparison DATA.
    #[must_use]
    pub const fn original_observer_slot_alignment_v1() -> usize {
        std::mem::align_of::<Slot>()
    }

    pub(super) fn use_original_startup_receiver_v1(&self) -> Result<bool, Error> {
        if self.is_original_receiving_scope_current_v1()? {
            return Ok(true);
        }
        Ok(!self.original_observers.has_piq_slot()?)
    }

    /// Closes only the existing FirstGlobal archive without refunding its charge.
    ///
    /// # Errors
    /// Rejects absent, contended or poisoned original archive custody.
    pub fn close_first_global_prefix_v1(&self) -> Result<(), Error> {
        let slot = self
            .original_observers
            .first_global
            .try_lock()
            .map_err(|_| Error::Service)?;
        let actual = &slot.as_ref().ok_or(Error::Service)?.original;
        actual.close_lifetime_v1();
        Ok(())
    }

    /// Prepares archive growth by debiting this same committed J's complete bound.
    ///
    /// Counts describe required work, not supplied funding. The consumed loan
    /// retains this actual owner and compares the native archive capacity.
    ///
    /// # Errors
    /// Preserves row geometry/arithmetic refusal or the same J's retained debt.
    pub fn prepare_create_intake_growth_from_continuation_v1<'funding, 'profile>(
        &'profile self,
        owner: &'funding mut ContinuationOriginal,
        lifetime: &ObservationLifetimeV1,
        previous: usize,
        additional: usize,
    ) -> Result<
        ControllerCreateIntakeObserverGrowthLoanV1<'funding, 'profile>,
        ControllerCreateIntakeObserverGrowthPreparationErrorV1,
    > {
        use ControllerCreateIntakeObserverGrowthPreparationErrorV1 as Preparation;
        let maximum = previous
            .checked_add(additional)
            .filter(|_| additional != 0)
            .ok_or(Preparation::Arithmetic)?;
        let row = crate::receiving::growing_fixed_property_archive_demand_v1(64 * 1024)?;
        let required = FixedPropertyArchiveV1::multiply_receiving_demand_data_v1(row, maximum)
            .map_err(|_| Preparation::Arithmetic)?;
        owner
            .reserve_observer_archive_growth_v1(self, required)
            .map_err(|_| Preparation::Funding)?;
        Ok(ControllerCreateIntakeObserverGrowthLoanV1 {
            funding: GrowthFunding::Continuation(owner),
            profile: self,
            lifetime: lifetime.clone(),
            previous,
            additional,
        })
    }

    /// Prepares archive growth by debiting actual additional rows on this same U.
    ///
    /// # Errors
    /// Preserves row geometry/arithmetic refusal or the same U's retained debt.
    pub fn prepare_create_intake_growth_from_storage_use_v1<'funding, 'profile>(
        &'profile self,
        owner: &'funding mut StorageUseOriginal,
        lifetime: &ObservationLifetimeV1,
        previous: usize,
        additional: usize,
    ) -> Result<
        ControllerCreateIntakeObserverGrowthLoanV1<'funding, 'profile>,
        ControllerCreateIntakeObserverGrowthPreparationErrorV1,
    > {
        use ControllerCreateIntakeObserverGrowthPreparationErrorV1 as Preparation;
        previous
            .checked_add(additional)
            .filter(|_| additional != 0)
            .ok_or(Preparation::Arithmetic)?;
        let row = crate::receiving::growing_fixed_property_archive_demand_v1(64 * 1024)?;
        let required = FixedPropertyArchiveV1::multiply_receiving_demand_data_v1(row, additional)
            .map_err(|_| Preparation::Arithmetic)?;
        owner
            .reserve_observer_archive_growth_v1(self, required)
            .map_err(|_| Preparation::Funding)?;
        Ok(ControllerCreateIntakeObserverGrowthLoanV1 {
            funding: GrowthFunding::StorageUse(owner),
            profile: self,
            lifetime: lifetime.clone(),
            previous,
            additional,
        })
    }


}

impl ControllerSelfProfileOriginalV1 {
    /// Attaches this actual first global origin to its same-profile native archive.
    ///
    /// # Errors
    /// Rejects foreign origin/profile custody, repeated attachment or another live purpose.
    /// Retains a failed archive preparation in the same native slot.
    pub fn attach_first_global_observers_v1(&self, origin: Origin) -> Result<(), Error> {
        self.original_observers
            .attach(self, Purpose::FirstGlobal, origin)
    }

    /// Requires this same actual first global archive and live original lifetime.
    ///
    /// # Errors
    /// Rejects absent, contended, closed or foreign lifetime custody.
    pub fn require_first_global_original_v1(
        &self,
        lifetime: &ObservationLifetimeV1,
    ) -> Result<(), Error> {
        self.original_observers
            .require_original(Purpose::FirstGlobal, lifetime)
    }

    /// Rechecks the profile while retaining its original first global slot.
    ///
    /// # Errors
    /// Rejects a missing or contended slot, or changed native profile/properties.
    pub fn recheck_first_global_profile_v1(&self) -> Result<(), Error> {
        self.original_observers
            .require_recheck_entry(Purpose::FirstGlobal)?;
        self.recheck()
    }

    /// Attaches this actual nix intake origin to its same-profile native archive.
    ///
    /// # Errors
    /// Rejects foreign origin/profile custody, repeated attachment or another live purpose.
    /// Retains a failed archive preparation in the same native slot.
    pub fn attach_nix_intake_observers_v1(&self, origin: Origin) -> Result<(), Error> {
        self.original_observers
            .attach(self, Purpose::NixIntake, origin)
    }

    /// Requires this same actual nix intake archive and live original lifetime.
    ///
    /// # Errors
    /// Rejects absent, contended, closed or foreign lifetime custody.
    pub fn require_nix_intake_original_v1(
        &self,
        lifetime: &ObservationLifetimeV1,
    ) -> Result<(), Error> {
        self.original_observers
            .require_original(Purpose::NixIntake, lifetime)
    }

    /// Rechecks the profile while retaining its original nix intake slot.
    ///
    /// # Errors
    /// Rejects a missing or contended slot, or changed native profile/properties.
    pub fn recheck_nix_intake_profile_v1(&self) -> Result<(), Error> {
        self.original_observers
            .require_recheck_entry(Purpose::NixIntake)?;
        self.recheck()
    }

    /// Attaches this actual q04 intake origin to its same-profile native archive.
    ///
    /// # Errors
    /// Rejects foreign origin/profile custody, repeated attachment or another live purpose.
    /// Retains a failed archive preparation in the same native slot.
    pub fn attach_q04_intake_observers_v1(&self, origin: Origin) -> Result<(), Error> {
        self.original_observers
            .attach(self, Purpose::Q04Intake, origin)
    }

    /// Requires this same actual q04 intake archive and live original lifetime.
    ///
    /// # Errors
    /// Rejects absent, contended, closed or foreign lifetime custody.
    pub fn require_q04_intake_original_v1(
        &self,
        lifetime: &ObservationLifetimeV1,
    ) -> Result<(), Error> {
        self.original_observers
            .require_original(Purpose::Q04Intake, lifetime)
    }

    /// Rechecks this original profile through its actual q04 intake archive.
    ///
    /// # Errors
    /// Rejects missing/closed selected archive or changed original profile and native properties.
    pub fn recheck_q04_intake_profile_v1(&self) -> Result<(), Error> {
        self.original_observers
            .require_recheck_entry(Purpose::Q04Intake)?;
        self.recheck()
    }

    /// Attaches this actual create intake origin to its same-profile native archive.
    ///
    /// # Errors
    /// Rejects foreign origin/profile custody, repeated attachment or another live purpose.
    /// Retains a failed archive preparation in the same native slot.
    pub fn attach_create_intake_observers_v1(&self, origin: Origin) -> Result<(), Error> {
        self.original_observers
            .attach(self, Purpose::CreateIntake, origin)
    }

    /// Requires this same actual create intake archive and live original lifetime.
    ///
    /// # Errors
    /// Rejects absent, contended, closed or foreign lifetime custody.
    pub fn require_create_intake_original_v1(
        &self,
        lifetime: &ObservationLifetimeV1,
    ) -> Result<(), Error> {
        self.original_observers
            .require_original(Purpose::CreateIntake, lifetime)
    }

    /// Rechecks this original profile through its actual create intake archive.
    ///
    /// # Errors
    /// Rejects missing/closed selected archive or changed original profile and native properties.
    pub fn recheck_create_intake_profile_v1(&self) -> Result<(), Error> {
        self.original_observers
            .require_recheck_entry(Purpose::CreateIntake)?;
        self.recheck()
    }
}
