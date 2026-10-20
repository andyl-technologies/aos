//! Keeps the actual taken Storage pair on its persistent Controller bookkeeping.
//!
//! Intrinsic links compare identity; they do not retain Journal files. The
//! private physical consumer must continuously borrow both actual Journals
//! through each reached native operation and independently owed post.

use super::*;
use aos_sandbox_broker::controller_receiving::ControllerStorageFloorRepresentationV1;
use crate::journal::StorageNativeOpeningOwnerLinkV1;
use crate::Journal;

/// Retains same-C physical representation for the actual initial Storage pair.
///
/// Only the genuine once-Storage receiver can mint this owner after its main
/// and distinct sidecar pass their paid take gates. It returns no account,
/// capacity, effect callback, native constructor or semantic completion token.
#[doc(hidden)]
#[must_use = "keep the same physical representation with its original Session"]
pub struct ControllerStorageFloorPhysicalReceivingV1 {
    main: StorageNativeOpeningOwnerLinkV1,
    sidecar: StorageNativeOpeningOwnerLinkV1,
    representation: ControllerStorageFloorRepresentationV1,
    runtime: Arc<tokio::runtime::Runtime>,
    profile: Option<Result<(), ResourceReservationErrorV1>>,
    pair: Option<Result<(), ResourceReservationErrorV1>>,
    debit: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<PhysicalFirstV1>,
}

#[derive(Clone, Copy)]
enum PhysicalFirstV1 { Profile, Pair, Debit }

impl ControllerStorageFloorPhysicalReceivingV1 {
    fn construction_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<StorageNativeOpeningOwnerLinkV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(size_of::<ResourceVector>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(size_of::<Result<(), ResourceReservationErrorV1>>()))
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?))
    }

    /// Borrows the same actual admitted Runtime as nonauthorizing mechanics.
    ///
    /// Its parent and this physical owner retain the original reactor. This
    /// supplies no account, role, property success or native IO permission.
    #[doc(hidden)]
    #[must_use]
    pub fn runtime_mechanics_v1(&self) -> &Arc<tokio::runtime::Runtime> {
        &self.runtime
    }

    /// Compares only the actual opaque launch profile to this original C.
    ///
    /// # Errors
    /// Retains a foreign profile, missing measured helper delivery or closure.
    pub fn require_controller_profile_v1(
        &mut self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.first.is_some() {
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.profile = Some(self.representation.require_same_profile_v1(profile.lower_original_v1())
            .map_err(ResourceReservationErrorV1::from));
        if matches!(self.profile, Some(Ok(()))) {
            Ok(())
        } else {
            self.first = Some(PhysicalFirstV1::Profile);
            Err(ControllerInitialBrokerSessionClosedV1)
        }
    }

    /// Compares the actual held pair and same original before fresh work.
    ///
    /// # Errors
    /// Retains pair substitution or closed original refusal without a native
    /// operation, fresh account, capacity return or success assertion.
    #[doc(hidden)]
    pub fn require_held_pair_v1(&mut self, main: &Journal, sidecar: &Journal)
        -> Result<(), ControllerInitialBrokerSessionClosedV1>
    {
        if self.first.is_some() { return Err(ControllerInitialBrokerSessionClosedV1); }
        self.pair = Some(if self.main.same_journal(main) && self.sidecar.same_journal(sidecar)
            && !self.main.same_journal(sidecar)
        { self.representation.require_persistent_current_v1().map_err(ResourceReservationErrorV1::from) }
        else { Err(ResourceReservationErrorV1::Conflict) });
        if matches!(self.pair, Some(Ok(()))) { Ok(()) } else {
            self.first = Some(PhysicalFirstV1::Pair);
            Err(ControllerInitialBrokerSessionClosedV1)
        }
    }

    /// Debits the actual fixed producer's cumulative physical representation.
    ///
    /// The private Security consumer supplies its compiled owners, native
    /// backing, helper/observer task peak and reached traffic before growth.
    /// This DATA returns no IO or completion grant. That consumer keeps both
    /// actual Journals borrowed throughout its subsequent native call.
    ///
    /// # Errors
    /// Retains pair substitution or same-C monotone debit refusal. Failed
    /// primaries cannot renew payment or reopen; only the already prepaid
    /// independently owed upper continuation remains available.
    pub fn debit_physical_representation_v1(
        &mut self,
        main: &Journal,
        sidecar: &Journal,
        actual: ResourceVector,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if self.first.is_some() {
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        if !matches!(self.profile, Some(Ok(()))) {
            self.profile = Some(Err(ResourceReservationErrorV1::Conflict));
            self.first = Some(PhysicalFirstV1::Profile);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.pair = Some(if self.main.same_journal(main)
            && self.sidecar.same_journal(sidecar) && !self.main.same_journal(sidecar)
        {
            Ok(())
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        });
        if !matches!(self.pair, Some(Ok(()))) {
            self.first = Some(PhysicalFirstV1::Pair);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.debit = Some(self.representation.debit_physical_representation_v1(actual)
            .map_err(ResourceReservationErrorV1::from));
        if matches!(self.debit, Some(Ok(()))) {
            Ok(())
        } else {
            self.first = Some(PhysicalFirstV1::Debit);
            Err(ControllerInitialBrokerSessionClosedV1)
        }
    }

    /// Retires consumed request arithmetic after the private native disposition.
    ///
    /// # Errors
    /// Preserves any failed arithmetic or unconsumed request. This argument-free
    /// stage cannot complete the persistent helper or issue another operation.
    #[doc(hidden)]
    pub fn retire_physical_request_after_native_disposal_v1(&mut self)
        -> Result<(), ControllerInitialBrokerSessionClosedV1>
    {
        if self.first.is_some() { return Err(ControllerInitialBrokerSessionClosedV1); }
        self.representation.retire_physical_request_after_native_disposal_v1()
            .map_err(|_| ControllerInitialBrokerSessionClosedV1)
    }

    /// Borrows the actual first pair or representation error without IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            PhysicalFirstV1::Profile => self.representation.failure().or_else(|| cause(&self.profile)),
            PhysicalFirstV1::Pair => cause(&self.pair),
            PhysicalFirstV1::Debit => self.representation.failure().or_else(|| cause(&self.debit)),
        }
    }
}

impl ControllerInitialBrokerSessionReceivingLoanV1<'_> {
    /// Transfers persistent bookkeeping for the same taken main/sidecar pair.
    ///
    /// This joins actual once-Storage take associations before construction.
    /// It moves no Journal, duplicates no FD and grants no physical authority.
    ///
    /// # Errors
    /// Parks foreign/incomplete pair or original representation failure on
    /// the actual initial receiver without permitting transfer reentry.
    pub fn take_storage_floor_physical_receiving_once_v1(
        &mut self,
        main: &Journal,
        sidecar: &Journal,
    ) -> Result<ControllerStorageFloorPhysicalReceivingV1, ControllerInitialBrokerSessionClosedV1> {
        if self.owner.physical_association.is_some() {
            self.owner.first.get_or_insert(FirstV1::StorageFloor);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        self.owner.physical_association = Some(self.require_storage_floor_journal_v1(main, sidecar));
        if !matches!(self.owner.physical_association, Some(Ok(()))) {
            self.owner.first.get_or_insert(FirstV1::StorageFloor);
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        let result = (|| {
            let runtime = self.owner.runtime.as_ref().cloned()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let construction = ControllerStorageFloorPhysicalReceivingV1::construction_demand_v1()?;
            let representation = self.owner.receiving.as_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?
                .take_storage_floor_representation_once_v1(construction)
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            Ok(ControllerStorageFloorPhysicalReceivingV1 {
                main: main.held_session_owner_link_v1(),
                sidecar: sidecar.held_session_owner_link_v1(),
                representation,
                runtime,
                profile: None,
                pair: None,
                debit: None,
                first: None,
            })
        })();
        match result {
            Ok(owner) => {
                self.owner.physical_transfer = Some(Ok(()));
                Ok(owner)
            }
            Err(cause) => {
                self.owner.physical_transfer = Some(Err(cause));
                self.owner.first.get_or_insert(FirstV1::StorageFloor);
                Err(ControllerInitialBrokerSessionClosedV1)
            }
        }
    }
}

fn cause(slot: &Option<Result<(), ResourceReservationErrorV1>>)
    -> Option<&(dyn Error + 'static)>
{
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

impl ControllerStorageFloorPhysicalReceivingV1 {
    /// Joins the real completed initial C and both held Storage Journals.
    ///
    /// # Errors
    /// Refuses a foreign initial owner, unfinished C post or replaced pair.
    #[doc(hidden)]
    pub fn require_completed_initial_pair_v1(
        &mut self,
        completed: &super::ControllerInitialSessionCompletedNativeBorrowV1<'_>,
        main: &Journal,
        sidecar: &Journal,
    ) -> Result<(), ControllerInitialBrokerSessionClosedV1> {
        if !completed.matches_main_v1(main) {
            return Err(ControllerInitialBrokerSessionClosedV1);
        }
        let initial = completed.owner.receiving.as_ref().ok_or(ControllerInitialBrokerSessionClosedV1)?;
        self.representation.require_initial_original_v1(initial)
            .map_err(|_| ControllerInitialBrokerSessionClosedV1)?;
        self.require_held_pair_v1(main, sidecar)
    }
}
