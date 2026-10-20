//! Pays the fixed Storage floor sibling from the original retained F.
//!
//! The captured writer owns native acquisition, exact-prefix replay and all
//! independent name posts. These receiving phases bind its real main/taken
//! sidecar; they provide no TPM, Required-mode or effect authority.

use super::*;
use aos_sandbox_core::component_receiving::complete_bound_delta_v1;
use crate::journal::StorageNativeOpeningOwnerLinkV1;

#[derive(Clone, Copy)]
enum First {
    Binding, Growth, Debit, Reentry, SidecarBinding, SidecarGrowth, SidecarDebit,
    MainBinding, MainGrowth, MainDebit,
    SessionReplayBinding, SessionReplayGrowth, SessionReplayDebit,
    AvailabilityBinding, AvailabilityGrowth, AvailabilityDebit,
}

pub(super) struct StorageFloorCaptureReceivingOriginalV2 {
    bound: ResourceVector,
    sidecar_bound: ResourceVector,
    main_bound: ResourceVector,
    session_replay_bound: ResourceVector,
    availability_bound: ResourceVector,
    availability_binding: Option<Result<(), StorageReceivingClosedV1>>,
    availability_growth: Option<Result<(ResourceVector, ResourceVector), aos_sandbox_core::AccountingError>>,
    availability_debit: Option<Result<(), aos_sandbox_core::AccountingError>>,
    main_binding: Option<Result<(), StorageReceivingClosedV1>>,
    main_growth: Option<Result<(ResourceVector, ResourceVector), aos_sandbox_core::AccountingError>>,
    main_debit: Option<Result<(), aos_sandbox_core::AccountingError>>,
    session_replay_binding: Option<Result<(), StorageReceivingClosedV1>>,
    session_replay_growth: Option<Result<(ResourceVector, ResourceVector), aos_sandbox_core::AccountingError>>,
    session_replay_debit: Option<Result<(), aos_sandbox_core::AccountingError>>,
    sidecar_binding: Option<Result<(), StorageReceivingClosedV1>>,
    sidecar_growth: Option<Result<(ResourceVector, ResourceVector), aos_sandbox_core::AccountingError>>,
    sidecar_debit: Option<Result<(), aos_sandbox_core::AccountingError>>,
    growth: Option<Result<(ResourceVector, ResourceVector), aos_sandbox_core::AccountingError>>,
    debit: Option<Result<(), aos_sandbox_core::AccountingError>>,
    binding: Option<Result<(), StorageReceivingClosedV1>>,
    sidecar: Option<StorageNativeOpeningOwnerLinkV1>,
    archive: Option<Result<(), aos_sandbox_core::AccountingError>>,
    entered: bool,
    first: Option<First>,
}

impl StorageFloorCaptureReceivingOriginalV2 {
    pub(super) const fn new() -> Self {
        Self {
            bound: ResourceVector::ZERO,
            sidecar_bound: ResourceVector::ZERO,
            main_bound: ResourceVector::ZERO,
            session_replay_bound: ResourceVector::ZERO,
            availability_bound: ResourceVector::ZERO,
            availability_binding: None,
            availability_growth: None,
            availability_debit: None,
            main_binding: None,
            main_growth: None,
            main_debit: None,
            session_replay_binding: None,
            session_replay_growth: None,
            session_replay_debit: None,
            sidecar_binding: None,
            sidecar_growth: None,
            sidecar_debit: None,
            growth: None,
            debit: None,
            binding: None,
            sidecar: None,
            archive: None,
            entered: false,
            first: None,
        }
    }

    pub(super) fn matches_taken_pair_v2(&self, main: &crate::Journal, sidecar: &crate::Journal) -> bool {
        self.entered && self.first.is_none()
            && matches!(self.debit, Some(Ok(())))
            && self.sidecar.as_ref().is_some_and(|held| held.same_journal(sidecar) && !held.same_journal(main))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Binding => self.binding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Growth => self.growth.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Debit => self.debit.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.archive.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Reentry => Some(&StorageReceivingClosedV1),
            First::SidecarBinding => self.sidecar_binding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SidecarGrowth => self.sidecar_growth.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SidecarDebit => self.sidecar_debit.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::MainBinding => self.main_binding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::MainGrowth => self.main_growth.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::MainDebit => self.main_debit.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SessionReplayBinding => self.session_replay_binding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SessionReplayGrowth => self.session_replay_growth.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::SessionReplayDebit => self.session_replay_debit.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::AvailabilityBinding => self.availability_binding.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::AvailabilityGrowth => self.availability_growth.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::AvailabilityDebit => self.availability_debit.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }
}

impl StoragePrepareReceivingLoanV1<'_> {
    /// Prepays the still-resident availability capsule on this same original F.
    ///
    /// The capsule survives positive per-request control disposal. Its complete
    /// bound is therefore a separate additive component beside the main and
    /// sidecar programmes, never a fresh ledger or reusable request allowance.
    /// This financial operation supplies no Session, clock, floor or effect.
    ///
    /// # Errors
    /// Retains another main/taken-sidecar, a prior refusal, growth overflow or
    /// actual original-ledger exhaustion before capsule/native backing grows.
    pub fn reserve_floor_availability_v3(&mut self, main: &crate::Journal,
        sidecar: &crate::Journal, complete: ResourceVector,
    ) -> Result<(), StorageReceivingClosedV1> {
        let receiving = self.receiving()?;
        let floor = &mut receiving.floor_capture;
        if floor.first.is_some() { return Err(StorageReceivingClosedV1); }
        floor.availability_binding = Some(if floor.matches_taken_pair_v2(main, sidecar)
            && receiving.session_identity.as_ref().is_some_and(|identity| identity.same_journal(main))
        { Ok(()) } else { Err(StorageReceivingClosedV1) });
        if !matches!(floor.availability_binding, Some(Ok(()))) {
            floor.first = Some(First::AvailabilityBinding);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }
        floor.availability_growth = Some(complete_bound_delta_v1(floor.availability_bound, complete));
        let Some(Ok((bound, delta))) = floor.availability_growth.as_ref() else {
            floor.first = Some(First::AvailabilityGrowth);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        };
        let (bound, delta) = (*bound, *delta);
        floor.availability_debit = Some(receiving.ledger.reserve(delta).map_err(|cause| *cause));
        if !matches!(floor.availability_debit, Some(Ok(()))) {
            floor.first = Some(First::AvailabilityDebit);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }
        floor.availability_bound = bound;
        Ok(())
    }

    /// Prepays the actual main floor programme on this same retained F ledger.
    ///
    /// Main and sidecar originals can coexist, so their complete representation
    /// bounds are separate additive components of the one genuine ledger. This
    /// component also permits the initial main cut before sidecar acquisition.
    /// It creates no account, currentness, writer, sidecar or effect permission.
    ///
    /// # Errors
    /// Retains a foreign main, earlier refusal, checked growth overflow or the
    /// original F debit refusal before any corresponding representation grows.
    pub fn reserve_floor_main_v3(&mut self, main: &crate::Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        let floor = &mut receiving.floor_capture;
        if floor.first.is_some() { return Err(StorageReceivingClosedV1); }
        floor.main_binding = Some(if receiving.session_identity.as_ref()
            .is_some_and(|identity| identity.same_journal(main))
        { Ok(()) } else { Err(StorageReceivingClosedV1) });
        if !matches!(floor.main_binding, Some(Ok(()))) {
            floor.first = Some(First::MainBinding);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }

        floor.main_growth = Some(complete_bound_delta_v1(floor.main_bound, complete));
        let Some(Ok((bound, delta))) = floor.main_growth.as_ref() else {
            floor.first = Some(First::MainGrowth);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        };
        let (bound, delta) = (*bound, *delta);
        floor.main_debit = Some(receiving.ledger.reserve(delta).map_err(|cause| *cause));
        if !matches!(floor.main_debit, Some(Ok(()))) {
            floor.first = Some(First::MainDebit);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }
        floor.main_bound = bound;
        Ok(())
    }


    /// Prepays canonical Session replay beside the actual floor programmes.
    ///
    /// This separate resident peak grows on the same original F ledger. It
    /// cannot substitute another writer or dispose a failed replay prefix.
    ///
    /// # Errors
    /// Retains a foreign main, prior refusal, checked growth or original debit
    /// failure before the captured replay owner or its nested models grow.
    pub fn reserve_session_replay_v3(&mut self, main: &crate::Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        let floor = &mut receiving.floor_capture;
        if floor.first.is_some() { return Err(StorageReceivingClosedV1); }
        floor.session_replay_binding = Some(if receiving.session_identity.as_ref()
            .is_some_and(|identity| identity.same_journal(main))
        { Ok(()) } else { Err(StorageReceivingClosedV1) });
        if !matches!(floor.session_replay_binding, Some(Ok(()))) {
            floor.first = Some(First::SessionReplayBinding);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }

        floor.session_replay_growth = Some(complete_bound_delta_v1(floor.session_replay_bound, complete));
        let Some(Ok((bound, delta))) = floor.session_replay_growth.as_ref() else {
            floor.first = Some(First::SessionReplayGrowth);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        };
        let (bound, delta) = (*bound, *delta);
        floor.session_replay_debit = Some(receiving.ledger.reserve(delta).map_err(|cause| *cause));
        if !matches!(floor.session_replay_debit, Some(Ok(()))) {
            floor.first = Some(First::SessionReplayDebit);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }
        floor.session_replay_bound = bound;
        Ok(())
    }

    /// Prepays this same main's complete floor-capture representation.
    ///
    /// The closed consumer raises one complete high water before each reached
    /// growth. Equal amounts never refund traffic, forget a resident prefix or
    /// replace the first accounting refusal.
    ///
    /// # Errors
    /// Retains substituted main identities, arithmetic and original-F refusal.
    pub fn reserve_floor_capture_v2(&mut self, main: &crate::Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        let floor = &mut receiving.floor_capture;
        if floor.first.is_some() { return Err(StorageReceivingClosedV1); }
        floor.binding = Some(if receiving.session_identity.as_ref()
            .is_some_and(|identity| identity.same_journal(main))
        { Ok(()) } else { Err(StorageReceivingClosedV1) });
        if !matches!(floor.binding, Some(Ok(()))) {
            floor.first = Some(First::Binding);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }

        floor.growth = Some(complete_bound_delta_v1(floor.bound, complete));
        let Some(Ok((bound, delta))) = floor.growth.as_ref() else {
            floor.first = Some(First::Growth);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        };
        let (bound, delta) = (*bound, *delta);
        floor.debit = Some(receiving.ledger.reserve(delta).map_err(|cause| *cause));
        if !matches!(floor.debit, Some(Ok(()))) {
            floor.first = Some(First::Debit);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }
        floor.bound = bound;
        Ok(())
    }

    /// Prepays the retained comparison archive once on this actual F/main.
    ///
    /// Main, sidecar and fixed credential names are already in their own native
    /// namespace suppliers. This phase adds their independent native/byte
    /// reservoirs before constructing the archive and before its first read.
    ///
    /// # Errors
    /// Retains missing main association, repeat entry or original-F refusal.
    pub fn reserve_floor_revalidation_once_v2(&mut self, main: &crate::Journal, demand: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        if receiving.floor_capture.archive.is_some()
            || !receiving.session_identity.as_ref().is_some_and(|identity| identity.same_journal(main))
        {
            receiving.floor_capture.first.get_or_insert(First::Reentry);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }
        receiving.floor_capture.archive = Some(receiving.ledger.reserve(demand).map_err(|cause| *cause));
        if matches!(receiving.floor_capture.archive, Some(Ok(()))) { Ok(()) } else {
            receiving.floor_capture.first.get_or_insert(First::Debit);
            receiving.first.get_or_insert(Failure::FloorCapture);
            Err(StorageReceivingClosedV1)
        }
    }

    pub(crate) fn enter_floor_capture_once_v2(&mut self, main: &crate::Journal)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.require_floor_capture_current_v2(main)?;
        let receiving = self.receiving()?;
        if receiving.floor_capture.entered || receiving.floor_capture.sidecar.is_some() {
            receiving.floor_capture.first.get_or_insert(First::Reentry);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }
        receiving.floor_capture.entered = true;
        Ok(())
    }

    pub(crate) fn require_floor_capture_current_v2(&mut self, main: &crate::Journal)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        if receiving.floor_capture.first.is_some()
            || !matches!(receiving.floor_capture.debit, Some(Ok(())))
            || !receiving.session_identity.as_ref().is_some_and(|identity| identity.same_journal(main))
        { return Err(StorageReceivingClosedV1); }
        Ok(())
    }

    pub(crate) fn retain_taken_floor_capture_v2(&mut self, main: &crate::Journal, sidecar: &crate::Journal)
        -> Result<(), StorageReceivingClosedV1>
    {
        self.require_floor_capture_current_v2(main)?;
        let receiving = self.receiving()?;
        if !receiving.floor_capture.entered || receiving.floor_capture.sidecar.is_some()
            || main.held_session_owner_link_v1().same_journal(sidecar)
        {
            receiving.floor_capture.first.get_or_insert(First::Reentry);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }
        receiving.floor_capture.sidecar = Some(sidecar.held_session_owner_link_v1());
        Ok(())
    }
}


impl StoragePrepareReceivingLoanV1<'_> {
    /// Prepays a complete retained sidecar operation on the original F ledger.
    ///
    /// The native consumer separately proves positive disposal before reusing
    /// its resident peak. This financial port cannot observe journals, reset
    /// traffic, authorize mutation, or manufacture a current floor.
    ///
    /// # Errors
    /// Retains a foreign main/taken sidecar, prior refusal, arithmetic overflow
    /// or exhausted original F envelope before any new representation grows.
    pub fn reserve_floor_sidecar_v2(&mut self, main: &crate::Journal,
        sidecar: &crate::Journal, complete: ResourceVector)
        -> Result<(), StorageReceivingClosedV1>
    {
        let receiving = self.receiving()?;
        let floor = &mut receiving.floor_capture;
        if floor.first.is_some() { return Err(StorageReceivingClosedV1); }
        floor.sidecar_binding = Some(if floor.matches_taken_pair_v2(main, sidecar)
            && receiving.session_identity.as_ref().is_some_and(|identity| identity.same_journal(main))
        { Ok(()) } else { Err(StorageReceivingClosedV1) });
        if !matches!(floor.sidecar_binding, Some(Ok(()))) {
            floor.first = Some(First::SidecarBinding);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }

        floor.sidecar_growth = Some(complete_bound_delta_v1(floor.sidecar_bound, complete));
        let Some(Ok((bound, delta))) = floor.sidecar_growth.as_ref() else {
            floor.first = Some(First::SidecarGrowth);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        };
        let (bound, delta) = (*bound, *delta);
        floor.sidecar_debit = Some(receiving.ledger.reserve(delta).map_err(|cause| *cause));
        if !matches!(floor.sidecar_debit, Some(Ok(()))) {
            floor.first = Some(First::SidecarDebit);
            receiving.first.get_or_insert(Failure::FloorCapture);
            return Err(StorageReceivingClosedV1);
        }
        floor.sidecar_bound = bound;
        Ok(())
    }
}
