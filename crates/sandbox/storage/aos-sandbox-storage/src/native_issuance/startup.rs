//! Staged consumer-interest startup under the original Storage receiving owner.
//!
//! Both selected ordinary and held recipes retain their actual writer before
//! validation. The ordinary adapter keeps its existing decode/capacity engine;
//! held rows keep their sole physical-history reducer and independent role pins.

use super::*;
use aos_sandbox_controller_domain::journal::{
    CapturedJournalOpenModeV1, ProtectedJournalPreopenReplayExtentV1,
    StorageNativeIssuanceCapturedJournalOpenV1,
};
use aos_sandbox_model::{AccountingError, ResourceVector};

#[derive(Clone, Copy)]
enum Failure {
    Native,
    Demand,
    Validation,
    Names,
    Current,
    Closed,
}

pub(crate) struct StorageNativeIssuanceStartupV1 {
    native: Option<StorageNativeIssuanceCapturedJournalOpenV1>,
    opened: Option<(Journal, aos_sandbox_controller_domain::RecoveryReport)>,
    owner: Option<StorageNativeIssuanceLedgerV1>,
    recovery: Option<aos_sandbox_controller_domain::RecoveryReport>,
    schema: Option<Result<ResourceVector, AccountingError>>,
    initialization: Option<Result<ResourceVector, AccountingError>>,
    validation: Option<Result<(), StorageNativeIssuanceErrorV1>>,
    names: Option<Result<(), JournalError>>,
    current: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    first: Option<Failure>,
    entered: bool,
    taken: bool,
}

impl StorageNativeIssuanceStartupV1 {
    pub(crate) fn new() -> Self {
        Self {
            native: Some(StorageNativeIssuanceCapturedJournalOpenV1::new()),
            opened: None,
            owner: None,
            recovery: None,
            schema: None,
            initialization: None,
            validation: None,
            names: None,
            current: None,
            first: None,
            entered: false,
            taken: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            Failure::Native => self.native.as_ref().and_then(StorageNativeIssuanceCapturedJournalOpenV1::failure),
            Failure::Demand => self.schema.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error)
                .or_else(|| self.initialization.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)),
            Failure::Validation => self.validation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Names => self.names.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Current => self.current.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Closed => None,
        };
        cause.or(Some(&aos_sandbox_controller_domain::StorageReceivingClosedV1))
    }

    pub(crate) fn open_once_v1(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        mode: CapturedJournalOpenModeV1,
        state_directory: &Path,
        profile: &crate::runtime::OriginalStartupProfileV1<'_>,
        coordinator: &StorageAdmissionCoordinator,
    ) -> Result<(), StorageNativeIssuanceErrorV1> {
        if self.entered || self.taken || self.first.is_some() {
            self.first.get_or_insert(Failure::Closed);
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        self.entered = true;
        let held = matches!(profile, crate::runtime::OriginalStartupProfileV1::Held(_));
        let (limits, mode) = if held {
            (held_custody::staged_held_limits_v1(), CapturedJournalOpenModeV1::ExistingOnly)
        } else {
            (journal_limits(), mode)
        };
        self.open_native_once(receiving, mode, limits)
            .map_err(|_| StorageNativeIssuanceErrorV1::Conflict)?;
        let Some((journal, recovery)) = self.opened.take() else {
            std::process::abort();
        };
        self.recovery = Some(recovery);
        // The normal owner is resident before its first boundary/reducer check.
        self.owner = Some(StorageNativeIssuanceLedgerV1 {
            journal,
            state_directory: state_directory.to_path_buf(),
            custody: if held {
                NativeIssuanceCustodyV1::RootOwnedHeld
            } else {
                NativeIssuanceCustodyV1::RootOwned
            },
        });
        let Some(owner) = self.owner.as_mut() else {
            std::process::abort();
        };
        self.validation = Some((|| {
            if held {
                owner.validate_boundary()?;
                owner.held_offer_funding()?;
            } else {
                owner.validate_opened_ordinary_v1()?;
            }
            // Independent Trust/key verification remains mandatory on the held
            // Runtime branch after its separately paid fourth writer opens.
            owner.validate_active_holds(coordinator)
        })());
        if matches!(self.validation, Some(Err(_))) {
            self.first = Some(Failure::Validation);
        }
        self.names = Some(owner.journal.validate_held_protected_names());
        if !matches!(self.names, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Names);
        }
        self.current = Some(receiving.require_startup_current_v1());
        if !matches!(self.current, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Current);
        }
        if self.first.is_some() {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        let Some(native) = self.native.take() else {
            std::process::abort();
        };
        if let Err(native) = receiving.settle_issuance_native_opening_once_v1(native) {
            self.native = Some(native);
            self.first = Some(Failure::Current);
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        Ok(())
    }

    fn open_native_once(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        mode: CapturedJournalOpenModeV1,
        limits: JournalLimits,
    ) -> Result<(), ()> {
        let Some(native) = self.native.as_mut() else {
            self.first = Some(Failure::Closed);
            return Err(());
        };
        let mut guard = receiving.borrow_issuance_startup_once_v1(native).map_err(|_| {
            self.first = Some(Failure::Native);
        })?;
        if guard.prepare_once_v1(limits, mode).is_err() {
            self.first = Some(Failure::Native);
            return Err(());
        }
        let Some(extent) = guard.captured_extent_v1() else {
            self.first = Some(Failure::Native);
            return Err(());
        };
        self.schema = Some(schema_demand(extent));
        // No initialization append occurs here. Existing future-retirement
        // preflight builds only bounded typed row successors and parser maps;
        // price those dominant representations from the actual retained rows.
        self.initialization = Some(schema_demand(extent));
        let (Some(Ok(schema)), Some(Ok(initialization))) = (self.schema.as_ref(), self.initialization.as_ref()) else {
            self.first = Some(Failure::Demand);
            return Err(());
        };
        if guard.reserve_schema_once_v1(*schema).is_err()
            || guard.replay_once_v1().is_err()
            || guard.reserve_initialization_once_v1(*initialization).is_err()
        {
            self.first = Some(Failure::Native);
            return Err(());
        }
        self.opened = match guard.take_opened_once_v1() {
            Ok(opened) => Some(opened),
            Err(_) => {
                self.first = Some(Failure::Native);
                return Err(());
            }
        };
        Ok(())
    }

    pub(crate) fn take_owner_once_v1(&mut self) -> Option<StorageNativeIssuanceLedgerV1> {
        if self.first.is_some() || !self.entered || self.taken || self.native.is_some() {
            return None;
        }
        self.taken = true;
        self.owner.take()
    }
}

fn schema_demand(extent: &ProtectedJournalPreopenReplayExtentV1) -> Result<ResourceVector, AccountingError> {
    crate::receiving_demand::startup_journal_model_demand_v1(
        extent,
        std::mem::size_of::<NativeIssuanceRowV1>() + std::mem::size_of::<NativeIssuanceIdentityIndexV1>(),
        std::mem::size_of::<StorageNativeIssuanceStartupV1>(),
        crate::receiving_demand::StorageStartupNamespaceRecipeV1::NativeIssuance,
    )
}
