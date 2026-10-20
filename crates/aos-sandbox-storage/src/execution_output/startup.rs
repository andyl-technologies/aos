//! Paid existing-only Output ledger startup through the original shared parser.
//!
//! The enclosing credential owner has already joined and paid the actual source
//! path and both key copies. This owner retains the same Native facade, writer,
//! key and parser Results; failure never reopens or provisions an Output ledger.

use super::*;
use aos_sandbox::journal::{
    CapturedJournalOpenModeV1, ProtectedJournalPreopenReplayExtentV1,
    StorageOutputCapturedJournalOpenV1,
};
use aos_sandbox_core::{AccountingError, ResourceVector};

#[derive(Clone, Copy)]
enum Failure {
    Native,
    Demand,
    Configuration,
    Rows,
    Names,
    Current,
    Closed,
}

pub(crate) struct ExecutionOutputLedgerStartupV1 {
    native: Option<StorageOutputCapturedJournalOpenV1>,
    opened: Option<(Journal, aos_sandbox::RecoveryReport)>,
    key: Option<ExecutionOutputLedgerKeyV1>,
    schema: Option<Result<ResourceVector, AccountingError>>,
    configuration: Option<Result<(), ExecutionOutputLedgerErrorV1>>,
    rows: Option<Result<u64, ExecutionOutputLedgerErrorV1>>,
    names: Option<Result<(), aos_sandbox::JournalError>>,
    names_originals: aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1,
    final_names: Option<Result<(), aos_sandbox::JournalError>>,
    final_names_originals: aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1,
    current: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    owner: Option<ExecutionOutputLedgerV1>,
    recovery: Option<aos_sandbox::RecoveryReport>,
    first: Option<Failure>,
    entered: bool,
    taken: bool,
}

impl ExecutionOutputLedgerStartupV1 {
    pub(crate) fn new() -> Self {
        Self {
            native: Some(StorageOutputCapturedJournalOpenV1::new()),
            opened: None,
            key: None,
            schema: None,
            configuration: None,
            rows: None,
            names: None,
            names_originals: aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::new(),
            final_names: None,
            final_names_originals: aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::new(),
            current: None,
            owner: None,
            recovery: None,
            first: None,
            entered: false,
            taken: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            Failure::Native => self.native.as_ref().and_then(StorageOutputCapturedJournalOpenV1::failure),
            Failure::Demand => self.schema.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Configuration => self.configuration.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Rows => self.rows.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Names => self.names_originals.failure()
                .or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error))
                .or_else(|| self.final_names_originals.failure())
                .or_else(|| self.final_names.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)),
            Failure::Current => self.current.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Closed => None,
        };
        cause.or(Some(&aos_sandbox::StorageReceivingClosedV1))
    }

    pub(crate) fn open_once_v1(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
        capacity_bytes: u64,
        key: &mut Option<ExecutionOutputLedgerKeyV1>,
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        if self.entered || self.taken || self.first.is_some() {
            self.first.get_or_insert(Failure::Closed);
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        self.entered = true;
        self.key = key.take();
        if self.key.is_none() {
            self.first = Some(Failure::Closed);
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        self.open_native_once(receiving).map_err(|_| ExecutionOutputLedgerErrorV1::Corrupt)?;
        let (Some((journal, _)), Some(key)) = (self.opened.as_mut(), self.key.as_ref()) else {
            std::process::abort();
        };
        self.configuration = Some(initialize_configuration_v1(journal, capacity_bytes, key, false));
        if matches!(self.configuration, Some(Err(_))) {
            self.first = Some(Failure::Configuration);
        } else {
            self.rows = Some(load_retained_output_bytes_v1(journal, capacity_bytes, key));
            if matches!(self.rows, Some(Err(_))) {
                self.first = Some(Failure::Rows);
            }
        }
        // The same real writer/key stay resident through both independent
        // posts, including a malformed configuration, sum or linked row.
        self.names = Some(journal.validate_held_protected_names_retaining(&mut self.names_originals));
        if !matches!(self.names, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Names);
        }
        self.current = Some(receiving.require_startup_current_v1());
        if !matches!(self.current, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Current);
        }
        if self.first.is_some() {
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        let (Some((journal, recovery)), Some(key), Some(Ok(retained_bytes))) =
            (self.opened.take(), self.key.take(), self.rows.as_ref())
        else {
            std::process::abort();
        };
        self.owner = Some(ExecutionOutputLedgerV1 {
            journal,
            key,
            capacity_bytes,
            retained_bytes: *retained_bytes,
        });
        self.recovery = Some(recovery);
        Ok(())
    }

    fn open_native_once(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), ()> {
        let Some(native) = self.native.as_mut() else {
            self.first = Some(Failure::Closed);
            return Err(());
        };
        let mut guard = receiving.borrow_output_startup_once_v1(native).map_err(|_| {
            self.first = Some(Failure::Native);
        })?;
        if guard.prepare_once_v1(JournalLimits::default(), CapturedJournalOpenModeV1::ExistingOnly).is_err() {
            self.first = Some(Failure::Native);
            return Err(());
        }
        let Some(extent) = guard.captured_extent_v1() else {
            self.first = Some(Failure::Native);
            return Err(());
        };
        self.schema = Some(schema_demand(extent));
        let Some(Ok(schema)) = self.schema.as_ref() else {
            self.first = Some(Failure::Demand);
            return Err(());
        };
        // Existing-only opens cannot initialize or repair. All decoder models
        // are covered by schema; the separate no-append init stage is explicit.
        if guard.reserve_schema_once_v1(*schema).is_err()
            || guard.replay_once_v1().is_err()
            || guard.reserve_initialization_once_v1(ResourceVector::ZERO).is_err()
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

    pub(crate) fn observe_final_names_once_v1(&mut self) -> Result<(), ExecutionOutputLedgerErrorV1> {
        if self.final_names.is_some() {
            self.first.get_or_insert(Failure::Closed);
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        let journal = if let Some(owner) = self.owner.as_ref() {
            &owner.journal
        } else if let Some((journal, _)) = self.opened.as_ref() {
            journal
        } else {
            self.first.get_or_insert(Failure::Closed);
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        };
        self.final_names = Some(journal.validate_held_protected_names_retaining(
            &mut self.final_names_originals,
        ));
        if !matches!(self.final_names, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Names);
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        Ok(())
    }

    pub(crate) fn owner(&self) -> Option<&ExecutionOutputLedgerV1> {
        self.owner.as_ref()
    }

    pub(crate) fn settle_native_once_v1(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), ExecutionOutputLedgerErrorV1> {
        if self.first.is_some() || self.owner.is_none() || self.taken
            || !matches!(self.final_names, Some(Ok(())))
        {
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        let Some(native) = self.native.take() else {
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        };
        if let Err(native) = receiving.settle_output_native_opening_once_v1(native) {
            self.native = Some(native);
            self.first = Some(Failure::Current);
            return Err(ExecutionOutputLedgerErrorV1::Corrupt);
        }
        self.names_originals.settle_positive_once_v1();
        self.final_names_originals.settle_positive_once_v1();
        Ok(())
    }

    pub(crate) fn take_owner_once_v1(&mut self) -> Option<ExecutionOutputLedgerV1> {
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
        std::mem::size_of::<RetainedOutputRecord>()
            + std::mem::size_of::<PhysicalBindingRecord>()
            + std::mem::size_of::<PhysicalDeletionRecord>(),
        std::mem::size_of::<ExecutionOutputLedgerStartupV1>(),
        crate::receiving_demand::StorageStartupNamespaceRecipeV1::ExecutionOutput,
    )
}
