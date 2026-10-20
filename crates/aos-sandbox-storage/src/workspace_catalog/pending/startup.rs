//! Staged workspace custody through the existing pending decoder and plan check.
//!
//! Native preparation/replay is paid before entry. The same actual Journal,
//! structural result and authenticated plan stay resident on every negative;
//! only complete positive posts permit traversal-facade disposal and transfer.

use super::*;
use aos_sandbox::journal::{
    CapturedJournalOpenModeV1, ProtectedJournalPreopenReplayExtentV1,
    StorageWorkspaceCapturedJournalOpenV1,
};
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};

#[derive(Debug, thiserror::Error)]
enum DemandError {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Journal(#[from] aos_sandbox::JournalError),
}

#[derive(Clone, Copy)]
enum Failure {
    Native,
    Demand,
    Allocation,
    Decode,
    Plan,
    Names,
    Current,
    Closed,
}

pub(crate) struct StorageWorkspaceStartupV1 {
    native: Option<StorageWorkspaceCapturedJournalOpenV1>,
    opened: Option<(Journal, RecoveryReport)>,
    loaded: Option<Result<LoadedPendingWorkspaceV1, StorageWorkspaceCatalogError>>,
    pending: Option<PendingStorageWorkspaceCatalogV1>,
    validated: Option<ValidatedPendingStorageWorkspaceCatalogV1>,
    schema: Option<Result<ResourceVector, AccountingError>>,
    initialization_demand: Option<Result<ResourceVector, DemandError>>,
    plan_check: Option<Result<(), StorageWorkspaceCatalogError>>,
    names: Option<Result<(), aos_sandbox::JournalError>>,
    names_originals: aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1,
    current: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    batch: Option<crate::native_commit_batch::StorageNativeCommitBatchV1>,
    first: Option<Failure>,
    entered: bool,
    taken: bool,
}

impl StorageWorkspaceStartupV1 {
    pub(crate) fn new() -> Self {
        Self {
            native: Some(StorageWorkspaceCapturedJournalOpenV1::new()),
            opened: None,
            loaded: None,
            pending: None,
            validated: None,
            schema: None,
            initialization_demand: None,
            plan_check: None,
            names: None,
            names_originals: aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::new(),
            current: None,
            batch: Some(crate::native_commit_batch::StorageNativeCommitBatchV1::new()),
            first: None,
            entered: false,
            taken: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            Failure::Native => self.native.as_ref().and_then(StorageWorkspaceCapturedJournalOpenV1::failure),
            Failure::Demand => self.schema.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error)
                .or_else(|| self.initialization_demand.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &dyn std::error::Error)),
            Failure::Allocation => self.batch.as_ref().and_then(|batch| batch.failure()),
            Failure::Decode => self.loaded.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Plan => self.plan_check.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Names => self.names_originals.failure().or_else(|| self.names.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error)),
            Failure::Current => self.current.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Closed => None,
        };
        cause.or(Some(&aos_sandbox::StorageReceivingClosedV1))
    }

    pub(crate) fn open_once_v1(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
        mode: CapturedJournalOpenModeV1,
        identity_pool: StorageIdentityPoolV1,
        plan: &mut Option<StorageWorkspaceCatalogPlanV1>,
    ) -> Result<(), StorageWorkspaceCatalogError> {
        if self.entered || self.taken || self.first.is_some() {
            self.first.get_or_insert(Failure::Closed);
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        self.entered = true;
        let Some(plan_ref) = plan.as_ref() else {
            self.first = Some(Failure::Closed);
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        };
        if self.open_native_once(receiving, mode, plan_ref).is_err() {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        if let Some(slots) = plan_ref.rows.len().checked_add(1) {
            let Some(batch) = self.batch.as_mut() else {
                std::process::abort();
            };
            if batch.prepare_once_v1(slots).is_err() {
                self.first = Some(Failure::Allocation);
            }
        } else {
            self.first = Some(Failure::Closed);
        }
        if self.first.is_none() {
            let Some((journal, recovery)) = self.opened.as_ref() else {
                std::process::abort();
            };
            self.loaded = Some(LoadedPendingWorkspaceV1::load(journal, recovery, identity_pool));
            if matches!(self.loaded, Some(Err(_))) {
                self.first = Some(Failure::Decode);
            } else {
                let (Some(Ok(loaded)), Some((journal, recovery))) =
                    (self.loaded.take(), self.opened.take())
                else {
                    std::process::abort();
                };
                let mut pending = loaded.into_pending(journal, recovery, identity_pool);
                pending.startup_native_batch = self.batch.take();
                self.pending = Some(pending);
                let Some(pending) = self.pending.as_ref() else {
                    std::process::abort();
                };
                self.plan_check = Some(validate_plan_against_pending(pending, plan_ref));
                if matches!(self.plan_check, Some(Err(_))) {
                    self.first = Some(Failure::Plan);
                }
            }
        }
        let journal = self.pending.as_ref().map(|pending| &pending.journal)
            .or_else(|| self.opened.as_ref().map(|(journal, _)| journal));
        self.names = journal.map(|journal|
            journal.validate_held_protected_names_retaining(&mut self.names_originals));
        if !matches!(self.names, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Names);
        }
        self.current = Some(receiving.require_startup_current_v1());
        if !matches!(self.current, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Current);
        }
        if self.first.is_some() {
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        let (Some(pending), Some(plan)) = (self.pending.take(), plan.take()) else {
            std::process::abort();
        };
        self.validated = Some(ValidatedPendingStorageWorkspaceCatalogV1 {
            pending, plan,
            #[cfg(target_os = "linux")]
            git_coverage_census: None,
        });
        let Some(native) = self.native.take() else {
            std::process::abort();
        };
        if let Err(native) = receiving.settle_workspace_native_opening_once_v1(native) {
            self.native = Some(native);
            self.first = Some(Failure::Current);
            return Err(StorageWorkspaceCatalogError::InvalidCandidate);
        }
        self.names_originals.settle_positive_once_v1();
        Ok(())
    }

    fn open_native_once(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
        mode: CapturedJournalOpenModeV1,
        plan: &StorageWorkspaceCatalogPlanV1,
    ) -> Result<(), ()> {
        let Some(native) = self.native.as_mut() else {
            self.first = Some(Failure::Closed);
            return Err(());
        };
        let mut guard = receiving.borrow_workspace_startup_once_v1(native).map_err(|_| {
            self.first = Some(Failure::Native);
        })?;
        if guard.prepare_once_v1(workspace_journal_limits(), mode).is_err() {
            self.first = Some(Failure::Native);
            return Err(());
        }
        let Some(extent) = guard.captured_extent_v1() else {
            self.first = Some(Failure::Native);
            return Err(());
        };
        // Compute BOTH upper bounds before replay closes the captured getter.
        self.schema = Some(schema_demand(extent));
        self.initialization_demand = Some(initialization_demand(extent, plan));
        let (Some(Ok(schema)), Some(Ok(initialization))) =
            (self.schema.as_ref(), self.initialization_demand.as_ref())
        else {
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


    pub(crate) fn take_validated_once_v1(&mut self) -> Option<ValidatedPendingStorageWorkspaceCatalogV1> {
        if self.first.is_some() || !self.entered || self.taken || self.native.is_some() {
            return None;
        }
        self.taken = true;
        self.validated.take()
    }
}

fn schema_demand(extent: &ProtectedJournalPreopenReplayExtentV1) -> Result<ResourceVector, AccountingError> {
    crate::receiving_demand::startup_journal_model_demand_v1(
        extent,
        std::mem::size_of::<WorkspaceRecordV1>() + std::mem::size_of::<StorageWorkspaceCatalogRowPlanV1>(),
        std::mem::size_of::<StorageWorkspaceStartupV1>(),
        crate::receiving_demand::StorageStartupNamespaceRecipeV1::Workspace,
    )?.checked_add(aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(
        "storage-workspaces.journal",
    ).map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?)
}

fn initialization_demand(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    plan: &StorageWorkspaceCatalogPlanV1,
) -> Result<ResourceVector, DemandError> {
    use crate::receiving_demand::{add, count, multiply};
    use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
    // Every JSON field has a finite private primitive carrier.128 times the
    // actual inline head/row layouts covers their fixed names/scalar/byte-array
    // encoding; the only unbounded string is priced from its actual media type.
    let head = std::mem::size_of::<CatalogHeadV1>() * 128;
    let head_shape = || RecordShape { key_bytes: HEAD_KEY.len(), value_bytes: Some(head) };
    let mut append = encoded_transaction_append_bytes([head_shape()].into_iter())
        .map_err(aos_sandbox::JournalError::from)?;
    for row in &plan.rows {
        let media_bytes = match &row.policy {
            StorageWorkspaceCatalogRowPolicyV1::MustBeAbsent => 0,
            StorageWorkspaceCatalogRowPolicyV1::MayRetainExactActive(creation)
            | StorageWorkspaceCatalogRowPolicyV1::MustConvergeActive(creation)
            | StorageWorkspaceCatalogRowPolicyV1::MustConvergeRetired { creation, .. } =>
                creation.root_image.media_type().as_str().len(),
        };
        let bytes = add(multiply(count(std::mem::size_of::<WorkspaceRecordV1>())?, 128)?,
            multiply(count(media_bytes)?, 6)?)?;
        let value_bytes = usize::try_from(bytes).map_err(|_| AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        })?;
        let shapes = [head_shape(), RecordShape {
            key_bytes: RECORD_KEY_PREFIX.len() + 32, value_bytes: Some(value_bytes),
        }];
        append = append.checked_add(encoded_transaction_append_bytes(shapes.into_iter())
            .map_err(aos_sandbox::JournalError::from)?)
            .ok_or(aos_sandbox::JournalError::JournalTooLarge)?;
    }
    let future = extent.native_bytes.checked_add(append).ok_or(aos_sandbox::JournalError::JournalTooLarge)?;
    let forecast = aos_sandbox::journal::protected_journal_preopen_replay_extent_for_prefix_v1(extent.limits, future)?;
    let slots = add(count(plan.rows.len())?, 1)?;
    let batch_memory = multiply(slots,
        count(std::mem::size_of::<aos_sandbox::journal::StorageStateNativeCommitAttemptV1>())?)?;
    let models = ResourceVector::ZERO
        .with(D::MemoryBytes, add(batch_memory, add(multiply(append, 32)?,
            multiply(multiply(count(plan.rows.len())?, count(std::mem::size_of::<StorageWorkspaceCatalogRowPlanV1>())?)?, 32)?)?)?)
        .with(D::MetadataEntries, multiply(count(plan.rows.len())?, 32)?)
        .with(D::StorageBytes, future).with(D::LogBytes, append);
    Ok(forecast.dominant_native_receiving_demand_v1()?
        .checked_add(forecast.dominant_semantic_receiving_demand_v1()?)?
        .checked_add(models)?
        .checked_add(aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(
            "storage-workspaces.journal",
        )?)?
        .checked_add(aos_sandbox::journal::ProtectedJournalCurrentnessOriginalsV1::named_demand_v1(
            "storage-workspaces.journal",
        )?)?)
}
