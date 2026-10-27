//! Captures Storage's fixed existing floor through its original F receiver.
//!
//! The sole captured-writer engine retains acquisition, exact-prefix replay,
//! final names and failed originals. This finite adapter supplies no floor
//! classification, TPM result, new writer or effect grant.

use super::*;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::{FloorSidecarDecodeShapeV1, sidecar_limits_v1};
use crate::{StoragePrepareReceivingLoanV1, StorageReceivingClosedV1};

#[derive(Debug, thiserror::Error)]
enum DemandError {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("the captured floor prefix differs from its typed shape")]
    Prefix,
}

/// Retains the fixed Storage floor before separate typed and physical admission.
#[must_use = "retain the failed sidecar and independently owed native posts"]
pub struct StorageBrokerFloorCapturedJournalOpenV2 {
    inner: FixedProtectedCapturedJournalOpenV1,
    residue: initial_checkpoint_residue::InitialCheckpointResidueOriginalV1,
    payer: Option<StorageNativeOpeningOwnerLinkV1>,
    fixed: Option<Result<ResourceVector, AccountingError>>,
    preparation: Option<Result<(), StorageReceivingClosedV1>>,
    limits: Option<Result<JournalLimits, JournalError>>,
    shape: Option<FloorSidecarDecodeShapeV1>,
    prefix: Option<Result<ResourceVector, DemandError>>,
    replay: Option<Result<(), StorageReceivingClosedV1>>,
    take: Option<Result<(), StorageReceivingClosedV1>>,
    opened: Option<(Journal, RecoveryReport)>,
    closed: Option<JournalError>,
}

impl StorageBrokerFloorCapturedJournalOpenV2 {
    /// Creates inert storage without opening names or accepting caller paths.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: FixedProtectedCapturedJournalOpenV1::new(FixedProtectedJournalRecipeV1::BrokerFloor),
            residue: initial_checkpoint_residue::InitialCheckpointResidueOriginalV1::new(),
            payer: None, fixed: None, preparation: None, limits: None, shape: None,
            prefix: None, replay: None, take: None, opened: None, closed: None,
        }
    }

    /// Supplies this exact native facade and the closed upper shell's bytes.
    ///
    /// The fixed namespace has six directories including root, journal and lock.
    /// Failed traversals retain their full independently priced descriptors.
    /// Two additional file descriptions and bounded metadata originals cover
    /// the fixed initial-pending artifact check before native transfer.
    ///
    /// # Errors
    /// Refuses unrepresentable constructor/native receiving geometry.
    pub fn fixed_preparation_demand_v2(upper_memory: usize) -> Result<ResourceVector, AccountingError> {
        let native = FixedProtectedCapturedJournalOpenV1::fixed_preparation_demand(
            FixedProtectedJournalRecipeV1::BrokerFloor,
        )?.with(D::MetadataEntries, 8);
        let memory = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(upper_memory))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory))?
            .checked_add(initial_checkpoint_residue::InitialCheckpointResidueOriginalV1::native_demand()?)
    }

    /// Captures the existing sibling after actual main/F association.
    ///
    /// The upper owner prepays this same supplier before its allocation. This
    /// method independently joins that amount before entering the native call.
    pub fn prepare_once(&mut self, main: &Journal,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>, upper_memory: usize)
    {
        if self.fixed.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.fixed = Some(Self::fixed_preparation_demand_v2(upper_memory));
        let Some(Ok(fixed)) = self.fixed.as_ref() else { return; };
        self.preparation = Some(receiving.reserve_floor_capture_v2(main, *fixed)
            .and_then(|()| receiving.enter_floor_capture_once_v2(main)));
        if !matches!(self.preparation, Some(Ok(()))) { return; }
        self.payer = Some(main.held_session_owner_link_v1());
        self.limits = Some(sidecar_limits_v1(main.configured_limits()).map_err(JournalError::from));
        if let Some(Ok(limits)) = self.limits {
            self.inner.prepare_once(limits, CapturedJournalOpenModeV1::ExistingOnly);
        }
    }

    /// Borrows only the actual pre-replay native prefix as comparison DATA.
    #[must_use]
    pub fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        if self.failure().is_none() { self.inner.captured_extent() } else { None }
    }

    /// Prepays native, semantic and sole typed-reader reservoirs before replay.
    pub fn replay_once(&mut self, main: &Journal,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>, shape: FloorSidecarDecodeShapeV1)
    {
        if self.replay.is_some() || self.failure().is_some()
            || !self.payer.as_ref().is_some_and(|payer| payer.same_journal(main))
        {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.shape = Some(shape);
        self.prefix = Some((|| {
            let extent = self.inner.captured_extent().ok_or(DemandError::Prefix)?;
            let limits = self.limits.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(DemandError::Prefix)?;
            if shape.main_limits != main.configured_limits() || shape.sidecar_limits != limits
                || extent.limits != limits || shape.native_bytes != extent.native_bytes
            { return Err(DemandError::Prefix); }
            let bytes = shape.inline_bytes.checked_add(shape.heap_bytes)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            let files = u64::try_from(shape.open_files)
                .map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
            let entries = u64::try_from(shape.named_entries)
                .map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::MetadataEntries })?;
            let typed = ResourceVector::ZERO.with(D::MemoryBytes, bytes)
                .with(D::OpenFiles, files).with(D::MetadataEntries, entries);
            let fixed = self.fixed.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(DemandError::Prefix)?;
            Ok(fixed.checked_add(extent.dominant_native_receiving_demand_v1()?)?
                .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
                .checked_add(typed)?)
        })());
        let Some(Ok(complete)) = self.prefix.as_ref() else { return; };
        self.replay = Some(receiving.reserve_floor_capture_v2(main, *complete));
        if matches!(self.replay, Some(Ok(()))) { self.inner.replay_once(); }
    }

    /// Moves the same native tuple after replay and independent final posts.
    ///
    /// The prepaid pending-name check must observe stable absence or a safe
    /// empty displaced file. Unresolved initialization artifacts remain intact
    /// and prevent transfer into the normal typed floor owner.
    #[must_use]
    pub fn take_opened(&mut self, main: &Journal,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>) -> Option<(Journal, RecoveryReport)>
    {
        if self.take.is_some() || self.failure().is_some() || !self.inner.replay_ready()
            || !self.payer.as_ref().is_some_and(|payer| payer.same_journal(main))
        { return None; }
        self.take = Some(receiving.require_floor_capture_current_v2(main));
        if !matches!(self.take, Some(Ok(()))) { return None; }
        self.residue.capture_once(main);
        if self.residue.failure().is_some() { return None; }
        self.opened = self.inner.take_opened();
        let (sidecar, _) = self.opened.as_ref()?;
        self.take = Some(receiving.retain_taken_floor_capture_v2(main, sidecar));
        if matches!(self.take, Some(Ok(()))) { self.opened.take() } else { None }
    }

    /// Borrows original finance, geometry or native failure without reentry.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        error(&self.fixed).or_else(|| error(&self.preparation))
            .or_else(|| error(&self.limits)).or_else(|| error(&self.prefix))
            .or_else(|| error(&self.replay)).or_else(|| error(&self.take))
            .or_else(|| self.residue.failure()).or_else(|| self.inner.failure())
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl Default for StorageBrokerFloorCapturedJournalOpenV2 {
    fn default() -> Self { Self::new() }
}
