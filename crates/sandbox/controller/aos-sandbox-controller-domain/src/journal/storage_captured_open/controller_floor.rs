//! Captures the existing Controller Storage floor through the same writer engine.
//!
//! The real Storage B loan associates its actual main Journal before selecting
//! this fixed sibling. A separately paid prefix admits replay; a main Session
//! payment, copied extent or matching pathname cannot replace that association.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::floor_sidecar_geometry::{
    SIDECAR_NAME_V1, sidecar_limits_v1,
};

use super::*;
use crate::controller_resource_reservation::ControllerInitialBrokerSessionOwnerLinkV1;
use crate::{ControllerInitialBrokerSessionClosedV1, ControllerInitialBrokerSessionReceivingLoanV1,
    ControllerInitialBrokerSessionRoleV1};

/// Retains the fixed Storage sidecar before its own genuine B replay admission.
///
/// Construction is inert. The opened Journal is custody DATA and supplies no
/// decoded floor, physical TPM authority or Session readiness.
#[must_use = "retain the whole failed sidecar and all independent posts"]
pub struct ControllerStorageFloorCapturedJournalOpenV1 {
    inner: FixedProtectedCapturedJournalOpenV1,
    residue: initial_checkpoint_residue::InitialCheckpointResidueOriginalV1,
    attempted: bool,
    owner: Option<ControllerInitialBrokerSessionOwnerLinkV1>,
    main: Option<StorageNativeOpeningOwnerLinkV1>,
    entry: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    coordinates: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    limits: Option<Result<JournalLimits, JournalError>>,
    replay_binding: Option<Result<(), JournalError>>,
    replay_entry: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    take_binding: Option<Result<(), JournalError>>,
    take_entry: Option<Result<(), ControllerInitialBrokerSessionClosedV1>>,
    closed: Option<JournalError>,
}

impl ControllerStorageFloorCapturedJournalOpenV1 {
    /// Creates empty custody without choosing a caller path, UID or limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: FixedProtectedCapturedJournalOpenV1::with_recipe(
                ProtectedCapturedJournalRecipeV1::JoinedControllerStorageFloor(None),
            ),
            residue: initial_checkpoint_residue::InitialCheckpointResidueOriginalV1::new(),
            attempted: false, owner: None, main: None, entry: None, coordinates: None,
            limits: None, replay_binding: None, replay_entry: None,
            take_binding: None, take_entry: None, closed: None,
        }
    }

    /// Supplies the fixed sibling's native acquisition and control geometry.
    ///
    /// The main's held files remain separately funded. Seven rooted directory
    /// descriptors plus lock/main and two failed/owed name traversals use the
    /// existing engine's 27-FD peak; no future positive disposal is credited.
    /// The initial-pending artifact has two separately priced retained opens
    /// and bounded metadata originals before final native transfer.
    ///
    /// # Errors
    /// Refuses unrepresentable native or writable construction geometry.
    #[must_use]
    pub fn fixed_preparation_demand() -> Result<ResourceVector, aos_sandbox_model::AccountingError> {
        let directory = controller::directory(ControllerInitialBrokerSessionRoleV1::Storage);
        let native = ProtectedWriterOpenOriginalsV1::fixed_writable_preparation_demand_v1::<Self>(
            7, (directory.len() + SIDECAR_NAME_V1.len()) as u16,
        )?;
        // The same native namespace consists of root plus six directory
        // components and the sidecar's main/lock names. Independent traversals
        // retain their complete file/byte reservoirs, not duplicate namespaces.
        // The extra constructor copy is memory beside the shared native owner.
        let memory = u64::try_from(std::mem::size_of::<Self>()).ok()
            .and_then(|bytes| native.get(D::MemoryBytes).checked_add(bytes))
            .ok_or(aos_sandbox_model::AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        native.with(D::MemoryBytes, memory).with(D::MetadataEntries, 9)
            .checked_add(initial_checkpoint_residue::InitialCheckpointResidueOriginalV1::native_demand()?)
    }

    /// Enters the distinct sidecar gate before any rooted acquisition.
    ///
    /// Limits come from this SAME main's original configuration through the
    /// sole shared sidecar recipe. Existing-only opening never creates names,
    /// repairs a tail or inherits the main Session prefix's payment.
    pub fn prepare_once(&mut self, main: &Journal,
        receiving: &mut ControllerInitialBrokerSessionReceivingLoanV1<'_>)
    {
        if self.attempted {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.attempted = true;
        self.owner = Some(receiving.owner_link_v1());
        self.entry = Some(receiving.enter_storage_floor_preparation_once_v1(main));
        if !matches!(self.entry, Some(Ok(()))) { return; }
        self.main = Some(main.held_session_owner_link_v1());
        self.coordinates = Some(receiving.controller_uid_v1().map(|uid| {
            self.inner.recipe = ProtectedCapturedJournalRecipeV1::JoinedControllerStorageFloor(Some(uid));
        }));
        if !matches!(self.coordinates, Some(Ok(()))) { return; }
        self.limits = Some(sidecar_limits_v1(main.configured_limits()).map_err(JournalError::from));
        if let Some(Ok(limits)) = self.limits {
            self.inner.prepare_once(limits, CapturedJournalOpenModeV1::ExistingOnly);
        }
    }

    /// Borrows only the actually held sidecar's prefix before its replay.
    #[must_use]
    pub fn captured_extent(&self) -> Option<&ProtectedJournalPreopenReplayExtentV1> {
        if self.failure().is_some() { None } else { self.inner.captured_extent() }
    }

    fn require_original(&self, main: &Journal,
        receiving: &ControllerInitialBrokerSessionReceivingLoanV1<'_>) -> Result<(), JournalError>
    {
        if !self.owner.as_ref().is_some_and(|owner| owner.same_owner_v1(&receiving.owner_link_v1()))
            || !self.main.as_ref().is_some_and(|original| original.same_journal(main)) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Replays only after the same original has paid this exact sibling extent.
    pub fn replay_once(&mut self, main: &Journal,
        receiving: &mut ControllerInitialBrokerSessionReceivingLoanV1<'_>)
    {
        if self.replay_binding.is_some() || self.failure().is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return;
        }
        self.replay_binding = Some(self.require_original(main, receiving));
        if !matches!(self.replay_binding, Some(Ok(()))) { return; }
        self.replay_entry = Some(receiving.enter_storage_floor_replay_once_v1(main));
        if matches!(self.replay_entry, Some(Ok(()))) { self.inner.replay_once(); }
    }

    /// Reports mechanical replay completion without a typed floor grant.
    #[must_use]
    pub fn replay_ready(&self) -> bool {
        self.failure().is_none() && self.inner.replay_ready()
    }

    /// Moves the same sibling after genuine B association and final native posts.
    ///
    /// Stable absence or a safe empty initial-pending file is required before
    /// transfer. Nonempty, unsafe or changing artifacts remain untouched and
    /// cannot be adopted as completed provisioning by normal startup.
    #[must_use]
    pub fn take_opened(&mut self, main: &Journal,
        receiving: &mut ControllerInitialBrokerSessionReceivingLoanV1<'_>) -> Option<(Journal, RecoveryReport)>
    {
        if self.take_entry.is_some() || !self.replay_ready() { return None; }
        self.take_binding = Some(self.require_original(main, receiving));
        if !matches!(self.take_binding, Some(Ok(()))) { return None; }
        let opening = self.inner.owner_link.as_ref()?;
        self.take_entry = Some(receiving.enter_storage_floor_take_once_v1(main, opening));
        if !matches!(self.take_entry, Some(Ok(()))) { return None; }
        self.residue.capture_once(main);
        if self.residue.failure().is_some() { return None; }
        self.inner.take_opened()
    }

    /// Reports positive movement of this exact native tuple only.
    #[must_use]
    pub fn was_taken_positive_v1(&self) -> bool {
        self.failure().is_none() && self.inner.was_taken_positive()
    }

    /// Borrows the earliest reached receiving, geometry or native cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
            slot.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
        }
        cause(&self.entry).or_else(|| cause(&self.coordinates)).or_else(|| cause(&self.limits))
            .or_else(|| self.inner.failure()).or_else(|| cause(&self.replay_binding))
            .or_else(|| cause(&self.replay_entry)).or_else(|| cause(&self.take_binding))
            .or_else(|| cause(&self.take_entry)).or_else(|| self.residue.failure())
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn receiving_owner_link_v1(&self) -> Option<&ControllerInitialBrokerSessionOwnerLinkV1> {
        self.owner.as_ref()
    }

    pub(crate) fn main_owner_link_v1(&self) -> Option<&StorageNativeOpeningOwnerLinkV1> {
        self.main.as_ref()
    }

    pub(crate) fn opening_owner_link_v1(&self) -> Option<&StorageNativeOpeningOwnerLinkV1> {
        self.inner.owner_link.as_ref()
    }
}

impl Default for ControllerStorageFloorCapturedJournalOpenV1 {
    fn default() -> Self { Self::new() }
}
