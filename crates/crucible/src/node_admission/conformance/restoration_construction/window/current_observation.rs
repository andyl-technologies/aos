//! Admits a fresh scheduling inspection beside immutable first-Observe ancestry.
//!
//! The concrete ConformanceRuntime quotes the real selected node and completes
//! its original whole-owner census before lending the runtime mutably. This
//! separate claim authorizes only its next ordinary Observe, never Begin/Input.

use super::continuation_suffix::SeedStage;
use super::*;
use crate::node_adapters::cnp::{
    CnpSemanticSource, OriginalSourceRestorationObservationConstructionData,
};
use crate::node_contract::{NodeRoute, RuntimeError, WorldActivation};
use crucible_node_provider::{
    client::CnpController,
    reference_packet::service::{
        PacketNative5SourceLaunch,
        native_startup::{
            PacketNativeRestoredSuffixObservationStorageData,
            PacketNativeRestoredSuffixStartupStorageData,
        },
    },
};
use std::cell::{Ref, RefMut};

/// Contains independently quoted current-inspection storage without action rights.
///
/// Only the actual selected Source constructor creates this fixed DATA. Its
/// original model geometry, Controller, Source and ordinal must match again at
/// consumption. The installed policy and opaque claim remain independent.
#[derive(Clone, Copy)]
pub struct OriginalRestoredSchedulingObservationConstructionData {
    pub(crate) process: u32,
    pub(crate) thread: ThreadId,
    pub(crate) source: *const PacketCompleteSemanticSource,
    pub(crate) controller: *const CnpController,
    pub(crate) read_owner: *const (),
    pub(crate) ordinal: u64,
    pub(crate) startup: PacketNativeRestoredSuffixStartupStorageData,
    pub(crate) provider: PacketNativeRestoredSuffixObservationStorageData,
    pub(crate) first: OriginalSourceRestorationObservationConstructionData,
    pub(crate) retained: usize,
    pub(crate) transient: usize,
    pub(crate) scratch: usize,
    pub(crate) requested: usize,
    pub(crate) runtime_retained: usize,
    pub(crate) runtime_transient: usize,
    pub(crate) runtime_scratch: usize,
    pub(crate) maximum: usize,
}

impl OriginalRestoredSchedulingObservationConstructionData {
    pub(crate) fn authenticate_owner_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
            || !std::ptr::eq(self.controller, controller)
            || self.ordinal == 0
            || self.requested
                != checked_sum(&[self.retained, self.transient, self.scratch], self.maximum)?
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Returns this independently added complete simultaneous requested extent.
    pub fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Names the fixed row, claim, ledger and actual result/borrow layouts.
    pub fn counter_scratch_data() -> usize {
        Self::fixed_counter_scratch_data()
            + NodeRuntime::original_current_scheduling_dispatch_counter_scratch_data()
            + crate::node_adapters::cnp::CnpSemanticNode::original_current_observation_node_counter_scratch_data()
    }

    pub(crate) fn fixed_counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<CurrentObservationLedger>()
            + size_of::<[RefCell<CurrentObservationLedger>; 3]>()
            + size_of::<OriginalRestoredInitialSchedulingAdmission>()
            + size_of::<Result<OriginalRestoredInitialSchedulingAdmission, RuntimeError>>()
            + size_of::<[Cell<Option<(usize, usize, usize)>>; 3]>()
            + size_of::<Option<(usize, usize, usize)>>()
            + size_of::<[usize; 4]>()
            + size_of::<OriginalRestoredSchedulingObservationAdmission>()
            + size_of::<Result<OriginalRestoredSchedulingObservationAdmission, RuntimeError>>()
            + size_of::<&mut OriginalRestoredSchedulingObservationAdmission>()
            + size_of::<OriginalRestoredSchedulingObservationClaim<'static>>()
            + size_of::<&OriginalRestoredSchedulingObservationClaim<'static>>()
            + size_of::<Ref<'static, CurrentObservationLedger>>()
            + size_of::<RefMut<'static, CurrentObservationLedger>>()
            + size_of::<Result<Ref<'static, CurrentObservationLedger>, std::cell::BorrowError>>()
            + size_of::<Result<RefMut<'static, CurrentObservationLedger>, std::cell::BorrowMutError>>(
            )
            + size_of::<Result<Ref<'static, CurrentObservationLedger>, RuntimeError>>()
            + size_of::<Result<RefMut<'static, CurrentObservationLedger>, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<u64, RuntimeError>>()
            + size_of::<Option<u64>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<[usize; 3]>()
            + size_of::<&Self>() * 2
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&CnpController>()
            + size_of::<&NodeRuntime>()
            + size_of::<&NodeRoute>()
            + size_of::<&WorldActivation>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<&[u8]>()
            + size_of::<&CompleteOriginalRestorationWindow>()
            + size_of::<CurrentObservationStage>() * 2
            + size_of::<u64>() * 2
            + size_of::<usize>() * 2
            + size_of::<Cell<bool>>() * 2
            + size_of::<bool>() * 2
            + size_of::<(usize, usize)>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<(&PacketNative5SourceLaunch, &[u8])>()
            + size_of::<Result<OriginalRestoredSchedulingObservationClaim<'static>, RuntimeError>>()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CurrentObservationStage {
    Empty,
    Quoted,
    Started,
    Verified,
    Failed,
}

pub(super) struct CurrentObservationLedger {
    row: Option<OriginalRestoredSchedulingObservationConstructionData>,
    completed: u64,
    exported_results: usize,
    stage: CurrentObservationStage,
}

impl CurrentObservationLedger {
    pub(super) fn authenticate_no_pending_data(&self) -> Result<(), RuntimeError> {
        if !matches!(
            self.stage,
            CurrentObservationStage::Empty | CurrentObservationStage::Verified
        ) {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(super) fn new() -> Self {
        Self {
            row: None,
            completed: 0,
            exported_results: 0,
            stage: CurrentObservationStage::Empty,
        }
    }

    pub(super) fn future_requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        // Returned validated observations can outlive their call. Their known
        // maximum backing remains a future commitment; no caller drop refunds
        // it and no scalar is represented as an observed actual owner.
        self.exported_results
            .checked_add(self.row.as_ref().map_or(0, |row| row.requested))
            .ok_or(RuntimeError::ResourceLimit)
    }
}

/// Retains the full-census admission for one original first-observation callback.
///
/// This private-construction owner spends before callback entry. The immutable
/// first Source and Node rows remain independent of its additional Runtime work.
pub struct OriginalRestoredInitialSchedulingAdmission {
    window: Rc<CompleteOriginalRestorationWindow>,
    runtime: *const NodeRuntime,
    selected: usize,
    attempted: bool,
}

impl OriginalRestoredInitialSchedulingAdmission {
    pub(crate) fn retain_work_data(
        window: &Rc<CompleteOriginalRestorationWindow>,
        runtime: &NodeRuntime,
        selected: usize,
        work: (usize, usize, usize),
    ) -> Result<(), RuntimeError> {
        window.origin()?;
        let slot = window
            .initial_scheduling_work
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if slot.get().is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        if checked_sum(
            &[work.0, work.1, work.2],
            window.policy.maximum_requested_bytes,
        )? > window.policy.maximum_requested_bytes
            || work.2 > window.policy.declared_observer_scratch_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        window.runtime.authenticate_runtime_data(
            runtime,
            &window
                .activation_world
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .record()
                .world_binding_hash,
        )?;
        slot.set(Some(work));
        window.whole_observation.require_observation();
        Ok(())
    }

    pub(crate) fn after_census_data(
        window: &Rc<CompleteOriginalRestorationWindow>,
        runtime: &NodeRuntime,
        selected: usize,
    ) -> Result<Self, RuntimeError> {
        window.whole_observation.authenticate_dispatch_data()?;
        if window
            .initial_scheduling_work
            .get(selected)
            .and_then(Cell::get)
            .is_none()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(Self {
            window: Rc::clone(window),
            runtime,
            selected,
            attempted: false,
        })
    }

    pub(crate) fn begin_data(
        &mut self,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        node: &crucible_node_contract::Id,
    ) -> Result<(), RuntimeError> {
        if std::mem::replace(&mut self.attempted, true)
            || !std::ptr::eq(self.runtime, runtime)
            || self.window.current_observation_source_index_data(node)? != self.selected
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.window
            .authenticate_initial_scheduling_identity_data(runtime, world, node)
    }
}

/// Retains one immutable whole-census admission until its selected dispatch.
///
/// The actual Runtime creates this owner only after retaining the independently
/// quoted row and completing the installed group's full census. It has no
/// decoder, Clone, public constructor or authority-bearing scalar accessors.
/// The caller ends its immutable capsule loan before taking a mutable one.
pub struct OriginalRestoredSchedulingObservationAdmission {
    window: Rc<CompleteOriginalRestorationWindow>,
    runtime: *const NodeRuntime,
    selected: usize,
    ordinal: u64,
    attempted: bool,
}

impl OriginalRestoredSchedulingObservationAdmission {
    pub(crate) fn after_original_census_data(
        window: &Rc<CompleteOriginalRestorationWindow>,
        runtime: &NodeRuntime,
        selected: usize,
        ordinal: u64,
    ) -> Result<Self, RuntimeError> {
        window.whole_observation.authenticate_dispatch_data()?;
        let ledger = window
            .current_observations
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if ledger.stage != CurrentObservationStage::Quoted
            || ledger.row.as_ref().is_none_or(|row| row.ordinal != ordinal)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(Self {
            window: Rc::clone(window),
            runtime,
            selected,
            ordinal,
            attempted: false,
        })
    }

    pub(crate) fn begin_original_data<'a>(
        &'a mut self,
        runtime: &NodeRuntime,
        world: &'a WorldActivation,
        launch: &'a PacketNative5SourceLaunch,
        canonical_launch5: &'a [u8],
        node: &crucible_node_contract::Id,
    ) -> Result<OriginalRestoredSchedulingObservationClaim<'a>, RuntimeError> {
        if std::mem::replace(&mut self.attempted, true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        if !std::ptr::eq(runtime, self.runtime)
            || self.window.current_observation_source_index_data(node)? != self.selected
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let ledger = self.window.current_observations[self.selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if ledger
            .row
            .as_ref()
            .is_none_or(|row| row.ordinal != self.ordinal)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        drop(ledger);
        self.window
            .begin_current_observation_data(runtime, world, node, launch, canonical_launch5)
    }
}

impl Drop for OriginalRestoredSchedulingObservationAdmission {
    fn drop(&mut self) {
        if let Ok(mut ledger) = self.window.current_observations[self.selected].try_borrow_mut()
            && ledger
                .row
                .as_ref()
                .is_some_and(|row| row.ordinal == self.ordinal)
            && ledger.stage != CurrentObservationStage::Verified
        {
            ledger.stage = CurrentObservationStage::Failed;
            self.window.whole_observation.require_observation();
        }
    }
}

/// Borrows a genuine admitted scheduling inspection under the same installed World.
///
/// No constructor, Clone, decoder, execution token or renewal operation is
/// exposed. Its producer finishes the full original census before native work.
/// Drop keeps a failed or incomplete attempt spent and requests a fresh census.
pub struct OriginalRestoredSchedulingObservationClaim<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    selected: usize,
    runtime: *const NodeRuntime,
    world: &'a WorldActivation,
    launch: &'a PacketNative5SourceLaunch,
    canonical_launch5: &'a [u8],
    row: OriginalRestoredSchedulingObservationConstructionData,
    completed: Cell<bool>,
    source_completed: Cell<bool>,
}

impl OriginalRestoredSchedulingObservationClaim<'_> {
    pub(crate) const RECEIPT_FAILURE: &'static str =
        "restored current Observe scheduling receipt failed after publication";

    pub(crate) const COMPLETION_FAILURE: &'static str =
        "restored current observation runtime completion failed after publication";

    pub(crate) fn world_data(&self) -> &WorldActivation {
        self.world
    }

    pub(crate) fn row_data(&self) -> &OriginalRestoredSchedulingObservationConstructionData {
        &self.row
    }

    pub(crate) fn launch_data(&self) -> (&PacketNative5SourceLaunch, &[u8]) {
        (self.launch, self.canonical_launch5)
    }

    pub(crate) fn authenticate_runtime_data(
        &self,
        runtime: &NodeRuntime,
        route: &NodeRoute,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.runtime, runtime) || route.owners.len() != 1 {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .window
            .sources
            .get(self.selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if route.node != source.installation().binding.compatibility.node_id
            || route.owners[0].owner != source.installation().owner.owner.id
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.window
            .runtime
            .authenticate_runtime_data(runtime, &self.world.record().world_binding_hash)?;
        self.authenticate_current_data(source, self.row.controller)
    }

    pub(crate) fn authenticate_current_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: *const CnpController,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.row.source, source)
            || self.row.controller != controller
            || self.completed.get()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let proof = self.window.original_complete_scope_proof_identity_data()?;
        self.window.authenticate_suffix_identity_data(
            self.selected,
            source,
            self.row.read_owner,
            self.world,
            proof,
        )?;
        let ledger = self.window.current_observations[self.selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if ledger.stage != CurrentObservationStage::Started
            || ledger
                .row
                .as_ref()
                .is_none_or(|row| row.ordinal != self.row.ordinal)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(crate) fn with_original_inputs_data(
        &self,
        source: &PacketCompleteSemanticSource,
        inspect: impl FnOnce(
            &OriginalInstalledRestorationObservationSigningInputs<'_>,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current_data(source, self.row.controller)?;
        self.window.with_original_observation_signing_inputs_data(
            self.selected,
            source,
            self.window.original_complete_scope_proof_identity_data()?,
            inspect,
        )
    }

    pub(crate) fn authenticate_terminal_member_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
    ) -> Result<(), RuntimeError> {
        self.authenticate_current_data(source, controller)?;
        let plan = self
            .window
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let scope = self
            .window
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.window
            .authenticate_original_complete_member_data(&plan, scope)?;
        self.authenticate_current_data(source, controller)
    }
}

impl Drop for OriginalRestoredSchedulingObservationClaim<'_> {
    fn drop(&mut self) {
        if !self.completed.get()
            && let Ok(mut ledger) = self.window.current_observations[self.selected].try_borrow_mut()
        {
            ledger.stage = CurrentObservationStage::Failed;
        }
        self.window.whole_observation.require_observation();
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn next_current_observation_ordinal_data(
        &self,
        node: &crucible_node_contract::Id,
    ) -> Result<u64, RuntimeError> {
        self.origin()?;
        let selected = self
            .sources
            .iter()
            .position(|source| &source.installation().binding.compatibility.node_id == node)
            .ok_or(RuntimeError::UnknownNode)?;
        let ledger = self.current_observations[selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !matches!(
            ledger.stage,
            CurrentObservationStage::Empty | CurrentObservationStage::Verified
        ) {
            return Err(RuntimeError::OutstandingObligations);
        }
        ledger
            .completed
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)
    }

    pub(crate) fn retain_current_observation_quote_data(
        &self,
        runtime: &NodeRuntime,
        plan: &InstalledConformancePlan,
        world: &WorldActivation,
        node: &crucible_node_contract::Id,
        row: OriginalRestoredSchedulingObservationConstructionData,
    ) -> Result<(), RuntimeError> {
        if self.restored_capture_in_flight.get() {
            return Err(RuntimeError::OutstandingObligations);
        }

        self.authenticate_original_installed_runtime_identity_data(
            runtime,
            &self.archive,
            plan,
            world.record(),
        )?;
        if row.maximum != self.policy.maximum_requested_bytes
            || row.scratch > self.policy.declared_observer_scratch_bytes
            || row.ordinal != self.next_current_observation_ordinal_data(node)?
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let selected = self
            .sources
            .iter()
            .position(|source| {
                std::ptr::eq(source.as_ref(), row.source)
                    && &source.installation().binding.compatibility.node_id == node
            })
            .ok_or(RuntimeError::ForeignAuthority)?;
        let initial = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .and_then(|row| row.restored_suffix.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if initial.controller != row.controller || initial.source != row.source {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_suffix_identity_data(
            selected,
            &self.sources[selected],
            row.read_owner,
            world,
            self.original_complete_scope_proof_identity_data()?,
        )?;
        self.suffix_seeds[selected].authenticate(SeedStage::Verified)?;
        self.node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original_owner_data(&self.sources[selected], row.read_owner)?;
        let mut ledger = self.current_observations[selected]
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        ledger.row = Some(row);
        ledger.stage = CurrentObservationStage::Quoted;
        self.whole_observation.require_observation();
        Ok(())
    }

    pub(crate) fn begin_current_observation_data<'a>(
        &'a self,
        runtime: &NodeRuntime,
        world: &'a WorldActivation,
        node: &crucible_node_contract::Id,
        launch: &'a PacketNative5SourceLaunch,
        canonical_launch5: &'a [u8],
    ) -> Result<OriginalRestoredSchedulingObservationClaim<'a>, RuntimeError> {
        if self.restored_capture_in_flight.get() {
            return Err(RuntimeError::OutstandingObligations);
        }

        self.whole_observation.authenticate_dispatch_data()?;
        let selected = self
            .sources
            .iter()
            .position(|source| &source.installation().binding.compatibility.node_id == node)
            .ok_or(RuntimeError::UnknownNode)?;
        let mut ledger = self.current_observations[selected]
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if ledger.stage != CurrentObservationStage::Quoted {
            return Err(RuntimeError::OutstandingObligations);
        }
        ledger.stage = CurrentObservationStage::Started;
        let row = ledger.row.ok_or(RuntimeError::OwnerUnavailable)?;
        drop(ledger);
        let claim = OriginalRestoredSchedulingObservationClaim {
            window: self,
            selected,
            runtime,
            world,
            launch,
            canonical_launch5,
            row,
            completed: Cell::new(false),
            source_completed: Cell::new(false),
        };
        claim.authenticate_current_data(&self.sources[selected], row.controller)?;
        Ok(claim)
    }

    pub(crate) fn current_observation_policy_data(&self) -> Result<(usize, usize), RuntimeError> {
        self.origin()?;
        Ok((
            self.policy.maximum_requested_bytes,
            self.policy.declared_observer_scratch_bytes,
        ))
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn current_observation_source_index_data(
        &self,
        node: &crucible_node_contract::Id,
    ) -> Result<usize, RuntimeError> {
        self.origin()?;
        self.sources
            .iter()
            .position(|source| &source.installation().binding.compatibility.node_id == node)
            .ok_or(RuntimeError::UnknownNode)
    }

    pub(crate) fn authenticate_current_observation_runtime_data(
        &self,
        runtime: &ConformanceRuntime,
        plan: &InstalledConformancePlan,
        world: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        self.cold
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_import_release_idle_data()?;
        runtime.authenticate_original_installed_runtime_data(
            self,
            &self.archive,
            plan,
            world.record(),
        )
    }
}

impl OriginalRestoredSchedulingObservationClaim<'_> {
    pub(crate) fn retain_source_completion_data(
        &self,
        evidence: &crate::node_adapters::cnp::OriginalSourceRestoredObservationCompletion<'_>,
    ) -> Result<(), RuntimeError> {
        evidence.authenticate_claim_data(&self.row, self.world)?;
        let source = self
            .window
            .sources
            .get(self.selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.authenticate_current_data(source, self.row.controller)?;
        if self.source_completed.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(crate) fn complete_runtime_data(&self, runtime: &NodeRuntime) -> Result<(), RuntimeError> {
        if !std::ptr::eq(self.runtime, runtime)
            || !self.source_completed.get()
            || self.completed.get()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.window
            .runtime
            .authenticate_runtime_data(runtime, &self.world.record().world_binding_hash)?;
        let mut ledger = self.window.current_observations[self.selected]
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if ledger.stage != CurrentObservationStage::Started
            || ledger
                .row
                .as_ref()
                .is_none_or(|row| row.ordinal != self.row.ordinal)
            || ledger.completed.checked_add(1) != Some(self.row.ordinal)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let exported = self
            .row
            .runtime_retained
            .checked_add(self.row.first.scheduling_observation_requested_bytes_data())
            .ok_or(RuntimeError::ResourceLimit)?;
        ledger.exported_results = ledger
            .exported_results
            .checked_add(exported)
            .ok_or(RuntimeError::ResourceLimit)?;
        ledger.completed = self.row.ordinal;
        ledger.stage = CurrentObservationStage::Verified;
        self.completed.set(true);
        Ok(())
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn quote_original_current_observation_data(
        &self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        ordinal: u64,
        maximum: usize,
    ) -> Result<OriginalRestoredSchedulingObservationConstructionData, RuntimeError> {
        if self.original_installed_source_index_data(source)? != selected
            || maximum != self.policy.maximum_requested_bytes
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let row = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?;
        row.authenticate_original_owner_data(source, read_owner)?;
        let first = row
            .source_observation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if OriginalRestoredSchedulingObservationConstructionData::counter_scratch_data()
            > self.policy.declared_observer_scratch_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        source.original_current_observation_construction_data(
            controller, read_owner, launch, raw5, ordinal, first, maximum,
        )
    }

    pub(crate) fn call_original_current_observation_into(
        &self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &mut CnpController,
        read_owner: *const (),
        claim: &OriginalRestoredSchedulingObservationClaim<'_>,
        retained: &mut Option<crate::node_scheduling::NativeSchedulingObservation>,
        returned: &mut Option<crate::node_scheduling::NativeSchedulingObservation>,
    ) -> Result<(), RuntimeError> {
        if self.original_installed_source_index_data(source)? != selected
            || !std::ptr::eq(self, claim.window)
            || selected != claim.selected
            || claim.row.read_owner != read_owner
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        claim.authenticate_current_data(source, controller)?;
        claim.with_original_inputs_data(source, |inputs| {
            source.call_original_current_observation_into(
                controller, inputs, claim, retained, returned,
            )
        })
    }

    pub(crate) fn authenticate_original_current_observation_data(
        &self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        world: &WorldActivation,
        ordinal: u64,
        actual: &crate::node_scheduling::NativeSchedulingObservation,
    ) -> Result<(), RuntimeError> {
        if self.original_installed_source_index_data(source)? != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let proof = self.original_complete_scope_proof_identity_data()?;
        self.authenticate_suffix_identity_data(selected, source, read_owner, world, proof)?;
        let ledger = self.current_observations[selected]
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !matches!(
            ledger.stage,
            CurrentObservationStage::Started | CurrentObservationStage::Verified
        ) {
            return Err(RuntimeError::OutstandingObligations);
        }
        let row = ledger.row.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        if row.ordinal != ordinal || row.read_owner != read_owner {
            return Err(RuntimeError::ForeignAuthority);
        }
        row.authenticate_owner_data(source, controller)?;
        self.with_original_observation_signing_inputs_data(selected, source, proof, |inputs| {
            source.authenticate_original_current_observation_data(
                controller,
                inputs,
                row,
                world,
                ordinal,
                actual,
                || {
                    self.authenticate_suffix_identity_data(
                        selected, source, read_owner, world, proof,
                    )?;
                    let plan = self
                        .plan
                        .upgrade()
                        .map_err(|_| RuntimeError::ForeignAuthority)?;
                    let scope = self
                        .complete_scope
                        .get()
                        .ok_or(RuntimeError::OwnerUnavailable)?
                        .scope_data()?;
                    self.authenticate_original_complete_member_data(&plan, scope)?;
                    self.authenticate_suffix_identity_data(
                        selected, source, read_owner, world, proof,
                    )
                },
            )
        })
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn authenticate_initial_scheduling_identity_data(
        &self,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        node: &crucible_node_contract::Id,
    ) -> Result<(), RuntimeError> {
        self.whole_observation.authenticate_dispatch_data()?;
        self.world_roster.authenticate_complete()?;
        self.current_observation_source_index_data(node)?;
        if !self
            .activation_world
            .get()
            .is_some_and(|original| original.same_authority(world))
            || !self.context_issued.get()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let plan = self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.authenticate_original_complete_identity_data(&plan, scope)?;
        self.runtime
            .authenticate_runtime_data(runtime, &world.record().world_binding_hash)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(super) fn require_original_current_inspections_settled_data(
        &self,
    ) -> Result<(), RuntimeError> {
        for observation in &self.current_observations {
            observation
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .authenticate_no_pending_data()?;
        }
        Ok(())
    }
}
