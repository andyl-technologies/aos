//! Installs the complete current model beneath a distinct fresh physical Hold.
//!
//! The installer owns the whole archive, immutable original policy, selected
//! target, fresh socket and every initialized prefix. Its Control starts without
//! a model. Installation preserves the captured logical gate and current model
//! fields; the separate physical Hold stays closed. The Control remains private
//! and fenced until distinct18 phase dispatch is implemented. This transition
//! alone cannot issue Commit, Arm, World, an old17 receipt or a phase admission.

use super::*;
use crate::protocol_snapshot::restored_settled17::{
    RestoredSettledNative18ModelAdoption, SealedHistoricalRestoredSettledNative17,
};
use crate::reference_packet::{
    continuation_models::{
        PacketModelCaptureBoundaryData, settled_reader::adoption18::CurrentModel18Program,
    },
    coordinator::PacketNative5CoordinatorInstallation,
    native_import18_policy::NativeImport18PolicyData,
};

mod storage;
mod target_construction;
pub use target_construction::{
    native_import18_target_construction_counter_scratch_data,
    native_import18_target_construction_data,
};

/// Retains the archive and fresh socket before any installing validation.
pub(crate) struct Native18ModelInstallationInputs {
    /// Retains the complete archive selected by the original Source occurrence.
    pub(crate) archive: Option<SealedHistoricalRestoredSettledNative17>,
    /// Retains the already owned fresh effect socket through every refusal.
    pub(crate) effect_socket: Option<UnixDatagram>,
}

/// Retains target construction from the same immutable selected launch.
struct Native18InstallationTarget {
    selection: Option<PacketControlSelection>,
    coordinator: Option<PacketNative5CoordinatorInstallation>,
}

/// Keeps the same model, archive and fresh Control through the held installation.
pub(crate) struct Native18ModelInstallation {
    process: u32,
    thread: ThreadId,
    failed: bool,
    installed: bool,
    policy: Rc<NativeImport18PolicyData>,
    inputs: Option<Native18ModelInstallationInputs>,
    target: Option<Native18InstallationTarget>,
    boundary: Option<PacketModelCaptureBoundaryData>,
    archive: Option<RestoredSettledNative18ModelAdoption>,
    control: Option<PacketControl>,
    hold: Option<Rc<PacketCompleteRestorePhysicalHold>>,
    completed: Option<CurrentModel18Program>,
}

impl Native18ModelInstallation {
    /// Prepares a model-absent target while retaining every original input.
    ///
    /// The enclosing genuine Source/SDK transition must independently admit
    /// archive/model validation, selected-launch cloning, coordinator decoding,
    /// canonical coordinator and inventory work,
    /// target/identity/Hold allocations and all constructor controls before entry.
    /// Immutable policy correspondence here is DATA, not proof of those admissions
    /// or ancestry.
    /// No model or socket is reconstructed from an old snapshot format.
    ///
    /// # Errors
    /// Refuses an occupied destination without changing inputs. After retaining
    /// the attempt, absent inputs, an invalid original coordinator, archive or
    /// model leaves this same attempt spent with each initialized owner retained.
    pub(crate) fn prepare_into(
        inputs: &mut Option<Native18ModelInstallationInputs>,
        policy: &Rc<NativeImport18PolicyData>,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(refused18());
        }
        *output = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            failed: true,
            installed: false,
            policy: Rc::clone(policy),
            inputs: inputs.take(),
            target: None,
            boundary: None,
            archive: None,
            control: None,
            hold: None,
            completed: None,
        });

        let owner = output.as_mut().ok_or_else(refused18)?;
        owner.policy.definitions_data()?;
        let inputs = owner.inputs.as_mut().ok_or_else(refused18)?;
        if inputs.effect_socket.is_none() {
            return Err(refused18());
        }

        // Retain the selected launch clone before decoding the coordinator.
        // A decode refusal cannot discard or replace this initialized target.
        owner.target = Some(Native18InstallationTarget {
            selection: Some(owner.policy.launch_data().selection.clone()),
            coordinator: None,
        });
        let target = owner.target.as_mut().ok_or_else(refused18)?;
        target.coordinator = Some(PacketNative5CoordinatorInstallation::decode(
            owner
                .policy
                .launch_data()
                .initial_coordinator
                .bytes
                .as_slice(),
            target.selection.as_ref().ok_or_else(refused18)?,
        )?);
        owner.boundary = Some(
            inputs
                .archive
                .as_ref()
                .ok_or_else(refused18)?
                .installation_boundary18_data()?,
        );

        let target = owner.target.take().ok_or_else(refused18)?;
        match target.into_model_absent_control() {
            Ok(control) => owner.control = Some(control),
            Err(prefix) => {
                owner.target = Some(prefix);
                return Err(refused18());
            }
        }
        let control = owner.control.as_mut().ok_or_else(refused18)?;
        let boundary = owner.boundary.take().ok_or_else(refused18)?;
        owner.hold = Some(Self::preparing_hold(control, boundary));
        control.complete_restored_hold = owner.hold.as_ref().map(Rc::clone);

        RestoredSettledNative18ModelAdoption::prepare_into(
            &mut inputs.archive,
            &owner.policy.launch_data().program,
            &mut owner.archive,
        )?;
        owner.failed = false;
        Ok(())
    }

    /// Moves the same fresh socket and complete current model beneath its Hold.
    ///
    /// A genuine Commit caller must independently authenticate original phase
    /// custody, admitted demand and the same installed SDK acknowledgement. The
    /// retained result stays private and fenced, including after successful
    /// installation: legacy17 activation cannot dispatch against this target.
    /// Captured logical gates, grants and failed state remain unchanged.
    ///
    /// # Errors
    /// Refuses foreign origin, incomplete/failed preparation, any repeated
    /// installation or inconsistent target/Hold custody. Binding refusal leaves
    /// the installing prefix retained and prevents another installation attempt.
    pub(crate) fn install_held(&mut self) -> Result<(), ProviderError> {
        self.authenticate_origin()?;
        if self.failed || self.installed {
            return Err(refused18());
        }
        let control = self.control.as_mut().ok_or_else(refused18)?;
        let hold = self.hold.as_ref().ok_or_else(refused18)?;
        Self::authenticate_model_absent_target(control, hold, HoldPhase::Preparing)?;
        let archive = self.archive.as_mut().ok_or_else(refused18)?;
        let inputs = self.inputs.as_mut().ok_or_else(refused18)?;

        // This state is nonrenewing even when a later binding refuses. All
        // owning destinations already exist before the actual socket moves.
        self.failed = true;
        hold.phase.set(HoldPhase::Installing);
        archive.bind_effect_socket(&mut inputs.effect_socket)?;
        archive.take_completed_into(&mut self.completed)?;
        Self::retain_completed_model(control, hold, &mut self.completed)?;
        self.installed = true;
        self.failed = false;
        Ok(())
    }

    fn model_absent_target(
        selection: PacketControlSelection,
        coordinator: PacketNative5CoordinatorInstallation,
    ) -> PacketControl {
        let mut control = PacketControl::from_checked_complete_birth(
            selection,
            NativeProgram::RestorationInProgress,
            coordinator,
        );
        control.fenced = true;
        control.immediate = false;
        control.restoration_activation_required = true;
        control
    }

    fn preparing_hold(
        control: &PacketControl,
        boundary: PacketModelCaptureBoundaryData,
    ) -> Rc<PacketCompleteRestorePhysicalHold> {
        Rc::new(PacketCompleteRestorePhysicalHold {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            control_identity: Rc::clone(&control.capture_identity),
            phase: Cell::new(HoldPhase::Preparing),
            cursor: boundary.local_cursor,
            inventory_hash: boundary.inventory_hash,
        })
    }

    fn authenticate_model_absent_target(
        control: &PacketControl,
        hold: &Rc<PacketCompleteRestorePhysicalHold>,
        phase: HoldPhase,
    ) -> Result<(), ProviderError> {
        hold.ensure_origin()?;
        if control.capture_creator != std::process::id()
            || !control.fenced
            || control.immediate
            || !control.restoration_activation_required
            || !matches!(control.program, NativeProgram::RestorationInProgress)
            || hold.phase.get() != phase
            || !Rc::ptr_eq(&hold.control_identity, &control.capture_identity)
            || control
                .complete_restored_hold
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(actual, hold))
        {
            return Err(refused18());
        }
        Ok(())
    }

    fn retain_completed_model(
        control: &mut PacketControl,
        hold: &Rc<PacketCompleteRestorePhysicalHold>,
        completed: &mut Option<CurrentModel18Program>,
    ) -> Result<(), ProviderError> {
        Self::authenticate_model_absent_target(control, hold, HoldPhase::Installing)?;
        // No allocator, serializer, callback or fallible operation follows the
        // completed model's move into its final retained Control destination.
        let program = completed.take().ok_or_else(refused18)?;
        control.program = match program {
            CurrentModel18Program::Producer(program) => NativeProgram::OutputOnly(program),
            CurrentModel18Program::Reactive(program) => NativeProgram::Connected(program),
        };
        hold.phase.set(HoldPhase::Held);
        Ok(())
    }

    fn authenticate_origin(&self) -> Result<(), ProviderError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused18());
        }
        Ok(())
    }
}

impl Native18InstallationTarget {
    /// Returns an incomplete prefix intact if either original field is absent.
    fn into_model_absent_control(self) -> Result<PacketControl, Self> {
        match self {
            Self {
                selection: Some(selection),
                coordinator: Some(coordinator),
            } => Ok(Native18ModelInstallation::model_absent_target(
                selection,
                coordinator,
            )),
            prefix => Err(prefix),
        }
    }
}

fn refused18() -> ProviderError {
    ProviderError::Conflict("original native18 model installation")
}

#[cfg(test)]
mod tests;
