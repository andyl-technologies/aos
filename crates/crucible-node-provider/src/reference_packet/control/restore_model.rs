//! Prepares captured models before moving the same fresh effect socket.
//!
//! The native MAC issuer and SDK installed mapping acknowledgement are separate
//! mandatory gates. All pending and displaced owners stay in this capsule. A
//! captured logical open gate is never rewritten to represent the fresh hold.

use super::*;
use crate::reference_packet::connected::{
    PacketDisplacedReactiveModel, PacketReactiveModelAdoption,
};
use crate::reference_packet::continuation_models::{
    PacketDisplacedProducerModel, PacketModelKind, PacketProducerModelAdoption,
};
use std::{cell::Cell, os::unix::net::UnixDatagram, rc::Rc, thread::ThreadId};

#[derive(Clone, Copy, PartialEq, Eq)]
enum HoldPhase {
    Preparing,
    Installing,
    Held,
    Released,
}

pub(crate) struct PacketCompleteRestorePhysicalHold {
    creator: u32,
    thread: ThreadId,
    control_identity: Rc<()>,
    phase: Cell<HoldPhase>,
    cursor: Position,
    inventory_hash: HashRef,
}

impl PacketCompleteRestorePhysicalHold {
    pub(crate) fn authenticate_held(&self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self.phase.get() != HoldPhase::Held {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn physical_gate_data(&self) -> Result<bool, ProviderError> {
        self.ensure_origin()?;
        match self.phase.get() {
            HoldPhase::Held => Ok(true),
            HoldPhase::Released => Ok(false),
            _ => Err(refused()),
        }
    }

    pub(crate) fn captured_boundary(&self) -> Result<(Position, &HashRef), ProviderError> {
        self.ensure_origin()?;
        Ok((self.cursor, &self.inventory_hash))
    }

    fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }
}

pub(crate) struct PacketPreparedCompleteModel {
    creator: u32,
    thread: ThreadId,
    hold: Rc<PacketCompleteRestorePhysicalHold>,
    control: Option<continuation::ControlRecord>,
    model: Option<super::super::continuation_models::PacketDecodedModelSnapshot>,
    producer: Option<PacketProducerModelAdoption>,
    reactive: Option<PacketReactiveModelAdoption>,
    original_program: Option<NativeProgram>,
    displaced_producer: Option<PacketDisplacedProducerModel>,
    displaced_reactive: Option<PacketDisplacedReactiveModel>,
    original_producer: Option<PacketProgram>,
    original_reactive: Option<super::super::connected::PacketConnectedProgram>,
    restored_producer: Option<PacketProgram>,
    restored_reactive: Option<super::super::connected::PacketConnectedProgram>,
    effect_socket: Option<UnixDatagram>,
}

impl PacketControl {
    pub(crate) fn bind_original_restored_evidence(
        &mut self,
        hold: &Rc<PacketCompleteRestorePhysicalHold>,
        evidence: super::super::service::ack_emitter::NativeRestoredControlEvidence,
    ) -> Result<(), ProviderError> {
        hold.authenticate_held()?;
        if self.capture_creator != std::process::id()
            || self.fenced
            || self.complete_restored_evidence.is_some()
            || self
                .complete_restored_hold
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(actual, hold))
            || !Rc::ptr_eq(&hold.control_identity, &self.capture_identity)
        {
            return Err(refused());
        }
        self.complete_restored_evidence = Some(evidence);
        Ok(())
    }

    pub(crate) fn prepare_original_complete_model_into(
        &self,
        pending: &mut Option<PacketDecodedControlSnapshot>,
        prepared: &mut Option<PacketPreparedCompleteModel>,
        maximum_model_bytes: usize,
    ) -> Result<(), ProviderError> {
        self.ensure_original_restore_target()?;
        if pending.is_none() || prepared.is_some() || self.complete_restored_hold.is_some() {
            return Err(refused());
        }
        let decoded = pending.as_ref().ok_or_else(refused)?;
        let boundary = decoded.model().capture_boundary_data(maximum_model_bytes)?;
        if boundary.gate_closed
            || boundary.retained_outputs != 0
            || decoded.model().record.configuration != self.selection.realize.configuration
            || (decoded.model().record.kind == PacketModelKind::Reactive)
                != self.program.is_connected()
        {
            return Err(refused());
        }
        // Install the attempt before taking either decoded data owner. The full
        // original pending Control and model remain available on every failure.
        *prepared = Some(PacketPreparedCompleteModel {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            hold: Rc::new(PacketCompleteRestorePhysicalHold {
                creator: std::process::id(),
                thread: std::thread::current().id(),
                control_identity: Rc::clone(&self.capture_identity),
                phase: Cell::new(HoldPhase::Preparing),
                cursor: boundary.local_cursor,
                inventory_hash: boundary.inventory_hash,
            }),
            control: None,
            model: None,
            producer: None,
            reactive: None,
            original_program: None,
            displaced_producer: None,
            displaced_reactive: None,
            original_producer: None,
            original_reactive: None,
            restored_producer: None,
            restored_reactive: None,
            effect_socket: None,
        });
        let capsule = prepared.as_mut().ok_or_else(refused)?;
        let (record, model) = pending
            .take()
            .ok_or_else(refused)?
            .into_original_model_parts();
        capsule.control = Some(record);
        capsule.model = Some(model);
        match capsule.model.as_ref().ok_or_else(refused)?.record.kind {
            PacketModelKind::Producer => PacketProgram::prepare_model_state_retained_into(
                &mut capsule.model,
                &mut capsule.producer,
            )?,
            PacketModelKind::Reactive => {
                super::super::connected::PacketConnectedProgram::prepare_model_state_retained_into(
                    &mut capsule.model,
                    &mut capsule.reactive,
                )?
            }
        }
        capsule.authenticate_prepared(self)
    }

    fn ensure_original_restore_target(&self) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id()
            || self.fenced
            || !self.realized
            || !self.admitted
            || self.staged.is_some()
            || self.active.is_some()
            || self.current_operation.is_some()
            || self.native_effect_attempted
            || !self.begins.is_empty()
            || !self.terminals.is_empty()
            || !self.begin_requests.is_empty()
        {
            return Err(refused());
        }
        Ok(())
    }

    // This entry is confined to the genuine native issuer. It calls the SDK's
    // same-mapping installed acknowledgement immediately before this field move.
    pub(in crate::reference_packet) fn install_original_complete_model(
        &mut self,
        capsule: &mut PacketPreparedCompleteModel,
    ) -> Result<Rc<PacketCompleteRestorePhysicalHold>, ProviderError> {
        capsule.authenticate_prepared(self)?;
        if self.complete_restored_hold.is_some() || capsule.original_program.is_some() {
            return Err(refused());
        }
        capsule.hold.phase.set(HoldPhase::Installing);
        self.complete_restored_hold = Some(Rc::clone(&capsule.hold));
        self.fenced = true;
        capsule.original_program = Some(std::mem::replace(
            &mut self.program,
            NativeProgram::RestorationInProgress,
        ));
        match capsule.original_program.take().ok_or_else(refused)? {
            NativeProgram::OutputOnly(program) => capsule.original_producer = Some(program),
            NativeProgram::Connected(program) => capsule.original_reactive = Some(program),
            NativeProgram::RestorationInProgress => return Err(refused()),
        }
        if let Some(adoption) = capsule.producer.as_mut() {
            PacketProgram::displace_original_restore_socket_into(
                &mut capsule.original_producer,
                &mut capsule.displaced_producer,
                &mut capsule.effect_socket,
            )?;
            capsule
                .displaced_producer
                .as_ref()
                .ok_or_else(refused)?
                .authenticate_fresh_data()?;
            adoption.bind_original_socket(&mut capsule.effect_socket)?;
            adoption.take_completed_into(&mut capsule.restored_producer)?;
            self.program =
                NativeProgram::OutputOnly(capsule.restored_producer.take().ok_or_else(refused)?);
        } else if let Some(adoption) = capsule.reactive.as_mut() {
            super::super::connected::PacketConnectedProgram::displace_original_restore_socket_into(
                &mut capsule.original_reactive,
                &mut capsule.displaced_reactive,
                &mut capsule.effect_socket,
            )?;
            capsule
                .displaced_reactive
                .as_ref()
                .ok_or_else(refused)?
                .authenticate_fresh_data()?;
            adoption.bind_original_socket(&mut capsule.effect_socket)?;
            adoption.take_completed_into(&mut capsule.restored_reactive)?;
            self.program =
                NativeProgram::Connected(capsule.restored_reactive.take().ok_or_else(refused)?);
        } else {
            return Err(refused());
        }
        // Logical inventory is exactly the captured inventory. This independent
        // physical hold is released only by the actual fresh WorldActivate path.
        self.fenced = false;
        capsule.hold.phase.set(HoldPhase::Held);
        Ok(Rc::clone(&capsule.hold))
    }

    pub(super) fn original_physical_gate_held(&self) -> Result<bool, ProviderError> {
        if self.capture_creator != std::process::id() || self.fenced {
            return Err(refused());
        }
        match &self.complete_restored_hold {
            Some(hold) => {
                hold.ensure_origin()?;
                if !Rc::ptr_eq(&hold.control_identity, &self.capture_identity) {
                    return Err(refused());
                }
                Ok(hold.phase.get() == HoldPhase::Held)
            }
            None => Ok(self.program.inventory()?.gate_closed),
        }
    }

    pub(super) fn release_original_physical_gate(&mut self) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() || self.fenced {
            return Err(refused());
        }
        if let Some(hold) = &self.complete_restored_hold {
            hold.authenticate_held()?;
            if !Rc::ptr_eq(&hold.control_identity, &self.capture_identity) {
                return Err(refused());
            }
            hold.phase.set(HoldPhase::Released);
            Ok(())
        } else {
            self.program.open_gate()
        }
    }
}

impl PacketPreparedCompleteModel {
    pub(crate) fn prepared_boundary(&self) -> Result<(Position, &HashRef), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || self.hold.phase.get() != HoldPhase::Preparing
        {
            return Err(refused());
        }
        self.hold.captured_boundary()
    }

    fn authenticate_prepared(&self, target: &PacketControl) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        target.ensure_original_restore_target()?;
        self.hold.ensure_origin()?;
        if self.hold.phase.get() != HoldPhase::Preparing
            || !Rc::ptr_eq(&self.hold.control_identity, &target.capture_identity)
            || self.control.is_none()
            || self.model.is_some()
            || self.producer.is_some() == self.reactive.is_some()
        {
            return Err(refused());
        }
        if let Some(model) = &self.producer {
            model.authenticate_prepared_data(&target.selection.realize.configuration)?;
        }
        if let Some(model) = &self.reactive {
            model.authenticate_prepared_data(&target.selection.realize.configuration)?;
        }
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original complete model/physical hold differs")
}

#[path = "restore_model/settled.rs"]
mod settled;

#[path = "restore_model/model_history.rs"]
mod model_history;
