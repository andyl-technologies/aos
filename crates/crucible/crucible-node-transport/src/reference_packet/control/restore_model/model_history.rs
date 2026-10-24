//! Borrows every retained complete-model adoption root without restoring authority.
//!
//! The caller separately admits the supplied capacity/alias banks and encoded
//! output before serialization. This records failed and displaced roots as DATA;
//! only the genuine fresh loader may create a new socket, physical hold or owner.
//!
//! ```text
//! {schema,capacities,aliases,capacity_rows,data:{creator,thread,hold_role,control,
//!  model,producer,reactive,original_program,displaced_producer,displaced_reactive,
//!  original_producer,original_reactive,restored_producer,restored_reactive,
//!  effect_socket_role}}
//! ```

use super::*;
use crate::reference_packet::connected::PacketConnectedProgram;
use crate::reference_packet::continuation_models::{
    ModelRecord, PacketDecodedModelSnapshot, settled_history as history,
};
use crate::retained_metadata::{
    MetadataObserver, ObserveMetadata,
    aliases::{MetadataAliasBank, MetadataSharedKind},
    records::MetadataRecordBank,
};
use serde::ser::SerializeStruct;
use std::mem::size_of;

type PreparedModelLoans<'a> = (
    &'a u32,
    &'a ThreadId,
    &'a Rc<PacketCompleteRestorePhysicalHold>,
    &'a Option<continuation::ControlRecord>,
    &'a Option<PacketDecodedModelSnapshot>,
    &'a Option<PacketProducerModelAdoption>,
    &'a Option<PacketReactiveModelAdoption>,
    &'a Option<NativeProgram>,
    &'a Option<PacketDisplacedProducerModel>,
    &'a Option<PacketDisplacedReactiveModel>,
    &'a Option<PacketProgram>,
    &'a Option<PacketConnectedProgram>,
    &'a Option<PacketProgram>,
    &'a Option<PacketConnectedProgram>,
    &'a Option<UnixDatagram>,
);

struct PreparedModelHistory<'a>(&'a PacketPreparedCompleteModel);
struct OriginalProgramHistory<'a>(&'a NativeProgram);

impl PacketPreparedCompleteModel {
    /// Borrows every original, prepared, displaced and restored partial owner.
    ///
    /// # Errors
    /// Refuses a foreign creator/thread or a short finite record/alias bank.
    /// This does not authenticate Capture or renew any historical hold phase.
    pub(crate) fn borrowed_settled_history_data<'a>(
        &'a self,
        actual_hold: &Rc<PacketCompleteRestorePhysicalHold>,
        records: &'a mut MetadataRecordBank,
        aliases: &'a mut MetadataAliasBank,
    ) -> Result<history::ModelHistory<'a, impl Serialize + 'a>, ProviderError> {
        self.authenticate_settled_history_hold_data(actual_hold)?;
        history::borrow(self, PreparedModelHistory(self), records, aliases)
    }

    /// Borrows fields beneath the whole graph's actual shared-owner checks.
    ///
    /// # Errors
    /// Refuses another originating owner or a different real Hold allocation.
    pub(crate) fn borrowed_settled_model_data(
        &self,
        actual_hold: &Rc<PacketCompleteRestorePhysicalHold>,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_settled_history_hold_data(actual_hold)?;
        Ok(PreparedModelHistory(self))
    }

    /// Appends actual owner capacities and shared edges without clearing banks.
    ///
    /// The complete native graph invokes the Hold child's walk exactly once in
    /// its separately encoded Hold role. A component-local bank cannot replace
    /// that single aggregate cross-root alias traversal.
    ///
    /// # Errors
    /// Refuses a foreign/misbound owner or the caller's remaining finite banks.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        actual_hold: &Rc<PacketCompleteRestorePhysicalHold>,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled_history_hold_data(actual_hold)?;
        observer.observe(self)
    }

    /// Borrows the actual retained Hold for the enclosing graph's single role.
    ///
    /// A preparing or failed capsule may be the sole owner of this allocation.
    /// The caller compares this loan with any actual Control Hold before writing
    /// the shared object once; the loan neither opens nor authenticates its gate.
    ///
    /// # Errors
    /// Refuses another originating process or thread.
    pub(crate) fn original_settled_history_hold_data(
        &self,
    ) -> Result<&Rc<PacketCompleteRestorePhysicalHold>, ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(&self.hold)
    }

    /// Checks the actual shared hold edge before the whole graph writer uses it.
    ///
    /// # Errors
    /// Refuses foreign creator/thread or a different original hold allocation.
    pub(crate) fn authenticate_settled_history_hold_data(
        &self,
        actual: &Rc<PacketCompleteRestorePhysicalHold>,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || !Rc::ptr_eq(&self.hold, actual)
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Names the defining owner and nested fixed writer/observer views.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        history::counter_scratch_data::<PreparedModelHistory<'static>>()
            + PacketCompleteRestorePhysicalHold::settled_history_counter_scratch_data()
            + continuation::ControlRecord::settled_history_counter_scratch_data()
            + PacketProducerModelAdoption::settled_history_counter_scratch_data()
            + PacketReactiveModelAdoption::settled_history_counter_scratch_data()
            + PacketDisplacedProducerModel::settled_history_counter_scratch_data()
            + PacketDisplacedReactiveModel::settled_history_counter_scratch_data()
            + PacketProgram::settled_model_counter_scratch_data()
            + PacketConnectedProgram::settled_model_counter_scratch_data()
            + size_of::<PreparedModelHistory<'static>>()
            + size_of::<Result<PreparedModelHistory<'static>, ProviderError>>()
            + size_of::<OriginalProgramHistory<'static>>()
            + size_of::<Option<OriginalProgramHistory<'static>>>()
            + size_of::<&PacketPreparedCompleteModel>()
            + size_of::<PreparedModelLoans<'static>>()
            + size_of::<Option<&NativeProgram>>()
            + size_of::<Option<()>>()
            + size_of::<&Option<()>>()
            + size_of::<&Rc<PacketCompleteRestorePhysicalHold>>()
            + size_of::<Result<&Rc<PacketCompleteRestorePhysicalHold>, ProviderError>>()
            + size_of::<Option<&continuation::ControlRecord>>()
            + size_of::<Option<&ModelRecord>>()
            + size_of::<Option<&str>>()
            + size_of::<Result<(), ProviderError>>()
    }
}

impl Serialize for PreparedModelHistory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketPreparedCompleteModel {
            creator,
            thread: _,
            hold,
            control,
            model,
            producer,
            reactive,
            original_program,
            displaced_producer,
            displaced_reactive,
            original_producer,
            original_reactive,
            restored_producer,
            restored_reactive,
            effect_socket,
        } = self.0;
        let mut state = serializer.serialize_struct("PreparedCompleteModelHistory", 16)?;
        state.serialize_field("schema", "source-private.packet-prepared-model-history/17")?;
        state.serialize_field("creator", creator)?;
        state.serialize_field("thread", "same-original-thread-history-only")?;
        // The complete graph encodes the shared Hold once. This closed edge is
        // checked against the supplied actual allocation before serialization.
        let _ = hold;
        state.serialize_field("hold_role", "native-complete-restore-physical-hold")?;
        state.serialize_field("control", control)?;
        state.serialize_field(
            "model",
            &model
                .as_ref()
                .map(|value| value.borrowed_settled_model_data()),
        )?;
        state.serialize_field(
            "producer",
            &producer
                .as_ref()
                .map(|value| value.borrowed_settled_model_data()),
        )?;
        state.serialize_field(
            "reactive",
            &reactive
                .as_ref()
                .map(|value| value.borrowed_settled_model_data()),
        )?;
        state.serialize_field(
            "original_program",
            &original_program.as_ref().map(OriginalProgramHistory),
        )?;
        state.serialize_field(
            "displaced_producer",
            &displaced_producer
                .as_ref()
                .map(|value| value.borrowed_settled_model_data()),
        )?;
        state.serialize_field(
            "displaced_reactive",
            &displaced_reactive
                .as_ref()
                .map(|value| value.borrowed_settled_model_data()),
        )?;
        state.serialize_field(
            "original_producer",
            &original_producer
                .as_ref()
                .map(|value| value.borrowed_settled_model_data()),
        )?;
        state.serialize_field(
            "original_reactive",
            &original_reactive
                .as_ref()
                .map(|value| value.borrowed_settled_model_data()),
        )?;
        state.serialize_field(
            "restored_producer",
            &restored_producer
                .as_ref()
                .map(|value| value.borrowed_settled_model_data()),
        )?;
        state.serialize_field(
            "restored_reactive",
            &restored_reactive
                .as_ref()
                .map(|value| value.borrowed_settled_model_data()),
        )?;
        state.serialize_field(
            "effect_socket_role",
            &effect_socket.as_ref().map(|_| "model-effect-socket"),
        )?;
        state.end()
    }
}

impl Serialize for OriginalProgramHistory<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OriginalProgramHistory", 2)?;
        match self.0 {
            NativeProgram::OutputOnly(value) => {
                state.serialize_field("kind", "producer")?;
                state.serialize_field("data", &value.borrowed_settled_model_data())?;
            }
            NativeProgram::Connected(value) => {
                state.serialize_field("kind", "reactive")?;
                state.serialize_field("data", &value.borrowed_settled_model_data())?;
            }
            NativeProgram::RestorationInProgress => {
                state.serialize_field("kind", "restoration_in_progress")?;
                state.serialize_field("data", &None::<()>)?;
            }
        }
        state.end()
    }
}

impl ObserveMetadata for PacketPreparedCompleteModel {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            creator,
            thread: _,
            hold,
            control,
            model,
            producer,
            reactive,
            original_program,
            displaced_producer,
            displaced_reactive,
            original_producer,
            original_reactive,
            restored_producer,
            restored_reactive,
            effect_socket: _,
        } = self;
        observer.observe(creator)?;
        observer.shared_original(
            MetadataSharedKind::NativeRestoredPhysicalHold,
            hold.as_ref(),
        )?;
        if let Some(control) = control {
            control.observe_settled_history_metadata_data(observer)?;
        }
        observer.observe(model)?;
        observer.observe(producer)?;
        observer.observe(reactive)?;
        if let Some(original) = original_program {
            match original {
                NativeProgram::OutputOnly(value) => observer.observe(value)?,
                NativeProgram::Connected(value) => observer.observe(value)?,
                NativeProgram::RestorationInProgress => {}
            }
        }
        observer.observe(displaced_producer)?;
        observer.observe(displaced_reactive)?;
        observer.observe(original_producer)?;
        observer.observe(original_reactive)?;
        observer.observe(restored_producer)?;
        observer.observe(restored_reactive)?;
        Ok(())
    }
}
