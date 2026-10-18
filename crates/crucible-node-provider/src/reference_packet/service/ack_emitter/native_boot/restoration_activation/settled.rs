//! Borrows every actual restoration stage field without creating a native permit.

use super::*;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

impl StageHistory for NativeRestorationActivationAttempt {
    fn write_history<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.ensure_origin().map_err(serde::ser::Error::custom)?;
        let NativeRestorationActivationAttempt {
            creator,
            thread,
            phase,
            original,
            incoming_slot,
            artifact,
            context,
            coordinator,
            manifest,
            terminal,
            verified,
            dispatched,
            published,
        } = self;
        let mut state = serializer.serialize_struct("NativeRestorationStageHistory", 14)?;
        state.serialize_field(
            "schema",
            "source-private.native-restoration-activation-history/1",
        )?;
        state.serialize_field("creator", creator)?;
        let _ = thread;
        state.serialize_field("thread", "same-original-thread-history-only")?;
        state.serialize_field("phase", phase)?;
        state.serialize_field("original", original)?;
        state.serialize_field("incoming_slot", incoming_slot)?;
        state.serialize_field("artifact", artifact)?;
        state.serialize_field("context", context)?;
        state.serialize_field("coordinator", coordinator)?;
        state.serialize_field("manifest", manifest)?;
        state.serialize_field("terminal", terminal)?;
        state.serialize_field("verified", verified)?;
        state.serialize_field("dispatched", dispatched)?;
        state.serialize_field("published", published)?;
        state.end()
    }
}

/// Writes a historical value through the defining owner, never a portable Scope.
pub(in crate::reference_packet::service::ack_emitter::native_boot) trait StageHistory {
    fn write_history<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>;
}

pub(in crate::reference_packet::service::ack_emitter::native_boot) struct StageOwner<'a, T>(
    pub &'a T,
);

impl<T: StageHistory> Serialize for StageOwner<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.write_history(serializer)
    }
}

struct Slot<'a, T>(&'a Option<Rc<RefCell<T>>>);
impl<T: StageHistory> Serialize for Slot<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            None => serializer.serialize_none(),
            Some(owner) => {
                let owner = owner.try_borrow().map_err(serde::ser::Error::custom)?;
                serializer.serialize_some(&StageOwner(&*owner))
            }
        }
    }
}

struct Slots<'a, T>(&'a [Option<Rc<RefCell<T>>>; 2]);
impl<T: StageHistory> Serialize for Slots<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut slots = serializer.serialize_tuple(2)?;
        for slot in self.0 {
            slots.serialize_element(&Slot(slot))?;
        }
        slots.end()
    }
}

pub(in crate::reference_packet::service::ack_emitter::native_boot) struct Stages<'a> {
    pub(in crate::reference_packet::service::ack_emitter::native_boot) creator: u32,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) thread: ThreadId,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) activation:
        &'a [Option<Rc<RefCell<NativeRestorationActivationAttempt>>>; 2],
    pub(in crate::reference_packet::service::ack_emitter::native_boot) uploads:
        &'a [Option<Rc<RefCell<NativeRestorationUploadAttempt>>>; 2],
    pub(in crate::reference_packet::service::ack_emitter::native_boot) first_observation:
        &'a Option<Rc<RefCell<NativeRestorationObservationAttempt>>>,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) capacities:
        &'a crate::retained_metadata::records::MetadataRecordBank,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) aliases:
        &'a crate::retained_metadata::aliases::MetadataAliasBank,
}

impl Serialize for Stages<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(serde::ser::Error::custom(
                "restoration-stage historical origin differs",
            ));
        }
        let mut state = serializer.serialize_struct("NativeRestorationStages", 8)?;
        state.serialize_field("schema", "source-private.native-restoration-stages/1")?;
        state.serialize_field("activation", &Slots(self.activation))?;
        state.serialize_field("aliases", self.aliases)?;
        state.serialize_field("alias_allocation", &self.aliases.allocation_facts())?;
        state.serialize_field("uploads", &Slots(self.uploads))?;
        state.serialize_field("first_observation", &Slot(self.first_observation))?;
        state.serialize_field("capacities", self.capacities)?;
        state.serialize_field("capacity_rows", &self.capacities.rows().len())?;
        state.end()
    }
}

impl NativeAckBoot {
    /// Records real stage capacities in the caller's separately preadmitted bank.
    ///
    /// This is a historical DATA loan. Partial/failed stages remain present and
    /// cannot select a Capture route, complete a phase or create a new permit.
    pub(crate) fn borrowed_restoration_stages_history_data<'a>(
        &'a self,
        records: &'a mut crate::retained_metadata::records::MetadataRecordBank,
        aliases: &'a mut crate::retained_metadata::aliases::MetadataAliasBank,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.ensure_origin()?;
        let mut observer =
            crate::retained_metadata::MetadataObserver::recording_with_aliases(records, aliases);
        self.observe_restoration_activation_metadata_data(&mut observer)?;
        self.observe_restoration_upload_metadata_data(&mut observer)?;
        self.observe_restoration_observation_metadata_data(&mut observer)?;
        let _ = observer.finish();
        Ok(Stages {
            creator: self.creator,
            thread: self.thread,
            activation: &self.restoration_activation,
            uploads: &self.restoration_uploads,
            first_observation: &self.restoration_observation,
            capacities: records,
            aliases,
        })
    }
}

impl NativeAckBoot {
    /// Counts the defining native writer, slot/borrow and recording headers.
    ///
    /// Actual record/alias vectors and emitted canonical banks are separate
    /// prospective terms; this fixed view sum does not cover their allocations.
    pub(crate) const fn restoration_stages_history_writer_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Result<Stages<'static>, ProviderError>>()
            + size_of::<
                Result<
                    std::cell::Ref<'static, NativeRestorationActivationAttempt>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<'static, NativeRestorationUploadAttempt>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<'static, NativeRestorationObservationAttempt>,
                    std::cell::BorrowError,
                >,
            >()
            + size_of::<
                std::slice::Iter<'static, Option<Rc<RefCell<NativeRestorationActivationAttempt>>>>,
            >()
            + size_of::<
                std::slice::Iter<'static, Option<Rc<RefCell<NativeRestorationUploadAttempt>>>>,
            >()
            + size_of::<Stages<'static>>()
            + size_of::<StageOwner<'static, NativeRestorationActivationAttempt>>()
            + size_of::<StageOwner<'static, NativeRestorationUploadAttempt>>()
            + size_of::<StageOwner<'static, NativeRestorationObservationAttempt>>()
            + size_of::<Slot<'static, NativeRestorationActivationAttempt>>()
            + size_of::<Slot<'static, NativeRestorationUploadAttempt>>()
            + size_of::<Slot<'static, NativeRestorationObservationAttempt>>()
            + size_of::<Slots<'static, NativeRestorationActivationAttempt>>()
            + size_of::<Slots<'static, NativeRestorationUploadAttempt>>()
            + size_of::<std::cell::Ref<'static, NativeRestorationActivationAttempt>>()
            + size_of::<std::cell::Ref<'static, NativeRestorationUploadAttempt>>()
            + size_of::<std::cell::Ref<'static, NativeRestorationObservationAttempt>>()
            + size_of::<crate::retained_metadata::MetadataObserver<'static>>()
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<serde_json::Value, serde_json::Error>>()
            + size_of::<Result<Vec<u8>, crucible_node_contract::ContractError>>()
    }
}

/// Borrows only stage payloads; aggregate banks belong to the enclosing graph.
struct CurrentStages17<'a> {
    boot: &'a NativeAckBoot,
}

impl Serialize for CurrentStages17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.boot
            .ensure_origin()
            .map_err(serde::ser::Error::custom)?;
        let mut state = serializer.serialize_struct("NativeCurrentRestorationStages17", 4)?;
        state.serialize_field(
            "schema",
            "source-private.native-current-restoration-stages/17",
        )?;
        state.serialize_field("activation", &Slots(&self.boot.restoration_activation))?;
        state.serialize_field("uploads", &Slots(&self.boot.restoration_uploads))?;
        state.serialize_field(
            "first_observation",
            &Slot(&self.boot.restoration_observation),
        )?;
        state.end()
    }
}

impl NativeAckBoot {
    /// Borrows current stages under the enclosing graph's existing bank pass.
    ///
    /// This lender never creates a recording observer or clears a bank. The
    /// caller walks these stages once with its own aggregate observer.
    ///
    /// # Errors
    /// Refuses a foreign originating process or thread.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn borrowed_current_restoration_stages17_data(
        &self,
    ) -> Result<impl Serialize + '_, ProviderError> {
        self.ensure_origin()?;
        Ok(CurrentStages17 { boot: self })
    }
}

impl NativeAckBoot {
    /// Names exact native shared payload layouts, separate from historical data.
    pub(crate) const fn current_stage_layouts17_data() -> [(usize, usize); 3] {
        use std::mem::{align_of, size_of};
        [
            (
                size_of::<RefCell<NativeRestorationActivationAttempt>>(),
                align_of::<RefCell<NativeRestorationActivationAttempt>>(),
            ),
            (
                size_of::<RefCell<NativeRestorationUploadAttempt>>(),
                align_of::<RefCell<NativeRestorationUploadAttempt>>(),
            ),
            (
                size_of::<RefCell<NativeRestorationObservationAttempt>>(),
                align_of::<RefCell<NativeRestorationObservationAttempt>>(),
            ),
        ]
    }
}

impl NativeAckBoot {
    /// Names the payload-only current-stage writer header used by native17.
    pub(crate) const fn current_stages17_writer_header_data() -> usize {
        std::mem::size_of::<CurrentStages17<'static>>()
    }
}
