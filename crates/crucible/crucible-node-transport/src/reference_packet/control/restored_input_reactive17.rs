//! Counts retained signed17 checkpoint DATA without issuing a native action.
//!
//! These private optional owners preserve independently decoded proof, model,
//! lineage and Source artifact partials. The live current-model validator and
//! independently funded same-Boot dispatch are separate consuming boundaries;
//! this module supplies no native action constructor or legacy Input fallback.

use super::*;
use crate::reference_packet::connected::PacketConnectedNativeRecord;
use crate::reference_packet::service::complete_restore::PacketNativeRestoredRecord;
use crate::reference_packet::service::restored_input_reactive17::*;
use crate::retained_metadata::MetadataObserver;

/// Retains independently decoded current proof and actual immutable lineage.
#[derive(serde::Serialize)]
pub(crate) struct NativeInputReactive17CheckpointAttempt {
    restored: Option<PacketNativeRestoredRecord>,
    underlying: Option<Box<PacketConnectedNativeRecord>>,
    expected_lineage: Option<PacketNativeRestoredRecord>,
    previous_artifact: Option<PacketRestoredInputReactive17Artifact>,
    previous_context: Option<PacketRestoredInputReactive17Context>,
    validated: bool,
}

impl NativeInputReactive17CheckpointAttempt {
    pub(crate) fn current_reactive_data(
        &self,
    ) -> Result<&PacketConnectedNativeRecord, ProviderError> {
        if !self.validated {
            return Err(refused());
        }
        self.underlying.as_deref().ok_or_else(refused)
    }

    pub(crate) fn observe_retained_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.restored)?;
        if let Some(record) = &self.underlying {
            observer.observe(record.as_ref())?;
            observer.boxed_value(record.as_ref())?;
        }
        observer.observe(&self.expected_lineage)?;
        observer.observe(&self.previous_artifact)?;
        observer.observe(&self.previous_context)?;
        observer.observe(&self.validated)
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("signed17 action current proof differs from actual native custody")
}

#[path = "restored_input_reactive17/observation.rs"]
mod observation;
#[path = "restored_input_reactive17/world.rs"]
mod world;
pub(crate) use observation::{
    NativeObservation17CheckpointAttempt, NativeObservation17CheckpointStorageData,
    NativeObservation17ProducerStorageData, NativeObservation17ProductionAttempt,
    NativeObservation17PublishedProductionData, capture17_checkpoint_counter_scratch_data,
    observation17_producer_counter_scratch_data,
};
