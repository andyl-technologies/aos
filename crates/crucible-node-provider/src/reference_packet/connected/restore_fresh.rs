//! Quotes every actual precharged reactive bank before selected restore inputs.

use super::*;
use crate::retained_metadata::MetadataObserver;

impl PacketConnectedProgram {
    pub(crate) fn observe_fresh_restore_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.current()?;
        if self.failed
            || !self.gate_closed
            || self.reached != Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
            || !self.reactions.is_empty()
            || !self.delivered_inputs.is_empty()
            || !self.publications.is_empty()
            || !self.outputs.is_empty()
            || !self.stages.is_empty()
            || !self.grants.is_empty()
            || !self.retired.is_empty()
            || self.reactions_completed != 0
            || self.packet_effects != 0
        {
            return Err(ProviderError::Correlation(
                "restore reactive is not the actual untouched owner",
            ));
        }
        observer.observe(&self.definition.schema)?;
        observer.vector::<PacketInputConnection>(self.definition.connections.capacity())?;
        for connection in &self.definition.connections {
            observer.observe(&connection.id)?;
            observer.observe(&connection.policy)?;
            observer.observe(&connection.producer)?;
            observer.observe(&connection.consumer)?;
        }
        observer.observe(&self.definition.output)?;
        observer.vector::<PacketReaction>(self.reactions.capacity())?;
        observer.vector::<PacketDeliveredInput>(self.delivered_inputs.capacity())?;
        observer.vector::<PacketPendingPublication>(self.publications.capacity())?;
        observer.vector::<PacketConnectedPublication>(self.outputs.capacity())?;
        observer.vector::<OriginalStage>(self.stages.capacity())?;
        observer.tree::<Id, PacketConnectedGrant>(self.grants.len())?;
        observer.tree::<Id, Vec<Id>>(self.retired.len())
    }
}
