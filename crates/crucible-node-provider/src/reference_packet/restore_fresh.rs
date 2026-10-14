//! Quotes the actual untouched producer owner before selected restore inputs.

use super::*;
use crate::retained_metadata::MetadataObserver;

impl PacketProgram {
    pub(crate) fn observe_fresh_restore_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        if self.failed
            || !self.gate_closed
            || self.next_event != 0
            || self.reached != Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
            || !self.outputs.is_empty()
            || !self.grants.is_empty()
            || !self.retired.is_empty()
            || self.private_mutations != 0
            || self.packet_effects != 0
        {
            return Err(ProviderError::Correlation(
                "restore producer is not the actual untouched owner",
            ));
        }
        observer.vector::<PacketEvent>(self.events.capacity())?;
        for event in &self.events {
            observer.observe(&event.id)?;
            observer.observe(&event.payload)?;
        }
        observer.vector::<PacketPublication>(self.outputs.capacity())?;
        observer.tree::<Id, PacketGrant>(self.grants.len())?;
        observer.tree::<Id, Vec<Id>>(self.retired.len())
    }
}
