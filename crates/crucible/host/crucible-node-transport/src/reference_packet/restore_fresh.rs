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

impl PacketProgram {
    pub(crate) fn observe_original_live_capture_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<Position, ProviderError> {
        let Self {
            effect_socket: _,
            events,
            next_event,
            reached,
            gate_closed,
            outputs,
            grants,
            private_mutations,
            packet_effects,
            retired,
            failed,
        } = self;
        if *failed
            || *gate_closed
            || !outputs.is_empty()
            || *next_event > events.len()
            || grants.values().any(|grant| !grant.complete)
        {
            return Err(ProviderError::Correlation(
                "native live producer Capture boundary",
            ));
        }
        observer.observe(events)?;
        observer.observe(next_event)?;
        observer.observe(reached)?;
        observer.observe(gate_closed)?;
        observer.observe(outputs)?;
        observer.observe(grants)?;
        observer.observe(private_mutations)?;
        observer.observe(packet_effects)?;
        observer.observe(retired)?;
        observer.observe(failed)?;
        // The actual datagram is inline in the owning service's Control/model.
        // Kernel custody and quiescent effect drainage remain separate guards.
        Ok(*reached)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- actual inert owner capacity controls.
#[expect(
    clippy::unwrap_used,
    reason = "capacity assertions intentionally panic"
)]
mod live_capture_tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn live_model_walk_counts_spare_bytes_and_populated_historical_children() {
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let evaluation = Position::new(U64::new(2), U64::new(0), Phase::Reaction);
        let completion = Position::new(U64::new(2), U64::new(1), Phase::Publication);
        let mut bytes = Vec::with_capacity(4096);
        bytes.extend_from_slice(b"actual retained payload");
        let payload_capacity = bytes.capacity();
        let event = PacketEvent {
            id: Id::new("stored-event").unwrap(),
            evaluation,
            completion,
            payload: Some(Bytes::new(bytes)),
        };
        let mut program = PacketProgram::new(vec![event], socket).unwrap();
        let mut closed = MetadataObserver::new();
        assert!(
            program
                .observe_original_live_capture_metadata(&mut closed)
                .is_err()
        );
        program.open_gate().unwrap();
        let mut initial = MetadataObserver::new();
        let cursor = program
            .observe_original_live_capture_metadata(&mut initial)
            .unwrap();
        let initial = initial.finish();
        assert!(
            initial.vector_capacity_bytes
                >= payload_capacity + program.events.capacity() * size_of::<PacketEvent>()
        );

        // This inert saved row exercises nested owned history geometry. It is
        // not an execution receipt, Source right or positive Capture control.
        let operation = Id::new("stored-grant").unwrap();
        let grant = PacketGrant {
            operation: operation.clone(),
            start: cursor,
            limit: cursor,
            inventory: program.inventory(),
            newborn: Vec::new(),
            complete: true,
        };
        program.grants.insert(operation, grant);
        let mut populated = MetadataObserver::new();
        assert_eq!(
            program
                .observe_original_live_capture_metadata(&mut populated)
                .unwrap(),
            cursor
        );
        let populated = populated.finish();
        assert!(populated.vector_capacity_bytes > initial.vector_capacity_bytes);
        assert!(populated.tree_entries > initial.tree_entries);
        program.grants.values_mut().next().unwrap().complete = false;
        assert!(
            program
                .observe_original_live_capture_metadata(&mut MetadataObserver::new())
                .is_err()
        );
    }
}
