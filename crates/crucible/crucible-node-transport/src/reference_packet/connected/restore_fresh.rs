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

impl PacketConnectedProgram {
    pub(crate) fn observe_original_live_capture_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<Position, ProviderError> {
        self.current()?;
        if self.gate_closed
            || !self.outputs.is_empty()
            || self.grants.values().any(|grant| !grant.complete)
        {
            return Err(ProviderError::Correlation(
                "native live reactive Capture boundary",
            ));
        }
        self.observe_original_live_owned_metadata_data(observer)?;
        self.current()?;
        Ok(self.reached)
    }

    /// Observes a stopped current inventory without requiring its outputs drained.
    ///
    /// The native17 caller independently proves grant-free current Control and
    /// its owning published checkpoint. This observer lends no action permission.
    ///
    /// # Errors
    /// Refuses failed/foreign or unopened models, unfinished native grants and
    /// finite metadata-counter overflow.
    pub(crate) fn observe_original_observation17_metadata_data(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<Position, ProviderError> {
        self.current()?;
        if self.gate_closed || self.grants.values().any(|grant| !grant.complete) {
            return Err(ProviderError::Correlation(
                "native signed Observe17 stopped boundary",
            ));
        }
        self.observe_original_live_owned_metadata_data(observer)?;
        self.current()?;
        Ok(self.reached)
    }

    // Both guarded borrowers enumerate the identical actual owned field walk.
    // Eligibility remains separate: Capture requires its public outputs drained.
    fn observe_original_live_owned_metadata_data(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            definition,
            native_pid,
            effect_socket: _,
            reached,
            gate_closed,
            reactions,
            delivered_inputs,
            publications,
            outputs,
            stages,
            grants,
            retired,
            reactions_completed,
            packet_effects,
            failed,
        } = self;
        observer.observe(definition)?;
        observer.observe(native_pid)?;
        observer.observe(reached)?;
        observer.observe(gate_closed)?;
        observer.observe(reactions)?;
        observer.observe(delivered_inputs)?;
        observer.observe(publications)?;
        observer.observe(outputs)?;
        observer.vector::<OriginalStage>(stages.capacity())?;
        for OriginalStage {
            record,
            record_ref,
            reply,
            commit,
        } in stages
        {
            observer.observe(record)?;
            observer.observe(record_ref)?;
            observe_input_reply(reply, observer)?;
            if let Some(OriginalCommit {
                record,
                record_ref,
                reply,
            }) = commit
            {
                observer.observe(record)?;
                observer.observe(record_ref)?;
                observe_input_reply(reply, observer)?;
            }
        }
        observer.observe(grants)?;
        observer.observe(retired)?;
        observer.observe(reactions_completed)?;
        observer.observe(packet_effects)?;
        observer.observe(failed)?;
        Ok(())
    }
}

fn observe_input_reply(
    reply: &PacketInputReply,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let PacketInputReply { result, evidence } = reply;
    observer.observe(result)?;
    observer.observe(&ReplyEvidenceMetadata(evidence))
}

// These closed borrowed views preserve the Vec and pair visit boundaries while
// charging the actual owned tuple slots and each independent child allocation.
// They create no replacement evidence and do not add a generic tuple observer.
struct ReplyEvidenceMetadata<'a>(&'a Vec<(ContentRef, Vec<u8>)>);

struct ReplyEvidenceRow<'a>(&'a ContentRef, &'a Vec<u8>);

impl crate::retained_metadata::ObserveMetadata for ReplyEvidenceMetadata<'_> {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.vector::<(ContentRef, Vec<u8>)>(self.0.capacity())?;
        for (reference, bytes) in self.0 {
            observer.observe(&ReplyEvidenceRow(reference, bytes))?;
        }
        Ok(())
    }
}

impl crate::retained_metadata::ObserveMetadata for ReplyEvidenceRow<'_> {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.observe(self.0)?;
        observer.observe(self.1)
    }
}

#[cfg(test)]
mod reply_evidence_metadata_tests {
    use super::*;

    #[test]
    fn actual_evidence_walk_preserves_tuple_slots_child_capacity_and_byte_visits()
    -> Result<(), ProviderError> {
        let mut first = Vec::with_capacity(37);
        first.extend_from_slice(b"first original");
        let mut second = Vec::with_capacity(101);
        second.extend_from_slice(b"second original retained bank");
        let mut evidence = Vec::with_capacity(7);
        evidence.push((
            canonical::content_ref(&first, "application/octet-stream")?,
            first,
        ));
        evidence.push((
            canonical::content_ref(&second, "application/octet-stream")?,
            second,
        ));
        let identity = (evidence.as_ptr(), evidence.len(), evidence.capacity());

        let mut actual = MetadataObserver::new();
        actual.observe(&ReplyEvidenceMetadata(&evidence))?;
        let actual = actual.finish();
        let mut children = MetadataObserver::new();
        for (reference, bytes) in &evidence {
            children.observe(reference)?;
            children.observe(bytes)?;
        }
        let children = children.finish();

        assert_eq!(actual.vector_banks, children.vector_banks + 1);
        assert_eq!(actual.capacity_records, children.capacity_records + 1);
        assert_eq!(
            actual.vector_capacity_bytes,
            children.vector_capacity_bytes
                + evidence.capacity() * std::mem::size_of::<(ContentRef, Vec<u8>)>()
        );
        assert_eq!(
            actual.observed_nodes,
            children.observed_nodes + 1 + evidence.len()
        );
        assert_eq!(actual.string_capacity_bytes, children.string_capacity_bytes);
        assert_eq!(
            identity,
            (evidence.as_ptr(), evidence.len(), evidence.capacity())
        );
        for (reference, bytes) in &evidence {
            reference.verify(bytes)?;
        }
        Ok(())
    }

    #[test]
    fn empty_evidence_walk_retains_original_spare_tuple_capacity() -> Result<(), ProviderError> {
        let evidence = Vec::with_capacity(9);
        let mut observer = MetadataObserver::new();
        observer.observe(&ReplyEvidenceMetadata(&evidence))?;
        let facts = observer.finish();
        assert_eq!(facts.vector_banks, 1);
        assert_eq!(facts.capacity_records, 1);
        assert_eq!(facts.observed_nodes, 1);
        assert_eq!(
            facts.vector_capacity_bytes,
            evidence.capacity() * std::mem::size_of::<(ContentRef, Vec<u8>)>()
        );
        Ok(())
    }
}

#[cfg(test)]
mod observation17_boundary_tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn model() -> Result<PacketConnectedProgram, ProviderError> {
        let (socket, _peer) = UnixDatagram::pair()?;
        PacketConnectedProgram::new(
            PacketConnectedDefinition {
                schema: "source-owned.packet-connected-program/4".into(),
                connections: vec![PacketInputConnection {
                    id: Id::new("actual-route")?,
                    policy: canonical::content_ref(b"policy", "application/octet-stream")?,
                    producer: Endpoint {
                        node_id: Id::new("producer")?,
                        port_id: Id::new("port")?,
                        lane_id: Id::new("lane")?,
                    },
                    consumer: Endpoint {
                        node_id: Id::new("consumer")?,
                        port_id: Id::new("port")?,
                        lane_id: Id::new("lane")?,
                    },
                    delay_ps: U64::new(1),
                }],
                output: None,
            },
            socket,
        )
    }

    #[test]
    fn observe_retains_complete_outputs_while_capture_keeps_its_drain_requirement() -> TestResult {
        let mut actual = model()?;
        actual.open_gate()?;
        let reaction = PacketReaction {
            input_event: Id::new("input")?,
            input_producer: Id::new("producer")?,
            input_sequence: U64::new(1),
            stage_operation: Id::new("stage")?,
            commit_request: Id::new("commit")?,
            payload: Bytes::new(b"original bytes".to_vec()),
            parent: Position::new(U64::new(0), U64::new(0), Phase::Delivery),
            evaluation: Position::new(U64::new(0), U64::new(0), Phase::Reaction),
        };
        let publication = Position::new(U64::new(0), U64::new(1), Phase::Publication);
        actual.outputs.push(PacketConnectedPublication {
            output: PacketPublication {
                event: Id::new("output")?,
                operation: Id::new("run")?,
                sequence: U64::new(1),
                evaluation: reaction.evaluation,
                publication,
                payload: reaction.payload.clone(),
            },
            pending: PacketPendingPublication {
                event: Id::new("output")?,
                reaction,
                reaction_operation: Id::new("run")?,
                publication,
            },
        });
        let before = (actual.outputs.as_ptr(), actual.outputs.capacity());
        assert!(
            actual
                .borrow_original_capture_inventory(&mut MetadataObserver::new())
                .is_err()
        );
        let borrowed =
            actual.borrow_original_observation17_inventory_data(&mut MetadataObserver::new())?;
        assert_eq!(
            serde_json::to_value(&borrowed)?,
            serde_json::to_value(actual.inventory()?)?
        );
        assert_eq!(before, (actual.outputs.as_ptr(), actual.outputs.capacity()));
        assert_eq!(
            actual.outputs[0].output.payload.as_slice(),
            b"original bytes"
        );
        Ok(())
    }

    #[test]
    fn unopened_failed_and_foreign_models_refuse_both_borrowers() -> TestResult {
        for changed in 0..3 {
            let mut actual = model()?;
            if changed != 0 {
                actual.open_gate()?;
            }
            if changed == 1 {
                actual.failed = true;
            }
            if changed == 2 {
                actual.native_pid = 0;
            }
            assert!(
                actual
                    .borrow_original_observation17_inventory_data(&mut MetadataObserver::new())
                    .is_err()
            );
            assert!(
                actual
                    .borrow_original_capture_inventory(&mut MetadataObserver::new())
                    .is_err()
            );
            assert!(actual.outputs.is_empty());
        }
        Ok(())
    }
}
