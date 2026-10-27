//! Quotes the defining reactive current-state validation without executing it.

use super::*;
use crate::retained_metadata::{
    RetainedProtocolMetadataFacts,
    serialization_storage::{OriginalSerializationStorageData, actual_serialization_storage_data},
};
use std::mem::{align_of, size_of};

impl ReactiveModel17Data {
    /// Quotes definition, original record and reply verification allocations.
    ///
    /// # Errors
    /// Refuses typed serialization, traversal or requested-layout overflow.
    pub(in crate::reference_packet) fn adoption18_validation_temporary_data(
        &self,
        facts: RetainedProtocolMetadataFacts,
    ) -> Result<usize, ProviderError> {
        // serialized_credit visits the definition before the route-ID set is
        // built. Sum all defining windows conservatively, including refusals.
        let definition = actual_serialization_storage_data(&self.0.definition, facts, usize::MAX)?;
        let routes = crate::retained_metadata::requested_storage::tree_storage_data(
            1,
            self.0.definition.connections.len(),
            size_of::<&Id>(),
            align_of::<&Id>(),
        )?;
        let mut requested = serialization_temporary(&definition)?
            .checked_add(routes)
            .ok_or_else(invalid)?;
        for stage in &self.0.stages {
            requested = requested
                .checked_add(record_and_reply_temporary(
                    &stage.record,
                    &stage.reply,
                    facts,
                )?)
                .ok_or_else(invalid)?;
            if let Some(commit) = &stage.commit {
                requested = requested
                    .checked_add(record_and_reply_temporary(
                        &commit.record,
                        &commit.reply,
                        facts,
                    )?)
                    .ok_or_else(invalid)?;
            }
        }
        Ok(requested)
    }

    /// Names the defining validation views, hash outputs and fixed controls.
    pub(in crate::reference_packet) fn adoption18_validation_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&ConnectedState>()
            + size_of::<&PacketConnectedDefinition>()
            + size_of::<std::slice::Iter<'static, OriginalStage>>()
            + size_of::<Option<&OriginalStage>>()
            + size_of::<Option<&OriginalCommit>>()
            + size_of::<&PacketStageRecord>()
            + size_of::<&PacketCommitRecord>()
            + size_of::<&PacketInputReply>()
            + size_of::<std::slice::Iter<'static, (ContentRef, Vec<u8>)>>()
            + size_of::<Option<&(ContentRef, Vec<u8>)>>()
            + size_of::<OriginalSerializationStorageData>()
            + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
            + size_of::<crucible_node_format::HashRef>()
            + size_of::<ContentRef>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + hash_hex_output_storage(blake3::Hash::to_hex)
            + size_of::<std::collections::BTreeSet<&Id>>()
            + size_of::<std::slice::Iter<'static, PacketInputConnection>>()
            + size_of::<Option<&PacketInputConnection>>()
            + size_of::<usize>() * 4
    }
}

fn record_and_reply_temporary(
    record: &impl Serialize,
    reply: &PacketInputReply,
    facts: RetainedProtocolMetadataFacts,
) -> Result<usize, ProviderError> {
    let row = actual_serialization_storage_data(record, facts, usize::MAX)?;
    let hash = "blake3-256".len() + "cnp.blob.v1".len() + 64;
    // verify_record constructs a ContentRef, while each evidence verification
    // constructs a HashRef. Account every actual retained evidence occurrence.
    let record_hash = hash
        .checked_add("application/json".len())
        .ok_or_else(invalid)?;
    let evidence_hashes = reply.evidence.len().checked_mul(hash).ok_or_else(invalid)?;
    serialization_temporary(&row)?
        .checked_add(record_hash)
        .and_then(|bytes| bytes.checked_add(evidence_hashes))
        .ok_or_else(invalid)
}

fn serialization_temporary(row: &OriginalSerializationStorageData) -> Result<usize, ProviderError> {
    row.dom_and_canonical_scratch_bytes
        .checked_add(row.canonical_output_requested_bytes)
        .and_then(|bytes| bytes.checked_add(row.serializer_temporary_requested_bytes))
        .ok_or_else(invalid)
}

// Infer the dependency's concrete hex-output type without constructing it or
// assuming its private inline String representation.
fn hash_hex_output_storage<T>(_: fn(&blake3::Hash) -> T) -> usize {
    size_of::<T>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bodies::InputResult, retained_metadata::MetadataObserver};

    #[test]
    fn adoption18_validation_quote_covers_actual_bytes_dom_and_reply_hash_work()
    -> Result<(), ProviderError> {
        let record = vec![Bytes::new(vec![7; 4097])];
        let evidence = vec![11; 1031];
        let reference = canonical::content_ref(&evidence, "application/octet-stream")?;
        let reply = PacketInputReply {
            result: InputResult {
                accepted_event_ids: vec![Id::new("retained-event")?],
                input_watermark: U64::new(1),
                custody_receipt: reference.clone(),
                inventory_hash: reference.hash.clone(),
            },
            evidence: vec![(reference.clone(), evidence.clone())],
        };
        let mut observer = MetadataObserver::new();
        observer.observe(&record)?;
        let facts = observer.finish();
        let quoted = record_and_reply_temporary(&record, &reply, facts)?;

        let value = serde_json::to_value(&record).map_err(ContractError::from)?;
        let canonical_bytes = canonical::canonical_json(&value)?;
        let mut observer = MetadataObserver::new();
        observer.observe(&value)?;
        let dom =
            crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())?;
        assert!(quoted >= dom + size_of::<serde_json::Value>() + canonical_bytes.capacity());
        reference.verify(&evidence)?;

        let mut more_evidence = reply.clone();
        more_evidence
            .evidence
            .push((reference.clone(), evidence.clone()));
        assert!(record_and_reply_temporary(&record, &more_evidence, facts)? > quoted);
        let mut changed = evidence;
        changed[0] ^= 1;
        assert!(reference.verify(&changed).is_err());
        assert_eq!(record_and_reply_temporary(&record, &reply, facts)?, quoted);
        Ok(())
    }
}
