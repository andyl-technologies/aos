//! Encodes complete current restore-input custody, including every failure partial.
//!
//! Native imported owners use their separate closed historical-heap codec. An
//! encoded-body reference cannot substitute for an initialized decoder graph.

use super::*;
use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
use crate::retained_metadata::MetadataObserver;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

struct CurrentCustody17<'a>(&'a OriginalCompleteRestoreInputCustody);
struct CurrentBanks17<'a>(&'a [InputBank; 6]);
struct CurrentBank17<'a>(&'a InputBank);
struct CurrentChunks17<'a>(&'a [OriginalRestoreInputChunk]);
struct CurrentSummaries17<'a>(&'a [HistoricalAliasSummary]);
struct CurrentByteBank17<'a>(&'a Vec<u8>);

impl OriginalCompleteRestoreInputCustody {
    /// Borrows all custody fields without moving banks or changing phase.
    ///
    /// # Errors
    /// Refuses foreign originating process/thread/actor history. Allocating,
    /// receiving, failed and partly decoded owners remain fully representable.
    pub(crate) fn borrowed_current17_data(&self) -> Result<impl Serialize + '_, ProviderError> {
        self.ensure_origin()?;
        Ok(CurrentCustody17(self))
    }

    /// Observes every actual retained child in the defining writer's order.
    ///
    /// # Errors
    /// Refuses foreign roots, borrowed recursive owners, exhausted metadata or
    /// checked layout overflow; retains every partial unchanged on failure.
    pub(crate) fn observe_current17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        let Self {
            creator,
            thread: _,
            quote,
            banks,
            chunks,
            summaries,
            native_encoded,
            native_owner,
            mapping_attempt,
            held_proof_quote_taken,
            next_input,
            phase: _,
        } = self;
        observer.observe(creator)?;
        quote.observe_current17_metadata_data(observer)?;
        for InputBank {
            bytes,
            transfer: _,
            transfer_length,
            begun,
            finished,
        } in banks
        {
            observer.observe(bytes)?;
            observer.observe(transfer_length)?;
            observer.observe(begun)?;
            observer.observe(finished)?;
        }
        observer.vector::<OriginalRestoreInputChunk>(chunks.capacity())?;
        for OriginalRestoreInputChunk {
            input,
            offset,
            length,
        } in chunks
        {
            observer.observe(input)?;
            observer.observe(offset)?;
            observer.observe(length)?;
        }
        observer.vector::<HistoricalAliasSummary>(summaries.capacity())?;
        if let Some(encoded) = native_encoded {
            observer.observe(encoded)?;
        }
        if let Some(owner) = native_owner {
            owner.observe_current17_metadata_data(observer)?;
        }
        if let Some(mapping) = mapping_attempt {
            mapping.observe_current17_metadata_data(observer)?;
        }
        observer.observe(held_proof_quote_taken)?;
        observer.observe(next_input)
    }

    /// Derives exact quote commitments using the original defining serializer.
    ///
    /// # Errors
    /// Refuses malformed request geometry, checked extents or serialization.
    pub(crate) fn current17_request_facts_data(
        request: &PacketCompleteRestorePrepareRequest,
    ) -> Result<([u8; 32], [usize; 6], usize, usize), ProviderError> {
        NativeRestoreInputAllocationQuote::current17_request_facts_data(request)
    }

    /// Reports actual native vector element layouts without exposing constructors.
    pub(crate) const fn current17_element_layouts_data() -> [(usize, usize); 2] {
        use std::mem::{align_of, size_of};
        [
            (
                size_of::<OriginalRestoreInputChunk>(),
                align_of::<OriginalRestoreInputChunk>(),
            ),
            (
                size_of::<HistoricalAliasSummary>(),
                align_of::<HistoricalAliasSummary>(),
            ),
        ]
    }

    /// Names borrowed views and exact primitive/iterator headers before encoding.
    pub(crate) fn current17_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<CurrentCustody17<'static>>()
            + size_of::<CurrentBanks17<'static>>()
            + size_of::<CurrentBank17<'static>>()
            + size_of::<CurrentChunks17<'static>>()
            + size_of::<CurrentSummaries17<'static>>()
            + size_of::<CurrentByteBank17<'static>>()
            + size_of::<Option<CurrentByteBank17<'static>>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<std::slice::Iter<'static, InputBank>>()
            + size_of::<std::slice::Iter<'static, OriginalRestoreInputChunk>>()
            + size_of::<std::slice::Iter<'static, HistoricalAliasSummary>>()
            + size_of::<(
                Option<u8>,
                usize,
                Option<[u8; 32]>,
                bool,
                Option<(u8, usize)>,
            )>()
            + NativeRestoreInputAllocationQuote::current17_counter_scratch_data()
    }
}

impl Serialize for CurrentByteBank17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (BorrowedCompactBytes::new(self.0), self.0.capacity()).serialize(serializer)
    }
}

impl Serialize for CurrentBank17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let InputBank {
            bytes,
            transfer,
            transfer_length,
            begun,
            finished,
        } = self.0;
        if *transfer_length > transfer.len() {
            return Err(serde::ser::Error::custom("native input transfer extent"));
        }
        // Full fixed storage is retained even beyond the currently used prefix.
        (
            CurrentByteBank17(bytes),
            transfer.as_slice(),
            transfer_length,
            begun,
            finished,
        )
            .serialize(serializer)
    }
}

impl Serialize for CurrentBanks17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(6))?;
        for bank in self.0 {
            sequence.serialize_element(&CurrentBank17(bank))?;
        }
        sequence.end()
    }
}

impl Serialize for CurrentChunks17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for OriginalRestoreInputChunk {
            input,
            offset,
            length,
        } in self.0
        {
            sequence.serialize_element(&(input, offset, length))?;
        }
        sequence.end()
    }
}

impl Serialize for CurrentSummaries17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for summary in self.0 {
            sequence.serialize_element(&summary.current17_data())?;
        }
        sequence.end()
    }
}

impl Serialize for CurrentCustody17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.ensure_origin().map_err(serde::ser::Error::custom)?;
        let OriginalCompleteRestoreInputCustody {
            creator,
            thread: _,
            quote,
            banks,
            chunks,
            summaries,
            native_encoded,
            native_owner,
            mapping_attempt,
            held_proof_quote_taken,
            next_input,
            phase,
        } = self.0;
        let quote = quote
            .borrowed_current17_data()
            .map_err(serde::ser::Error::custom)?;
        let native_owner = native_owner
            .as_ref()
            .map(|owner| owner.borrowed_current17_data())
            .transpose()
            .map_err(serde::ser::Error::custom)?;
        let mapping = mapping_attempt
            .as_ref()
            .map(|owner| owner.borrowed_current17_data())
            .transpose()
            .map_err(serde::ser::Error::custom)?;
        let phase = match phase {
            CustodyPhase::Allocating => "allocating",
            CustodyPhase::Receiving => "receiving",
            CustodyPhase::Complete => "complete",
            CustodyPhase::Failed => "failed",
        };
        let mut fields = serializer.serialize_struct("NativeCurrentInputCustody17", 15)?;
        fields.serialize_field("schema", "source-private.native-current-input-custody/17")?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("thread_role", "same-original-native-thread-history-only")?;
        fields.serialize_field("quote", &quote)?;
        fields.serialize_field("banks", &CurrentBanks17(banks))?;
        fields.serialize_field("chunks", &CurrentChunks17(chunks))?;
        fields.serialize_field("chunk_capacity", &chunks.capacity())?;
        fields.serialize_field("decoder_summaries", &CurrentSummaries17(summaries))?;
        fields.serialize_field("decoder_summary_capacity", &summaries.capacity())?;
        fields.serialize_field(
            "native_encoded",
            &native_encoded.as_ref().map(CurrentByteBank17),
        )?;
        fields.serialize_field("native_owner", &native_owner)?;
        fields.serialize_field("mapping_attempt", &mapping)?;
        fields.serialize_field("held_proof_quote_taken", held_proof_quote_taken)?;
        fields.serialize_field("next_input", next_input)?;
        fields.serialize_field("phase", phase)?;
        fields.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_bank(
        bank: &InputBank,
        input: &[u8],
        build: bool,
    ) -> Result<
        Option<
            crate::protocol_snapshot::restored_settled17::current_custody::HistoricalInputBank17,
        >,
        ProviderError,
    > {
        use crate::protocol_snapshot::owned11::{json_value::HistoricalJsonLimits, typed::Ledger};
        use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};
        let mut records = MetadataRecordBank::reserve(4)?;
        let mut observer = MetadataObserver::recording(&mut records);
        observer.observe(&bank.bytes)?;
        let _ = observer.finish();
        let encoded = serde_json::to_vec(&records).unwrap();
        let rows = ValidatedMetadataRecords::validate(&encoded, 4, 4096)?;
        let mut ledger = Ledger::new(
            rows.rows(),
            HistoricalJsonLimits {
                maximum_input_bytes: 4096,
                maximum_nodes: 1024,
                maximum_depth: 32,
                maximum_owned_backing_bytes: 4096,
                maximum_tree_entries: 16,
            },
        );
        let result = ledger.read(input, build)?;
        if ledger.rows.next().is_some() {
            return Err(refused());
        }
        Ok(result)
    }

    #[test]
    fn bank_writer_keeps_full_fixed_storage_and_partial_bytes() {
        let mut bank = InputBank::new();
        bank.bytes.try_reserve_exact(11).unwrap();
        bank.bytes.extend_from_slice(b"part");
        bank.transfer[..3].copy_from_slice(b"old");
        bank.transfer[127] = 93;
        bank.transfer_length = 3;
        bank.begun = true;
        let value = serde_json::to_value(CurrentBank17(&bank)).unwrap();

        assert_eq!(value[0][1], bank.bytes.capacity());
        assert_eq!(value[1].as_array().unwrap().len(), 128);
        assert_eq!(value[1][127], 93);
        assert_eq!(value[2], 3);
        assert_eq!(value[3], true);
        assert_eq!(value[4], false);
        assert_eq!(bank.bytes, b"part");
        let input = serde_json::to_vec(&value).unwrap();
        assert!(read_bank(&bank, &input, false).unwrap().is_none());
        let decoded = read_bank(&bank, &input, true).unwrap().unwrap();
        assert_eq!(decoded.bytes, bank.bytes);
        assert_eq!(decoded.bytes.capacity(), bank.bytes.capacity());
        assert_eq!(decoded.transfer, bank.transfer);
        assert_eq!(decoded.transfer_length, bank.transfer_length);
        assert!(decoded.begun && !decoded.finished);

        let mut short = value.clone();
        short[1].as_array_mut().unwrap().pop();
        let mut trailing = value.clone();
        trailing
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::Null);
        let mut changed_capacity = value;
        changed_capacity[0][1] = serde_json::json!(bank.bytes.capacity() + 1);
        for changed in [short, trailing, changed_capacity] {
            let input = serde_json::to_vec(&changed).unwrap();
            assert!(read_bank(&bank, &input, false).is_err());
            assert!(read_bank(&bank, &input, true).is_err());
        }
    }

    #[test]
    fn repeated_chunk_history_is_preserved_in_order() {
        let chunks = [
            OriginalRestoreInputChunk {
                input: 2,
                offset: 0,
                length: 4,
            },
            OriginalRestoreInputChunk {
                input: 2,
                offset: 0,
                length: 4,
            },
            OriginalRestoreInputChunk {
                input: 2,
                offset: 4,
                length: 1,
            },
        ];
        let value = serde_json::to_value(CurrentChunks17(&chunks)).unwrap();
        assert_eq!(value, serde_json::json!([[2, 0, 4], [2, 0, 4], [2, 4, 1]]));
    }
}
