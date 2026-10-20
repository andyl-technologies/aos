//! Retains the complete current native restoration-input custody as inert DATA.
//!
//! Its recursive imported heap uses the separate concrete `current_import17`
//! codec. A retained original body or completion flag cannot stand in for that
//! actual partially reconstructed graph. No input token or native owner is built.

use super::current_contracts::CurrentField17;
use super::current_import17::{HistoricalPreparedNativeMapping17, HistoricalSealedNativeImport17};
use super::current_inline::FixedArray32Field17;
use crate::ProviderError;
use crate::connection::{
    OriginalCompleteRestoreInputCustody, settled17::HistoricalReversedByteBank17,
};
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};
use crate::retained_metadata::records::MetadataRecordKind;

#[path = "current_custody/quote.rs"]
mod quote;
pub(crate) use quote::{HistoricalInputQuote17, HistoricalProofQuote17};

/// Retains a complete native custody projection, including all failure partials.
pub(crate) struct HistoricalRestoreInputCustody17 {
    pub(crate) creator: u32,
    pub(crate) quote: HistoricalInputQuote17,
    pub(crate) banks: [HistoricalInputBank17; 6],
    pub(crate) chunks: Vec<HistoricalInputChunk17>,
    pub(crate) summaries: Vec<HistoricalDecoderSummary17>,
    pub(crate) native_encoded: Option<Vec<u8>>,
    pub(crate) native_owner: Option<HistoricalSealedNativeImport17>,
    pub(crate) mapping_attempt: Option<HistoricalPreparedNativeMapping17>,
    pub(crate) held_proof_quote_taken: bool,
    pub(crate) next_input: usize,
    pub(crate) phase: HistoricalCustodyPhase17,
}

pub(crate) struct HistoricalInputBank17 {
    pub(crate) bytes: Vec<u8>,
    pub(crate) transfer: [u8; 128],
    pub(crate) transfer_length: usize,
    pub(crate) begun: bool,
    pub(crate) finished: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalInputChunk17 {
    pub(crate) input: usize,
    pub(crate) offset: usize,
    pub(crate) length: usize,
}

/// Retains initialized old-decoder scratch independently of the outer alias bank.
pub(crate) struct HistoricalDecoderSummary17 {
    pub(crate) kind_tag: Option<u8>,
    pub(crate) layout: usize,
    pub(crate) view_digest: Option<[u8; 32]>,
    pub(crate) in_progress: bool,
    pub(crate) content_edge: Option<(u8, usize)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HistoricalCustodyPhase17 {
    Allocating,
    Receiving,
    Complete,
    Failed,
}

pub(super) fn role(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn scalar<T: HistoricalType>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<T, ProviderError> {
    ledger.read::<T>(input, true)?.ok_or_else(invalid)
}

pub(super) fn fixed_usizes<const N: usize>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<[usize; N], ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut output = [0; N];
    for value in &mut output {
        *value = scalar(fields.next_value()?.ok_or_else(invalid)?, ledger)?;
    }
    fields.finish()?;
    Ok(output)
}

fn native_vector<T: HistoricalType>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    layout: (usize, usize),
) -> Result<(usize, Option<Vec<T>>), ProviderError> {
    let capacity = ledger.row_aligned(MetadataRecordKind::Vector, layout.0, layout.1)?;
    if capacity
        .checked_mul(layout.0)
        .is_none_or(|bytes| bytes > ledger.limits.maximum_owned_backing_bytes)
        || capacity
            .checked_mul(std::mem::size_of::<T>())
            .is_none_or(|bytes| bytes > ledger.limits.maximum_owned_backing_bytes)
    {
        return Err(invalid());
    }
    let mut fields = Fields::array(input)?;
    let mut output = Vec::new();
    if build {
        output.try_reserve_exact(capacity).map_err(|_| invalid())?;
        if output.capacity() != capacity {
            return Err(invalid());
        }
    }
    let mut length = 0usize;
    while let Some(raw) = fields.next_value()? {
        length = length.checked_add(1).ok_or_else(invalid)?;
        if length > capacity {
            return Err(invalid());
        }
        if let Some(value) = ledger.read::<T>(raw, build)? {
            output.push(value);
        }
    }
    Ok((capacity, build.then_some(output)))
}

fn bank_length(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<usize, ProviderError> {
    let mut bank = Fields::array(input)?;
    let mut bytes = Fields::array(bank.next_value()?.ok_or_else(invalid)?)?;
    let compact = bytes.next_value()?.ok_or_else(invalid)?;
    let capacity = scalar(bytes.next_value()?.ok_or_else(invalid)?, ledger)?;
    bytes.finish()?;
    Ok(
        crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes::validate(
            compact,
            ledger.limits.maximum_input_bytes,
            capacity,
        )?
        .decoded_length(),
    )
}

impl HistoricalType for HistoricalInputBank17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let bytes = ledger
            .read::<HistoricalReversedByteBank17>(fields.next_value()?.ok_or_else(invalid)?, build)?;
        let mut transfer_fields = Fields::array(fields.next_value()?.ok_or_else(invalid)?)?;
        let mut transfer = [0; 128];
        for byte in &mut transfer {
            *byte = scalar(transfer_fields.next_value()?.ok_or_else(invalid)?, ledger)?;
        }
        transfer_fields.finish()?;
        let transfer_length = scalar(fields.next_value()?.ok_or_else(invalid)?, ledger)?;
        let begun = scalar(fields.next_value()?.ok_or_else(invalid)?, ledger)?;
        let finished = scalar(fields.next_value()?.ok_or_else(invalid)?, ledger)?;
        fields.finish()?;
        if transfer_length > transfer.len() {
            return Err(invalid());
        }
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            bytes: bytes.ok_or_else(invalid)?.0,
            transfer,
            transfer_length,
            begun,
            finished,
        }))
    }
}

impl HistoricalType for HistoricalInputChunk17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let [input, offset, length] = fixed_usizes(input, ledger)?;
        if input >= 6 || length == 0 || length > 4096 || offset.checked_add(length).is_none() {
            return Err(invalid());
        }
        Ok(build.then_some(Self {
            input,
            offset,
            length,
        }))
    }
}

impl HistoricalType for HistoricalDecoderSummary17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let kind_tag: Option<u8> = scalar(fields.next_value()?.ok_or_else(invalid)?, ledger)?;
        // This explicit17 DATA projection appends tags for newer shared kinds;
        // it does not participate in the old11 alias-row admission grammar.
        if kind_tag.is_some_and(|tag| tag > 34) {
            return Err(invalid());
        }
        let layout = scalar(fields.next_value()?.ok_or_else(invalid)?, ledger)?;
        let raw_digest = fields.next_value()?.ok_or_else(invalid)?;
        let view_digest = if raw_digest == b"null" {
            None
        } else {
            Some(FixedArray32Field17::read(raw_digest, ledger, true)?.ok_or_else(invalid)?)
        };
        let in_progress = scalar(fields.next_value()?.ok_or_else(invalid)?, ledger)?;
        let edge = fields.next_value()?.ok_or_else(invalid)?;
        let content_edge = if edge == b"null" {
            None
        } else {
            let mut edge = Fields::array(edge)?;
            let tag: u8 = scalar(edge.next_value()?.ok_or_else(invalid)?, ledger)?;
            if tag > 1 {
                return Err(invalid());
            }
            let index = scalar(edge.next_value()?.ok_or_else(invalid)?, ledger)?;
            edge.finish()?;
            Some((tag, index))
        };
        fields.finish()?;
        Ok(build.then_some(Self {
            kind_tag,
            layout,
            view_digest,
            in_progress,
            content_edge,
        }))
    }
}

impl HistoricalType for HistoricalRestoreInputCustody17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role(
            fields.named("schema")?,
            "source-private.native-current-input-custody/17",
        )?;
        let creator = ledger.read::<u32>(fields.named("creator")?, build)?;
        role(
            fields.named("thread_role")?,
            "same-original-native-thread-history-only",
        )?;
        let quote = ledger.read::<HistoricalInputQuote17>(fields.named("quote")?, build)?;
        let mut bank_fields = Fields::array(fields.named("banks")?)?;
        let mut banks = [const { None }; 6];
        let mut bank_lengths = [0; 6];
        for (bank, length) in banks.iter_mut().zip(&mut bank_lengths) {
            let raw = bank_fields.next_value()?.ok_or_else(invalid)?;
            *length = bank_length(raw, ledger)?;
            *bank = ledger.read::<HistoricalInputBank17>(raw, build)?;
        }
        bank_fields.finish()?;
        let layouts = OriginalCompleteRestoreInputCustody::current17_element_layouts_data();
        let raw_chunks = fields.named("chunks")?;
        let mut checked_chunks = Fields::array(raw_chunks)?;
        while let Some(raw) = checked_chunks.next_value()? {
            let [input, offset, length] = fixed_usizes(raw, ledger)?;
            if input >= 6
                || length == 0
                || length > 4096
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > bank_lengths[input])
            {
                return Err(invalid());
            }
        }
        let (actual_chunk_capacity, chunks) =
            native_vector::<HistoricalInputChunk17>(raw_chunks, ledger, build, layouts[0])?;
        let chunk_capacity: usize = scalar(fields.named("chunk_capacity")?, ledger)?;
        if actual_chunk_capacity != chunk_capacity {
            return Err(invalid());
        }
        let (actual_summary_capacity, summaries) = native_vector::<HistoricalDecoderSummary17>(
            fields.named("decoder_summaries")?,
            ledger,
            build,
            layouts[1],
        )?;
        let summary_capacity: usize = scalar(fields.named("decoder_summary_capacity")?, ledger)?;
        if actual_summary_capacity != summary_capacity {
            return Err(invalid());
        }
        let native_encoded = ledger
            .read::<Option<HistoricalReversedByteBank17>>(fields.named("native_encoded")?, build)?;
        let native_owner = ledger
            .read::<Option<HistoricalSealedNativeImport17>>(fields.named("native_owner")?, build)?;
        let mapping_attempt = ledger.read::<Option<HistoricalPreparedNativeMapping17>>(
            fields.named("mapping_attempt")?,
            build,
        )?;
        let held_proof_quote_taken =
            ledger.read::<bool>(fields.named("held_proof_quote_taken")?, build)?;
        let next_input: usize = scalar(fields.named("next_input")?, ledger)?;
        if next_input > 6 {
            return Err(invalid());
        }
        let phase = match plain_string(fields.named("phase")?)? {
            "allocating" => HistoricalCustodyPhase17::Allocating,
            "receiving" => HistoricalCustodyPhase17::Receiving,
            "complete" => HistoricalCustodyPhase17::Complete,
            "failed" => HistoricalCustodyPhase17::Failed,
            _ => return Err(invalid()),
        };
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        let [a, b, c, d, e, f] = banks;
        let banks = [
            a.ok_or_else(invalid)?,
            b.ok_or_else(invalid)?,
            c.ok_or_else(invalid)?,
            d.ok_or_else(invalid)?,
            e.ok_or_else(invalid)?,
            f.ok_or_else(invalid)?,
        ];
        let chunks = chunks.ok_or_else(invalid)?;
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            quote: quote.ok_or_else(invalid)?,
            banks,
            chunks,
            summaries: summaries.ok_or_else(invalid)?,
            native_encoded: native_encoded.ok_or_else(invalid)?.map(|bank| bank.0),
            native_owner: native_owner.ok_or_else(invalid)?,
            mapping_attempt: mapping_attempt.ok_or_else(invalid)?,
            held_proof_quote_taken: held_proof_quote_taken.ok_or_else(invalid)?,
            next_input,
            phase,
        }))
    }
}

impl HistoricalRestoreInputCustody17 {
    /// Joins both nested quote role edges to the actual enclosing native roots.
    ///
    /// # Errors
    /// Refuses a different actor, codec or physical frame-bank alias group.
    pub(crate) fn authenticate_quote_groups_data(
        &self,
        actor: usize,
        codec: usize,
        frames: usize,
    ) -> Result<(), ProviderError> {
        if self.quote.actor_group != actor
            || self.quote.codec_group != codec
            || self.quote.held_proof.actor_group != actor
            || self.quote.held_proof.codec_group != codec
            || self.quote.held_proof.frames_group != frames
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Joins the full retained input quote and finished banks to their Prepare.
    ///
    /// This DATA comparison does not establish receipt, input installation,
    /// reconstruction success or native currentness.
    ///
    /// # Errors
    /// Refuses changed exact request commitment/roster/limits, impossible retained
    /// bank capacity or a finished bank whose full ContentRef no longer matches.
    pub(crate) fn authenticate_prepare_data(
        &self,
        request: &crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestorePrepareRequest,
    ) -> Result<(), ProviderError> {
        let (digest, lengths, rows, nodes) =
            OriginalCompleteRestoreInputCustody::current17_request_facts_data(request)?;
        if self.quote.request_digest != digest
            || self.quote.input_lengths != lengths
            || self.quote.maximum_metadata_rows != rows
            || self.quote.maximum_nodes != nodes
            || self.quote.actor_group != self.quote.held_proof.actor_group
            || self.quote.codec_group != self.quote.held_proof.codec_group
        {
            return Err(invalid());
        }
        let target = &request.restoration;
        let references = [
            &request.native_protocol,
            &request.native_control,
            &request.native_anchor,
            &target.owner_state,
            &target.journal,
            &target.mapping,
        ];
        for ((bank, length), reference) in self.banks.iter().zip(lengths).zip(references) {
            if bank.bytes.capacity() > length || bank.bytes.len() > length {
                return Err(invalid());
            }
            if bank.finished {
                reference.verify(&bank.bytes)?;
            }
        }
        Ok(())
    }
}

/// Names closed reader/field views independently of dynamic reconstructed banks.
pub(crate) fn current_custody17_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<HistoricalRestoreInputCustody17>()
        + size_of::<HistoricalInputQuote17>()
        + size_of::<HistoricalProofQuote17>()
        + size_of::<HistoricalInputBank17>()
        + size_of::<HistoricalInputChunk17>()
        + size_of::<HistoricalDecoderSummary17>()
        + size_of::<HistoricalCustodyPhase17>()
        + size_of::<[Option<HistoricalInputBank17>; 6]>()
        + size_of::<[usize; 6]>()
        + size_of::<[u8; 128]>()
        + size_of::<[u8; 32]>()
        + 4 * size_of::<Fields<'static>>()
        + size_of::<crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes<'static>>()
        + size_of::<Vec<HistoricalInputChunk17>>()
        + size_of::<Vec<HistoricalDecoderSummary17>>()
        + size_of::<Result<Option<HistoricalRestoreInputCustody17>, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + OriginalCompleteRestoreInputCustody::current17_counter_scratch_data()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "decoder summary fixture assertions")]
mod summary_tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::retained_metadata::records::ValidatedMetadataRecords;

    #[test]
    fn explicit17_summary_tags_round_trip_and_unknown_tags_refuse() {
        let rows = ValidatedMetadataRecords::validate(b"[]", 1, 65536).unwrap();
        let limits = HistoricalJsonLimits {
            maximum_input_bytes: 65536,
            maximum_nodes: 1024,
            maximum_depth: 32,
            maximum_owned_backing_bytes: 65536,
            maximum_tree_entries: 1024,
        };
        for tag in 0..=34 {
            let input = format!("[{tag},24,null,true,null]");
            let mut ledger = Ledger::new(rows.rows(), limits);
            let decoded = ledger
                .read::<HistoricalDecoderSummary17>(input.as_bytes(), true)
                .unwrap()
                .unwrap();
            assert_eq!(decoded.kind_tag, Some(tag));
            assert_eq!(decoded.layout, 24);
            assert!(decoded.in_progress);
            assert!(decoded.view_digest.is_none());
            assert!(decoded.content_edge.is_none());
            assert!(ledger.rows.next().is_none());
        }

        for build in [false, true] {
            let mut ledger = Ledger::new(rows.rows(), limits);
            assert!(
                ledger
                    .read::<HistoricalDecoderSummary17>(b"[35,24,null,true,null]", build)
                    .is_err()
            );
        }
    }
}
