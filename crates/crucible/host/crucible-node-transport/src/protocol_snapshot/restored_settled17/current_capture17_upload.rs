//! Borrows exact upload transaction state without reconstructing native rights.
//!
//! The defining whole graph must first complete its real BlobLedger and native
//! supervisor roots. These leaves consume only their actual repeated alias
//! edges and preserve exact source fields/metadata cursors. No parsed row,
//! digest, possession result or published label can construct a live scope.

use super::{
    current_contracts::{CurrentField17, Optional17},
    current_inline::FixedArray32Field17,
    current_lineage17::{BorrowedLineageField17, loan},
    current_shared::read_reference17,
};
use crate::{
    ProviderError,
    envelope::RequestOrigin,
    protocol_snapshot::owned11::typed::{Fields, Ledger, invalid, plain_string},
    reference_packet::service::{
        native_startup::PacketNativeStartupAllocationRow,
        original_native_supervisor_alignment17_data, original_native_supervisor_layout,
    },
    retained_metadata::aliases::MetadataSharedKind,
};
use crucible_node_format::{ContentRef, Id, U64};
use serde_json::Value;
use std::mem::size_of;

/// Preserves all exact transaction phases as inert historical DATA.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum CurrentCaptureUploadPhase17 {
    Installed,
    EffectFailed,
    ReplyFailed,
    ReplyComplete,
    Publishing,
    Published,
    Failed,
}

/// Preserves each defining Blob effect/reply phase, including partial failures.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum CurrentBlobUploadPhase17 {
    EffectRunning,
    EffectFailed,
    EffectComplete,
    ReplyRunning,
    ReplyFailed,
    ReplyComplete,
}

/// Borrows immutable row/stamp data beside already completed actual root edges.
pub(crate) struct BorrowedCaptureUploadStorage17<'body> {
    pub(crate) definition: &'body [u8],
    pub(crate) ledger_group: usize,
    pub(crate) supervisor_group: usize,
    pub(crate) before: [u8; 32],
    pub(crate) input: [u8; 32],
    pub(crate) row: PacketNativeStartupAllocationRow,
    pub(crate) reply_geometry: [usize; 11],
}

/// Borrows real Progress/Verified identities without manufacturing possession.
pub(crate) enum BorrowedCaptureUploadResult17<'body, 'rows> {
    Progress {
        transfer: BorrowedLineageField17<'body, 'rows, Id>,
        next_offset: U64,
        maximum_chunk_bytes: U64,
    },
    Verified {
        ledger_group: usize,
        origin: RequestOrigin,
        session: BorrowedLineageField17<'body, 'rows, Id>,
        incarnation: BorrowedLineageField17<'body, 'rows, Id>,
        transfer: BorrowedLineageField17<'body, 'rows, Id>,
        content: BorrowedLineageField17<'body, 'rows, ContentRef>,
    },
}

/// Borrows all initialized effect/result/reply fields and their real alias joins.
pub(crate) struct BorrowedCaptureUploadEffect17<'body, 'rows> {
    pub(crate) definition: &'body [u8],
    pub(crate) ledger_group: usize,
    pub(crate) supervisor_group: usize,
    pub(crate) input: [u8; 32],
    pub(crate) before: [u8; 32],
    pub(crate) after: Option<[u8; 32]>,
    pub(crate) phase: CurrentBlobUploadPhase17,
    pub(crate) result: Option<BorrowedCaptureUploadResult17<'body, 'rows>>,
    pub(crate) reply: BorrowedLineageField17<'body, 'rows, Option<Value>>,
}

/// Borrows the actual once transaction, without a native owner constructor.
pub(crate) struct BorrowedCurrentCaptureUpload17<'body, 'rows> {
    pub(crate) definition: &'body [u8],
    pub(crate) storage: BorrowedCaptureUploadStorage17<'body>,
    pub(crate) effect: Option<BorrowedCaptureUploadEffect17<'body, 'rows>>,
    pub(crate) admitted: PacketNativeStartupAllocationRow,
    pub(crate) publication_record: Option<usize>,
    pub(crate) phase: CurrentCaptureUploadPhase17,
}

fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next_value()?.ok_or_else(invalid)
}

fn marker(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

fn ledger_edge(ledger: &mut Ledger<'_, '_, '_>) -> Result<usize, ProviderError> {
    let layouts = crate::blob::original_blob_layouts();
    let (alignment, _, _) = crate::blob::original_blob_alignment17_data();
    read_reference17(
        ledger,
        MetadataSharedKind::BlobLedger,
        (layouts.state, alignment),
    )
}

fn supervisor_edge(ledger: &mut Ledger<'_, '_, '_>) -> Result<usize, ProviderError> {
    read_reference17(
        ledger,
        MetadataSharedKind::NativeSupervisor,
        (
            original_native_supervisor_layout(),
            original_native_supervisor_alignment17_data(),
        ),
    )
}

fn fixed32(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<[u8; 32], ProviderError> {
    FixedArray32Field17::read(input, ledger, true)?.ok_or_else(invalid)
}

// Failed installation retains the exact proposed row even if it was short or
// arithmetically invalid. Decoding these three scalars confers no spending right.
fn row(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    let mut fields = Fields::object(input)?;
    let retained_requested_bytes = ledger
        .read::<U64>(fields.named("retained_requested_bytes")?, true)?
        .ok_or_else(invalid)?;
    let maximum_simultaneous_transient_bytes = ledger
        .read::<U64>(fields.named("maximum_simultaneous_transient_bytes")?, true)?
        .ok_or_else(invalid)?;
    let declared_counter_scratch_bytes = ledger
        .read::<U64>(fields.named("declared_counter_scratch_bytes")?, true)?
        .ok_or_else(invalid)?;
    fields.finish()?;
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes,
        maximum_simultaneous_transient_bytes,
        declared_counter_scratch_bytes,
    })
}

fn geometry(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<[usize; 11], ProviderError> {
    let mut fields = Fields::object(input)?;
    let mut values = [0usize; 11];
    for (value, name) in values.iter_mut().zip([
        "dom_and_canonical_scratch_bytes",
        "retained_value_backing_bytes",
        "projected_parser_requested_bytes",
        "canonical_output_requested_bytes",
        "serializer_temporary_requested_bytes",
        "declared_counter_scratch_bytes",
        "maximum_encoded_bytes",
        "sequence_elements",
        "sequence_containers",
        "serialized_value_nodes",
        "serialized_capacity_records",
    ]) {
        *value = ledger
            .read::<usize>(fields.named(name)?, true)?
            .ok_or_else(invalid)?;
    }
    fields.finish()?;
    Ok(values)
}

fn storage<'body>(
    input: &'body [u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<BorrowedCaptureUploadStorage17<'body>, ProviderError> {
    let mut fields = Fields::object(input)?;
    marker(
        fields.named("schema")?,
        "source-private.native-capture-upload-storage/17",
    )?;
    marker(fields.named("ledger")?, "current-native-blob-ledger")?;
    marker(fields.named("supervisor")?, "current-native-supervisor")?;
    let before_raw = fields.named("before")?;
    let input_raw = fields.named("input")?;
    let row_raw = fields.named("row")?;
    let reply_raw = fields.named("reply_geometry")?;
    fields.finish()?;

    let ledger_group = ledger_edge(ledger)?;
    let supervisor_group = supervisor_edge(ledger)?;
    let before = fixed32(before_raw, ledger)?;
    let input_stamp = fixed32(input_raw, ledger)?;
    let row = row(row_raw, ledger)?;
    let reply_geometry = geometry(reply_raw, ledger)?;
    Ok(BorrowedCaptureUploadStorage17 {
        definition: input,
        ledger_group,
        supervisor_group,
        before,
        input: input_stamp,
        row,
        reply_geometry,
    })
}

fn result<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<Option<BorrowedCaptureUploadResult17<'body, 'rows>>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    let mut fields = Fields::array(input)?;
    let result = match plain_string(next(&mut fields)?)? {
        "progress" => {
            let transfer = loan(next(&mut fields)?, ledger)?;
            let next_offset = ledger
                .read::<U64>(next(&mut fields)?, true)?
                .ok_or_else(invalid)?;
            let maximum_chunk_bytes = ledger
                .read::<U64>(next(&mut fields)?, true)?
                .ok_or_else(invalid)?;
            BorrowedCaptureUploadResult17::Progress {
                transfer,
                next_offset,
                maximum_chunk_bytes,
            }
        }
        "verified" => {
            marker(next(&mut fields)?, "current-native-blob-ledger")?;
            let key_raw = next(&mut fields)?;
            let content_raw = next(&mut fields)?;
            let ledger_group = ledger_edge(ledger)?;
            let mut key = Fields::array(key_raw)?;
            let origin = match plain_string(next(&mut key)?)? {
                "controller" => RequestOrigin::Controller,
                "provider" => RequestOrigin::Provider,
                _ => return Err(invalid()),
            };
            let session = loan(next(&mut key)?, ledger)?;
            let incarnation = loan(next(&mut key)?, ledger)?;
            let transfer = loan(next(&mut key)?, ledger)?;
            key.finish()?;
            let content = loan(content_raw, ledger)?;
            BorrowedCaptureUploadResult17::Verified {
                ledger_group,
                origin,
                session,
                incarnation,
                transfer,
                content,
            }
        }
        _ => return Err(invalid()),
    };
    fields.finish()?;
    Ok(Some(result))
}

fn effect<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<Option<BorrowedCaptureUploadEffect17<'body, 'rows>>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    let mut fields = Fields::object(input)?;
    marker(
        fields.named("schema")?,
        "source-private.native-capture-upload-attempt/17",
    )?;
    marker(fields.named("ledger")?, "current-native-blob-ledger")?;
    marker(fields.named("supervisor")?, "current-native-supervisor")?;
    let input_raw = fields.named("input")?;
    let before_raw = fields.named("before")?;
    let after_raw = fields.named("after")?;
    let phase = match plain_string(fields.named("phase")?)? {
        "effect-running" => CurrentBlobUploadPhase17::EffectRunning,
        "effect-failed" => CurrentBlobUploadPhase17::EffectFailed,
        "effect-complete" => CurrentBlobUploadPhase17::EffectComplete,
        "reply-running" => CurrentBlobUploadPhase17::ReplyRunning,
        "reply-failed" => CurrentBlobUploadPhase17::ReplyFailed,
        "reply-complete" => CurrentBlobUploadPhase17::ReplyComplete,
        _ => return Err(invalid()),
    };
    let result_raw = fields.named("result")?;
    let reply_raw = fields.named("reply")?;
    fields.finish()?;

    let ledger_group = ledger_edge(ledger)?;
    let supervisor_group = supervisor_edge(ledger)?;
    let input_stamp = fixed32(input_raw, ledger)?;
    let before = fixed32(before_raw, ledger)?;
    let after = <Optional17<FixedArray32Field17> as CurrentField17>::read(after_raw, ledger, true)?
        .ok_or_else(invalid)?;
    let result = result(result_raw, ledger)?;
    let reply = loan(reply_raw, ledger)?;
    if let Some(BorrowedCaptureUploadResult17::Verified {
        ledger_group: verified_group,
        ..
    }) = &result
        && *verified_group != ledger_group
    {
        return Err(invalid());
    }
    if matches!(
        phase,
        CurrentBlobUploadPhase17::EffectComplete
            | CurrentBlobUploadPhase17::ReplyRunning
            | CurrentBlobUploadPhase17::ReplyComplete
    ) && (after.is_none() || result.is_none())
    {
        return Err(invalid());
    }
    if phase == CurrentBlobUploadPhase17::ReplyComplete && reply_raw.first() != Some(&b'{') {
        return Err(invalid());
    }
    Ok(Some(BorrowedCaptureUploadEffect17 {
        definition: input,
        ledger_group,
        supervisor_group,
        input: input_stamp,
        before,
        after,
        phase,
        result,
        reply,
    }))
}

/// Borrows the actual source-order upload leaf after complete graph root checks.
///
/// This parser retains inert fields only. The enclosing reader must join the
/// exact actual ingress original/body to its stamps and Source/once history;
/// this leaf cannot authenticate a live Scope or turn row labels into credit.
///
/// # Errors
/// Refuses malformed/unknown/missing/reordered fields, wrong closed variants,
/// absent/changed actual alias roots, metadata mismatch or inconsistent phases.
pub(crate) fn read_current_capture17_upload_data<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<BorrowedCurrentCaptureUpload17<'body, 'rows>, ProviderError> {
    let mut fields = Fields::object(input)?;
    marker(
        fields.named("schema")?,
        "source-private.native-capture-upload-action/17",
    )?;
    let storage_raw = fields.named("storage")?;
    let effect_raw = fields.named("effect")?;
    let admitted_raw = fields.named("admitted")?;
    let publication_raw = fields.named("publication_record")?;
    let phase_raw = fields.named("phase")?;
    fields.finish()?;

    let storage = storage(storage_raw, ledger)?;
    let effect = effect(effect_raw, ledger)?;
    let admitted = row(admitted_raw, ledger)?;
    let publication_record = ledger
        .read::<Option<usize>>(publication_raw, true)?
        .ok_or_else(invalid)?;
    let phase = match plain_string(phase_raw)? {
        "installed" => CurrentCaptureUploadPhase17::Installed,
        "effect_failed" => CurrentCaptureUploadPhase17::EffectFailed,
        "reply_failed" => CurrentCaptureUploadPhase17::ReplyFailed,
        "reply_complete" => CurrentCaptureUploadPhase17::ReplyComplete,
        "publishing" => CurrentCaptureUploadPhase17::Publishing,
        "published" => CurrentCaptureUploadPhase17::Published,
        "failed" => CurrentCaptureUploadPhase17::Failed,
        _ => return Err(invalid()),
    };
    if let Some(effect) = &effect
        && (effect.ledger_group != storage.ledger_group
            || effect.supervisor_group != storage.supervisor_group
            || effect.input != storage.input
            || effect.before != storage.before)
    {
        return Err(invalid());
    }
    if phase != CurrentCaptureUploadPhase17::Failed {
        admitted.requested_peak_data()?;
        for (have, need) in [
            (
                admitted.retained_requested_bytes,
                storage.row.retained_requested_bytes,
            ),
            (
                admitted.maximum_simultaneous_transient_bytes,
                storage.row.maximum_simultaneous_transient_bytes,
            ),
            (
                admitted.declared_counter_scratch_bytes,
                storage.row.declared_counter_scratch_bytes,
            ),
        ] {
            if have < need {
                return Err(invalid());
            }
        }
    }
    match phase {
        CurrentCaptureUploadPhase17::Installed
            if effect.is_some() || publication_record.is_some() =>
        {
            return Err(invalid());
        }
        CurrentCaptureUploadPhase17::ReplyComplete
        | CurrentCaptureUploadPhase17::Publishing
        | CurrentCaptureUploadPhase17::Published => {
            if effect
                .as_ref()
                .is_none_or(|effect| effect.phase != CurrentBlobUploadPhase17::ReplyComplete)
            {
                return Err(invalid());
            }
        }
        _ => {}
    }
    if phase == CurrentCaptureUploadPhase17::Published && publication_record.is_none()
        || phase != CurrentCaptureUploadPhase17::Published
            && phase != CurrentCaptureUploadPhase17::Failed
            && publication_record.is_some()
    {
        return Err(invalid());
    }
    Ok(BorrowedCurrentCaptureUpload17 {
        definition: input,
        storage,
        effect,
        admitted,
        publication_record,
        phase,
    })
}

/// Names exact borrowed leaf/result/alias/parser and fixed scalar view headers.
pub(crate) fn current_capture17_upload_counter_scratch_data() -> usize {
    size_of::<BorrowedCurrentCaptureUpload17<'static, 'static>>()
        + size_of::<BorrowedCaptureUploadStorage17<'static>>()
        + size_of::<BorrowedCaptureUploadEffect17<'static, 'static>>()
        + size_of::<Option<BorrowedCaptureUploadEffect17<'static, 'static>>>()
        + size_of::<BorrowedCaptureUploadResult17<'static, 'static>>()
        + size_of::<Option<BorrowedCaptureUploadResult17<'static, 'static>>>()
        + size_of::<BorrowedLineageField17<'static, 'static, Id>>() * 3
        + size_of::<BorrowedLineageField17<'static, 'static, ContentRef>>()
        + size_of::<BorrowedLineageField17<'static, 'static, Option<Value>>>()
        + size_of::<Fields<'static>>() * 3
        + size_of::<[usize; 11]>()
        + size_of::<[&str; 11]>()
        + size_of::<std::slice::IterMut<'static, usize>>()
        + size_of::<std::array::IntoIter<&'static str, 11>>()
        + size_of::<
            std::iter::Zip<
                std::slice::IterMut<'static, usize>,
                std::array::IntoIter<&'static str, 11>,
            >,
        >()
        + size_of::<PacketNativeStartupAllocationRow>() * 2
        + size_of::<[(U64, U64); 3]>()
        + size_of::<std::array::IntoIter<(U64, U64), 3>>()
        + size_of::<[u8; 32]>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<Option<[u8; 32]>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<BorrowedCurrentCaptureUpload17<'static, 'static>, ProviderError>>()
}
