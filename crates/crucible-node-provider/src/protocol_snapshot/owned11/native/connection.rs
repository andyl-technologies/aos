//! Restores the complete native connection as inert historical typed owners.

use super::super::{
    reader::HistoricalFrameReaderFacts,
    state::{HistoricalAuthority, HistoricalCorrelations, next, tag},
    typed::{Fields, invalid, plain_string},
};
use super::{
    policy::HistoricalNativePolicy, shared::NativeLedger, token::HistoricalNativeAckToken,
};
use crate::{
    ProviderError,
    retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind},
    transport::DecodedCompactOriginalFrames,
};
use std::rc::Rc;

/// Retains native transport history without creating a stream or live registrar.
pub struct HistoricalNativeConnection {
    /// Retains the checked historical actor alias group.
    pub actor_group: usize,
    /// Retains all actual authority fields and backing capacities.
    pub authority: HistoricalAuthority,
    /// Retains the full original correlation ledger.
    pub correlations: HistoricalCorrelations,
    /// Retains the checked schema/codec owner group, without a live verifier.
    pub codec_group: usize,
    /// Shares complete immutable policy data with boot and token owners.
    pub policy: Rc<HistoricalNativePolicy>,
    /// Shares the complete physical literal bank with the assigned identity.
    pub frames: Rc<DecodedCompactOriginalFrames>,
    /// Retains actual reader fields without inferring a new receiving cut.
    pub reader: HistoricalFrameReaderFacts,
    /// Shares the exact original ledger retained independently by Connection.
    pub blob_ledger: Rc<super::blob::HistoricalNativeBlobLedger>,
    /// Identifies the checked original supervisor group.
    pub supervisor_group: usize,
    /// Retains the original packet-schema installation flag.
    pub packet_schema: bool,
    /// Retains the original connected-schema installation flag.
    pub connected_packet_schema: bool,
    /// Retains the sticky transport fence as historical data.
    pub fenced: bool,
    /// Retains the full historical verified admission, with no installation right.
    pub admission: HistoricalNativeAckToken,
}

pub(super) fn codec(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
) -> Result<(usize, Option<Rc<HistoricalNativePolicy>>), ProviderError> {
    let layout = crate::connection::owned_codec_enum_layout();
    let (start, group) = ledger.begin(MetadataSharedKind::Codec, layout)?;
    let mut fields = Fields::array(input)?;
    tag(&mut fields, "source-private.native-codec/11")?;
    let policy_view = next(&mut fields)?;
    let mut selected = Fields::array(policy_view)?;
    let policy_tag = plain_string(next(&mut selected)?)?;
    if policy_tag == "source-private.native5-policy-owned-fresh-restore-allocation/18" {
        if !ledger.requires_invocation_class()? {
            return Err(invalid());
        }
    } else if !matches!(
        policy_tag,
        "source-private.native5-policy-owned-selected/13"
            | "source-private.native5-policy-owned-complete-restore/14"
            | "source-private.native5-policy-owned-restore-transfer/15"
            | "source-private.native5-policy-owned-restore-input-emitter/16"
            | "source-private.native5-policy-owned-capture-allocation/17"
    ) {
        return Err(invalid());
    }
    let policy = ledger.policy(policy_view, build)?;
    fields.finish()?;
    ledger.finish(start, group, layout, input)?;
    Ok((group, policy))
}

pub(super) fn read(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeConnection>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        if ledger.requires_invocation_class()? {
            super::outer::COMPLETE_NATIVE_INVOCATION_CONNECTION_FORMAT
        } else if ledger.requires_startup_class()? {
            super::outer::COMPLETE_NATIVE_STARTUP_CONNECTION_FORMAT
        } else {
            super::outer::COMPLETE_NATIVE_CONNECTION_FORMAT
        },
    )?;
    if plain_string(next(&mut fields)?)? != "historical-source-owner" {
        return Err(invalid());
    }
    let actor_layout = std::mem::size_of::<crate::protocol_snapshot::ProtocolCaptureOwner>();
    if ledger.ledger.row(MetadataRecordKind::Shared, 1)? != actor_layout {
        return Err(invalid());
    }
    let actor_group = ledger.ledger.shared(
        MetadataSharedKind::ProtocolOwner,
        actor_layout,
        b"historical-source-owner",
        b"",
    )?;
    let authority = ledger
        .ledger
        .read::<HistoricalAuthority>(next(&mut fields)?, build)?;
    let correlation_start = ledger.ledger.rows.encoded_position();
    let correlations = ledger
        .ledger
        .read::<HistoricalCorrelations>(next(&mut fields)?, build)?;
    ledger.correlation_capacity_span =
        Some((correlation_start, ledger.ledger.rows.encoded_position()));
    let (codec_group, policy) = codec(next(&mut fields)?, ledger, build)?;
    let (schema_group, _) = codec(next(&mut fields)?, ledger, build)?;
    if codec_group != schema_group {
        return Err(invalid());
    }
    let frame_view = next(&mut fields)?;
    let frames = ledger.frames(frame_view, build, MetadataSharedKind::FrameBank)?;
    let reader_frames = ledger.frames(frame_view, build, MetadataSharedKind::FrameBank)?;
    if build
        && !Rc::ptr_eq(
            frames.as_ref().ok_or_else(invalid)?,
            reader_frames.as_ref().ok_or_else(invalid)?,
        )
    {
        return Err(invalid());
    }
    let reader = ledger
        .ledger
        .read::<HistoricalFrameReaderFacts>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    if reader.failed {
        return Err(invalid());
    }
    let blob_ledger = ledger.blobs(next(&mut fields)?, build)?;
    let supervisor = next(&mut fields)?;
    let supervisor_layout = crate::reference_packet::service::original_native_supervisor_layout();
    if plain_string(supervisor)? != "source-private.native-supervisor-owner/11"
        || ledger.ledger.row(MetadataRecordKind::Shared, 1)? != supervisor_layout
    {
        return Err(invalid());
    }
    let supervisor_group = ledger.ledger.shared(
        MetadataSharedKind::NativeSupervisor,
        supervisor_layout,
        supervisor,
        b"",
    )?;
    let packet_schema = ledger.ledger.read::<bool>(next(&mut fields)?, build)?;
    let connected_packet_schema = ledger.ledger.read::<bool>(next(&mut fields)?, build)?;
    let fenced = ledger.ledger.read::<bool>(next(&mut fields)?, build)?;
    tag(&mut fields, "provider")?;
    let admission = super::token::read(
        next(&mut fields)?,
        ledger,
        build,
        crate::reference_packet::service::ack_emitter::original_native_ack_boot_layout(),
    )?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeConnection {
        actor_group,
        authority: authority.ok_or_else(invalid)?,
        correlations: correlations.ok_or_else(invalid)?,
        codec_group,
        policy: policy.ok_or_else(invalid)?,
        frames: frames.ok_or_else(invalid)?,
        reader,
        blob_ledger: blob_ledger.ok_or_else(invalid)?,
        supervisor_group,
        packet_schema: packet_schema.ok_or_else(invalid)?,
        connected_packet_schema: connected_packet_schema.ok_or_else(invalid)?,
        fenced: fenced.ok_or_else(invalid)?,
        admission: admission.ok_or_else(invalid)?,
    }))
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativeConnection,
    actor_group,
    authority,
    correlations,
    codec_group,
    policy,
    frames,
    reader,
    blob_ledger,
    supervisor_group,
    packet_schema,
    connected_packet_schema,
    fenced,
    admission
);

pub(crate) mod current17;
