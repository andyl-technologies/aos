//! Retains the full input/proof quote fields and exact actual shared role groups.

use super::*;
use crate::protocol_snapshot::ProtocolCaptureOwner;
use crate::protocol_snapshot::restored_settled17::current_shared::read_reference17;
use crate::retained_metadata::aliases::MetadataSharedKind;
use crate::transport::original_frames::OriginalFrameReservation;
use std::{
    cell::RefCell,
    mem::{align_of, size_of},
};

pub(crate) struct HistoricalInputQuote17 {
    pub(crate) actor_group: usize,
    pub(crate) codec_group: usize,
    pub(crate) request_digest: [u8; 32],
    pub(crate) input_lengths: [usize; 6],
    pub(crate) maximum_metadata_rows: usize,
    pub(crate) maximum_nodes: usize,
    pub(crate) raw_input_bytes: usize,
    pub(crate) historical_backing_bytes: usize,
    pub(crate) reconstruction_lookup_bytes: usize,
    pub(crate) requested_geometry_bytes: usize,
    pub(crate) declared_scratch_and_owner_bytes: usize,
    pub(crate) custody_layout_bytes: usize,
    pub(crate) held_proof: HistoricalProofQuote17,
    pub(crate) sdk_requested_bytes: usize,
}

pub(crate) struct HistoricalProofQuote17 {
    pub(crate) actor_group: usize,
    pub(crate) codec_group: usize,
    pub(crate) frames_group: usize,
    pub(crate) maximum_frames: usize,
    pub(crate) requested_bytes: usize,
    pub(crate) prebuilding: bool,
}

fn actor(ledger: &mut Ledger<'_, '_, '_>) -> Result<usize, ProviderError> {
    read_reference17(
        ledger,
        MetadataSharedKind::ProtocolOwner,
        (
            size_of::<ProtocolCaptureOwner>(),
            align_of::<ProtocolCaptureOwner>(),
        ),
    )
}

fn codec(ledger: &mut Ledger<'_, '_, '_>) -> Result<usize, ProviderError> {
    read_reference17(
        ledger,
        MetadataSharedKind::Codec,
        crate::connection::native_codec_shared_layout17_data(),
    )
}

impl HistoricalType for HistoricalProofQuote17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role(
            fields.named("schema")?,
            "source-private.restore-proof-quote-history/17",
        )?;
        role(fields.named("actor_role")?, "native-connection-actor")?;
        let actor_group = actor(ledger)?;
        role(fields.named("codec_role")?, "native-connection-codec")?;
        let codec_group = codec(ledger)?;
        role(fields.named("bank_role")?, "native-connection-frames")?;
        let frames_group = read_reference17(
            ledger,
            MetadataSharedKind::FrameBank,
            (
                size_of::<RefCell<OriginalFrameReservation>>(),
                align_of::<RefCell<OriginalFrameReservation>>(),
            ),
        )?;
        let maximum_frames = ledger.read::<usize>(fields.named("maximum_frames")?, build)?;
        let requested_bytes = ledger.read::<usize>(fields.named("requested_bytes")?, build)?;
        let prebuilding = ledger.read::<bool>(fields.named("prebuilding")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            actor_group,
            codec_group,
            frames_group,
            maximum_frames: maximum_frames.ok_or_else(invalid)?,
            requested_bytes: requested_bytes.ok_or_else(invalid)?,
            prebuilding: prebuilding.ok_or_else(invalid)?,
        }))
    }
}

impl HistoricalType for HistoricalInputQuote17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role(
            fields.named("schema")?,
            "source-private.native-input-allocation-quote/17",
        )?;
        role(fields.named("actor_role")?, "native-connection-actor")?;
        let actor_group = actor(ledger)?;
        role(fields.named("codec_role")?, "native-connection-codec")?;
        let codec_group = codec(ledger)?;
        let request_digest =
            FixedArray32Field17::read(fields.named("request_digest")?, ledger, true)?
                .ok_or_else(invalid)?;
        let input_lengths = fixed_usizes(fields.named("input_lengths")?, ledger)?;
        let maximum_metadata_rows =
            ledger.read::<usize>(fields.named("maximum_metadata_rows")?, build)?;
        let maximum_nodes = ledger.read::<usize>(fields.named("maximum_nodes")?, build)?;
        let raw_input_bytes = ledger.read::<usize>(fields.named("raw_input_bytes")?, build)?;
        let historical_backing_bytes =
            ledger.read::<usize>(fields.named("historical_backing_bytes")?, build)?;
        let reconstruction_lookup_bytes =
            ledger.read::<usize>(fields.named("reconstruction_lookup_bytes")?, build)?;
        let requested_geometry_bytes =
            ledger.read::<usize>(fields.named("requested_geometry_bytes")?, build)?;
        let declared_scratch_and_owner_bytes =
            ledger.read::<usize>(fields.named("declared_scratch_and_owner_bytes")?, build)?;
        let custody_layout_bytes =
            ledger.read::<usize>(fields.named("custody_layout_bytes")?, build)?;
        let held_proof =
            ledger.read::<HistoricalProofQuote17>(fields.named("held_proof")?, build)?;
        let sdk_requested_bytes =
            ledger.read::<usize>(fields.named("sdk_requested_bytes")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            actor_group,
            codec_group,
            request_digest,
            input_lengths,
            maximum_metadata_rows: maximum_metadata_rows.ok_or_else(invalid)?,
            maximum_nodes: maximum_nodes.ok_or_else(invalid)?,
            raw_input_bytes: raw_input_bytes.ok_or_else(invalid)?,
            historical_backing_bytes: historical_backing_bytes.ok_or_else(invalid)?,
            reconstruction_lookup_bytes: reconstruction_lookup_bytes.ok_or_else(invalid)?,
            requested_geometry_bytes: requested_geometry_bytes.ok_or_else(invalid)?,
            declared_scratch_and_owner_bytes: declared_scratch_and_owner_bytes
                .ok_or_else(invalid)?,
            custody_layout_bytes: custody_layout_bytes.ok_or_else(invalid)?,
            held_proof: held_proof.ok_or_else(invalid)?,
            sdk_requested_bytes: sdk_requested_bytes.ok_or_else(invalid)?,
        }))
    }
}
