//! Reads the stable compact original-frame leaf through one native17 group.

use super::*;
use crate::transport::{
    DecodedCompactOriginalFrames, ValidatedCompactOriginalFrames,
    original_frames::OriginalFrameReservation,
};

/// Retains complete original literal DATA and its checked archive-local group.
pub(crate) struct HistoricalNativeFrameRoot17 {
    pub(crate) frames: DecodedCompactOriginalFrames,
    pub(crate) group: usize,
}

/// Checks the complete compact leaf and exact requested backing before building.
///
/// # Errors
/// Refuses malformed literal/descriptor geometry, metadata or alias disagreement,
/// exceeded literal admission, or unavailable final backing.
pub(crate) fn read_native17_frame_root_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<HistoricalNativeFrameRoot17>, usize), ProviderError> {
    let start = ledger.rows.encoded_position();
    let layout = size_of::<RefCell<OriginalFrameReservation>>();
    if ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<RefCell<OriginalFrameReservation>>(),
    )? != layout
    {
        return Err(invalid());
    }
    let group = ledger.shared_begin(MetadataSharedKind::FrameBank)?;
    let plan = ValidatedCompactOriginalFrames::validate(
        input,
        ledger.limits.maximum_input_bytes,
        ledger.maximum_literal_bytes,
    )?;
    let mut fields = Fields::array(input)?;
    for _ in 0..4 {
        next(&mut fields)?;
    }
    let bytes = usize::try_from(unsigned(next(&mut fields)?)?).map_err(|_| invalid())?;
    let slots = usize::try_from(unsigned(next(&mut fields)?)?).map_err(|_| invalid())?;
    if ledger.row_aligned(MetadataRecordKind::Vector, 1, align_of::<u8>())? != bytes
        || ledger.row_aligned(
            MetadataRecordKind::Vector,
            crate::transport::original_frames::original_frame_slot_layout(),
            crate::transport::original_frames::original_frame_slot_alignment_data(),
        )? != slots
    {
        return Err(invalid());
    }
    ledger.literal_bytes = ledger
        .literal_bytes
        .checked_add(plan.allocated_bytes())
        .ok_or_else(invalid)?;
    if ledger.literal_bytes > ledger.maximum_literal_bytes {
        return Err(invalid());
    }
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout, input, rows)?;
    plan.native17_target_data(ledger)?;
    let frames = if build {
        Some(plan.reconstruct()?)
    } else {
        None
    };
    Ok((
        frames.map(|frames| HistoricalNativeFrameRoot17 { frames, group }),
        group,
    ))
}
