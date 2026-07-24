//! Shared-memory frame conversion for the uniform I/O lifecycle.

use crucible_shmem::FrameEntry;

use super::{DeviceError, PendingResponse, Request};

/// Converts an inbound shared-memory frame into the uniform request shape.
pub(super) fn request_from_frame(frame: &FrameEntry) -> Result<Request, DeviceError> {
    Ok(Request::new(
        frame.delivery_icount,
        frame.seq,
        frame.payload()?.to_vec(),
    ))
}

/// Converts a pending response into an outbound shared-memory frame.
pub(super) fn frame_from_pending_response(
    pending: &PendingResponse,
) -> Result<FrameEntry, DeviceError> {
    Ok(FrameEntry::new(
        pending.delivery_icount(),
        pending.key.src_node,
        pending.key.seq,
        &pending.response.payload,
    )?)
}
