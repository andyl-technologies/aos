//! Identifies the unique actual terminal inside an evidence-bearing reply prefix.
//!
//! The real prefix places its Response before BlobBegin/Chunk/Finish requests.
//! Position alone is not terminal identity. The caller retains and authenticates
//! the complete sent/ACK prefix; this borrowed lookup creates no dispatch right.

use crate::{
    ProviderError,
    envelope::{Envelope, MessageKind},
};

/// Borrows the unique correlated Response and its actual retained frame index.
///
/// # Errors
/// Refuses an absent or duplicate Response and any changed method, route,
/// correlation, operation or response extension. Evidence requests are skipped.
pub(crate) fn original_restored_response_data<'a>(
    original: &Envelope,
    frames: &'a [Envelope],
) -> Result<(usize, &'a Envelope), ProviderError> {
    if original.message != MessageKind::Request
        || original.request_id.0.is_none()
        || !matches!(
            original.method,
            crate::envelope::Method::Activate
                | crate::envelope::Method::WorldActivate
                | crate::envelope::Method::Observe
        )
    {
        return Err(ProviderError::Correlation(
            "restored prefix original domain differs",
        ));
    }
    let mut terminal = None;
    for (index, frame) in frames.iter().enumerate() {
        if frame.message != MessageKind::Response {
            continue;
        }
        if frame.method != original.method
            || frame.request_id != original.request_id
            || frame.session_id != original.session_id
            || frame.incarnation_id != original.incarnation_id
            || frame.node_id != original.node_id
            || frame.execution_owner_id != original.execution_owner_id
            || frame.capture_owner_id != original.capture_owner_id
            || frame.operation_id != original.operation_id
            || !frame.extensions.is_empty()
            || terminal.replace((index, frame)).is_some()
        {
            return Err(ProviderError::Correlation(
                "restored prefix terminal response differs",
            ));
        }
    }
    terminal.ok_or(ProviderError::Correlation(
        "restored prefix terminal response absent",
    ))
}

/// Names the complete borrowed lookup and returned actual-index views.
pub(crate) fn original_restored_response_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&Envelope>()
        + size_of::<&[Envelope]>()
        + size_of::<std::slice::Iter<'static, Envelope>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, Envelope>>>()
        + size_of::<(usize, &Envelope)>()
        + size_of::<Option<(usize, &Envelope)>>()
        + size_of::<Result<(usize, &Envelope), ProviderError>>()
        + size_of::<MessageKind>() * 2
}
