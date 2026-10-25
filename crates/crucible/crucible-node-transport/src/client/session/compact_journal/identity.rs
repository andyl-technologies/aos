//! Hashes compact originals by borrowing the defining request projection.
//!
//! Root fields have fixed ASCII JCS order. The body and extension maps use the
//! authoritative borrowed object writers at their actual enclosing depth.
//! Neither whole-envelope Value projection is constructed. Canonical text,
//! object ordering, escaping, diagnostics and recursive controls still require
//! independent transient admission before Source selection.

use super::{Envelope, HashRef, MessageKind, ProviderError, RequestOrigin, credit};
use crate::client::compact_json::{Output, field};
use crucible_node_format::{ContractError, canonical};
use std::io::{self, Write};

mod storage;
pub(super) use storage::{counter_scratch_data, storage_data};

pub(super) fn request_hash(
    request: &Envelope,
    origin: RequestOrigin,
    canonical_envelope_bytes: usize,
) -> Result<HashRef, ProviderError> {
    request.validate()?;
    if request.message != MessageKind::Request || request.method == crate::envelope::Method::Hello {
        return Err(ProviderError::Correlation(
            "only requests have request identity",
        ));
    }

    let expected = projection_bytes(request, origin, canonical_envelope_bytes)?;
    let mut output = Output::new(expected)?;
    let result = write_projection(request, origin, &mut output);
    if output.refused {
        return Err(credit());
    }
    result?;
    if output.bytes.len() != expected {
        return Err(ProviderError::Frame("compact request projection extent"));
    }

    Ok(canonical::hash("cnp.request.v1", &output.bytes)?)
}

fn projection_bytes(
    request: &Envelope,
    origin: RequestOrigin,
    envelope_bytes: usize,
) -> Result<usize, ProviderError> {
    let mut sequence = request.sequence.get();
    let mut digits = 1usize;
    while sequence >= 10 {
        sequence /= 10;
        digits += 1;
    }
    let origin_bytes = match origin {
        RequestOrigin::Controller => "controller".len(),
        RequestOrigin::Provider => "provider".len(),
    };
    // Each complete pair includes its adjacent comma. The projection removes
    // two pairs and inserts one; object order cannot change the total length.
    envelope_bytes
        .checked_sub(b"\"message\":\"request\",".len())
        .and_then(|bytes| bytes.checked_sub(b"\"sequence\":\"\",".len() + digits))
        .and_then(|bytes| bytes.checked_add(b"\"request_origin\":\"\",".len() + origin_bytes))
        .ok_or_else(credit)
}

fn write_projection(
    request: &Envelope,
    origin: RequestOrigin,
    output: &mut Output,
) -> Result<(), ProviderError> {
    // Exhaustive borrowing forces review of this projection if Envelope grows.
    let Envelope {
        protocol,
        message: _,
        session_id,
        incarnation_id,
        node_id,
        execution_owner_id,
        capture_owner_id,
        request_id,
        operation_id,
        sequence: _,
        method,
        body,
        extensions,
    } = request;

    output.write_all(b"{\"body\":")?;
    canonical::canonical_json_object_to_writer_at_depth(body, output, 1)?;
    field(output, b",\"capture_owner_id\":", capture_owner_id)?;
    field(output, b",\"execution_owner_id\":", execution_owner_id)?;
    output.write_all(b",\"extensions\":")?;
    canonical::canonical_json_btree_object_to_writer_at_depth(extensions, output, 1)?;
    field(output, b",\"incarnation_id\":", incarnation_id)?;
    field(output, b",\"method\":", method)?;
    field(output, b",\"node_id\":", node_id)?;
    field(output, b",\"operation_id\":", operation_id)?;
    field(output, b",\"protocol\":", protocol)?;
    field(output, b",\"request_id\":", request_id)?;
    field(output, b",\"request_origin\":", &origin)?;
    field(output, b",\"session_id\":", session_id)?;
    output.write_all(b"}")?;
    Ok(())
}
