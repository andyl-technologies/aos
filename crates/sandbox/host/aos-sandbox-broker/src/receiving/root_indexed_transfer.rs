//! Shares the strict indexed frame/copy/digest programme between Root owners.
//!
//! The fixed lexical stages below retain the original allocation, exact frame,
//! canonical decode/cumulative copy, positive disposal and digest blocks once.
//! Private adapters preserve the actual native receiver and genuine role gates;
//! no callback, mutable native owner getter or supplied completion is accepted.

/// Expands the sole indexed programme with a private finite lexical adapter.
///
/// The native adapter operates on an opaque same-owner frame scope. Legacy
/// adapters expand their existing local native/byte slots without runtime
/// wrappers. The adapter is not a publicly implementable runtime trait.
#[doc(hidden)]
#[macro_export]
macro_rules! root_indexed_transfer_receive_v1 {
    ($adapter:ident) => {{
        $adapter! { extent, total }
        $adapter! { allocate, total }
        while $adapter! { has_next } {
            $adapter! { prepare_frame, current_frame }
            $adapter! { receive_frame, current_frame }
            $adapter! { bind_copy, current_frame, total }
            $adapter! { dispose_frame, current_frame }
        }
        $adapter! { digest, total }
    }};
}

/// Expands the original extent DATA/native-buffer block.
#[doc(hidden)]
#[macro_export]
macro_rules! root_indexed_transfer_extent_v1 {
    (index: $index:ident, total: $total:ident, error: $error:expr $(,)?) => {
    let $total = usize::try_from($index.total()).map_err(|_| $error)?;
    };
}

/// Expands the original allocate DATA/native-buffer block.
#[doc(hidden)]
#[macro_export]
macro_rules! root_indexed_transfer_allocate_v1 {
    (allocation: $allocation:ident, bytes: $bytes:ident, total: $total:ident, positive: $positive:ident $(,)?) => {
    *$allocation = Some($bytes.try_reserve_exact($total));
    $positive($allocation)?;

    };
}

/// Expands the original prepare frame DATA/native-buffer block.
#[doc(hidden)]
#[macro_export]
macro_rules! root_indexed_transfer_prepare_frame_v1 {
    (index: $index:ident, next_chunk: $next_chunk:ident, frame: $frame:ident, current_frame: $current_frame:ident, error: $error:expr $(,)?) => {
        let offset = u64::from(*$next_chunk).checked_mul(::aos_sandbox_protocol::domain_ledger::create_q04_history::CLAIM_CHUNK_BYTES as u64)
            .ok_or($error)?;
        let remaining = $index.total().checked_sub(offset).ok_or($error)?;
        let payload = usize::try_from(remaining.min(::aos_sandbox_protocol::domain_ledger::create_q04_history::CLAIM_CHUNK_BYTES as u64))
            .map_err(|_| $error)?;
        let frame_bytes = ::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::FRAME_HEADER_BYTES + ::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::CHUNK_HEADER_BYTES + payload;
        *$frame = Some(::aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1::new());
        let $current_frame = $frame.as_mut().ok_or($error)?;
        $current_frame.prepare_exact_once(frame_bytes).map_err(|_| $error)?;
    };
}

/// Expands the original bind copy DATA/native-buffer block.
#[doc(hidden)]
#[macro_export]
macro_rules! root_indexed_transfer_bind_copy_v1 {
    (frame_binding: $frame_binding:ident, current_frame: $current_frame:ident, purpose: $purpose:ident, body: $body:ident, first_sequence: $first_sequence:ident, next_chunk: $next_chunk:ident, index: $index:ident, bytes: $bytes:ident, total: $total:ident, positive: $positive:ident $(,)?) => {
        *$frame_binding = Some((|| {
            let envelope = ::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::FrameEnvelopeV1::decode($current_frame.bytes(), ::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::FrameCoordinatesV1 {
                kind: $purpose.chunk_kind(),
                lane: $body.open.lane,
                sequence: $first_sequence.checked_add(u64::from(*$next_chunk)).ok_or(::aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1::Extent)?,
                root_nonce: $body.root_nonce,
                controller_nonce: $body.open.controller_nonce,
            })?;
            let chunk = ::aos_sandbox_protocol::domain_ledger::create_storage_history::transport::ChunkEnvelopeV1::decode(envelope.payload(), $index, *$next_chunk)?;
            let reached = $bytes.len().checked_add(chunk.payload().len())
                .ok_or(::aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1::Extent)?;
            if reached > $total || reached > $bytes.capacity() {
                return Err(::aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1::Extent);
            }
            $bytes.extend_from_slice(chunk.payload());
            Ok(())
        })());
        $positive($frame_binding)?;
    };
}

/// Expands the original dispose frame DATA/native-buffer block.
#[doc(hidden)]
#[macro_export]
macro_rules! root_indexed_transfer_dispose_frame_v1 {
    (frame: $frame:ident, frame_binding: $frame_binding:ident, next_chunk: $next_chunk:ident, error: $error:expr $(,)?) => {
        // Exact framed bytes, checksum, next-index geometry and cumulative
        // copy have all completed. Dispose this positive raw frame before
        // the next bounded frame. A failed frame stays in frame.
        drop($frame.take());
        *$frame_binding = None;
        *$next_chunk = (*$next_chunk).checked_add(1).ok_or($error)?;
    };
}

/// Expands the original digest DATA/native-buffer block.
#[doc(hidden)]
#[macro_export]
macro_rules! root_indexed_transfer_digest_v1 {
    (digest: $digest:ident, bytes: $bytes:ident, total: $total:ident, purpose: $purpose:ident, index: $index:ident, positive: $positive:ident $(,)?) => {{
    *$digest = Some(if $bytes.len() != $total {
        Err(::aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1::Correlation)
    } else {
        $purpose.commitment($bytes).and_then(|observed| {
            if observed == $index.digest() { Ok(()) }
            else { Err(::aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1::Correlation) }
        })
    });
    $positive($digest).map(|_| ())
    }};
}
