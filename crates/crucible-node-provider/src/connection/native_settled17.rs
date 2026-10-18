//! Owns the emitted-order native Connection17 graph as inert historical DATA.
//!
//! The native entrypoint reads the actual schema-first serializer. Canonicalized
//! Controller17 documents retain their separate existing structural validator.
//! Every leaf consumes the caller's same capacity/alias Ledger; no span itself
//! asserts child validity and no decoded owner becomes a transport or token.

use super::*;
use crate::handshake::HistoricalAuthority17;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string, unsigned,
};
use crate::retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind};
use crucible_node_contract::{Id, U64};
use std::{
    cell::{Cell, RefCell},
    mem::{align_of, size_of},
};

mod blobs;
mod children;
mod frames;
mod identities;
mod reader;
mod tokens;
mod writer;

pub(crate) use blobs::{
    HistoricalNativeBlobReceiver17, HistoricalOperationPin17, NativeBlobReceiver17GroupIds,
    read_native17_blob_receiver_data, read_native17_operation_pin_data,
};
pub(crate) use frames::{HistoricalNativeFrameRoot17, read_native17_frame_root_data};
pub(crate) use identities::{HistoricalAckIdentity17, HistoricalRestoreIdentity17};
pub(crate) use reader::{
    HistoricalCurrentNativeConnection17, NativeConnection17GroupIds, read_native17_connection_data,
    read_native17_connection_fields_data,
};
pub(crate) use tokens::{HistoricalAckToken17, HistoricalPrepareToken17};

pub(crate) fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next()?.ok_or_else(invalid)
}

pub(crate) fn exact(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn reference<T>(
    ledger: &mut Ledger<'_, '_, '_>,
    kind: MetadataSharedKind,
) -> Result<usize, ProviderError> {
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, align_of::<T>())? != size_of::<T>() {
        return Err(invalid());
    }
    ledger.shared_reference(kind, size_of::<T>())
}

pub(crate) fn inline_digest(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<[u8; 32], ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut digest = [0; 32];
    for byte in &mut digest {
        *byte = ledger
            .read::<u8>(next(&mut fields)?, true)?
            .ok_or_else(invalid)?;
    }
    fields.finish()?;
    Ok(digest)
}

pub(crate) fn deadline(ledger: &mut Ledger<'_, '_, '_>) -> Result<usize, ProviderError> {
    type Payload = Cell<crate::operational_time::OperationalDeadline>;
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, align_of::<Payload>())?
        != size_of::<Payload>()
    {
        return Err(invalid());
    }
    ledger.shared(
        MetadataSharedKind::OperationalDeadline,
        size_of::<Payload>(),
        b"native-shared-operational-deadline-history-only",
        b"",
    )
}

/// Verifies immutable policy content DATA without constructing an installed owner.
///
/// # Errors
/// Refuses an invalid reference, changed extent or changed ordinary blob digest.
pub(crate) fn authenticate_native17_policy_content_data(
    reference: &crucible_node_contract::ContentRef,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    crate::connection::restore_held_proof::authenticate_content_bytes(reference, bytes)
}

#[cfg(test)]
mod tests;

pub(crate) mod logical17;

pub(crate) use reader::{
    preflight_rooted_native17_connection_authority_data,
    read_rooted_native17_connection_authority_into_data,
};

pub(crate) use reader::{
    read_native17_codec_root_data, read_rooted_native17_connection_fields_data,
};
