//! Rebuilds independent typed quarantine bodies without an intermediate DOM.
//!
//! Bootstrap DTOs are untrusted historical DATA. Schema/state/row eligibility is
//! deliberately not inferred from decoding: failed prefixes may be ineligible.
//! Raw Envelope bodies, common response maps and typed results own separate
//! backing and consume separate capacity rows, even when their values agree.

use super::{invalid, read::next};
use crate::connection::{ReceivedBody, ReceivedFrame};
use crate::envelope::Envelope;
use crate::protocol_snapshot::owned11::{
    envelope::ValidatedHistoricalEnvelope,
    typed::{Fields, Ledger, plain_string},
};
use crate::reference_packet::service::{
    complete_restore::import18::bootstrap_ack::{
        PacketNativeImport18BootstrapAckState, PacketNativeImport18BootstrapRequest,
        PacketNativeImport18BootstrapResponseBody, PacketNativeImport18BootstrapResult,
    },
    native_startup::PacketNativeStartupAllocationRow,
};
use crate::retained_metadata::records::MetadataRecordKind;
use crate::{
    ProviderError,
    bodies::{NotificationBody, ResponseShape},
};
use crucible_node_format::{Bytes, U64};
use serde::{Deserialize, de::value::BorrowedStrDeserializer};
use std::mem::{align_of, size_of};

pub(super) use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::PacketNativeImport18BootstrapReceivedBody as BootstrapBody;

pub(super) fn envelope(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<Envelope>, ProviderError> {
    let plan = ValidatedHistoricalEnvelope::validate_compact_custody18(
        input,
        ledger.rows.clone(),
        ledger.limits,
    )?;
    ledger.rows = plan.remaining_records();
    if build {
        Ok(Some(plan.reconstruct()?))
    } else {
        Ok(None)
    }
}

pub(super) fn frame(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<ReceivedFrame>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let envelope = envelope(next(&mut fields)?, ledger, build)?;
    let mut body = Fields::array(next(&mut fields)?)?;
    fields.finish()?;
    let body = match plain_string(next(&mut body)?)? {
        "notification" => {
            boxed::<NotificationBody>(ledger)?;
            let value = ledger.read::<NotificationBody>(next(&mut body)?, build)?;
            body.finish()?;
            value.map(|value| ReceivedBody::Notification(Box::new(value)))
        }
        "bootstrap-request" => {
            boxed::<BootstrapBody>(ledger)?;
            let value = request(next(&mut body)?, ledger, build)?;
            body.finish()?;
            value.map(|value| {
                ReceivedBody::NativeImport18Bootstrap(Box::new(BootstrapBody::Request(value)))
            })
        }
        "bootstrap-response" => {
            boxed::<BootstrapBody>(ledger)?;
            let shape = ledger.read::<ResponseShape>(next(&mut body)?, build)?;
            let result_bytes = next(&mut body)?;
            let result = if result_bytes == b"null" {
                None
            } else {
                result(result_bytes, ledger, build)?
            };
            body.finish()?;
            shape.map(|shape| {
                ReceivedBody::NativeImport18Bootstrap(Box::new(BootstrapBody::Response(
                    PacketNativeImport18BootstrapResponseBody { shape, result },
                )))
            })
        }
        _ => return Err(invalid()),
    };
    match (envelope, body) {
        (Some(envelope), Some(body)) => Ok(Some(ReceivedFrame { envelope, body })),
        (None, None) if !build => Ok(None),
        _ => Err(invalid()),
    }
}

fn boxed<T>(ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
    if ledger.row_aligned(MetadataRecordKind::Boxed, 1, align_of::<T>())? != size_of::<T>() {
        return Err(invalid());
    }
    Ok(())
}

// The old native allocation reader validates arithmetic eligibility. Quarantined
// DATA must also preserve an invalid original row without issuing its grant.
fn allocation(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<PacketNativeStartupAllocationRow>, ProviderError> {
    let mut fields = Fields::object(input)?;
    let retained = ledger.read::<U64>(fields.named("retained_requested_bytes")?, build)?;
    let transient =
        ledger.read::<U64>(fields.named("maximum_simultaneous_transient_bytes")?, build)?;
    let scratch = ledger.read::<U64>(fields.named("declared_counter_scratch_bytes")?, build)?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(PacketNativeStartupAllocationRow {
        retained_requested_bytes: retained.ok_or_else(invalid)?,
        maximum_simultaneous_transient_bytes: transient.ok_or_else(invalid)?,
        declared_counter_scratch_bytes: scratch.ok_or_else(invalid)?,
    }))
}

fn request(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<PacketNativeImport18BootstrapRequest>, ProviderError> {
    let mut fields = Fields::object(input)?;
    let schema = ledger.read::<String>(fields.named("schema")?, build)?;
    let recipe_identity = ledger.read::<Bytes>(fields.named("recipe_identity")?, build)?;
    let initial_funding = allocation(fields.named("initial_funding")?, ledger, build)?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(PacketNativeImport18BootstrapRequest {
        schema: schema.ok_or_else(invalid)?,
        recipe_identity: recipe_identity.ok_or_else(invalid)?,
        initial_funding: initial_funding.ok_or_else(invalid)?,
    }))
}

fn result(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<PacketNativeImport18BootstrapResult>, ProviderError> {
    let mut fields = Fields::object(input)?;
    let schema = ledger.read::<String>(fields.named("schema")?, build)?;
    let state = scalar::<PacketNativeImport18BootstrapAckState>(fields.named("state")?)?;
    let recipe_identity = ledger.read::<Bytes>(fields.named("recipe_identity")?, build)?;
    let initial_funding = allocation(fields.named("initial_funding")?, ledger, build)?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(PacketNativeImport18BootstrapResult {
        schema: schema.ok_or_else(invalid)?,
        state,
        recipe_identity: recipe_identity.ok_or_else(invalid)?,
        initial_funding: initial_funding.ok_or_else(invalid)?,
    }))
}

fn scalar<'a, T: Deserialize<'a>>(input: &'a [u8]) -> Result<T, ProviderError> {
    T::deserialize(BorrowedStrDeserializer::<ScalarError>::new(plain_string(
        input,
    )?))
    .map_err(|_| invalid())
}

#[derive(Debug)]
struct ScalarError;

impl std::fmt::Display for ScalarError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid compact custody18 scalar")
    }
}

impl std::error::Error for ScalarError {}

impl serde::de::Error for ScalarError {
    fn custom<T: std::fmt::Display>(_: T) -> Self {
        Self
    }
}
