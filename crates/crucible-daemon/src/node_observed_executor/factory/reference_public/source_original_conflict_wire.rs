//! Checks exact canonical original and hostile frames in a separate wire arena.
//!
//! This reader interprets only the closed transport observation DTO. It does
//! not infer evidence dependencies from payload JSON or confer source authority.

use crucible_node_contract::{Bytes, HashRef, Id, U64, canonical};
use crucible_node_provider::{
    ProviderError,
    bodies::{EffectCertainty, OperationState, ResponseShape, decode_request, decode_response},
    envelope::{Envelope, RequestOrigin},
};
use serde::Deserialize;
use serde_json::Value;

use super::source_original_conflict_policy::OriginalConflictPremise;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema: String,
    encoding: String,
    scope: Scope,
    rows: Vec<Row>,
    bytes: Bytes,
    incomplete: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    session: Id,
    incarnation: Id,
    connection: Id,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum WireOrigin {
    Controller,
    Provider,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    transmission: U64,
    origin: WireOrigin,
    request_id: Id,
    original_identity: HashRef,
    attempted_identity: HashRef,
    original_request: (usize, usize),
    original_response: (usize, usize),
    sent_sequence: U64,
    write_completed: bool,
    conflict_refusal_verified: bool,
    request_start: usize,
    request_length: usize,
    received: Option<(usize, usize)>,
}

pub(super) fn verify(
    value: &Value,
    originals: &[OriginalConflictPremise],
) -> Result<(), ProviderError> {
    let wire: Wire = serde_json::from_value(value.clone())
        .map_err(crucible_node_contract::ContractError::from)?;
    if wire.schema != "crucible.reference.original-wire-conflicts.v1"
        || wire.encoding != "canonical-transmitted-and-decoded-envelope-v1"
        || wire.incomplete
        || wire.rows.len() != 3
        || originals.len() != 3
    {
        return Err(changed());
    }
    let mut cursor = 0usize;
    let mut sequence = U64::new(0);
    let mut received_sequence = U64::new(0);
    for (index, (row, premise)) in wire.rows.iter().zip(originals).enumerate() {
        if row.transmission != U64::new(index as u64 + 1)
            || row.origin != WireOrigin::Controller
            || row.request_id != premise.request
            || wire.scope.connection != premise.connection
            || !row.write_completed
            || !row.conflict_refusal_verified
            || row.sent_sequence <= sequence
        {
            return Err(changed());
        }
        let original_bytes = range(&wire.bytes, row.original_request, &mut cursor)?;
        premise.original_request.verify(original_bytes)?;
        let response_bytes = range(&wire.bytes, row.original_response, &mut cursor)?;
        premise.original_response.verify(response_bytes)?;
        let original = envelope(original_bytes)?;
        let response = envelope(response_bytes)?;
        original.matches_response(&response)?;
        let sent = envelope(range(
            &wire.bytes,
            (row.request_start, row.request_length),
            &mut cursor,
        )?)?;
        let received = envelope(range(
            &wire.bytes,
            row.received.ok_or_else(changed)?,
            &mut cursor,
        )?)?;
        sent.matches_response(&received)?;
        if received.sequence <= response.sequence || received.sequence <= received_sequence {
            return Err(ProviderError::Correlation(
                "changed conflict provider-lane chronology",
            ));
        }
        if sent.sequence != row.sent_sequence
            || sent.sequence <= original.sequence
            || sent.request_id.0.as_ref() != Some(&premise.request)
            || sent.session_id.0.as_ref() != Some(&wire.scope.session)
            || sent.incarnation_id.0.as_ref() != Some(&wire.scope.incarnation)
            || sent.body != premise.changed_body
            || original.request_hash(RequestOrigin::Controller)? != row.original_identity
            || sent.request_hash(RequestOrigin::Controller)? != row.attempted_identity
            || row.original_identity == row.attempted_identity
        {
            return Err(changed());
        }
        let mut expected = original.clone();
        expected.body = premise.changed_body.clone();
        expected.sequence = sent.sequence;
        if expected != sent {
            return Err(changed());
        }
        let typed = decode_request(sent.method, &sent.body)?;
        let actual = decode_response(&typed, &received.body)?;
        if !matches!(actual.shape,
            ResponseShape::Error { operation_state: OperationState::NotStarted, ref error, .. }
                if error.code == "CONFLICT" && error.effect == EffectCertainty::NotStarted && !error.retryable)
        {
            return Err(changed());
        }
        sequence = sent.sequence;
        received_sequence = received.sequence;
    }
    if cursor != wire.bytes.as_slice().len() {
        return Err(changed());
    }
    Ok(())
}

fn range<'a>(
    bytes: &'a Bytes,
    (start, length): (usize, usize),
    cursor: &mut usize,
) -> Result<&'a [u8], ProviderError> {
    let end = start.checked_add(length).ok_or_else(changed)?;
    if start != *cursor || length == 0 {
        return Err(changed());
    }
    let body = bytes.as_slice().get(start..end).ok_or_else(changed)?;
    *cursor = end;
    Ok(body)
}

fn envelope(bytes: &[u8]) -> Result<Envelope, ProviderError> {
    let value = canonical::parse_json(bytes, 1024 * 1024)?;
    if canonical::canonical_json(&value)? != bytes {
        return Err(changed());
    }
    let envelope: Envelope =
        serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
    envelope.validate()?;
    Ok(envelope)
}

fn changed() -> ProviderError {
    ProviderError::Correlation("original changed-body wire population differs")
}
