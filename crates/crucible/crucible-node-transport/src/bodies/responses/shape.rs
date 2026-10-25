//! Decodes the selected live response fields without a tagged-enum buffer.
//!
//! The wire parser has already retained the complete object. Reading its status
//! selects one closed field schema directly; the remaining fields deserialize
//! from that same borrowed map. Historical generic Deserialize stays unchanged.

use super::*;
use serde::de::{DeserializeOwned, Error, Visitor, value::MapDeserializer};
use std::mem::size_of;

enum Status {
    Accepted,
    Completed,
    Error,
}

struct StatusVisitor;

impl<'de> Visitor<'de> for StatusVisitor {
    type Value = Status;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("variant identifier")
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Status, E> {
        match value {
            "accepted" => Ok(Status::Accepted),
            "completed" => Ok(Status::Completed),
            "error" => Ok(Status::Error),
            _ => Err(E::unknown_variant(
                value,
                &["accepted", "completed", "error"],
            )),
        }
    }
}

impl<'de> Deserialize<'de> for Status {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The original internally tagged decoder reads an identifier here.
        // General enum decoding would also accept an externally tagged map.
        deserializer.deserialize_identifier(StatusVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessfulFields {
    operation_state: OperationState,
    result: Map<String, Value>,
    extensions: Extensions,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorFields {
    operation_state: OperationState,
    error: ErrorRecord,
    extensions: Extensions,
}

type Field<'a> = (&'a str, &'a Value);
type OriginalField<'a> = (&'a String, &'a Value);
type FieldIterator<'a> =
    std::iter::FilterMap<serde_json::map::Iter<'a>, fn(OriginalField<'a>) -> Option<Field<'a>>>;
type FieldDeserializer<'a> = MapDeserializer<'a, FieldIterator<'a>, serde_json::Error>;

/// Decodes one closed live response directly from its original borrowed fields.
///
/// # Errors
/// Refuses invalid canonical geometry, absent or malformed status/fields,
/// unknown fields, cross-variant fields or inconsistent operation state.
pub(crate) fn decode_response_shape(
    body: &Map<String, Value>,
) -> Result<ResponseShape, ContractError> {
    super::super::object_decode::validate_geometry(body)?;
    let status = body
        .get("status")
        .ok_or_else(|| serde_json::Error::missing_field("status"))?;
    let shape = match Status::deserialize(status)? {
        Status::Accepted => {
            let fields: SuccessfulFields = decode_fields(body)?;
            ResponseShape::Accepted {
                operation_state: fields.operation_state,
                result: fields.result,
                extensions: fields.extensions,
            }
        }
        Status::Completed => {
            let fields: SuccessfulFields = decode_fields(body)?;
            ResponseShape::Completed {
                operation_state: fields.operation_state,
                result: fields.result,
                extensions: fields.extensions,
            }
        }
        Status::Error => {
            let fields: ErrorFields = decode_fields(body)?;
            ResponseShape::Error {
                operation_state: fields.operation_state,
                error: fields.error,
                extensions: fields.extensions,
            }
        }
    };
    shape.validate()?;
    Ok(shape)
}

fn decode_fields<T: DeserializeOwned>(body: &Map<String, Value>) -> Result<T, serde_json::Error> {
    let fields: FieldIterator<'_> = body.iter().filter_map(response_field);
    T::deserialize(FieldDeserializer::new(fields))
}

fn response_field((key, value): OriginalField<'_>) -> Option<Field<'_>> {
    (key != "status").then_some((key.as_str(), value))
}

/// Names the closed live response decoder's fixed borrowed and result controls.
pub(crate) const fn response_shape_decode_counter_scratch_data() -> usize {
    size_of::<&Map<String, Value>>()
        + size_of::<&Value>()
        + size_of::<Status>()
        + size_of::<StatusVisitor>()
        + size_of::<Result<Status, serde_json::Error>>()
        + size_of::<SuccessfulFields>()
        + size_of::<ErrorFields>()
        + size_of::<Result<SuccessfulFields, serde_json::Error>>()
        + size_of::<Result<ErrorFields, serde_json::Error>>()
        + size_of::<FieldIterator<'static>>()
        + size_of::<FieldDeserializer<'static>>()
        + size_of::<Option<Field<'static>>>()
        + size_of::<ResponseShape>()
        + size_of::<Result<ResponseShape, ContractError>>()
        + size_of::<Result<(), ContractError>>()
}

#[cfg(test)]
mod tests;
