//! Materializes the defining Envelope directly from its private immutable bank.
//!
//! The concrete constructor's field order is checked before each field is
//! consumed. Body and extension trees are built directly into their final
//! owners, without a whole-envelope Value or a second recursive deserializer.
//! Ordinary scalar deserializers still validate IDs, enums and decimal U64s.

use super::*;
use crate::envelope::{Envelope, Nullable};
use crucible_node_format::Id;
use serde::de::{DeserializeOwned, value::BorrowedStrDeserializer};

impl CompactJson {
    /// Materializes a bank produced by the defining Envelope serializer.
    ///
    /// This allocates one fresh Envelope population. The original immutable
    /// bank remains independently retained, and the caller must admit the full
    /// output, bounded recursive controls and failed constructor prefixes.
    /// It does not validate method bodies, correlation or native receipts.
    ///
    /// # Errors
    /// Refuses changed field order or geometry, invalid scalar contracts or
    /// unavailable array storage. Arbitrary Value banks are not this format.
    pub(in crate::client) fn materialize_envelope(&self) -> Result<Envelope, ProviderError> {
        let mut fields = envelope_fields(&self.bytes)?;
        let envelope = Envelope {
            protocol: text(field(&mut fields, "protocol")?)?.to_owned(),
            message: scalar(field(&mut fields, "message")?)?,
            session_id: nullable(field(&mut fields, "session_id")?)?,
            incarnation_id: nullable(field(&mut fields, "incarnation_id")?)?,
            node_id: nullable(field(&mut fields, "node_id")?)?,
            execution_owner_id: nullable(field(&mut fields, "execution_owner_id")?)?,
            capture_owner_id: nullable(field(&mut fields, "capture_owner_id")?)?,
            request_id: nullable(field(&mut fields, "request_id")?)?,
            operation_id: nullable(field(&mut fields, "operation_id")?)?,
            sequence: scalar(field(&mut fields, "sequence")?)?,
            method: scalar(field(&mut fields, "method")?)?,
            body: object(field(&mut fields, "body")?)?,
            extensions: object(field(&mut fields, "extensions")?)?,
        };
        finish(&fields)?;
        Ok(envelope)
    }
}

fn envelope_fields(bytes: &[u8]) -> Result<Cursor<'_>, ProviderError> {
    let mut cursor = Cursor { rest: bytes };
    if cursor.take(1)? != [OBJECT] || cursor.extent()? != 13 {
        return Err(invalid());
    }
    let fields = payload(&mut cursor)?;
    finish(&cursor)?;
    Ok(fields)
}

fn field<'a>(cursor: &mut Cursor<'a>, name: &str) -> Result<BorrowedValue<'a>, ProviderError> {
    if cursor.string()? != name {
        return Err(invalid());
    }
    cursor.value()
}

fn text(value: BorrowedValue<'_>) -> Result<&str, ProviderError> {
    let mut cursor = Cursor { rest: value.0 };
    let text = cursor.string()?;
    finish(&cursor)?;
    Ok(text)
}

fn scalar<T: DeserializeOwned>(value: BorrowedValue<'_>) -> Result<T, ProviderError> {
    T::deserialize(BorrowedStrDeserializer::<ScalarError>::new(text(value)?)).map_err(|_| invalid())
}

fn nullable(value: BorrowedValue<'_>) -> Result<Nullable<Id>, ProviderError> {
    if value.0 == [NULL] {
        Ok(Nullable(None))
    } else {
        scalar(value).map(|id| Nullable(Some(id)))
    }
}

fn object<T: Default + Extend<(String, Value)>>(
    value: BorrowedValue<'_>,
) -> Result<T, ProviderError> {
    let mut cursor = Cursor { rest: value.0 };
    if cursor.take(1)? != [OBJECT] {
        return Err(invalid());
    }
    let object = object_payload(&mut cursor)?;
    finish(&cursor)?;
    Ok(object)
}

fn object_payload<T: Default + Extend<(String, Value)>>(
    cursor: &mut Cursor<'_>,
) -> Result<T, ProviderError> {
    let count = cursor.extent()?;
    let mut children = payload(cursor)?;
    let mut values = T::default();
    for _ in 0..count {
        let key = children.string()?.to_owned();
        // Private constructors supply unique keys. Build the actual destination
        // map directly: Envelope extensions and JSON objects use different map
        // types. Reserved serde_json marker keys remain ordinary JSON DATA.
        values.extend([(key, owned(children.value()?)?)]);
    }
    finish(&children)?;
    Ok(values)
}

fn owned(value: BorrowedValue<'_>) -> Result<Value, ProviderError> {
    let mut cursor = Cursor { rest: value.0 };
    let result = match cursor.take(1)?[0] {
        NULL => Value::Null,
        FALSE => Value::Bool(false),
        TRUE => Value::Bool(true),
        UNSIGNED => Value::Number(cursor.word()?.into()),
        SIGNED => Value::Number(i64::from_le_bytes(cursor.word()?.to_le_bytes()).into()),
        FLOAT => Value::Number(
            serde_json::Number::from_f64(f64::from_bits(cursor.word()?)).ok_or_else(invalid)?,
        ),
        STRING => {
            let length = cursor.extent()?;
            let text = std::str::from_utf8(cursor.take(length)?).map_err(|_| invalid())?;
            Value::String(text.to_owned())
        }
        ARRAY => {
            let count = cursor.extent()?;
            let mut children = payload(&mut cursor)?;
            let mut values = Vec::new();
            values.try_reserve_exact(count).map_err(|_| refused())?;
            for _ in 0..count {
                values.push(owned(children.value()?)?);
            }
            finish(&children)?;
            Value::Array(values)
        }
        OBJECT => Value::Object(object_payload(&mut cursor)?),
        _ => return Err(invalid()),
    };
    finish(&cursor)?;
    Ok(result)
}

fn payload<'a>(cursor: &mut Cursor<'a>) -> Result<Cursor<'a>, ProviderError> {
    let extent = cursor.extent()?;
    Ok(Cursor {
        rest: cursor.take(extent)?,
    })
}

fn finish(cursor: &Cursor<'_>) -> Result<(), ProviderError> {
    if cursor.rest.is_empty() {
        Ok(())
    } else {
        Err(invalid())
    }
}

#[derive(Debug)]
struct ScalarError;

impl std::fmt::Display for ScalarError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid compact envelope scalar")
    }
}

impl std::error::Error for ScalarError {}

impl serde::de::Error for ScalarError {
    fn custom<T: std::fmt::Display>(_: T) -> Self {
        Self
    }
}
