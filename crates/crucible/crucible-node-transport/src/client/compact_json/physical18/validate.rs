//! Checks untrusted bank geometry and typed root fields without owning copies.
//!
//! Root fields follow the defining Envelope serializer. Nested objects use
//! strict UTF-8 key order, so adjacent borrowed comparisons exclude duplicate
//! keys without a key set. This format does not apply to paid deep native data.

use super::super::{
    ARRAY, BorrowedValue, Cursor, FALSE, FLOAT, MAXIMUM_DEPTH, NULL, OBJECT, SIGNED, STRING, TRUE,
    UNSIGNED, check_container,
};
use super::{ProviderError, invalid};
use crate::envelope::{MessageKind, Method};
use crucible_node_format::Id;
use serde::{Deserialize, de::value::BorrowedStrDeserializer};
use std::mem::size_of;

const FIELDS: [&str; 13] = [
    "protocol",
    "message",
    "session_id",
    "incarnation_id",
    "node_id",
    "execution_owner_id",
    "capture_owner_id",
    "request_id",
    "operation_id",
    "sequence",
    "method",
    "body",
    "extensions",
];

pub(super) fn envelope(bytes: &[u8]) -> Result<(), ProviderError> {
    let mut root = Cursor { rest: bytes };
    if root.take(1)? != [OBJECT] || root.extent()? != FIELDS.len() {
        return Err(invalid());
    }
    let extent = root.extent()?;
    let mut fields = Cursor {
        rest: root.take(extent)?,
    };
    finish(&root)?;

    for (index, name) in FIELDS.into_iter().enumerate() {
        if fields.string()? != name {
            return Err(invalid());
        }
        let value = fields.value()?;
        match index {
            0 => {
                text(value)?;
            }
            1 => {
                MessageKind::deserialize(BorrowedStrDeserializer::<ScalarError>::new(text(value)?))
                    .map_err(|_| invalid())?;
            }
            2..=8 => {
                if value.0 != [NULL] && !Id::is_valid_str(text(value)?) {
                    return Err(invalid());
                }
            }
            9 => {
                // U64's serde implementation owns a String. Check its defining
                // unsigned decimal grammar on borrowed bytes instead.
                crate::protocol_snapshot::owned11::typed::unsigned(text(value)?.as_bytes())?;
            }
            10 => {
                Method::deserialize(BorrowedStrDeserializer::<ScalarError>::new(text(value)?))
                    .map_err(|_| invalid())?;
            }
            11 | 12 => {
                if value.0.first() != Some(&OBJECT) {
                    return Err(invalid());
                }
                let mut body = Cursor { rest: value.0 };
                validate_value(&mut body, 1)?;
                finish(&body)?;
            }
            _ => return Err(invalid()),
        }
    }
    finish(&fields)
}

fn text(value: BorrowedValue<'_>) -> Result<&str, ProviderError> {
    let mut cursor = Cursor { rest: value.0 };
    let text = cursor.string()?;
    finish(&cursor)?;
    Ok(text)
}

fn validate_value(cursor: &mut Cursor<'_>, depth: usize) -> Result<(), ProviderError> {
    match cursor.take(1)?[0] {
        NULL | FALSE | TRUE => {}
        UNSIGNED => {
            cursor.word()?;
        }
        SIGNED => {
            // Positive integers have a unique unsigned encoding in the actual
            // serializer; accepting them as signed would lose variant identity.
            if i64::from_le_bytes(cursor.word()?.to_le_bytes()) >= 0 {
                return Err(invalid());
            }
        }
        FLOAT => {
            if !f64::from_bits(cursor.word()?).is_finite() {
                return Err(invalid());
            }
        }
        STRING => {
            let length = cursor.extent()?;
            std::str::from_utf8(cursor.take(length)?).map_err(|_| invalid())?;
        }
        tag @ (ARRAY | OBJECT) => validate_container(cursor, depth, tag)?,
        _ => return Err(invalid()),
    }
    Ok(())
}

fn validate_container(cursor: &mut Cursor<'_>, depth: usize, tag: u8) -> Result<(), ProviderError> {
    let count = cursor.extent()?;
    check_container(depth, count, tag == ARRAY)?;
    let extent = cursor.extent()?;
    let mut children = Cursor {
        rest: cursor.take(extent)?,
    };
    // Every array child has a tag; every object entry has at least a string
    // header and a value tag. Refuse impossible counts before walking them.
    let minimum_entry_bytes = if tag == ARRAY { 1 } else { 10 };
    if count > extent / minimum_entry_bytes {
        return Err(invalid());
    }

    let mut previous_key = None;
    for _ in 0..count {
        if tag == OBJECT {
            let key = children.string()?;
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(invalid());
            }
            previous_key = Some(key);
        }
        validate_value(&mut children, depth + 1)?;
    }
    finish(&children)
}

fn finish(cursor: &Cursor<'_>) -> Result<(), ProviderError> {
    if cursor.rest.is_empty() {
        Ok(())
    } else {
        Err(invalid())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    let recursive = size_of::<Cursor<'static>>() * 2
        + size_of::<&mut Cursor<'static>>() * 2
        + size_of::<Option<&str>>()
        + size_of::<&str>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<Result<(), ProviderError>>() * 3
        + size_of::<Result<&str, ProviderError>>()
        + size_of::<Result<&[u8], ProviderError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<usize>() * 5
        + size_of::<u64>()
        + size_of::<[u8; 8]>()
        + size_of::<u8>();

    (MAXIMUM_DEPTH + 1) * recursive
        + size_of::<[&str; 13]>()
        + size_of::<std::iter::Enumerate<std::array::IntoIter<&str, 13>>>()
        + size_of::<BorrowedValue<'static>>()
        + size_of::<Result<BorrowedValue<'static>, ProviderError>>()
        + size_of::<MessageKind>()
        + size_of::<Method>()
        + size_of::<Result<MessageKind, ScalarError>>()
        + size_of::<Result<Method, ScalarError>>()
        + size_of::<BorrowedStrDeserializer<'static, ScalarError>>()
        + size_of::<ScalarError>()
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<std::fmt::Arguments<'static>>()
}

#[derive(Debug)]
struct ScalarError;

impl std::fmt::Display for ScalarError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid compact envelope18 scalar")
    }
}

impl std::error::Error for ScalarError {}

impl serde::de::Error for ScalarError {
    fn custom<T: std::fmt::Display>(_: T) -> Self {
        Self
    }
}
