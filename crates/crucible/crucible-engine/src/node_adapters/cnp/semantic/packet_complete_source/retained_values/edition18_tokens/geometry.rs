//! Names actual token, traversal, decoder and owning-census requested geometry.

use super::*;
use std::{
    alloc::{Layout, LayoutError},
    collections::TryReserveError,
};

/// Quotes actual token, cache, chunk and cloned-string constructor banks.
///
/// # Errors
/// Refuses chunk/layout overflow or the independent total construction bound.
pub(super) fn token_storage(
    tokens: usize,
    strings: usize,
    transient: usize,
    scratch: usize,
    maximum: usize,
) -> Result<LiteralValue18Storage, RuntimeError> {
    let chunks = chunks_for(tokens)?;
    let retained = checked_sum(
        [
            size_of::<LiteralValue18TokenAttempt>(),
            chunks
                .checked_mul(size_of::<Vec<LiteralToken18>>())
                .ok_or(RuntimeError::ResourceLimit)?,
            tokens
                .checked_mul(size_of::<LiteralToken18>())
                .ok_or(RuntimeError::ResourceLimit)?,
            tokens
                .checked_mul(size_of::<usize>())
                .ok_or(RuntimeError::ResourceLimit)?,
            strings,
        ],
        maximum,
    )?;
    LiteralValue18Storage::new(retained, transient, scratch, maximum)
}

/// Counts actual deep Value capacities under a separately funded traversal.
///
/// # Errors
/// Refuses insufficient population, layout overflow or retained backing bounds.
pub(super) fn value_backing(
    value: &Value,
    observed_nodes: usize,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    // The enclosing census prewalk independently admits this T bank and S.
    // `maximum` here bounds retained backing only; it must not also constrain
    // the separately funded transient traversal bank.
    observed_nodes
        .checked_mul(size_of::<walk::Frame<'_>>())
        .ok_or(RuntimeError::ResourceLimit)?;
    let mut walker = walk::Walker::new(value, observed_nodes)?;
    let mut bytes = 0usize;
    while walker.next_token()?.is_some() {
        match walker.current_value() {
            Some(Value::String(value)) => bytes = checked_sum([bytes, value.capacity()], maximum)?,
            Some(Value::Array(values)) => {
                bytes = checked_sum(
                    [
                        bytes,
                        values
                            .capacity()
                            .checked_mul(size_of::<Value>())
                            .ok_or(RuntimeError::ResourceLimit)?,
                    ],
                    maximum,
                )?
            }
            Some(Value::Object(values)) => {
                bytes = checked_sum([bytes, map_storage(values.len(), maximum)?], maximum)?;
                for key in values.keys() {
                    bytes = checked_sum([bytes, key.capacity()], maximum)?;
                }
            }
            _ => {}
        }
    }
    Ok(bytes)
}

/// Names the actual disposable borrowed traversal and direct allocator controls.
pub(crate) fn traversal_counter_scratch_data() -> usize {
    size_of::<walk::Walker<'static>>()
        + size_of::<walk::Frame<'static>>()
        + size_of::<Vec<walk::Frame<'static>>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<Option<&Value>>() * 3
        + size_of::<Option<&mut walk::Frame<'static>>>()
        + size_of::<Option<(&String, &Value)>>()
        + size_of::<walk::BorrowedToken18<'static>>()
        + size_of::<Result<Option<walk::BorrowedToken18<'static>>, RuntimeError>>()
        + size_of::<&Value>()
        + size_of::<&serde_json::Number>()
        + size_of::<Option<u64>>()
        + size_of::<Option<i64>>()
        + size_of::<Option<f64>>()
        + size_of::<u64>() * 2
        + size_of::<i64>()
        + size_of::<f64>()
        + size_of::<[u8; 8]>() * 2
        + size_of::<usize>() * 5
        + size_of::<Result<(), TryReserveError>>()
        + size_of::<TryReserveError>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Option<usize>>()
        + size_of::<bool>()
}

pub(super) fn checked_row_counter_scratch_data() -> usize {
    // LiteralValue18Storage::new folds its three actual axes; checked_sum's
    // accumulator/element and checked option are independent local views.
    size_of::<LiteralValue18Storage>()
        + size_of::<Result<LiteralValue18Storage, RuntimeError>>()
        + size_of::<[usize; 3]>()
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<[usize; 2]>()
        + size_of::<std::array::IntoIter<usize, 2>>()
        + size_of::<usize>() * 6
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, RuntimeError>>()
}

/// Names flat token ownership, handoff, census and checked-row controls.
pub(super) fn token_owner_counter_scratch_data() -> usize {
    checked_row_counter_scratch_data()
        + size_of::<LiteralValue18TokenAttempt>()
        + size_of::<LiteralValue18Data>()
        + size_of::<Result<&LiteralValue18Data, RuntimeError>>()
        + size_of::<&LiteralValue18TokenAttempt>()
        + size_of::<&mut LiteralValue18TokenAttempt>()
        + size_of::<&LiteralValue18Data>()
        + size_of::<&mut LiteralValue18Data>()
        + size_of::<&mut Option<LiteralValue18Data>>()
        + size_of::<Option<LiteralValue18Data>>()
        + size_of::<&mut Vec<Vec<LiteralToken18>>>()
        + size_of::<&mut Vec<usize>>()
        + size_of::<(bool, bool, bool)>()
        + size_of::<&Vec<LiteralToken18>>()
        + size_of::<&mut Vec<LiteralToken18>>()
        + size_of::<Option<&mut Vec<LiteralToken18>>>()
        + size_of::<&LiteralToken18>()
        + size_of::<Option<&mut LiteralToken18>>()
        + size_of::<&str>()
        + size_of::<&mut String>()
        + size_of::<LiteralToken18>()
        + size_of::<std::slice::Iter<'static, Vec<LiteralToken18>>>()
        + size_of::<std::slice::Iter<'static, LiteralToken18>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<Result<(), TryReserveError>>()
        + size_of::<TryReserveError>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Option<usize>>()
        + size_of::<[usize; 5]>()
        + size_of::<std::array::IntoIter<usize, 5>>()
        + size_of::<[usize; 8]>()
}

fn index_counter_scratch_data() -> usize {
    size_of::<Vec<index::Frame<'static>>>()
        + size_of::<&mut Vec<Vec<LiteralToken18>>>()
        + size_of::<&mut Vec<usize>>()
        + size_of::<index::Frame<'static>>()
        + size_of::<Option<index::Frame<'static>>>()
        + size_of::<&mut [index::Frame<'static>]>()
        + size_of::<Option<&mut index::Frame<'static>>>()
        + size_of::<Option<&index::Frame<'static>>>()
        + size_of::<&mut usize>()
        + size_of::<Option<&mut usize>>()
        + size_of::<Option<&str>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Vec<LiteralToken18>>>>()
        + size_of::<std::slice::Iter<'static, LiteralToken18>>()
        + size_of::<usize>() * 5
        + size_of::<bool>() * 2
        + size_of::<Result<(), TryReserveError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Option<usize>>()
}

/// Names all actual quote/encode/token-census and index controls.
pub(crate) fn encode_counter_scratch_data() -> usize {
    traversal_counter_scratch_data()
        + token_owner_counter_scratch_data()
        + index_counter_scratch_data()
        + size_of::<super::encode::LiteralValue18EncodeQuote>()
        + size_of::<LiteralValue18Storage>()
        + size_of::<Result<super::encode::LiteralValue18EncodeQuote, RuntimeError>>()
        + size_of::<Result<LiteralValue18Storage, RuntimeError>>()
        + size_of::<[usize; 4]>()
        + size_of::<std::array::IntoIter<usize, 4>>()
}

/// Names the closed borrowed token-reader and canonical unsigned parser controls.
pub(crate) fn read_counter_scratch_data() -> usize {
    token_owner_counter_scratch_data()
        + index_counter_scratch_data()
        + size_of::<super::read::LiteralValue18ReadQuote>()
        + size_of::<Result<super::read::LiteralValue18ReadQuote, RuntimeError>>()
        + size_of::<&Value>()
        + size_of::<&Map<String, Value>>()
        + size_of::<&[Value]>()
        + size_of::<Result<&[Value], RuntimeError>>()
        + size_of::<Option<&Value>>()
        + size_of::<Option<&str>>()
        + size_of::<Option<bool>>()
        + size_of::<Option<&Vec<Value>>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, Value>>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<(usize, &Value)>()
        + size_of::<walk::BorrowedToken18<'static>>()
        + size_of::<Result<walk::BorrowedToken18<'static>, RuntimeError>>()
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<u8>()
        + size_of::<u64>() * 2
        + size_of::<Option<u64>>()
        + size_of::<Result<u64, RuntimeError>>()
        + size_of::<i64>()
        + size_of::<f64>()
        + size_of::<usize>() * 6
        + size_of::<bool>()
}

fn tree_counter_scratch_data() -> usize {
    // These are the actual public facade's five scalar arguments, the defining
    // value_layout helper's same five arguments and its four checked locals.
    size_of::<[usize; 5]>() * 2
        + size_of::<[usize; 4]>()
        + size_of::<Layout>()
        + size_of::<Result<Layout, LayoutError>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Option<usize>>()
        + size_of::<&usize>()
}

/// Names literal assembly, actual retained child census and direct tree controls.
pub(crate) fn decode_counter_scratch_data() -> usize {
    super::decode::LiteralValue18DecodeAttempt::retirement_counter_scratch_data()
        + checked_row_counter_scratch_data()
        + traversal_counter_scratch_data()
        + tree_counter_scratch_data()
        + size_of::<super::decode::LiteralValue18DecodeAttempt>()
        + size_of::<&super::decode::LiteralValue18DecodeAttempt>()
        + size_of::<&mut super::decode::LiteralValue18DecodeAttempt>()
        + size_of::<super::decode::LiteralValue18DecodeQuote>()
        + size_of::<super::decode::Frame>()
        + size_of::<Option<super::decode::Frame>>()
        + size_of::<Option<&super::decode::Frame>>()
        + size_of::<Option<&mut super::decode::Frame>>()
        + size_of::<std::slice::Iter<'static, super::decode::Frame>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<serde_json::map::Iter<'static>>()
        + size_of::<serde_json::map::Keys<'static>>()
        + size_of::<
            std::iter::Chain<std::option::Iter<'static, Value>, std::option::Iter<'static, Value>>,
        >()
        + size_of::<std::option::Iter<'static, Value>>()
        + size_of::<Option<&Value>>()
        + size_of::<Option<&mut Value>>()
        + size_of::<Option<&usize>>()
        + size_of::<&LiteralValue18Data>()
        + size_of::<Result<&LiteralToken18, RuntimeError>>()
        + size_of::<&str>()
        + size_of::<Option<&str>>()
        + size_of::<(bool, bool, bool)>()
        + size_of::<Option<&LiteralToken18>>()
        + size_of::<&LiteralToken18>()
        + size_of::<&mut Vec<Value>>()
        + size_of::<&mut Map<String, Value>>()
        + size_of::<&mut Option<String>>()
        + size_of::<&mut String>()
        + size_of::<Option<&String>>()
        + size_of::<Option<&mut String>>()
        + size_of::<Value>()
        + size_of::<Option<Value>>()
        + size_of::<Option<serde_json::Number>>()
        + size_of::<Result<(), TryReserveError>>()
        + size_of::<Result<super::decode::LiteralValue18DecodeQuote, RuntimeError>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<usize>() * 14
        + size_of::<[usize; 6]>()
        + size_of::<std::array::IntoIter<usize, 6>>()
        + size_of::<Option<usize>>()
        + size_of::<u64>()
        + size_of::<i64>()
        + size_of::<f64>()
        + size_of::<[u8; 8]>()
}
