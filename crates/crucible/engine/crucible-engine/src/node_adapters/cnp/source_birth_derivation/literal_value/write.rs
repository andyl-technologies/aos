//! Writes bounded literal frames using the retained codec's shared traversal.

use super::{
    walk::{BorrowedToken18 as Token, Walker},
    *,
};
use serde_json::{Number, Value};
use std::io::Write;

/// Writes one literal Value frame without cloning keys, strings or Values.
///
/// A bounded iterative prewalk determines the exact header before output starts.
/// A second walk writes directly to the caller's sink. On an I/O error the sink
/// retains its actual written prefix and the caller still owns the input.
///
/// # Errors
/// Refuses unsupported numeric representations, logical limits, arithmetic or
/// workspace allocation failure, or the actual output error. It does not flush.
pub fn write_value(
    value: &Value,
    output: &mut impl Write,
    limits: StreamLimits,
) -> Result<StreamStatistics, StreamError> {
    let statistics = measure(value, limits)?;
    output.write_all(MAGIC)?;
    output.write_all(&wire_integer(statistics.wire_bytes - HEADER_BYTES)?.to_be_bytes())?;
    output.write_all(&wire_integer(statistics.values)?.to_be_bytes())?;
    output.write_all(&wire_integer(statistics.depth)?.to_be_bytes())?;

    let mut walker = Walker::<false>::new(value, statistics.values).map_err(traversal_error)?;
    while let Some(token) = walker.next().map_err(traversal_error)? {
        match token {
            Token::Null => output.write_all(&[0])?,
            Token::Bool(false) => output.write_all(&[1])?,
            Token::Bool(true) => output.write_all(&[2])?,
            Token::Unsigned(value) => write_number(output, 3, value)?,
            Token::Signed(value) => write_number(output, 4, value)?,
            Token::FloatBits(value) => write_number(output, 5, value)?,
            Token::String(value) => write_text(output, 6, value)?,
            Token::ArrayStart => output.write_all(&[7])?,
            Token::ArrayEnd => output.write_all(&[8])?,
            Token::ObjectStart => output.write_all(&[9])?,
            Token::Key(value) => write_text(output, 10, value)?,
            Token::ObjectEnd => output.write_all(&[11])?,
        }
    }
    Ok(statistics)
}

fn write_number(output: &mut impl Write, tag: u8, value: u64) -> Result<(), StreamError> {
    output.write_all(&[tag])?;
    output.write_all(&value.to_be_bytes())?;
    Ok(())
}

fn write_text(output: &mut impl Write, tag: u8, value: &str) -> Result<(), StreamError> {
    output.write_all(&[tag])?;
    output.write_all(&wire_integer(value.len())?.to_be_bytes())?;
    output.write_all(value.as_bytes())?;
    Ok(())
}

fn measure(value: &Value, limits: StreamLimits) -> Result<StreamStatistics, StreamError> {
    let mut walker = Walker::<true>::streaming(value, limits.maximum_values);
    let mut statistics = StreamStatistics {
        wire_bytes: HEADER_BYTES,
        values: 0,
        depth: 0,
    };
    let mut depth = 0usize;
    while let Some(token) = walker.next().map_err(traversal_error)? {
        if let Some(current) = walker.current_value() {
            statistics.values = checked_add(statistics.values, 1)?;
            // Feature unification must never silently change a Number's exact
            // representation into another primitive supported by the wire.
            if let Value::Number(number) = current {
                let rebuilt = match token {
                    Token::Unsigned(value) => Some(Number::from(value)),
                    Token::Signed(bits) => {
                        Some(Number::from(i64::from_ne_bytes(bits.to_ne_bytes())))
                    }
                    Token::FloatBits(bits) => Number::from_f64(f64::from_bits(bits)),
                    _ => None,
                };
                if rebuilt.as_ref() != Some(number) {
                    return Err(StreamError::Format(
                        StreamFormatReason::NumberCannotRoundTripExactly,
                    ));
                }
            }
        }
        let bytes = match token {
            Token::Unsigned(_) | Token::Signed(_) | Token::FloatBits(_) => 9,
            Token::String(text) | Token::Key(text) => checked_add(9, text.len())?,
            Token::ArrayStart | Token::ObjectStart => {
                depth = checked_add(depth, 1)?;
                statistics.depth = statistics.depth.max(depth);
                1
            }
            Token::ArrayEnd | Token::ObjectEnd => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(StreamError::Format(StreamFormatReason::UnbalancedTraversal))?;
                1
            }
            Token::Null | Token::Bool(_) => 1,
        };
        statistics.wire_bytes = checked_add(statistics.wire_bytes, bytes)?;
        if statistics.wire_bytes > limits.maximum_wire_bytes {
            return Err(StreamError::Limit(StreamLimitReason::WireBytes));
        }
    }
    Ok(statistics)
}
