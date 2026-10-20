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
    emit(&mut walker, output)?;
    Ok(statistics)
}

/// Owns a pre-reserved borrowed-iterator bank for a synchronous export.
///
/// Construction takes no source loan. The caller admits the requested backing
/// and fixed header before construction, checks actual capacity, then moves this
/// owner into its export call. No frame bank grows while source loans are live.
pub struct LiteralWriteWorkspace<'a> {
    frames: Vec<super::walk::Frame<'a>>,
    slots: usize,
}

impl<'a> LiteralWriteWorkspace<'a> {
    /// Reports the requested frame backing and fixed workspace header.
    ///
    /// This restriction is operational workspace, never a semantic depth cap or
    /// a claim about the actual input population.
    ///
    /// # Errors
    /// Refuses unrepresentable requested storage.
    pub fn requested_bytes(slots: usize) -> Result<[usize; 2], StreamError> {
        Ok([
            slots
                .checked_mul(std::mem::size_of::<super::walk::Frame<'a>>())
                .ok_or(StreamError::Limit(StreamLimitReason::SizeOverflow))?,
            std::mem::size_of::<Self>(),
        ])
    }

    /// Allocates an empty bank after independent parent admission.
    ///
    /// # Errors
    /// Refuses allocation failure or capacity exceeding the admitted request.
    pub fn new(slots: usize) -> Result<Self, StreamError> {
        let mut frames = Vec::new();
        frames.try_reserve_exact(slots)?;
        if frames.capacity() > slots {
            return Err(StreamError::Limit(
                StreamLimitReason::TraversalWorkspaceOrValues,
            ));
        }
        Ok(Self { frames, slots })
    }

    /// Reports the actual allocated backing and fixed workspace header.
    pub fn retained_bytes(&self) -> [usize; 2] {
        [
            self.frames.capacity() * std::mem::size_of::<super::walk::Frame<'a>>(),
            std::mem::size_of::<Self>(),
        ]
    }
}

/// Writes one literal using only the caller's pre-reserved frame bank.
///
/// All temporary source iterators are cleared on success and failure. The same
/// allocation is reused for measure and emission and for subsequent fields.
///
/// # Errors
/// Refuses the original wire/numeric/work limits, exhausted operational frame
/// slots, or the actual sink error. The workspace never grows.
pub fn write_value_in<'a>(
    value: &'a Value,
    output: &mut impl Write,
    limits: StreamLimits,
    workspace: &mut LiteralWriteWorkspace<'a>,
) -> Result<StreamStatistics, StreamError> {
    debug_assert!(workspace.frames.is_empty());
    debug_assert!(workspace.frames.capacity() <= workspace.slots);
    let mut walker = Walker::<false>::from_bank(
        value,
        limits.maximum_values,
        std::mem::take(&mut workspace.frames),
    );
    let statistics = measure_walk(&mut walker, limits);
    workspace.frames = walker.into_bank();
    let statistics = statistics?;
    output.write_all(MAGIC)?;
    output.write_all(&wire_integer(statistics.wire_bytes - HEADER_BYTES)?.to_be_bytes())?;
    output.write_all(&wire_integer(statistics.values)?.to_be_bytes())?;
    output.write_all(&wire_integer(statistics.depth)?.to_be_bytes())?;
    let mut walker = Walker::<false>::from_bank(
        value,
        limits.maximum_values,
        std::mem::take(&mut workspace.frames),
    );
    let result = emit(&mut walker, output);
    workspace.frames = walker.into_bank();
    result?;
    Ok(statistics)
}

fn emit<const GROW: bool>(
    walker: &mut Walker<'_, GROW>,
    output: &mut impl Write,
) -> Result<(), StreamError> {
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
    Ok(())
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
    measure_walk(&mut walker, limits)
}

fn measure_walk<const GROW: bool>(
    walker: &mut Walker<'_, GROW>,
    limits: StreamLimits,
) -> Result<StreamStatistics, StreamError> {
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
