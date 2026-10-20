//! Reads only the closed shallow token grammar, without Value deserialization.

use super::*;

/// Quotes actual shallow-token clones without holding the raw document loan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LiteralValue18ReadQuote {
    tokens: usize,
    containers: usize,
    strings: usize,
    storage: LiteralValue18Storage,
}

impl LiteralValue18ReadQuote {
    /// Returns the independently admitted token-reader constructor row.
    pub(crate) fn requested_storage_data(self) -> (usize, usize, usize) {
        self.storage.requested_storage_data()
    }
}

fn chunks(input: &Value) -> Result<&[Value], RuntimeError> {
    let object = input.as_object().ok_or(RuntimeError::UnsupportedFacet)?;
    if object.len() != 2 || object.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let chunks = object
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or(RuntimeError::UnsupportedFacet)?;
    if chunks.is_empty() || chunks.len() > MAX_ARRAY_ELEMENTS {
        return Err(RuntimeError::UnsupportedFacet);
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let chunk = chunk.as_array().ok_or(RuntimeError::UnsupportedFacet)?;
        if chunk.is_empty()
            || chunk.len() > MAX_ARRAY_ELEMENTS
            || (index + 1 != chunks.len() && chunk.len() != MAX_ARRAY_ELEMENTS)
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
    }
    Ok(chunks)
}

/// Parses canonical unsigned decimal without allocating an error payload.
///
/// # Errors
/// Refuses an empty, nondecimal, noncanonical or out-of-range string.
pub(super) fn parse_unsigned(input: &str) -> Result<u64, RuntimeError> {
    if input.is_empty() || (input.len() > 1 && input.starts_with('0')) {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let mut value = 0u64;
    for byte in input.bytes() {
        if !byte.is_ascii_digit() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(RuntimeError::UnsupportedFacet)?;
    }
    Ok(value)
}

fn token(input: &Value) -> Result<walk::BorrowedToken18<'_>, RuntimeError> {
    let object = input.as_object().ok_or(RuntimeError::UnsupportedFacet)?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(RuntimeError::UnsupportedFacet)?;
    let fields = match kind {
        "null" | "arrayStart" | "arrayEnd" | "objectStart" | "objectEnd" => 1,
        "bool" | "unsigned" | "signed" | "floatBits" | "string" | "key" => 2,
        _ => return Err(RuntimeError::UnsupportedFacet),
    };
    if object.len() != fields {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let value = object.get("value");
    Ok(match kind {
        "null" => walk::BorrowedToken18::Null,
        "arrayStart" => walk::BorrowedToken18::ArrayStart,
        "arrayEnd" => walk::BorrowedToken18::ArrayEnd,
        "objectStart" => walk::BorrowedToken18::ObjectStart,
        "objectEnd" => walk::BorrowedToken18::ObjectEnd,
        "bool" => walk::BorrowedToken18::Bool(
            value
                .and_then(Value::as_bool)
                .ok_or(RuntimeError::UnsupportedFacet)?,
        ),
        "string" => walk::BorrowedToken18::String(
            value
                .and_then(Value::as_str)
                .ok_or(RuntimeError::UnsupportedFacet)?,
        ),
        "key" => walk::BorrowedToken18::Key(
            value
                .and_then(Value::as_str)
                .ok_or(RuntimeError::UnsupportedFacet)?,
        ),
        "unsigned" => walk::BorrowedToken18::Unsigned(parse_unsigned(
            value
                .and_then(Value::as_str)
                .ok_or(RuntimeError::UnsupportedFacet)?,
        )?),
        "signed" => {
            let bits = parse_unsigned(
                value
                    .and_then(Value::as_str)
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            )?;
            if i64::from_ne_bytes(bits.to_ne_bytes()) >= 0 {
                return Err(RuntimeError::UnsupportedFacet);
            }
            walk::BorrowedToken18::Signed(bits)
        }
        "floatBits" => {
            let bits = parse_unsigned(
                value
                    .and_then(Value::as_str)
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            )?;
            if !f64::from_bits(bits).is_finite() {
                return Err(RuntimeError::UnsupportedFacet);
            }
            walk::BorrowedToken18::FloatBits(bits)
        }
        _ => return Err(RuntimeError::UnsupportedFacet),
    })
}

/// Quotes every actual token/String clone from a borrowed shallow document.
///
/// The raw document and its parser/DOM constructor stay independently funded.
/// This method performs no parser, serialization or Value::Deserialize call.
///
/// # Errors
/// Refuses unknown/missing fields, noncanonical chunks or numeric payloads,
/// nonfinite float bits and the independent requested-storage ceiling.
pub(crate) fn quote_read_data(
    input: &Value,
    maximum: usize,
) -> Result<LiteralValue18ReadQuote, RuntimeError> {
    let mut tokens = 0usize;
    let mut containers = 0usize;
    let mut strings = 0usize;
    for chunk in chunks(input)? {
        for value in chunk.as_array().ok_or(RuntimeError::UnsupportedFacet)? {
            let token = token(value)?;
            tokens = tokens.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
            if matches!(
                token,
                walk::BorrowedToken18::ArrayStart | walk::BorrowedToken18::ObjectStart
            ) {
                containers = containers
                    .checked_add(1)
                    .ok_or(RuntimeError::ResourceLimit)?;
            }
            if let walk::BorrowedToken18::String(text) | walk::BorrowedToken18::Key(text) = token {
                strings = checked_sum([strings, text.len()], maximum)?;
            }
        }
    }
    let storage = geometry::token_storage(
        tokens,
        strings,
        containers
            .checked_mul(size_of::<index::Frame<'_>>())
            .ok_or(RuntimeError::ResourceLimit)?,
        geometry::read_counter_scratch_data(),
        maximum,
    )?;
    Ok(LiteralValue18ReadQuote {
        tokens,
        containers,
        strings,
        storage,
    })
}

/// Retains typed tokens under an independently admitted exact shallow-read row.
///
/// # Errors
/// Refuses reuse, changed geometry, malformed input or allocation failure.
/// The same output attempt owns every constructed child on refusal/unwind.
pub(crate) fn read_into_data(
    input: &Value,
    quote: LiteralValue18ReadQuote,
    output: &mut LiteralValue18TokenAttempt,
    maximum: usize,
) -> Result<(), RuntimeError> {
    output.begin()?;
    if quote_read_data(input, maximum)? != quote {
        return Err(RuntimeError::ForeignAuthority);
    }
    output.prepare_chunks(quote.tokens)?;
    let mut index = 0usize;
    for chunk in chunks(input)? {
        for value in chunk.as_array().ok_or(RuntimeError::UnsupportedFacet)? {
            output.push(index, token(value)?)?;
            index = index.checked_add(1).ok_or(RuntimeError::ResourceLimit)?;
        }
    }
    if index != quote.tokens {
        return Err(RuntimeError::ForeignAuthority);
    }
    index::finish(&mut output.data, quote.containers)?;
    output.finish();
    Ok(())
}

impl LiteralValue18Data {
    /// Counts the actual canonically chunked token sequence.
    ///
    /// # Errors
    /// Refuses empty/oversized/noncanonical chunks or checked length overflow.
    pub(super) fn token_count(&self) -> Result<usize, RuntimeError> {
        if self.chunks.is_empty() || self.chunks.len() > MAX_ARRAY_ELEMENTS {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut count = 0usize;
        for (index, chunk) in self.chunks.iter().enumerate() {
            if chunk.is_empty()
                || chunk.len() > MAX_ARRAY_ELEMENTS
                || (index + 1 != self.chunks.len() && chunk.len() != MAX_ARRAY_ELEMENTS)
            {
                return Err(RuntimeError::UnsupportedFacet);
            }
            count = count
                .checked_add(chunk.len())
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(count)
    }

    /// Borrows the actual token at a checked global sequence index.
    ///
    /// # Errors
    /// Refuses an index outside the retained token sequence.
    pub(super) fn token(&self, index: usize) -> Result<&LiteralToken18, RuntimeError> {
        self.chunks
            .get(index / MAX_ARRAY_ELEMENTS)
            .and_then(|chunk| chunk.get(index % MAX_ARRAY_ELEMENTS))
            .ok_or(RuntimeError::UnsupportedFacet)
    }
}
