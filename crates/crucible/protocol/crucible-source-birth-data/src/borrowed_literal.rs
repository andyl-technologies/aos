//! Shares the original immutable literal-span cursor without owner adoption.
//!
//! This fixed-stack framing primitive returns slices of its original input.
//! It does not parse arbitrary JSON, canonicalize, allocate a DOM or grant
//! historical, native, Source or installation authority.

use crate::ProviderError;

type BorrowedFieldPair<'a> = (&'a [u8], &'a [u8]);

/// Borrows one literal array or object through the original fixed-stack cursor.
///
/// This checks framing only; it is not a canonical JSON validator or authority.
/// The original immutable input must outlive every returned slice.
pub struct OrderedFields<'a> {
    input: &'a [u8],
    position: usize,
    closing: u8,
    first: bool,
}

const FIELD_SPAN_STACK_BYTES: usize = 128;

impl<'a> OrderedFields<'a> {
    /// Names the original cursor's fixed typed headers and span stack.
    ///
    /// Input backing, constructor admission and recursive consumers are separate.
    pub fn counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + FIELD_SPAN_STACK_BYTES
            + size_of::<Result<Option<&[u8]>, ProviderError>>()
            + size_of::<Result<Option<BorrowedFieldPair<'static>>, ProviderError>>()
            + size_of::<Result<&[u8], ProviderError>>()
            + size_of::<Result<&str, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<usize>() * 2
            + size_of::<u8>()
            + size_of::<bool>() * 2
    }

    /// Opens the original array framing without decoding child values.
    ///
    /// # Errors
    /// Refuses a missing opening or closing bracket.
    pub fn array(input: &'a [u8]) -> Result<Self, ProviderError> {
        Self::new(input, b'[', b']')
    }

    /// Opens the original object framing without decoding child values.
    ///
    /// # Errors
    /// Refuses a missing opening or closing brace.
    pub fn object(input: &'a [u8]) -> Result<Self, ProviderError> {
        Self::new(input, b'{', b'}')
    }

    fn new(input: &'a [u8], opening: u8, closing: u8) -> Result<Self, ProviderError> {
        if input.first() != Some(&opening) || input.last() != Some(&closing) {
            return Err(invalid());
        }
        Ok(Self {
            input,
            position: 1,
            closing,
            first: true,
        })
    }

    /// Returns the next literal child while retaining the original input.
    ///
    /// # Errors
    /// Preserves delimiter, span-stack, trailing-input and incomplete-string
    /// refusals. It does not accept arbitrary JSON grammar by itself.
    pub fn next_value(&mut self) -> Result<Option<&'a [u8]>, ProviderError> {
        if self.input.get(self.position) == Some(&self.closing) {
            if self.position + 1 != self.input.len() {
                return Err(invalid());
            }
            return Ok(None);
        }
        if !self.first {
            self.require(b',')?;
        }
        self.first = false;
        Ok(Some(self.span()?))
    }

    /// Returns the next raw object key and value without allocating.
    ///
    /// # Errors
    /// Preserves the original cursor and colon-delimiter refusals.
    pub fn pair(&mut self) -> Result<Option<BorrowedFieldPair<'a>>, ProviderError> {
        let Some(key) = self.next_value()? else {
            return Ok(None);
        };
        self.require(b':')?;
        Ok(Some((key, self.span()?)))
    }

    /// Reads the next original field only when its unescaped name matches.
    ///
    /// # Errors
    /// Refuses missing, reordered or escaped names and the original span errors.
    pub fn named(&mut self, name: &str) -> Result<&'a [u8], ProviderError> {
        let (key, value) = self.pair()?.ok_or_else(invalid)?;
        if plain_string(key)? != name {
            return Err(invalid());
        }
        Ok(value)
    }

    /// Requires the original exact end without an additional child.
    ///
    /// # Errors
    /// Refuses trailing fields or the original terminal cursor errors.
    pub fn finish(&mut self) -> Result<(), ProviderError> {
        if self.next_value()?.is_some() {
            return Err(invalid());
        }
        Ok(())
    }

    fn require(&mut self, byte: u8) -> Result<(), ProviderError> {
        if self.input.get(self.position) != Some(&byte) {
            return Err(invalid());
        }
        self.position += 1;
        Ok(())
    }

    fn span(&mut self) -> Result<&'a [u8], ProviderError> {
        let start = self.position;
        let mut stack = [0u8; FIELD_SPAN_STACK_BYTES];
        let mut depth = 0usize;
        let mut string = false;
        let mut escaped = false;
        while let Some(byte) = self.input.get(self.position).copied() {
            if !string && depth == 0 && (byte == b',' || byte == b':' || byte == self.closing) {
                break;
            }
            self.position += 1;
            if string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    string = false;
                }
                continue;
            }
            match byte {
                b'"' => string = true,
                b'[' | b'{' => {
                    if depth == stack.len() {
                        return Err(invalid());
                    }
                    stack[depth] = if byte == b'[' { b']' } else { b'}' };
                    depth += 1;
                }
                b']' | b'}' => {
                    if depth == 0 || stack[depth - 1] != byte {
                        return Err(invalid());
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        if self.position == start || string || depth != 0 {
            return Err(invalid());
        }
        Ok(&self.input[start..self.position])
    }
}

/// Borrows the original unescaped UTF-8 JSON string interior.
///
/// # Errors
/// Refuses missing quotes, control characters, escapes or invalid UTF-8.
pub fn plain_string(input: &[u8]) -> Result<&str, ProviderError> {
    if input.len() < 2 || input.first() != Some(&b'"') || input.last() != Some(&b'"') {
        return Err(invalid());
    }
    let text = &input[1..input.len() - 1];
    if text
        .iter()
        .any(|byte| *byte < 32 || matches!(*byte, b'"' | b'\\'))
    {
        return Err(invalid());
    }
    std::str::from_utf8(text).map_err(|_| invalid())
}

fn invalid() -> ProviderError {
    ProviderError::Frame("typed historical field grammar or roster")
}

#[cfg(test)]
#[path = "borrowed_literal/tests.rs"]
mod tests;
