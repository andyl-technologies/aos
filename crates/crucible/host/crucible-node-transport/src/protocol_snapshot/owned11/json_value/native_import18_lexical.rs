//! Shares actual historical JSON lexical primitives with explicit18 preflight.
//!
//! This cursor preserves source field order and duplicates. It deliberately
//! performs lexical work only: an effective-value visitor must enforce object,
//! array, RawValue first-key/remaining-key and adapter-pass semantics. It never
//! constructs a recursive Value, grants a phase or changes ordinary readers.

use super::{Cursor, StringToken, borrowed_json_string_matches_data};
use crate::ProviderError;
use std::mem::size_of;

/// Borrows one actual JSON string token and its validated decoded width.
#[derive(Clone, Copy)]
pub(crate) struct NativeImport18JsonStringSpanData<'a> {
    quoted: &'a [u8],
    token: StringToken<'a>,
}

impl NativeImport18JsonStringSpanData<'_> {
    /// Returns the complete original quoted token without decoding or copying.
    pub(crate) const fn quoted_data(&self) -> &[u8] {
        self.quoted
    }

    /// Returns the actual UTF-8 output width established by the shared scanner.
    pub(crate) const fn decoded_bytes_data(&self) -> usize {
        self.token.decoded_bytes
    }

    /// Compares decoded text using the existing defining Unicode/escape walk.
    ///
    /// # Errors
    /// Refuses malformed escape, UTF-8 or surrogate syntax.
    pub(crate) fn matches_data(&self, expected: &str) -> Result<bool, ProviderError> {
        borrowed_json_string_matches_data(self.quoted, expected)
    }

    /// Decodes into an actual caller-retained text bank after independent credit.
    ///
    /// The caller installs the bank before entry, admits this token's exact
    /// decoded width and retains its capacity/partial text on either outcome.
    /// No tree, native input or memory admission is produced by this operation.
    ///
    /// # Errors
    /// Refuses a used output, backing reservation or shared lexical failure.
    pub(crate) fn decode_into_data(&self, output: &mut String) -> Result<(), ProviderError> {
        if !output.is_empty() {
            return Err(invalid());
        }
        output
            .try_reserve_exact(self.token.decoded_bytes)
            .map_err(|_| exhausted())?;
        let mut cursor = Cursor::new(self.token.encoded);
        while cursor.position < cursor.input.len() {
            output.push(cursor.character()?);
        }
        if output.len() != self.token.decoded_bytes {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Names one borrowed token without assuming a complete structural grammar.
#[derive(Clone, Copy)]
pub(crate) enum NativeImport18JsonLexicalTokenData<'a> {
    /// Borrows one fully checked string token.
    String(NativeImport18JsonStringSpanData<'a>),
    /// Borrows number syntax without the historical serializer-only32-byte cap.
    ///
    /// The effective visitor separately uses the actual locked scalar parser
    /// under its admitted error/formatter row; lexical syntax is not a Number.
    Number(&'a str),
    /// Names a JSON Boolean.
    Bool(bool),
    /// Names JSON null.
    Null,
    /// Opens an array.
    Array,
    /// Closes an array.
    ArrayEnd,
    /// Opens an object.
    Object,
    /// Closes an object.
    ObjectEnd,
    /// Separates an object key from its value.
    Colon,
    /// Separates object entries or array elements.
    Comma,
}

/// Advances actual contiguous text with the existing lexical implementation.
///
/// Source text may be a separately retained, independently decoded RawValue
/// String bank. Position is scalar DATA; the effective visitor owns all nesting
/// and normalization state and must consume complete input before success.
pub(crate) struct NativeImport18JsonLexicalCursorData<'a> {
    cursor: Cursor<'a>,
}

impl<'a> NativeImport18JsonLexicalCursorData<'a> {
    /// Borrows UTF-8 input without allocating or interpreting any RawValue key.
    pub(crate) fn new_data(input: &'a str) -> Self {
        Self {
            cursor: Cursor::new(input.as_bytes()),
        }
    }

    /// Resumes a saved lexical position in the same caller-retained input bank.
    ///
    /// # Errors
    /// Refuses an out-of-bounds or non-UTF-8-boundary position. The caller must
    /// supply a position previously returned for this exact immutable bank.
    pub(crate) fn resume_data(input: &'a str, position: usize) -> Result<Self, ProviderError> {
        if !input.is_char_boundary(position) {
            return Err(invalid());
        }
        Ok(Self {
            cursor: Cursor {
                input: input.as_bytes(),
                position,
            },
        })
    }

    /// Returns the scalar offset after all completely consumed token bytes.
    pub(crate) const fn position_data(&self) -> usize {
        self.cursor.position
    }

    /// Advances one token without imposing ordering or unique object keys.
    ///
    /// # Errors
    /// Refuses malformed literals, string/number syntax or unknown punctuation.
    /// Structural separators and complete-input grammar belong to the visitor.
    pub(crate) fn next_data(
        &mut self,
    ) -> Result<Option<NativeImport18JsonLexicalTokenData<'a>>, ProviderError> {
        use NativeImport18JsonLexicalTokenData as Token;

        self.cursor.whitespace();
        let start = self.cursor.position;
        let Some(byte) = self.cursor.peek() else {
            return Ok(None);
        };
        let token = match byte {
            b'"' => {
                let token = self.cursor.string()?;
                Token::String(NativeImport18JsonStringSpanData {
                    quoted: &self.cursor.input[start..self.cursor.position],
                    token,
                })
            }
            b'n' => {
                self.cursor.literal(b"null")?;
                self.require_primitive_end_data()?;
                Token::Null
            }
            b't' => {
                self.cursor.literal(b"true")?;
                self.require_primitive_end_data()?;
                Token::Bool(true)
            }
            b'f' => {
                self.cursor.literal(b"false")?;
                self.require_primitive_end_data()?;
                Token::Bool(false)
            }
            b'-' | b'0'..=b'9' => Token::Number(self.number_span_data()?),
            b'[' | b']' | b'{' | b'}' | b':' | b',' => {
                self.cursor.advance()?;
                match byte {
                    b'[' => Token::Array,
                    b']' => Token::ArrayEnd,
                    b'{' => Token::Object,
                    b'}' => Token::ObjectEnd,
                    b':' => Token::Colon,
                    _ => Token::Comma,
                }
            }
            _ => return Err(invalid()),
        };
        Ok(Some(token))
    }

    fn number_span_data(&mut self) -> Result<&'a str, ProviderError> {
        // This is the same lexical path as Cursor::number. Its historical
        // MAXIMUM_NUMBER_BYTES/serializer-roundtrip contract is not imported:
        // ordinary locked serde accepts longer finite decimal spellings too.
        let start = self.cursor.position;
        if self.cursor.peek() == Some(b'-') {
            self.cursor.advance()?;
        }
        match self.cursor.advance()? {
            b'0' => {}
            b'1'..=b'9' => {
                while self.cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.cursor.advance()?;
                }
            }
            _ => return Err(invalid()),
        }
        if self.cursor.peek() == Some(b'.') {
            self.cursor.advance()?;
            self.cursor.digits()?;
        }
        if matches!(self.cursor.peek(), Some(b'e' | b'E')) {
            self.cursor.advance()?;
            if matches!(self.cursor.peek(), Some(b'+' | b'-')) {
                self.cursor.advance()?;
            }
            self.cursor.digits()?;
        }
        self.require_primitive_end_data()?;
        std::str::from_utf8(&self.cursor.input[start..self.cursor.position]).map_err(|_| invalid())
    }

    fn require_primitive_end_data(&self) -> Result<(), ProviderError> {
        if matches!(
            self.cursor.peek(),
            None | Some(b' ' | b'\n' | b'\r' | b'\t' | b',' | b']' | b'}')
        ) {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

/// Names direct lexical/string bank controls before their first walk or decode.
pub(crate) fn native_import18_json_lexical_counter_scratch_data() -> usize {
    super::borrowed_json_string_comparison_counter_scratch_data()
        + super::borrowed_json_string_storage_counter_scratch_data()
        + size_of::<NativeImport18JsonLexicalCursorData<'static>>()
        + size_of::<Result<NativeImport18JsonLexicalCursorData<'static>, ProviderError>>()
        + size_of::<NativeImport18JsonLexicalTokenData<'static>>()
        + size_of::<Option<NativeImport18JsonLexicalTokenData<'static>>>()
        + size_of::<Result<Option<NativeImport18JsonLexicalTokenData<'static>>, ProviderError>>()
        + size_of::<NativeImport18JsonStringSpanData<'static>>()
        + size_of::<Cursor<'static>>()
        + size_of::<StringToken<'static>>()
        + size_of::<&mut String>()
        + size_of::<std::collections::TryReserveError>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<&str>()
        + size_of::<&[u8]>()
        + size_of::<[u8; 4]>()
        + size_of::<Option<u8>>()
        + size_of::<Result<char, ProviderError>>()
        + size_of::<Result<&'static str, ProviderError>>()
        + size_of::<std::str::Utf8Error>()
        + size_of::<Result<&'static str, std::str::Utf8Error>>()
        + size_of::<usize>() * 3
        + size_of::<Result<(), ProviderError>>()
}

fn invalid() -> ProviderError {
    ProviderError::Frame("explicit18 effective JSON lexical grammar")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("explicit18 effective JSON text bank")
}
