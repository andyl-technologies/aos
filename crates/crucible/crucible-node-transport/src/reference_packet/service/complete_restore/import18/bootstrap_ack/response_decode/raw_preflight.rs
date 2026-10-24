//! Scans the closed Bootstrap response before allocating a JSON tree.
//!
//! JSON whitespace, field order and equivalent ASCII escapes remain valid wire
//! spellings. Fixed buffers reject expanded values and duplicate/unknown fields
//! before a generic parser can construct them. This grants no receive or MAC
//! authority and does not establish raw-literal provenance.

use super::*;
use base64::Engine;
use crucible_node_format::values::MAX_ID_BYTES;

#[derive(Clone, Copy)]
enum Object {
    Envelope,
    Body,
    Result,
    Funding,
    CommonExtensions,
    ReceiptExtensions,
    Receipt,
}

impl Object {
    fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Envelope => &preflight::ENVELOPE_FIELDS,
            Self::Body => &preflight::BODY_FIELDS,
            Self::Result => &preflight::RESULT_FIELDS,
            Self::Funding => &preflight::FUNDING_FIELDS,
            Self::CommonExtensions => &[],
            Self::ReceiptExtensions => &[NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT],
            Self::Receipt => &preflight::RECEIPT_FIELDS,
        }
    }
}

struct Ascii {
    bytes: [u8; MAX_ID_BYTES],
    length: usize,
}

impl Ascii {
    fn text(&self) -> Result<&str, ProviderError> {
        std::str::from_utf8(&self.bytes[..self.length]).map_err(|_| refused())
    }
}

struct Scanner<'a> {
    original: &'a Envelope,
    input: &'a [u8],
    position: usize,
}

/// Checks closed raw Bootstrap response spelling before generic JSON parsing.
///
/// The caller separately funds the actual raw bank and this fixed scanner, then
/// independently admits the closed DOM/parser/typed owners. No owning output,
/// SDK transition, receipt authentication or Source completion is produced.
///
/// # Errors
/// Refuses malformed JSON, unknown/duplicate fields, non-ASCII or over-width
/// text, wrong fixed grammar, mismatched IDs or noncanonical numeric/digest text.
pub fn native_import18_bootstrap_raw_preflight_data(
    original: &Envelope,
    raw: &[u8],
) -> Result<(), ProviderError> {
    let mut scanner = Scanner {
        original,
        input: raw,
        position: 0,
    };
    scanner.object(Object::Envelope)?;
    scanner.whitespace();
    if scanner.position != raw.len() {
        return Err(refused());
    }
    Ok(())
}

impl Scanner<'_> {
    fn whitespace(&mut self) {
        while self
            .input
            .get(self.position)
            .is_some_and(|byte| b" \t\r\n".contains(byte))
        {
            self.position += 1;
        }
    }

    fn byte(&mut self) -> Result<u8, ProviderError> {
        let byte = self.input.get(self.position).copied().ok_or_else(refused)?;
        self.position += 1;
        Ok(byte)
    }

    fn punctuation(&mut self, expected: u8) -> Result<(), ProviderError> {
        self.whitespace();
        if self.byte()? != expected {
            return Err(refused());
        }
        Ok(())
    }

    fn string(&mut self) -> Result<Ascii, ProviderError> {
        self.punctuation(b'"')?;
        let mut value = Ascii {
            bytes: [0; MAX_ID_BYTES],
            length: 0,
        };
        loop {
            let mut byte = self.byte()?;
            match byte {
                b'"' => return Ok(value),
                b'\\' => {
                    byte = match self.byte()? {
                        b'"' => b'"',
                        b'\\' => b'\\',
                        b'/' => b'/',
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'u' => {
                            let mut code = 0u16;
                            for _ in 0..4 {
                                let digit = self.byte()?;
                                let nibble = match digit {
                                    b'0'..=b'9' => digit - b'0',
                                    b'a'..=b'f' => digit - b'a' + 10,
                                    b'A'..=b'F' => digit - b'A' + 10,
                                    _ => return Err(refused()),
                                };
                                code = (code << 4) | u16::from(nibble);
                            }
                            u8::try_from(code)
                                .ok()
                                .filter(u8::is_ascii)
                                .ok_or_else(refused)?
                        }
                        _ => return Err(refused()),
                    }
                }
                0..=31 | 128..=255 => return Err(refused()),
                _ => {}
            }
            *value.bytes.get_mut(value.length).ok_or_else(refused)? = byte;
            value.length += 1;
        }
    }

    fn object(&mut self, object: Object) -> Result<(), ProviderError> {
        self.punctuation(b'{')?;
        let fields = object.fields();
        let mut seen = 0u16;
        self.whitespace();
        if self.input.get(self.position) == Some(&b'}') {
            self.position += 1;
            return if fields.is_empty() {
                Ok(())
            } else {
                Err(refused())
            };
        }
        loop {
            let key = self.string()?;
            let text = key.text()?;
            let index = fields
                .iter()
                .position(|field| text == *field)
                .ok_or_else(refused)?;
            let bit = 1u16
                .checked_shl(u32::try_from(index).map_err(|_| refused())?)
                .ok_or_else(refused)?;
            if seen & bit != 0 {
                return Err(refused());
            }
            seen |= bit;
            self.punctuation(b':')?;
            self.field(object, fields[index])?;
            self.whitespace();
            match self.byte()? {
                b'}' => break,
                b',' => {}
                _ => return Err(refused()),
            }
        }
        let complete = 1u16
            .checked_shl(u32::try_from(fields.len()).map_err(|_| refused())?)
            .and_then(|mask| mask.checked_sub(1))
            .ok_or_else(refused)?;
        if seen != complete {
            return Err(refused());
        }
        Ok(())
    }

    fn field(&mut self, object: Object, field: &str) -> Result<(), ProviderError> {
        use Object::*;
        match (object, field) {
            (Envelope, "body") => self.object(Body),
            (Envelope, "extensions") => self.object(ReceiptExtensions),
            (Body, "result") => self.object(Result),
            (Body, "extensions") => self.object(CommonExtensions),
            (Result, "initial_funding") => self.object(Funding),
            (ReceiptExtensions, NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT) => self.object(Receipt),
            (Envelope, "node_id" | "execution_owner_id" | "capture_owner_id" | "operation_id") => {
                self.whitespace();
                for expected in *b"null" {
                    if self.byte()? != expected {
                        return Err(refused());
                    }
                }
                Ok(())
            }
            (Envelope, "session_id" | "incarnation_id" | "request_id") => {
                let original = self.original;
                let expected = match field {
                    "session_id" => original.session_id.0.as_ref(),
                    "incarnation_id" => original.incarnation_id.0.as_ref(),
                    _ => original.request_id.0.as_ref(),
                }
                .ok_or_else(refused)?;
                self.exact(expected.as_str())
            }
            (Envelope, "protocol") => self.exact("CNP/1"),
            (Envelope, "message") => self.exact("response"),
            (Envelope, "method") => self.exact("native_import18_bootstrap"),
            (Envelope, "sequence") => self.exact("2"),
            (Body, "status" | "operation_state") => self.exact("completed"),
            (Result, "schema") => self.exact(NATIVE_IMPORT18_BOOTSTRAP_RESULT_SCHEMA),
            (Result | Receipt, "state") => self.exact("bootstrap_only"),
            (Receipt, "schema") => self.exact(NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT),
            (Receipt, "algorithm") => self.exact(PACKET_COMPLETE_RESTORE_ALGORITHM),
            (Result, "recipe_identity")
            | (Receipt, "context_digest" | "assigned_response" | "mac") => self.digest(),
            (Funding, _) => self.decimal(),
            _ => Err(refused()),
        }
    }

    fn exact(&mut self, expected: &str) -> Result<(), ProviderError> {
        if self.string()?.text()? != expected {
            return Err(refused());
        }
        Ok(())
    }

    fn decimal(&mut self) -> Result<(), ProviderError> {
        let value = self.string()?;
        let text = value.text()?;
        if text.is_empty()
            || text.len() > 20
            || text.len() > 1 && text.starts_with('0')
            || !text.bytes().all(|byte| byte.is_ascii_digit())
            || text.parse::<u64>().is_err()
        {
            return Err(refused());
        }
        Ok(())
    }

    fn digest(&mut self) -> Result<(), ProviderError> {
        let value = self.string()?;
        let mut digest = [0; 32];
        if value.length != 43
            || base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode_slice(&value.bytes[..value.length], &mut digest)
                .map_err(|_| refused())?
                != 32
        {
            return Err(refused());
        }
        Ok(())
    }
}

/// Names all closed object frames and fixed ASCII/decoder controls before entry.
pub fn native_import18_bootstrap_raw_preflight_counter_scratch_data() -> usize {
    let object_frame = size_of::<Object>()
        + size_of::<Ascii>()
        + size_of::<u16>()
        + size_of::<&[&str]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<&mut Scanner<'static>>()
        + size_of::<&str>();
    let scalar_controls = size_of::<Ascii>()
        + size_of::<Result<Ascii, ProviderError>>()
        + size_of::<[u8; 32]>()
        + size_of::<Result<usize, base64::DecodeSliceError>>()
        + size_of::<Result<&str, std::str::Utf8Error>>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + size_of::<[usize; 4]>()
        + size_of::<Result<u8, ProviderError>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<std::str::Bytes<'static>>();

    // Each defining object keeps its own key/roster/control view. Counting all
    // seven also dominates the smaller simultaneous recursive depth.
    size_of::<Scanner<'static>>() + 7 * object_frame + scalar_controls
}

fn refused() -> ProviderError {
    ProviderError::Correlation("closed raw Bootstrap18 response")
}

#[cfg(test)]
#[path = "raw_preflight/tests.rs"]
mod tests;
