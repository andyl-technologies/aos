//! Reads uniquely bounded normative sections and writes independent primitive CBOR.
//!
//! ```text
//! section = one exact top-level heading through the next top-level heading
//! Value = uint | bstr | tstr | [Value] | {uint: Value}
//! ```

#![allow(
    dead_code,
    reason = "each isolated consumer uses its own subset of the shared oracle"
)]

use alloc::{format, string::String, vec::Vec};

/// Supplies the exact UTF-8 reference compiled into each sandbox consumer.
pub(super) const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));

/// Returns the sole exact top-level section without normalizing line endings.
///
/// # Errors
/// Rejects CRLF input and missing or duplicate exact top-level headings.
pub(super) fn section<'a>(source: &'a str, heading: &str) -> Result<&'a str, String> {
    if source.contains('\r') {
        return Err("reference must retain LF bytes".into());
    }
    let marker = format!("## {heading}\n");
    let mut starts = source.match_indices(&marker).filter_map(|(offset, _)| {
        (offset == 0 || source.as_bytes()[offset - 1] == b'\n').then_some(offset)
    });
    let start = starts.next().ok_or_else(|| format!("missing {heading}"))?;
    if starts.next().is_some() {
        return Err(format!("duplicate {heading}"));
    }
    let body = &source[start + marker.len()..];
    Ok(body.split_once("\n## ").map_or(body, |(body, _)| body))
}

/// Reads a uniquely named contiguous Markdown table with exact column counts.
///
/// # Errors
/// Rejects missing/duplicate headers, malformed separator rows or field counts.
pub(super) fn table<'a>(
    body: &'a str,
    header: &str,
    columns: usize,
) -> Result<Vec<Vec<&'a str>>, String> {
    let marker = format!("{header}\n");
    if body.matches(&marker).count() != 1 {
        return Err(format!("table header must occur once: {header}"));
    }
    let remainder = body.split_once(&marker).ok_or("missing table")?.1;
    let mut lines = remainder.split('\n');
    let separator = lines.next().ok_or("missing table separator")?;
    if separator != format!("|{}", " --- |".repeat(columns)) {
        return Err("unexpected table separator".into());
    }
    lines
        .take_while(|line| line.starts_with('|'))
        .map(|line| {
            if !line.ends_with('|') {
                return Err("unterminated table row".into());
            }
            let cells: Vec<_> = line[1..line.len() - 1].split('|').map(str::trim).collect();
            if cells.len() != columns {
                return Err("unexpected column count".into());
            }
            Ok(cells)
        })
        .collect()
}

/// Reads all complete fences of the specified language in a bounded section.
///
/// # Errors
/// Rejects missing closing fences and an unexpected number of matching blocks.
pub(super) fn blocks<'a>(
    body: &'a str,
    language: &str,
    count: usize,
) -> Result<Vec<&'a str>, String> {
    let marker = format!("```{language}\n");
    let mut result = Vec::new();
    let mut remaining = body;
    while let Some((_, tail)) = remaining.split_once(&marker) {
        let (value, tail) = tail.split_once("\n```").ok_or("unterminated fence")?;
        result.push(value);
        remaining = tail;
    }
    if result.len() != count {
        return Err(format!(
            "expected {count} {language} blocks, got {}",
            result.len()
        ));
    }
    Ok(result)
}

/// Reads one inline literal after an exact unique prose marker.
///
/// # Errors
/// Rejects missing/duplicate markers or an unterminated inline literal.
pub(super) fn literal_after<'a>(body: &'a str, marker: &str) -> Result<&'a str, String> {
    if body.matches(marker).count() != 1 {
        return Err(format!("inline marker must occur once: {marker}"));
    }
    body.split_once(marker)
        .ok_or("missing inline marker")?
        .1
        .split_once('`')
        .map(|(value, _)| value)
        .ok_or_else(|| "unterminated inline literal".into())
}

/// Removes exactly one pair of inline-code delimiters.
///
/// # Errors
/// Rejects a field that is not a complete inline-code literal.
pub(super) fn unquote(value: &str) -> Result<&str, String> {
    value
        .strip_prefix('`')
        .and_then(|value| value.strip_suffix('`'))
        .ok_or_else(|| "expected inline literal".into())
}

/// Decodes lowercase hexadecimal bytes while permitting published line breaks.
///
/// # Errors
/// Rejects odd digit counts, uppercase or nonhexadecimal characters.
pub(super) fn hexadecimal(value: &str) -> Result<Vec<u8>, String> {
    let digits: String = value
        .chars()
        .filter(|value| !value.is_ascii_whitespace())
        .collect();
    if !digits.len().is_multiple_of(2)
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid lowercase hexadecimal bytes".into());
    }
    (0..digits.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&digits[offset..offset + 2], 16)
                .map_err(|error| format!("hexadecimal byte: {error}"))
        })
        .collect()
}

/// Reads a decimal quantity while preserving its numeric meaning.
///
/// # Errors
/// Rejects empty or malformed digits and quantities outside `u64`.
pub(super) fn decimal(value: &str) -> Result<u64, String> {
    let digits: String = value.chars().filter(|value| *value != ',').collect();
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid decimal quantity".into());
    }
    digits
        .parse()
        .map_err(|error| format!("decimal quantity: {error}"))
}

/// Reads the fixed-width hexadecimal words used by the published gear and masks.
///
/// # Errors
/// Rejects absent prefixes, wrong widths and malformed hexadecimal words.
pub(super) fn word(value: &str) -> Result<u64, String> {
    let digits = value.strip_prefix("0x").ok_or("missing word prefix")?;
    if hexadecimal(digits)?.len() != 8 {
        return Err("word must contain eight bytes".into());
    }
    u64::from_str_radix(digits, 16).map_err(|error| format!("hexadecimal word: {error}"))
}

/// Replaces one observed field for a mutation control without changing the file.
///
/// # Panics
/// Panics if the specified original field does not occur exactly once.
pub(super) fn changed(source: &str, original: &str, replacement: &str) -> String {
    assert_eq!(
        source.matches(original).count(),
        1,
        "mutation must isolate one field"
    );
    source.replacen(original, replacement, 1)
}

/// Holds a primitive model independent of every owning format encoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Value {
    /// Unsigned integer.
    Uint(u64),
    /// Exact byte string.
    Bytes(Vec<u8>),
    /// Exact UTF-8 text.
    Text(String),
    /// Ordered array.
    Array(Vec<Self>),
    /// Unsigned-key map in canonical field order.
    Map(Vec<(u64, Self)>),
}

impl Value {
    /// Serializes primitive values with minimal definite-length CBOR arguments.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.write(&mut output);
        output
    }

    fn write(&self, output: &mut Vec<u8>) {
        match self {
            Self::Uint(value) => argument(output, 0, *value),
            Self::Bytes(value) => {
                argument(output, 2, value.len() as u64);
                output.extend(value);
            }
            Self::Text(value) => {
                argument(output, 3, value.len() as u64);
                output.extend(value.as_bytes());
            }
            Self::Array(values) => {
                argument(output, 4, values.len() as u64);
                for value in values {
                    value.write(output);
                }
            }
            Self::Map(fields) => {
                argument(output, 5, fields.len() as u64);
                for (key, value) in fields {
                    argument(output, 0, *key);
                    value.write(output);
                }
            }
        }
    }
}

fn argument(output: &mut Vec<u8>, major: u8, value: u64) {
    match value {
        0..=23 => output.push((major << 5) | value as u8),
        24..=255 => output.extend([(major << 5) | 24, value as u8]),
        256..=65_535 => {
            output.push((major << 5) | 25);
            output.extend((value as u16).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            output.push((major << 5) | 26);
            output.extend((value as u32).to_be_bytes());
        }
        _ => {
            output.push((major << 5) | 27);
            output.extend(value.to_be_bytes());
        }
    }
}
