//! Borrows canonical children from the retained original private boot frame.
//!
//! The strict frame parser and closed boot DTO checks precede this lexical
//! projection. The canonical encoder checks the actual copied child against
//! its original bytes without constructing another output bank. These slices
//! are DATA; the original claimant still authenticates every digest and grant.

use crate::ProviderError;
use crucible_node_format::{ContractError, canonical};
use serde_json::Value;
use std::{io, mem::size_of};

/// Borrows the two independently authenticated canonical child literals.
pub(in crate::reference_packet::service::ack_emitter::native_boot) struct CanonicalBootChildren<'a>
{
    /// Borrows the original Source binding inside the retained second frame.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) source: &'a [u8],
    /// Borrows the original host registration in that same retained frame.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) registration: &'a [u8],
}

/// Checks canonical child correspondence without allocating output banks.
///
/// # Errors
/// Refuses missing or repeated selected literals, invalid lexical structure,
/// noncanonical child bytes, or an error from the authoritative JCS encoder.
pub(in crate::reference_packet::service::ack_emitter::native_boot) fn borrow_canonical_children_data<
    'a,
>(
    body: &'a [u8],
    source: &Value,
    registration: &Value,
) -> Result<CanonicalBootChildren<'a>, ProviderError> {
    let mut cursor = Cursor { body, position: 0 };
    cursor.take(b'{')?;
    let mut source_body = None;
    let mut registration_body = None;

    loop {
        cursor.whitespace();
        if cursor.body.get(cursor.position) == Some(&b'}') {
            cursor.position += 1;
            break;
        }
        let key = cursor.value()?;
        cursor.take(b':')?;
        let value = cursor.value()?;
        let selected = match key {
            b"\"source_birth\"" => Some(&mut source_body),
            b"\"expected_host_registration\"" => Some(&mut registration_body),
            _ => None,
        };
        if let Some(slot) = selected
            && slot.replace(value).is_some()
        {
            return Err(refused());
        }
        cursor.whitespace();
        match cursor.body.get(cursor.position) {
            Some(b',') => cursor.position += 1,
            Some(b'}') => {
                cursor.position += 1;
                break;
            }
            _ => return Err(refused()),
        }
    }
    cursor.whitespace();
    if cursor.position != body.len() {
        return Err(refused());
    }
    let source_body = source_body.ok_or_else(refused)?;
    let registration_body = registration_body.ok_or_else(refused)?;
    verify(source, source_body)?;
    verify(registration, registration_body)?;
    Ok(CanonicalBootChildren {
        source: source_body,
        registration: registration_body,
    })
}

struct Cursor<'a> {
    body: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn whitespace(&mut self) {
        while self
            .body
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn take(&mut self, expected: u8) -> Result<(), ProviderError> {
        self.whitespace();
        if self.body.get(self.position) != Some(&expected) {
            return Err(refused());
        }
        self.position += 1;
        Ok(())
    }

    fn value(&mut self) -> Result<&'a [u8], ProviderError> {
        // The original strict parser owns grammar validation. This bounded
        // cursor only preserves nested delimiters and quoted byte boundaries.
        self.whitespace();
        let start = self.position;
        let mut stack = [0u8; 64];
        let mut depth = 0usize;
        let mut string = false;
        while let Some(&byte) = self.body.get(self.position) {
            if string {
                match byte {
                    b'\\' => {
                        self.position += 1;
                        self.body.get(self.position).ok_or_else(refused)?;
                    }
                    b'"' => {
                        string = false;
                        if depth == 0 {
                            self.position += 1;
                            return self.body.get(start..self.position).ok_or_else(refused);
                        }
                    }
                    _ => {}
                }
            } else {
                match byte {
                    b'"' => string = true,
                    b'{' | b'[' => {
                        *stack.get_mut(depth).ok_or_else(refused)? =
                            if byte == b'{' { b'}' } else { b']' };
                        depth += 1;
                    }
                    b'}' | b']' if depth > 0 => {
                        depth -= 1;
                        if stack[depth] != byte {
                            return Err(refused());
                        }
                        if depth == 0 {
                            self.position += 1;
                            return self.body.get(start..self.position).ok_or_else(refused);
                        }
                    }
                    b',' | b'}' | b':' if depth == 0 => break,
                    _ => {}
                }
            }
            self.position += 1;
        }
        let value = self.body.get(start..self.position).ok_or_else(refused)?;
        let end = value
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .and_then(|last| last.checked_add(1))
            .ok_or_else(refused)?;
        value.get(..end).ok_or_else(refused)
    }
}

struct BodyMatch<'a> {
    expected: &'a [u8],
    written: usize,
    differs: bool,
}

impl io::Write for BodyMatch<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self.written.checked_add(bytes.len());
        if end.and_then(|end| self.expected.get(self.written..end)) != Some(bytes) {
            self.differs = true;
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn verify(value: &Value, expected: &[u8]) -> Result<(), ProviderError> {
    let mut check = BodyMatch {
        expected,
        written: 0,
        differs: false,
    };
    let result = canonical::canonical_json_to_writer(value, &mut check);
    if check.differs {
        return Err(refused());
    }
    result?;
    if check.written != expected.len() {
        return Err(refused());
    }
    Ok(())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native startup canonical child literal differs")
}

/// Counts the independent fixed lexical, comparison and returned-slice views.
pub(super) const fn counter_scratch_data() -> usize {
    2 * size_of::<Cursor<'static>>()
        + 3 * size_of::<&mut Cursor<'static>>()
        + size_of::<[u8; 64]>()
        + 6 * size_of::<usize>()
        + 4 * size_of::<bool>()
        + 3 * size_of::<u8>()
        + 2 * size_of::<Option<&u8>>()
        + size_of::<Option<&mut u8>>()
        + size_of::<Result<&u8, ProviderError>>()
        + size_of::<Result<&mut u8, ProviderError>>()
        + 4 * size_of::<Option<&[u8]>>()
        + size_of::<Option<&mut Option<&[u8]>>>()
        + 4 * size_of::<Result<&[u8], ProviderError>>()
        + 8 * size_of::<&[u8]>()
        + 3 * size_of::<&Value>()
        + 2 * size_of::<BodyMatch<'static>>()
        + 2 * size_of::<&mut BodyMatch<'static>>()
        + size_of::<Result<(), ContractError>>()
        + 4 * size_of::<Result<(), ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<io::Error>()
        + size_of::<io::ErrorKind>()
        + size_of::<io::Result<usize>>()
        + size_of::<io::Result<()>>()
        + size_of::<std::slice::Iter<'static, u8>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<std::ops::RangeTo<usize>>()
        + 4 * size_of::<CanonicalBootChildren<'static>>()
        + 2 * size_of::<Result<CanonicalBootChildren<'static>, ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_children_borrow_original_nested_opaque_literals() {
        let source = json!({
            "source_birth": {"escaped": "quoted \\\"},[]: delimiters"},
            "$serde_json::private::RawValue": "not JSON",
            "values": [null, true, 1e9, "λ", [1, 2]],
        });
        let registration = json!({"host": ["value", {"key": "embedded source_birth"}]});
        let body = canonical::canonical_json(&json!({
            "other": {"source_birth": "nested decoy"},
            "source_birth": source,
            "expected_host_registration": registration,
        }))
        .unwrap();
        let source_bytes = canonical::canonical_json(&source).unwrap();
        let host_bytes = canonical::canonical_json(&registration).unwrap();

        let borrowed = borrow_canonical_children_data(&body, &source, &registration).unwrap();

        for (child, expected) in [
            (borrowed.source, source_bytes),
            (borrowed.registration, host_bytes),
        ] {
            let offset = body
                .windows(expected.len())
                .position(|bytes| bytes == expected)
                .unwrap();
            assert_eq!(child, expected);
            assert_eq!(child.as_ptr(), body[offset..].as_ptr());
        }
    }

    #[test]
    fn changed_missing_duplicate_and_noncanonical_children_are_refused() {
        let source = json!({"a": 1});
        let registration = json!({"b": 2});
        for body in [
            br#"{"source_birth":{"a":1}}"#.as_slice(),
            br#"{"source_birth":{"a":1},"source_birth":{"a":1},"expected_host_registration":{"b":2}}"#,
            br#"{"source_birth":{ "a":1},"expected_host_registration":{"b":2}}"#,
            br#"{"source_birth":{"a":2},"expected_host_registration":{"b":2}}"#,
            br#"{"source_birth":{"a":1},"expected_host_registration":{"b":3}}"#,
            br#"{"source_birth":{"a":1},"expected_host_registration":{ "b":2}}"#,
            br#"{"\u0073ource_birth":{"a":1},"expected_host_registration":{"b":2}}"#,
            br#"{"source_birth":{"a":1},"expected_host_registration":{"b":2}"#,
        ] {
            assert!(borrow_canonical_children_data(body, &source, &registration).is_err());
        }
    }

    #[test]
    fn noncanonical_numeric_spelling_cannot_replace_the_original_child() {
        let source = json!({"number": 1e9});
        let registration = json!({});
        let body = br#"{"source_birth":{"number":1e9},"expected_host_registration":{}}"#;
        assert_eq!(
            canonical::canonical_json(&source).unwrap(),
            br#"{"number":1000000000}"#
        );

        let result = borrow_canonical_children_data(body, &source, &registration);

        assert!(matches!(
            result,
            Err(ProviderError::Correlation(
                "native startup canonical child literal differs"
            ))
        ));
    }
}
