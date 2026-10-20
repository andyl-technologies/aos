//! Extracts reviewed published bytes without using any format encoder.

use super::core_model::identity::Digest;
use alloc::{format, string::String, vec::Vec};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));

/// Decodes a hexadecimal fixture with insignificant ASCII whitespace.
///
/// # Panics
///
/// Panics if the fixture contains non-hexadecimal digits or an incomplete byte.
pub(super) fn hexadecimal(text: &str) -> Vec<u8> {
    let digits: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    assert!(digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(digits.len() % 2, 0);

    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

/// Decodes a fixed-size hexadecimal fixture.
///
/// # Panics
///
/// Panics if the fixture is malformed or its decoded length differs from `N`.
pub(super) fn fixed<const N: usize>(text: &str) -> [u8; N] {
    hexadecimal(text).try_into().unwrap()
}

/// Decodes a 32-byte hexadecimal digest fixture.
///
/// # Panics
///
/// Panics if the fixture is malformed or does not describe exactly 32 bytes.
pub(super) fn digest(text: &str) -> Digest {
    fixed(text)
}

/// Selects a unique complete heading and the numbered hex block below it.
///
/// # Panics
///
/// Panics if the heading is missing or duplicated, the block is absent or
/// unterminated, or its hexadecimal fixture is malformed.
pub(super) fn wire(heading: &str, index: usize) -> Vec<u8> {
    let marker = format!("{heading}\n");
    assert_eq!(REFERENCE.matches(&marker).count(), 1, "{heading}");
    let section = REFERENCE
        .split_once(&marker)
        .unwrap()
        .1
        .split("\n##")
        .next()
        .unwrap();
    let encoded = section.split("```hex\n").nth(index + 1).unwrap();

    hexadecimal(encoded.split_once("```").unwrap().0)
}

/// Computes a content-domain digest directly from the published wire bytes.
#[allow(
    dead_code,
    reason = "the private token-model import only uses this module's wire readers"
)]
pub(super) fn domain_digest(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    hash.update(&[0]);
    hash.update(bytes);
    *hash.finalize().as_bytes()
}

#[allow(
    dead_code,
    reason = "the private token-model import only uses this module's wire readers"
)]
fn section<'a>(document: &'a str, heading: &str) -> Result<&'a str, &'static str> {
    let marker = format!("{heading}\n");
    let mut matches = document
        .match_indices(&marker)
        .filter(|(offset, _)| *offset == 0 || document.as_bytes().get(offset - 1) == Some(&b'\n'));
    let (offset, _) = matches.next().ok_or("missing heading")?;
    if matches.next().is_some() {
        return Err("duplicate heading");
    }

    let body = &document[offset + marker.len()..];
    body.split("\n## ").next().ok_or("missing section")
}

// Exact surrounding text distinguishes a field from other digests in its section.
#[allow(
    dead_code,
    reason = "the private token-model import only uses this module's wire readers"
)]
fn literal_digest(
    document: &str,
    heading: &str,
    prefix: &str,
    suffix: &str,
) -> Result<Digest, &'static str> {
    let body = section(document, heading)?;
    let mut matches = body
        .match_indices(prefix)
        .filter(|(offset, _)| *offset == 0 || body.as_bytes().get(offset - 1) == Some(&b'\n'));
    let (offset, _) = matches.next().ok_or("missing literal")?;
    if matches.next().is_some() {
        return Err("duplicate literal");
    }

    let value = &body[offset + prefix.len()..];
    let (digits, _) = value.split_once(suffix).ok_or("damaged literal suffix")?;
    if digits.len() != 64 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("damaged digest");
    }

    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16)
            .map_err(|_| "damaged digest")?;
    }
    Ok(digest)
}

/// Compares a unique bounded published digest literal with a primitive calculation.
///
/// The in-memory controls retain the real section and alter only the selected
/// literal or its boundary. They prove missing, duplicate, malformed and valid
/// but changed digest values cannot be hidden by unchanged published wire blocks.
///
/// # Panics
///
/// Panics if the published literal is absent, ambiguous, malformed or differs
/// from `expected`, or if a mutation control does not discriminate the change.
#[allow(
    dead_code,
    reason = "the private token-model import only uses this module's wire readers"
)]
pub(super) fn assert_published_digest(heading: &str, prefix: &str, suffix: &str, expected: Digest) {
    assert_eq!(
        literal_digest(REFERENCE, heading, prefix, suffix),
        Ok(expected)
    );

    let body = section(REFERENCE, heading).unwrap();
    let bounded = format!("{heading}\n{body}\n");
    let digits: String = expected.iter().map(|byte| format!("{byte:02x}")).collect();
    let literal = format!("{prefix}{digits}{suffix}");
    assert_eq!(bounded.matches(&literal).count(), 1);

    let missing = bounded.replacen(&literal, "", 1);
    let duplicate = format!("{bounded}{literal}\n");
    let malformed = bounded.replacen(&literal, &format!("{prefix}g{}{suffix}", &digits[1..]), 1);
    let changed_first = if digits.starts_with('0') { '1' } else { '0' };
    let changed = bounded.replacen(
        &literal,
        &format!("{prefix}{changed_first}{}{suffix}", &digits[1..]),
        1,
    );

    for (name, document) in [
        ("missing", missing),
        ("duplicate", duplicate),
        ("malformed", malformed),
        ("changed", changed),
        (
            "missing heading",
            bounded.replacen(&format!("{heading}\n"), "", 1),
        ),
        ("duplicate heading", format!("{bounded}{heading}\n")),
        (
            "split section",
            bounded.replacen(&literal, &format!("## Interrupted\n{literal}"), 1),
        ),
    ] {
        assert_ne!(
            literal_digest(&document, heading, prefix, suffix),
            Ok(expected),
            "{name}: {prefix}"
        );
    }

    let surrounded = format!("## Earlier\n{literal}\n{bounded}## Later\n{literal}\n");
    assert_eq!(
        literal_digest(&surrounded, heading, prefix, suffix),
        Ok(expected)
    );
}
