//! Strict bounded decoder for canonical documentation NARs.
//!
//! RFC-0015 documentation objects are deliberately smaller than the general
//! Nix archive language: one non-executable regular file at the archive root,
//! no directory entries, links, devices, or trailing data. Keeping this parser
//! beside the closed documentation model gives native Hub, the Worker, browser
//! tooling, and offline clients one evaluator-free validation path.

use crate::{DocumentationError, MAX_DOCUMENT_BYTES, Result};

const NAR_MAGIC: &[u8] = b"nix-archive-1";

/// Decodes one bounded, non-executable regular-file NAR.
///
/// The returned slice borrows the exact file contents from `input`. Every NAR
/// string length and padding byte is checked before advancing, and no trailing
/// bytes are accepted.
///
/// # Errors
///
/// Returns [`DocumentationError::Invalid`] when the archive is truncated,
/// over-sized, non-canonical, executable, not a regular root file, or carries
/// any additional node or trailing data.
pub fn decode_single_file_nar(input: &[u8]) -> Result<&[u8]> {
    let max_nar = MAX_DOCUMENT_BYTES
        .checked_add(512)
        .ok_or_else(|| DocumentationError::Invalid("NAR size limit overflow".into()))?;
    if input.len() > max_nar {
        return Err(DocumentationError::Invalid(format!(
            "documentation NAR is {} bytes; limit is {max_nar}",
            input.len()
        )));
    }

    let mut decoder = Decoder { input, offset: 0 };
    decoder.expect_string(NAR_MAGIC, "archive magic")?;
    decoder.expect_string(b"(", "root open")?;
    decoder.expect_string(b"type", "root type key")?;
    decoder.expect_string(b"regular", "root type")?;
    let next = decoder.string("contents key")?;
    if next == b"executable" {
        return Err(DocumentationError::Invalid(
            "documentation NAR root must not be executable".into(),
        ));
    }
    if next != b"contents" {
        return Err(DocumentationError::Invalid(
            "documentation NAR root must contain one regular file".into(),
        ));
    }
    let contents = decoder.string("file contents")?;
    if contents.is_empty() || contents.len() > MAX_DOCUMENT_BYTES {
        return Err(DocumentationError::Invalid(format!(
            "documentation file size {} is outside 1..={MAX_DOCUMENT_BYTES}",
            contents.len()
        )));
    }
    decoder.expect_string(b")", "root close")?;
    if decoder.offset != input.len() {
        return Err(DocumentationError::Invalid(
            "documentation NAR has trailing data".into(),
        ));
    }
    Ok(contents)
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn string(&mut self, label: &str) -> Result<&'a [u8]> {
        let end_len = self.offset.checked_add(8).ok_or_else(|| {
            DocumentationError::Invalid(format!("{label} length offset overflow"))
        })?;
        let encoded_len = self.input.get(self.offset..end_len).ok_or_else(|| {
            DocumentationError::Invalid(format!("documentation NAR is truncated at {label}"))
        })?;
        let length = u64::from_le_bytes(encoded_len.try_into().map_err(|_| {
            DocumentationError::Invalid(format!("invalid {label} length encoding"))
        })?);
        let length = usize::try_from(length).map_err(|_| {
            DocumentationError::Invalid(format!("{label} length exceeds this runtime"))
        })?;
        let start = end_len;
        let end = start.checked_add(length).ok_or_else(|| {
            DocumentationError::Invalid(format!("{label} content length overflow"))
        })?;
        let padded_end = end
            .checked_add(7)
            .map(|value| value & !7)
            .ok_or_else(|| DocumentationError::Invalid(format!("{label} padding overflow")))?;
        let value = self.input.get(start..end).ok_or_else(|| {
            DocumentationError::Invalid(format!("documentation NAR is truncated at {label}"))
        })?;
        let padding = self.input.get(end..padded_end).ok_or_else(|| {
            DocumentationError::Invalid(format!("documentation NAR is truncated after {label}"))
        })?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(DocumentationError::Invalid(format!(
                "documentation NAR has non-zero padding after {label}"
            )));
        }
        self.offset = padded_end;
        Ok(value)
    }

    fn expect_string(&mut self, expected: &[u8], label: &str) -> Result<()> {
        if self.string(label)? != expected {
            return Err(DocumentationError::Invalid(format!(
                "documentation NAR has invalid {label}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_string(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u64).to_le_bytes());
        output.extend_from_slice(value);
        while output.len() % 8 != 0 {
            output.push(0);
        }
    }

    fn fixture(contents: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        for value in [
            NAR_MAGIC,
            b"(".as_slice(),
            b"type".as_slice(),
            b"regular".as_slice(),
            b"contents".as_slice(),
            contents,
            b")".as_slice(),
        ] {
            push_string(&mut output, value);
        }
        output
    }

    #[test]
    fn accepts_the_exact_single_file_profile() {
        let nar = fixture(br#"{"schema":"aos.package-documentation/v1"}"#);
        assert_eq!(
            decode_single_file_nar(&nar).expect("valid NAR"),
            br#"{"schema":"aos.package-documentation/v1"}"#
        );
    }

    #[test]
    fn rejects_executable_nodes_trailing_data_and_nonzero_padding() {
        let mut executable = Vec::new();
        for value in [
            NAR_MAGIC,
            b"(".as_slice(),
            b"type".as_slice(),
            b"regular".as_slice(),
            b"executable".as_slice(),
            b"".as_slice(),
            b"contents".as_slice(),
            b"x".as_slice(),
            b")".as_slice(),
        ] {
            push_string(&mut executable, value);
        }
        assert!(decode_single_file_nar(&executable).is_err());

        let mut trailing = fixture(b"x");
        trailing.push(0);
        assert!(decode_single_file_nar(&trailing).is_err());

        let mut padding = fixture(b"x");
        let content = padding
            .windows(8)
            .position(|window| window == b"contents")
            .expect("contents token");
        let contents_len = (content + 8 + 8 + 7) & !7;
        let file_padding = contents_len + 8 + 1;
        padding[file_padding] = 1;
        assert!(decode_single_file_nar(&padding).is_err());
    }

    #[test]
    fn rejects_directory_and_truncation_without_panicking() {
        let mut directory = Vec::new();
        for value in [
            NAR_MAGIC,
            b"(".as_slice(),
            b"type".as_slice(),
            b"directory".as_slice(),
        ] {
            push_string(&mut directory, value);
        }
        assert!(decode_single_file_nar(&directory).is_err());
        for length in 0..fixture(b"x").len() {
            assert!(decode_single_file_nar(&fixture(b"x")[..length]).is_err());
        }
    }
}
