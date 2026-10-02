//! Strict bounded decoder for canonical documentation NARs.
//!
//! Native package references use a directory containing `options.json` and optional
//! builder target metadata. The regular-file decoder serves single-document
//! artifacts. The typed root reader also exposes bounded symlink targets for
//! consumers that validate and retain those targets before following them. All
//! readers preserve exact bytes and reject extra nodes or trailing data.
//!
//! Each token uses NAR's length-prefixed, eight-byte-aligned string encoding.
//! The supported single-node profiles have these token sequences:
//!
//! ```text
//! nix-archive-1 ( type regular contents <exact document bytes> )
//! nix-archive-1 ( type symlink target /nix/store/.../input.json )
//! ```

use crate::{DocumentationError, MAX_DOCUMENT_BYTES, Result};

const NAR_MAGIC: &[u8] = b"nix-archive-1";

const MAX_SYMLINK_TARGET_BYTES: usize = 4096;

/// Identifies one checked native document NAR root without following links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NarRoot<'a> {
    /// Borrows the exact non-executable regular-file contents.
    Regular(&'a [u8]),
    /// Borrows a UTF-8 symlink target whose destination remains unchecked.
    Symlink(&'a str),
}

/// Decodes one bounded regular-file or symlink NAR root.
///
/// Regular files retain the same profile as [`decode_single_file_nar`]. Symlink
/// targets are nonempty UTF-8 strings of at most 4096 bytes without NUL bytes.
/// This reader checks archive structure only: callers must validate destination
/// authority, path normalization, link depth and cycles, and retain each target
/// before reading it. It never resolves a target on the host filesystem.
///
/// # Errors
/// Returns [`DocumentationError::Invalid`] for oversized, malformed, executable,
/// directory, unknown, truncated, or trailing archive data, invalid padding, or
/// an empty, oversized, non-UTF-8, or NUL-containing symlink target.
pub fn decode_document_root_nar(input: &[u8]) -> Result<NarRoot<'_>> {
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
    let root = match decoder.string("root type")? {
        b"regular" => {
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
            NarRoot::Regular(contents)
        }
        b"symlink" => {
            decoder.expect_string(b"target", "symlink target key")?;
            let bytes = decoder.string("symlink target")?;
            if bytes.is_empty() || bytes.len() > MAX_SYMLINK_TARGET_BYTES || bytes.contains(&0) {
                return Err(DocumentationError::Invalid(
                    "documentation symlink target exceeds its canonical bounds".into(),
                ));
            }
            let target = std::str::from_utf8(bytes).map_err(|_| {
                DocumentationError::Invalid("documentation symlink target is not UTF-8".into())
            })?;
            NarRoot::Symlink(target)
        }
        _ => {
            return Err(DocumentationError::Invalid(
                "unsupported documentation NAR root type".into(),
            ));
        }
    };
    decoder.expect_string(b")", "root close")?;
    if decoder.offset != input.len() {
        return Err(DocumentationError::Invalid(
            "documentation NAR has trailing data".into(),
        ));
    }
    Ok(root)
}

/// Decodes one bounded, non-executable regular-file NAR.
///
/// The returned slice borrows the exact file contents from `input`. Every NAR
/// string length and padding byte is checked before advancing, and no trailing
/// bytes are accepted. Symlink roots remain unsupported by this strict reader.
///
/// # Errors
/// Returns [`DocumentationError::Invalid`] when the archive is truncated,
/// oversized, non-canonical, executable, not a regular root file, or carries
/// any additional node or trailing data.
pub fn decode_single_file_nar(input: &[u8]) -> Result<&[u8]> {
    match decode_document_root_nar(input)? {
        NarRoot::Regular(contents) => Ok(contents),
        NarRoot::Symlink(_) => Err(DocumentationError::Invalid(
            "documentation NAR root must contain one regular file".into(),
        )),
    }
}

/// Extracts `options.json` from a native package documentation directory NAR.
///
/// Accepts only the non-executable reference and optional ordinary builder metadata
/// at `nix-support/aos-target-platform`. The returned bytes are borrowed unchanged.
///
/// # Errors
/// Returns an error for oversized, malformed, executable, linked, duplicate,
/// unordered, unexpected, or trailing archive content, or a missing reference.
pub fn decode_native_documentation_nar(input: &[u8]) -> Result<&[u8]> {
    decode_native_artifact_nar(input, "options.json")
}

/// Extracts one exact JSON member from a native package artifact directory NAR.
///
/// Accepts `deployment.json`, `options.json`, or `qualification.json` and optional builder
/// metadata at `nix-support/aos-target-platform`. It preserves borrowed document
/// bytes and accepts no other archive nodes. Callers authenticate the complete
/// NAR and verify the member digest against signed metadata before decoding it.
///
/// # Errors
/// Returns an error for unsupported members, oversized, malformed, executable,
/// linked, duplicate, unordered, unexpected, missing, or trailing archive data.
pub fn decode_native_artifact_nar<'a>(input: &'a [u8], member: &str) -> Result<&'a [u8]> {
    if !matches!(
        member,
        "deployment.json" | "options.json" | "qualification.json"
    ) {
        return Err(DocumentationError::Invalid(
            "unsupported native artifact member".into(),
        ));
    }
    let limit = crate::runtime::MAX_RUNTIME_DOCUMENT_BYTES;
    if input.len() > limit + 4096 {
        return Err(DocumentationError::Invalid(
            "native documentation NAR exceeds its limit".into(),
        ));
    }
    let mut decoder = Decoder { input, offset: 0 };
    decoder.expect_string(NAR_MAGIC, "archive magic")?;
    decoder.expect_string(b"(", "root open")?;
    decoder.expect_string(b"type", "root type key")?;
    decoder.expect_string(b"directory", "root type")?;
    let mut previous: &[u8] = b"";
    let mut document = None;
    loop {
        let token = decoder.string("directory field")?;
        if token == b")" {
            break;
        }
        if token != b"entry" {
            return Err(DocumentationError::Invalid(
                "unexpected native documentation directory field".into(),
            ));
        }
        decoder.expect_string(b"(", "entry open")?;
        decoder.expect_string(b"name", "entry name key")?;
        let name = decoder.string("entry name")?;
        if name <= previous {
            return Err(DocumentationError::Invalid(
                "native documentation entries must be unique and ordered".into(),
            ));
        }
        previous = name;
        decoder.expect_string(b"node", "entry node key")?;
        match name {
            name if name == member.as_bytes() => document = Some(decoder.regular_contents(limit)?),
            b"nix-support" => {
                decoder.expect_string(b"(", "support directory open")?;
                decoder.expect_string(b"type", "support type key")?;
                decoder.expect_string(b"directory", "support type")?;
                decoder.expect_string(b"entry", "support entry")?;
                decoder.expect_string(b"(", "support entry open")?;
                decoder.expect_string(b"name", "support name key")?;
                decoder.expect_string(b"aos-target-platform", "support name")?;
                decoder.expect_string(b"node", "support node key")?;
                decoder.regular_contents(256)?;
                decoder.expect_string(b")", "support entry close")?;
                decoder.expect_string(b")", "support directory close")?;
            }
            _ => {
                return Err(DocumentationError::Invalid(
                    "unexpected native documentation artifact entry".into(),
                ));
            }
        }
        decoder.expect_string(b")", "entry close")?;
    }
    if decoder.offset != input.len() {
        return Err(DocumentationError::Invalid(
            "native documentation NAR has trailing data".into(),
        ));
    }
    document.ok_or_else(|| DocumentationError::Invalid(format!("native artifact has no {member}")))
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn regular_contents(&mut self, limit: usize) -> Result<&'a [u8]> {
        self.expect_string(b"(", "file open")?;
        self.expect_string(b"type", "file type key")?;
        self.expect_string(b"regular", "file type")?;
        self.expect_string(b"contents", "file contents key")?;
        let contents = self.string("file contents")?;
        if contents.is_empty() || contents.len() > limit {
            return Err(DocumentationError::Invalid(
                "native documentation file exceeds its bounds".into(),
            ));
        }
        self.expect_string(b")", "file close")?;
        Ok(contents)
    }

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

    fn symlink_fixture(target: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        for value in [
            NAR_MAGIC, b"(", b"type", b"symlink", b"target", target, b")",
        ] {
            push_string(&mut output, value);
        }
        output
    }

    #[test]
    fn typed_roots_borrow_exact_bytes_and_leave_links_unresolved() {
        let regular = fixture(b"exact document\n");
        assert_eq!(
            decode_document_root_nar(&regular).unwrap(),
            NarRoot::Regular(b"exact document\n")
        );

        let target = "/nix/store/00000000000000000000000000000000-evaluation/input.json";
        let symlink = symlink_fixture(target.as_bytes());
        assert_eq!(
            decode_document_root_nar(&symlink).unwrap(),
            NarRoot::Symlink(target)
        );
        assert!(decode_single_file_nar(&symlink).is_err());

        // Destination authority belongs to the store consumer, not the archive
        // reader. No target is opened or normalized while decoding this node.
        let relative = symlink_fixture(b"../outside-store");
        assert_eq!(
            decode_document_root_nar(&relative).unwrap(),
            NarRoot::Symlink("../outside-store")
        );
    }

    #[test]
    fn symlink_roots_reject_invalid_targets_padding_and_trailing_data() {
        for target in [b"".as_slice(), b"invalid\0target", b"\xff"] {
            assert!(decode_document_root_nar(&symlink_fixture(target)).is_err());
        }
        let oversized = vec![b'a'; MAX_SYMLINK_TARGET_BYTES + 1];
        assert!(decode_document_root_nar(&symlink_fixture(&oversized)).is_err());

        let valid = symlink_fixture(b"x");
        for length in 0..valid.len() {
            assert!(decode_document_root_nar(&valid[..length]).is_err());
        }
        let mut trailing = valid.clone();
        trailing.extend_from_slice(&[0; 8]);
        assert!(decode_document_root_nar(&trailing).is_err());

        let mut padding = valid;
        let target_offset = padding
            .windows(6)
            .position(|value| value == b"target")
            .unwrap();
        let contents_offset = (target_offset + 6 + 7) & !7;
        padding[contents_offset + 8 + 1] = 1;
        assert!(decode_document_root_nar(&padding).is_err());
    }

    #[test]
    fn symlink_roots_reject_reordered_or_additional_fields() {
        for fields in [
            vec![
                NAR_MAGIC,
                b"(",
                b"type",
                b"symlink",
                b"contents",
                b"x",
                b")",
            ],
            vec![
                NAR_MAGIC, b"(", b"type", b"symlink", b"target", b"x", b"target", b"y", b")",
            ],
        ] {
            let mut archive = Vec::new();
            for field in fields {
                push_string(&mut archive, field);
            }
            assert!(decode_document_root_nar(&archive).is_err());
        }
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

    fn native_fixture() -> Vec<u8> {
        native_member_fixture(b"options.json", true)
    }

    fn native_member_fixture(member: &[u8], with_support: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        for token in [NAR_MAGIC, b"(", b"type", b"directory"] {
            push_string(&mut bytes, token);
        }
        let support: &[&[u8]] = &[
            b"entry",
            b"(",
            b"name",
            b"nix-support",
            b"node",
            b"(",
            b"type",
            b"directory",
            b"entry",
            b"(",
            b"name",
            b"aos-target-platform",
            b"node",
            b"(",
            b"type",
            b"regular",
            b"contents",
            b"x86_64-linux",
            b")",
            b")",
            b")",
            b")",
        ];
        let document: &[&[u8]] = &[
            b"entry",
            b"(",
            b"name",
            member,
            b"node",
            b"(",
            b"type",
            b"regular",
            b"contents",
            b"{}",
            b")",
            b")",
        ];
        let mut entries = vec![(member, document)];
        if with_support {
            entries.push((b"nix-support", support));
        }
        entries.sort_by_key(|(name, _)| *name);
        for (_, tokens) in entries {
            for token in tokens {
                push_string(&mut bytes, token);
            }
        }
        push_string(&mut bytes, b")");
        bytes
    }

    #[test]
    fn native_deployment_member_preserves_exact_bytes_with_or_without_metadata() {
        for support in [false, true] {
            let fixture = native_member_fixture(b"deployment.json", support);
            assert_eq!(
                decode_native_artifact_nar(&fixture, "deployment.json").unwrap(),
                b"{}"
            );
            assert!(decode_native_artifact_nar(&fixture, "options.json").is_err());
            for length in 0..fixture.len() {
                assert!(decode_native_artifact_nar(&fixture[..length], "deployment.json").is_err());
            }
            let mut trailing = fixture;
            trailing.push(0);
            assert!(decode_native_artifact_nar(&trailing, "deployment.json").is_err());
        }
    }

    #[test]
    fn native_qualification_member_preserves_exact_bytes() {
        for support in [false, true] {
            let fixture = native_member_fixture(b"qualification.json", support);
            assert_eq!(
                decode_native_artifact_nar(&fixture, "qualification.json").unwrap(),
                b"{}"
            );
            assert!(decode_native_artifact_nar(&fixture, "deployment.json").is_err());
        }
    }

    #[test]
    fn native_member_rejects_links_unknown_names_and_missing_documents() {
        let mut linked = native_member_fixture(b"deployment.json", false);
        let start = linked
            .windows(b"regular".len())
            .position(|window| window == b"regular")
            .unwrap();
        linked[start..start + 7].copy_from_slice(b"symlink");
        assert!(decode_native_artifact_nar(&linked, "deployment.json").is_err());
        let fixture = native_member_fixture(b"deployment.json", false);
        for name in [
            "../deployment.json",
            "nix-support/aos-target-platform",
            "unknown.json",
        ] {
            assert!(decode_native_artifact_nar(&fixture, name).is_err());
        }
        let mut empty = Vec::new();
        for token in [NAR_MAGIC, b"(", b"type", b"directory", b")"] {
            push_string(&mut empty, token);
        }
        assert!(decode_native_artifact_nar(&empty, "deployment.json").is_err());
    }

    #[test]
    fn native_directory_preserves_exact_reference_and_builder_metadata() {
        assert_eq!(
            decode_native_documentation_nar(&native_fixture()).unwrap(),
            b"{}"
        );
    }

    #[test]
    fn native_directory_rejects_truncation_trailing_bytes_and_other_entries() {
        let fixture = native_fixture();
        for length in 0..fixture.len() {
            assert!(decode_native_documentation_nar(&fixture[..length]).is_err());
        }
        let mut changed = fixture.clone();
        changed.push(0);
        assert!(decode_native_documentation_nar(&changed).is_err());
        let start = fixture
            .windows(b"options.json".len())
            .position(|window| window == b"options.json")
            .unwrap();
        let mut changed = fixture;
        changed[start] = b'x';
        assert!(decode_native_documentation_nar(&changed).is_err());
    }
}
