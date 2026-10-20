//! Owns version-1 prefix magic and bounded first-line shebang interpretation.

use super::{Error, ShebangValue};
use alloc::string::ToString;

/// The maximum plaintext prefix examined by `magic/1` and `shebang/1`.
pub const MAGIC_PREFIX_LIMIT: usize = 64 * 1024;

/// A member of the closed content classifier registry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Magic {
    /// ELF magic, even if the later executable parse fails.
    Elf,
    /// A first-line `#!` marker.
    Shebang,
    /// A Unix archive signature.
    Ar,
    /// An ordinary zstd frame signature.
    Zstd,
    /// A gzip signature.
    Gzip,
    /// A POSIX ustar signature at offset 257.
    Tar,
    /// UTF-8 text without NUL or disallowed ASCII control bytes.
    Text,
    /// No preceding classifier matched.
    Other,
}

impl Magic {
    /// Returns the registered classifier name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Elf => "elf",
            Self::Shebang => "shebang",
            Self::Ar => "ar",
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
            Self::Tar => "tar",
            Self::Text => "text",
            Self::Other => "other",
        }
    }

    /// Resolves a name in the closed classifier registry.
    ///
    /// # Errors
    /// Returns [`Error::InvalidValue`] for unregistered names.
    pub fn parse(name: &str) -> Result<Self, Error> {
        match name {
            "elf" => Ok(Self::Elf),
            "shebang" => Ok(Self::Shebang),
            "ar" => Ok(Self::Ar),
            "zstd" => Ok(Self::Zstd),
            "gzip" => Ok(Self::Gzip),
            "tar" => Ok(Self::Tar),
            "text" => Ok(Self::Text),
            "other" => Ok(Self::Other),
            _ => Err(Error::InvalidValue),
        }
    }
}

/// Classifies at most the first 64 KiB using the exact `magic/1` rules.
///
/// Signatures take precedence in registry order. Text requires valid UTF-8 and
/// permits tab, newline, form feed, and carriage return among ASCII controls.
/// The empty prefix is text. Bytes after the prefix limit never affect the result.
pub fn classify_magic(plaintext: &[u8]) -> Magic {
    let prefix = &plaintext[..plaintext.len().min(MAGIC_PREFIX_LIMIT)];
    if prefix.starts_with(b"\x7fELF") {
        Magic::Elf
    } else if prefix.starts_with(b"#!") {
        Magic::Shebang
    } else if prefix.starts_with(b"!<arch>\n") {
        Magic::Ar
    } else if prefix.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Magic::Zstd
    } else if prefix.starts_with(&[0x1f, 0x8b]) {
        Magic::Gzip
    } else if matches!(prefix.get(257..263), Some(b"ustar\0" | b"ustar ")) {
        Magic::Tar
    } else if core::str::from_utf8(prefix).is_ok()
        && prefix
            .iter()
            .all(|&b| b >= 32 && b != 127 || matches!(b, 9 | 10 | 12 | 13))
    {
        Magic::Text
    } else {
        Magic::Other
    }
}

/// Parses a bounded shebang first line under the exact `shebang/1` rules.
///
/// Leading and trailing spaces and tabs are removed. The interpreter must be
/// absolute; the remaining argument is retained as one unsplit string. A final
/// carriage return is removed so CRLF input yields the same line interpretation.
/// `complete` means the supplied prefix contains the entire object.
///
/// # Errors
/// Returns [`Error::MalformedExecutable`] for non-shebang, invalid UTF-8, NUL,
/// relative or missing interpreters, or a first line extending beyond the bound.
pub fn parse_shebang(prefix: &[u8], complete: bool) -> Result<ShebangValue, Error> {
    let complete = complete && prefix.len() <= MAGIC_PREFIX_LIMIT;
    let prefix = &prefix[..prefix.len().min(MAGIC_PREFIX_LIMIT)];
    let body = prefix
        .strip_prefix(b"#!")
        .ok_or(Error::MalformedExecutable)?;
    let line = match body.iter().position(|&b| b == b'\n') {
        Some(end) => &body[..end],
        None if complete => body,
        None => return Err(Error::MalformedExecutable),
    };
    if line.contains(&0) {
        return Err(Error::MalformedExecutable);
    }
    let line = core::str::from_utf8(line).map_err(|_| Error::MalformedExecutable)?;
    let line = line
        .strip_suffix('\r')
        .unwrap_or(line)
        .trim_matches([' ', '\t']);
    let split = line.find([' ', '\t']).unwrap_or(line.len());
    let interpreter = &line[..split];
    if !interpreter.starts_with('/') {
        return Err(Error::MalformedExecutable);
    }
    let argument = line[split..].trim_matches([' ', '\t']);
    Ok(ShebangValue {
        interpreter: interpreter.to_string(),
        argument: if argument.is_empty() {
            None
        } else {
            Some(argument.to_string())
        },
    })
}
