//! Canonical descriptor-store names for detached mounts and source pins.
//!
//! This module owns only strict name encoding and decoding. The keeper owns
//! descriptor adoption, manager readback, and custody effects.
//!
//! ```text
//! aos-mount-v1-<64 lowercase hexadecimal digits>
//! aos-source-v1-<64 lowercase hexadecimal digits>
//! ```

use crate::{MountError, Result};

pub(super) const NAME_PREFIX: &str = "aos-mount-v1-";
const SOURCE_NAME_PREFIX: &str = "aos-source-v1-";
const DIGEST_HEX_LENGTH: usize = 64;

/// An opaque, versioned name used to associate a descriptor with durable state.
///
/// Names have the exact form `aos-mount-v1-` followed by 64 lowercase
/// hexadecimal digits. Keeping the accepted language this narrow makes names
/// safe both in systemd's newline protocol and in colon-separated
/// `LISTEN_FDNAMES`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KernelMountName(String);

impl KernelMountName {
    /// Constructs a stable opaque name from a 256-bit resource digest.
    #[must_use]
    pub fn from_digest(digest: [u8; 32]) -> Self {
        Self(hex_name(NAME_PREFIX, digest))
    }

    /// Parses an exact systemd descriptor-store name.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown version, wrong length, uppercase digit,
    /// delimiter, control byte, or any non-hexadecimal suffix byte.
    pub fn parse(value: &str) -> Result<Self> {
        validate_digest_name(value, NAME_PREFIX)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact name transmitted to and restored by systemd.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decodes the canonical 256-bit resource digest carried by the name.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        decode_name_digest(&self.0, NAME_PREFIX)
    }
}

/// An opaque descriptor-store name for one broker-minted source realization.
///
/// Names use `aos-source-v1-` followed by the lowercase hexadecimal realization
/// handle. The disjoint prefix prevents a retained source descriptor from ever
/// being adopted as a detached resource mount.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourcePinName(String);

impl SourcePinName {
    /// Constructs the sole canonical name for a source-realization handle.
    #[must_use]
    pub fn from_digest(digest: [u8; 32]) -> Self {
        Self(hex_name(SOURCE_NAME_PREFIX, digest))
    }

    /// Parses one canonical source descriptor-store name.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown prefix, wrong length, uppercase or
    /// non-hexadecimal suffix, or protocol delimiter.
    pub fn parse(value: &str) -> Result<Self> {
        validate_digest_name(value, SOURCE_NAME_PREFIX)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact name transmitted to systemd.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decodes the source-realization handle embedded in this name.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        decode_name_digest(&self.0, SOURCE_NAME_PREFIX)
    }
}

fn hex_name(prefix: &str, digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(prefix.len() + DIGEST_HEX_LENGTH);
    name.push_str(prefix);
    for byte in digest {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}

fn validate_digest_name(value: &str, prefix: &str) -> Result<()> {
    let suffix = value.strip_prefix(prefix).ok_or_else(|| {
        MountError::State("descriptor-store name has an unknown prefix".into())
    })?;
    if suffix.len() != DIGEST_HEX_LENGTH
        || !suffix
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(MountError::State(
            "descriptor-store name is not canonical".into(),
        ));
    }
    Ok(())
}

fn decode_name_digest(value: &str, prefix: &str) -> [u8; 32] {
    let suffix = &value.as_bytes()[prefix.len()..];
    let mut digest = [0_u8; 32];
    for (index, pair) in suffix.chunks_exact(2).enumerate() {
        digest[index] = (hex_value(pair[0]) << 4) | hex_value(pair[1]);
    }
    digest
}

const fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn opaque_names_are_canonical_and_round_trip() {
        let name = KernelMountName::from_digest([0xab; 32]);
        assert_eq!(
            name.as_str(),
            "aos-mount-v1-abababababababababababababababababababababababababababababababab"
        );
        assert_eq!(KernelMountName::parse(name.as_str()).unwrap(), name);
        assert_eq!(name.digest(), [0xab; 32]);

        for invalid in [
            "aos-mount-v2-abababababababababababababababababababababababababababababababab",
            "aos-mount-v1-ABababababababababababababababababababababababababababababababab",
            "aos-mount-v1-abababababababababababababababababababababababababababababababag",
            "aos-mount-v1-abab",
            "aos-mount-v1-abababababababababababababababababababababababababababababababa:",
        ] {
            assert!(
                KernelMountName::parse(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn both_profiles_preserve_every_digest_byte_including_zero() {
        for byte in 0..=u8::MAX {
            let mount = KernelMountName::from_digest([byte; 32]);
            let source = SourcePinName::from_digest([byte; 32]);

            assert_eq!(KernelMountName::parse(mount.as_str()).unwrap(), mount);
            assert_eq!(SourcePinName::parse(source.as_str()).unwrap(), source);
            assert_eq!(mount.digest(), [byte; 32]);
            assert_eq!(source.digest(), [byte; 32]);
        }
    }

    #[test]
    fn disjoint_prefixes_fail_before_suffix_validation() {
        for suffix in ["", "0", "INVALID"] {
            let mount = format!("{NAME_PREFIX}{suffix}");
            let source = format!("{SOURCE_NAME_PREFIX}{suffix}");

            assert!(matches!(
                KernelMountName::parse(&source),
                Err(MountError::State(message))
                    if message == "descriptor-store name has an unknown prefix"
            ));
            assert!(matches!(
                SourcePinName::parse(&mount),
                Err(MountError::State(message))
                    if message == "descriptor-store name has an unknown prefix"
            ));
        }
    }

    #[test]
    fn both_profiles_keep_exact_noncanonical_suffix_errors() {
        for suffix in [
            String::new(),
            "0".repeat(63),
            "0".repeat(65),
            format!("{}A", "0".repeat(63)),
            format!("{}g", "0".repeat(63)),
            format!("{}:", "0".repeat(63)),
            format!("{}\n", "0".repeat(63)),
            format!("{}\0", "0".repeat(63)),
            format!("{}é", "0".repeat(62)),
        ] {
            let mount = format!("{NAME_PREFIX}{suffix}");
            let source = format!("{SOURCE_NAME_PREFIX}{suffix}");

            assert!(matches!(
                KernelMountName::parse(&mount),
                Err(MountError::State(message))
                    if message == "descriptor-store name is not canonical"
            ));
            assert!(matches!(
                SourcePinName::parse(&source),
                Err(MountError::State(message))
                    if message == "descriptor-store name is not canonical"
            ));
        }
    }
}
