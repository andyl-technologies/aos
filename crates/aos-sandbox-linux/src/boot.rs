//! Linux kernel-incarnation identity.
//!
//! Mount IDs are unique only for one running kernel. [`KernelBootId`] binds
//! durable observations to `/proc/sys/kernel/random/boot_id`, preventing a
//! broker restart after node reboot from adopting a numerically reused mount.

use crate::{Error, Result};

const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const BOOT_ID_TEXT_BYTES: usize = 36;
const BOOT_ID_FILE_MAXIMUM_BYTES: usize = BOOT_ID_TEXT_BYTES + 1;

/// Identifies one running Linux kernel instance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KernelBootId([u8; 16]);

impl KernelBootId {
    /// Reads the current kernel boot identity from its fixed procfs ABI.
    ///
    /// # Errors
    ///
    /// Returns an error when procfs cannot be read within its exact bound or
    /// the kernel returns a noncanonical, nil, or malformed UUID.
    pub fn current() -> Result<Self> {
        let bytes = std::fs::read(BOOT_ID_PATH).map_err(|source| Error::Syscall {
            operation: "read kernel boot ID",
            source,
        })?;
        if bytes.len() > BOOT_ID_FILE_MAXIMUM_BYTES {
            return Err(malformed("procfs value exceeds its fixed bound"));
        }
        Self::parse(&bytes)
    }

    /// Parses the kernel's canonical lowercase UUID representation.
    ///
    /// A single final newline is accepted because procfs emits one. Other
    /// whitespace, uppercase digits, alternate UUID spellings, and nil are
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns an error unless `bytes` is one exact non-nil lowercase UUID.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        if bytes.len() != BOOT_ID_TEXT_BYTES {
            return Err(malformed("UUID has an invalid length"));
        }

        let mut output = [0_u8; 16];
        let mut output_index = 0;
        let mut high_nibble = None;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if matches!(index, 8 | 13 | 18 | 23) {
                if byte != b'-' {
                    return Err(malformed("UUID separators are noncanonical"));
                }
                continue;
            }
            let nibble = hex_nibble(byte).ok_or_else(|| {
                malformed("UUID contains a non-lowercase-hex byte")
            })?;
            if let Some(high) = high_nibble.take() {
                output[output_index] = (high << 4) | nibble;
                output_index += 1;
            } else {
                high_nibble = Some(nibble);
            }
        }
        if high_nibble.is_some() || output_index != output.len() || output == [0; 16] {
            return Err(malformed("UUID is incomplete or nil"));
        }
        Ok(Self(output))
    }

    /// Returns the exact 128-bit boot identity.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

fn malformed(message: impl Into<String>) -> Error {
    Error::MalformedKernelResponse {
        object: "kernel boot ID",
        message: message.into(),
    }
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_kernel_boot_id_round_trips() {
        let parsed = KernelBootId::parse(b"00112233-4455-6677-8899-aabbccddeeff\n")
            .unwrap_or_else(|error| panic!("valid boot ID failed: {error}"));
        assert_eq!(
            parsed.into_bytes(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                0xcc, 0xdd, 0xee, 0xff,
            ]
        );
    }

    #[test]
    fn alternate_and_nil_spellings_fail_closed() {
        for invalid in [
            &b"00112233-4455-6677-8899-AABBCCDDEEFF"[..],
            &b"00112233445566778899aabbccddeeff"[..],
            &b"00000000-0000-0000-0000-000000000000"[..],
            &b"00112233-4455-6677-8899-aabbccddeeff\n\n"[..],
        ] {
            assert!(KernelBootId::parse(invalid).is_err());
        }
    }
}
