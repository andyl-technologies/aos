//! Linux kernel-incarnation identity.
//!
//! Mount IDs are unique only for one running kernel. [`KernelBootId`] binds
//! durable observations to `/proc/sys/kernel/random/boot_id`, preventing a
//! broker restart after node reboot from adopting a numerically reused mount.
//! The retained Root pair uses a separate original acquisition destination;
//! it shares the UUID parser but never allocates an unbounded input vector.

use std::error::Error as StdError;
use std::fs::File;

use rustix::fs::{Mode, OFlags, StatFs};

use crate::{Error, Result};

const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const BOOT_ID_TEXT_BYTES: usize = 36;
const BOOT_ID_FILE_MAXIMUM_BYTES: usize = BOOT_ID_TEXT_BYTES + 1;
const ORIGINAL_BOOT_ID_BYTES: usize = BOOT_ID_FILE_MAXIMUM_BYTES + 1;

/// Identifies one running Linux kernel instance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KernelBootId([u8; 16]);

impl KernelBootId {
    /// Decodes a non-nil boot identifier from retained untrusted bytes.
    ///
    /// This DATA conversion does not observe the current kernel or establish
    /// that the identifier belongs to the running kernel.
    ///
    /// # Errors
    ///
    /// Returns an error when `bytes` is the nil identifier.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self> {
        if bytes == [0; 16] {
            return Err(malformed("UUID is incomplete or nil"));
        }
        Ok(Self(bytes))
    }

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
            let nibble = hex_nibble(byte)
                .ok_or_else(|| malformed("UUID contains a non-lowercase-hex byte"))?;
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

/// Retains one bounded original boot-ID acquisition for the Root startup pair.
///
/// The destination holds its original file, every reached native result and
/// partial input through refusal. It accepts no imported descriptor or bytes
/// and returns only borrowed canonical DATA, not currentness or authority.
/// Its fixed storage bounds this input, not allocator/native cost, syscall
/// latency, parser scratch, physical fit or the caller's unpaid obligations.
pub struct RootOriginalKernelBootIdAttemptV1 {
    open: Option<std::result::Result<File, rustix::io::Errno>>,
    filesystem: Option<std::result::Result<StatFs, rustix::io::Errno>>,
    bytes: [u8; ORIGINAL_BOOT_ID_BYTES],
    reads: [Option<std::result::Result<usize, rustix::io::Errno>>; ORIGINAL_BOOT_ID_BYTES],
    filled: usize,
    eof: Option<usize>,
    parsed: Option<Result<KernelBootId>>,
    entered: bool,
    refusal: Option<OriginalBootRefusalV1>,
}

#[derive(Debug, thiserror::Error)]
enum OriginalBootRefusalV1 {
    #[error("original Root boot-ID acquisition was already entered")]
    AlreadyEntered,
    #[error("original Root boot-ID descriptor is not procfs")]
    NonProcfs,
    #[error("original Root boot-ID input exceeds 37 bytes")]
    Oversized,
    #[error("original Root boot-ID observation is incomplete or invalid")]
    Unavailable,
}

impl RootOriginalKernelBootIdAttemptV1 {
    /// Installs vacant native slots and fixed input storage without IO.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            open: None,
            filesystem: None,
            bytes: [0; ORIGINAL_BOOT_ID_BYTES],
            reads: [None; ORIGINAL_BOOT_ID_BYTES],
            filled: 0,
            eof: None,
            parsed: None,
            entered: false,
            refusal: None,
        }
    }

    /// Observes once and borrows the canonical identity or earliest real cause.
    ///
    /// All results remain in this same destination. The caller must retain it
    /// through failed custody; this type does not enforce terminal disposition.
    /// At most 38 reads progress or stop. A returned zero establishes EOF;
    /// filling all 38 bytes retains an oversize witness without claiming EOF.
    ///
    /// # Errors
    ///
    /// Borrows original open, filesystem, read or parser errors. This retained
    /// arm additionally rejects non-procfs descriptors, oversize input and
    /// reentry. EINTR and EAGAIN stop immediately; no retry or IO deadline is
    /// supplied. The unchanged parser may allocate its fixed error message.
    pub fn observe_once(
        &mut self,
    ) -> std::result::Result<&KernelBootId, &(dyn StdError + 'static)> {
        if self.entered {
            self.refusal
                .get_or_insert(OriginalBootRefusalV1::AlreadyEntered);
        } else {
            self.entered = true;
            self.refusal = self.observe_body().err();
        }

        if let Some(cause) = self.failure() {
            return Err(cause);
        }
        self.parsed
            .as_ref()
            .filter(|_| self.eof.is_some())
            .and_then(|result| result.as_ref().ok())
            .ok_or(&OriginalBootRefusalV1::Unavailable as &(dyn StdError + 'static))
    }

    /// Borrows the earliest resident native or parser failure without IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        if let Some(Err(cause)) = &self.open {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.filesystem {
            return Some(cause);
        }
        for result in &self.reads {
            if let Some(Err(cause)) = result {
                return Some(cause);
            }
        }
        if let Some(Err(cause)) = &self.parsed {
            return Some(cause);
        }
        self.refusal.as_ref().map(|cause| cause as _)
    }

    fn observe_body(&mut self) -> std::result::Result<(), OriginalBootRefusalV1> {
        // The literal CStr avoids a path-string allocation. Every successful
        // original lands in its resident slot before another native operation.
        self.open = Some(
            rustix::fs::open(
                c"/proc/sys/kernel/random/boot_id",
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map(File::from),
        );
        let file = self.open
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(OriginalBootRefusalV1::Unavailable)?;

        self.filesystem = Some(rustix::fs::fstatfs(file));
        let filesystem = self.filesystem
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(OriginalBootRefusalV1::Unavailable)?;
        // This is retained-arm strengthening only, not a claim that procfs or
        // a canonical UUID proves the PID1 producer/recipient association.
        if filesystem.f_type as u64 != 0x9fa0 {
            return Err(OriginalBootRefusalV1::NonProcfs);
        }

        for index in 0..self.reads.len() {
            let available = self.bytes.len() - self.filled;
            self.reads[index] = Some(rustix::io::read(file, &mut self.bytes[self.filled..]));
            let count = self.reads[index]
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .copied()
                .ok_or(OriginalBootRefusalV1::Unavailable)?;
            if count > available {
                return Err(OriginalBootRefusalV1::Unavailable);
            }

            if count == 0 {
                self.eof = Some(index);
                self.parsed = Some(KernelBootId::parse(&self.bytes[..self.filled]));
                return if self.parsed.as_ref().is_some_and(Result::is_ok) {
                    Ok(())
                } else {
                    Err(OriginalBootRefusalV1::Unavailable)
                };
            }

            self.filled += count;
            if self.filled == self.bytes.len() {
                return Err(OriginalBootRefusalV1::Oversized);
            }
        }
        Err(OriginalBootRefusalV1::Unavailable)
    }
}

impl Default for RootOriginalKernelBootIdAttemptV1 {
    fn default() -> Self {
        Self::new()
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
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );
        assert_eq!(KernelBootId::from_bytes(parsed.into_bytes()).unwrap(), parsed);
    }

    #[test]
    fn retained_nil_boot_identifier_fails_closed() {
        assert!(KernelBootId::from_bytes([0; 16]).is_err());
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
