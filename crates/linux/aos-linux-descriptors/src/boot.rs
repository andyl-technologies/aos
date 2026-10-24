//! Linux kernel-incarnation identity.
//!
//! Mount IDs are unique only for one running kernel. [`KernelBootId`] binds
//! durable observations to `/proc/sys/kernel/random/boot_id`, preventing a
//! broker restart after node reboot from adopting a numerically reused mount.
//! The retained Root pair uses a separate original acquisition destination;
//! it shares the UUID parser but never allocates an unbounded input vector.

use std::error::Error as StdError;
use std::fs::File;
use std::io::Read as _;

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
        let mut file = File::open(BOOT_ID_PATH).map_err(|source| Error::Syscall {
            operation: "read kernel boot ID",
            source,
        })?;
        let received = read_current_boot_id_v1(&mut file);
        // std::fs::read closed this file before constructing the outer error
        // or parsing. Preserve that retirement frontier with the bounded read.
        drop(file);
        let (bytes, filled) = received.map_err(|source| Error::Syscall {
            operation: "read kernel boot ID",
            source,
        })?;
        parse_current_boot_id_v1(&bytes[..filled])
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

// One extra byte proves an oversized value without reading the rest of an
// untrusted source. EOF is still required for every accepted 36/37-byte value.
// This private helper takes the actual opened file, not a supplied observer or
// currentness receipt; its tests exercise parsing DATA on ordinary fixture files.
fn read_current_boot_id_v1(
    file: &mut File,
) -> std::io::Result<([u8; BOOT_ID_FILE_MAXIMUM_BYTES + 1], usize)> {
    let mut bytes = [0_u8; BOOT_ID_FILE_MAXIMUM_BYTES + 1];
    let mut filled = 0;

    loop {
        let count = match file.read(&mut bytes[filled..]) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(source) => return Err(source),
        };
        if count == 0 {
            return Ok((bytes, filled));
        }

        // File::read cannot return more than the supplied slice. The following
        // rejection therefore runs before filled could reach a new iteration
        // with an empty destination, and no read buffer or Vec grows.
        filled += count;
        if filled > BOOT_ID_FILE_MAXIMUM_BYTES {
            return Ok((bytes, filled));
        }
    }
}

fn parse_current_boot_id_v1(bytes: &[u8]) -> Result<KernelBootId> {
    if bytes.len() > BOOT_ID_FILE_MAXIMUM_BYTES {
        return Err(malformed("procfs value exceeds its fixed bound"));
    }
    KernelBootId::parse(bytes)
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
    file_retired: bool,
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
    /// Maximum original descriptors retained by this fixed reader.
    pub const MAXIMUM_RETAINED_FILES_V1: usize = 1;

    /// Returns the dominant fixed reservoir and bounded parser diagnostic bytes.
    #[must_use]
    pub fn dominant_requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_add(128)
    }

    /// Reports the maximum bytes returned by the fixed original read loop.
    #[must_use]
    pub const fn maximum_requested_read_bytes_v2() -> usize {
        ORIGINAL_BOOT_ID_BYTES
    }

    /// Reports the reader's resident namespace charge.
    ///
    /// Fixed input, result and control carriers use byte permits. The actual
    /// procfs descriptor uses its separate descriptor permit; no map is added.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize {
        0
    }

    /// Retires only the actual file after complete canonical EOF observation.
    ///
    /// All bytes, read/filesystem/parser outcomes and the one-shot latch remain.
    /// This closes a temporary input, never a resource refund or currentness
    /// claim. A failed or partial original is never consumed by this method.
    ///
    /// # Errors
    /// Retains a refusal for incomplete, failed or repeated disposal. The
    /// original native/parser failure continues to precede that refusal.
    pub fn retire_positive_file_once(&mut self) -> std::result::Result<(), &(dyn StdError + 'static)> {
        if self.file_retired || self.failure().is_some() || self.eof.is_none()
            || !matches!(self.parsed, Some(Ok(_))) || !matches!(self.open, Some(Ok(_)))
        {
            self.entered = true;
            self.refusal.get_or_insert(OriginalBootRefusalV1::Unavailable);
            return Err(self.failure().unwrap_or(&OriginalBootRefusalV1::Unavailable));
        }
        drop(self.open.take());
        self.file_retired = true;
        Ok(())
    }

    /// Returns the fixed native observation slot bound for incoming resource accounting.
    ///
    /// This passive bound includes the retained read slots and original open,
    /// filesystem and parser slots. It performs no observation or admission.
    #[must_use]
    pub const fn native_cell_bound_v1() -> usize {
        // Every fixed read slot plus original open, filesystem and parser slots.
        ORIGINAL_BOOT_ID_BYTES + 3
    }

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
            file_retired: false,
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
    fn vacant_boot_reader_cannot_dispose_then_reenter_as_an_original() {
        let mut attempt = RootOriginalKernelBootIdAttemptV1::new();

        assert!(attempt.retire_positive_file_once().is_err());
        assert!(attempt.failure().is_some());
        assert!(attempt.observe_once().is_err());
        assert!(!attempt.file_retired);
        assert!(attempt.open.is_none());
        assert_eq!(attempt.filled, 0);
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

    struct OrdinaryBootFixtureV1 {
        file: File,
        path: std::path::PathBuf,
    }

    impl OrdinaryBootFixtureV1 {
        fn new(bytes: &[u8]) -> Self {
            use std::io::{Seek as _, Write as _};
            use std::sync::atomic::{AtomicU64, Ordering};

            static NEXT: AtomicU64 = AtomicU64::new(0);
            let serial = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aos-ordinary-boot-id-{}-{serial}", std::process::id(),
            ));
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.rewind().unwrap();
            Self { file, path }
        }
    }

    impl Drop for OrdinaryBootFixtureV1 {
        fn drop(&mut self) {
            let _removed = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn ordinary_bounded_read_preserves_both_canonical_eof_spellings() {
        for bytes in [
            &b"00112233-4455-6677-8899-aabbccddeeff"[..],
            &b"00112233-4455-6677-8899-aabbccddeeff\n"[..],
        ] {
            let mut fixture = OrdinaryBootFixtureV1::new(bytes);
            let expected = KernelBootId::parse(bytes).unwrap();

            let (bytes, filled) = read_current_boot_id_v1(&mut fixture.file).unwrap();
            let observed = parse_current_boot_id_v1(&bytes[..filled]).unwrap();

            assert_eq!(observed, expected);
        }
    }

    #[test]
    fn ordinary_bounded_read_rejects_oversize_at_the_first_proving_byte() {
        use std::io::Seek as _;

        let mut input = b"00112233-4455-6677-8899-aabbccddeeff\n".to_vec();
        input.extend_from_slice(&[b'x'; 128]);
        let mut fixture = OrdinaryBootFixtureV1::new(&input);

        let (bytes, filled) = read_current_boot_id_v1(&mut fixture.file).unwrap();
        let error = parse_current_boot_id_v1(&bytes[..filled]).unwrap_err();

        assert!(matches!(error, Error::MalformedKernelResponse {
            object: "kernel boot ID", ref message,
        } if message == "procfs value exceeds its fixed bound"));
        assert_eq!(fixture.file.stream_position().unwrap(), 38);
    }

    #[test]
    fn ordinary_bounded_read_keeps_parser_failures_after_actual_eof() {
        for input in [
            &b""[..],
            &b"00112233-4455-6677-8899-aabbccddee"[..],
            &b"00112233-4455-6677-8899-AABBCCDDEEFF"[..],
            &b"00000000-0000-0000-0000-000000000000\n"[..],
            &b"00112233-4455-6677-8899-aabbccddeeffx"[..],
        ] {
            let mut fixture = OrdinaryBootFixtureV1::new(input);
            let expected = KernelBootId::parse(input).unwrap_err().to_string();

            let (bytes, filled) = read_current_boot_id_v1(&mut fixture.file).unwrap();
            let actual = parse_current_boot_id_v1(&bytes[..filled]).unwrap_err();

            assert_eq!(actual.to_string(), expected);
        }
    }

    #[test]
    fn ordinary_bounded_read_keeps_native_error_before_parser_refusal() {
        let mut directory = File::open(std::env::temp_dir()).unwrap();

        let error = read_current_boot_id_v1(&mut directory).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::IsADirectory);
    }

}
