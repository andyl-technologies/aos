//! Candidate-C heap-image snapshot format (RFC-0007 doc 31 §1, stage 1).
//!
//! A heap image is the used bytes of one serial permanent-lane reservation
//! ([`SharedFlatStoreArena`]) plus the metadata needed to remap it: the
//! reservation's domain, its capacity, and the two used-lane lengths. Reloading
//! is address-free — the bytes are copied to the same offsets in a fresh mapping
//! and the *original domain* is re-registered against the new base — so every
//! Candidate-C `(domain, index)` word in the image resolves unchanged with no
//! per-pointer rebase pass (doc 31 §3.3 end state).
//!
//! This stage-1 layer proves that round-trip in isolation over a fully-forced,
//! thunk-free value graph. It does **not** yet serialize the out-of-arena
//! residuals (the global symbol table, string contexts, the module table) or
//! collapse thunk cells — those are stage 2+ (doc 31 §1.4, §3.2). In-process the
//! symbol table is shared, so a same-process round trip needs none of them.
//!
//! # Wire format (little-endian)
//!
//! ```text
//! heap-image v1:
//!   magic:    8 bytes  = IMAGE_MAGIC ("AOSNIXH1")
//!   version:  u32      = IMAGE_VERSION
//!   domain:   u32      = the reservation's 23-bit Candidate-C domain
//!   capacity: u64      = the reservation's virtual size in bytes
//!   low_len:  u64      = permanent (upward) used-lane byte length
//!   high_len: u64      = rewindable (downward) used-lane byte length
//!   low:      low_len bytes   (the permanent lane, offset 0)
//!   high:     high_len bytes  (the rewindable lane, ending at `capacity`)
//!   digest:   u64      = xxh3-64 of every preceding byte (integrity guard)
//! ```

use xxhash_rust::xxh3::xxh3_64;

use thiserror::Error;

use super::flat::SharedFlatStoreArena;
use super::reservation::{ArenaDomainId, ReservedArena};
use super::reservation_registry::reservation_base;

/// Magic tag at the start of every serialized heap image (`"AOSNIXH1"`).
pub const IMAGE_MAGIC: [u8; 8] = *b"AOSNIXH1";

/// The heap-image wire-format version. Bumped on any layout change so a stale
/// image is a clean, loud miss rather than a silent misparse.
pub const IMAGE_VERSION: u32 = 1;

/// Byte length of the fixed image header preceding the lane bytes.
const HEADER_LEN: usize = 8 + 4 + 4 + 8 + 8 + 8;

/// A captured Candidate-C reservation heap image.
///
/// Holds the reservation identity and its two used-lane byte ranges. Serialize
/// with [`HeapImage::to_bytes`] and reload with [`HeapImage::from_bytes`] +
/// [`restore_reservation`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeapImage {
    /// The reservation's 23-bit Candidate-C domain, re-registered on restore so
    /// dumped words resolve unchanged.
    pub domain: u32,
    /// The reservation's virtual capacity in bytes (the restore mapping size).
    pub capacity: u64,
    /// The permanent, upward-growing lane bytes, at offset zero.
    pub low: Vec<u8>,
    /// The rewindable, downward-growing lane bytes, ending at `capacity`.
    pub high: Vec<u8>,
}

impl HeapImage {
    /// Serializes the image to its little-endian wire form with a trailing
    /// integrity digest.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.low.len() + self.high.len() + 8);
        out.extend_from_slice(&IMAGE_MAGIC);
        out.extend_from_slice(&IMAGE_VERSION.to_le_bytes());
        out.extend_from_slice(&self.domain.to_le_bytes());
        out.extend_from_slice(&self.capacity.to_le_bytes());
        out.extend_from_slice(&(self.low.len() as u64).to_le_bytes());
        out.extend_from_slice(&(self.high.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.low);
        out.extend_from_slice(&self.high);
        let digest = xxh3_64(&out);
        out.extend_from_slice(&digest.to_le_bytes());
        out
    }

    /// Parses and integrity-checks an image from its wire form.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Truncated`] when `bytes` is shorter than the
    /// declared layout, [`SnapshotError::BadMagic`] or
    /// [`SnapshotError::UnsupportedVersion`] on a header mismatch, and
    /// [`SnapshotError::IntegrityMismatch`] when the trailing digest does not
    /// match the recomputed one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapshotError> {
        if bytes.len() < HEADER_LEN + 8 {
            return Err(SnapshotError::Truncated {
                needed: HEADER_LEN + 8,
                got: bytes.len(),
            });
        }
        if bytes[0..8] != IMAGE_MAGIC {
            return Err(SnapshotError::BadMagic);
        }
        let version = u32::from_le_bytes(read4(bytes, 8));
        if version != IMAGE_VERSION {
            return Err(SnapshotError::UnsupportedVersion { version });
        }
        let domain = u32::from_le_bytes(read4(bytes, 12));
        let capacity = u64::from_le_bytes(read8(bytes, 16));
        let low_len = u64::from_le_bytes(read8(bytes, 24)) as usize;
        let high_len = u64::from_le_bytes(read8(bytes, 32)) as usize;

        let lanes_start = HEADER_LEN;
        let digest_start = lanes_start
            .checked_add(low_len)
            .and_then(|end| end.checked_add(high_len))
            .ok_or(SnapshotError::Truncated {
                needed: usize::MAX,
                got: bytes.len(),
            })?;
        let total = digest_start
            .checked_add(8)
            .ok_or(SnapshotError::Truncated {
                needed: usize::MAX,
                got: bytes.len(),
            })?;
        if bytes.len() < total {
            return Err(SnapshotError::Truncated {
                needed: total,
                got: bytes.len(),
            });
        }

        let expected = xxh3_64(&bytes[..digest_start]);
        let actual = u64::from_le_bytes(read8(bytes, digest_start));
        if expected != actual {
            return Err(SnapshotError::IntegrityMismatch { expected, actual });
        }

        let low = bytes[lanes_start..lanes_start + low_len].to_vec();
        let high = bytes[lanes_start + low_len..digest_start].to_vec();
        Ok(Self {
            domain,
            capacity,
            low,
            high,
        })
    }
}

/// Captures a heap image of a reservation-backed serial flat arena.
///
/// # Errors
///
/// Returns [`SnapshotError::NotReservationBacked`] when `arena` uses the chunked
/// compatibility backend, which is not address-free and cannot be snapshotted.
pub fn capture_reservation(arena: &SharedFlatStoreArena) -> Result<HeapImage, SnapshotError> {
    let (domain, capacity, low, high) = arena
        .capture_reservation_image()
        .ok_or(SnapshotError::NotReservationBacked)?;
    Ok(HeapImage {
        domain: domain.raw(),
        capacity: capacity as u64,
        low,
        high,
    })
}

/// Restores a heap image into a fresh reservation-backed serial flat arena.
///
/// Maps a new reservation of the image's capacity, copies the used lanes to
/// their original offsets, and re-registers the image's domain against the new
/// base so every dumped `(domain, index)` word resolves unchanged.
///
/// # Errors
///
/// Returns [`SnapshotError::InvalidDomain`] when the stored domain is out of the
/// valid Candidate-C range, [`SnapshotError::DomainAlreadyLive`] when that domain
/// is still registered (the source reservation must be dropped first — see the
/// domain-preservation invariant in [`crate::heap::reservation::image`]), or
/// [`SnapshotError::Reservation`] when the mapping or registration fails.
pub fn restore_reservation(image: &HeapImage) -> Result<SharedFlatStoreArena, SnapshotError> {
    let domain = ArenaDomainId::from_raw(image.domain)
        .ok_or(SnapshotError::InvalidDomain { raw: image.domain })?;
    if reservation_base(domain).is_some() {
        return Err(SnapshotError::DomainAlreadyLive {
            domain: image.domain,
        });
    }
    let arena = ReservedArena::from_reloaded_image(
        domain,
        image.capacity as usize,
        &image.low,
        &image.high,
    )?;
    Ok(SharedFlatStoreArena::from_reserved(arena))
}

/// Reads a fixed 4-byte little-endian field at `offset`.
///
/// The caller must have bounds-checked that `offset + 4 <= bytes.len()`.
fn read4(bytes: &[u8], offset: usize) -> [u8; 4] {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    buf
}

/// Reads a fixed 8-byte little-endian field at `offset`.
///
/// The caller must have bounds-checked that `offset + 8 <= bytes.len()`.
fn read8(bytes: &[u8], offset: usize) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    buf
}

/// A heap-image capture, parse, or restore failure.
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// The arena uses the chunked compatibility backend, which is not
    /// address-free and cannot be snapshotted.
    #[error("heap image requires a Candidate-C reservation-backed arena")]
    NotReservationBacked,
    /// The serialized image was shorter than its declared layout.
    #[error("heap image is truncated: need {needed} bytes, got {got}")]
    Truncated {
        /// The byte length the declared layout requires.
        needed: usize,
        /// The byte length actually supplied.
        got: usize,
    },
    /// The image did not begin with [`IMAGE_MAGIC`].
    #[error("heap image magic tag is invalid")]
    BadMagic,
    /// The image's format version is not understood by this build.
    #[error("heap image version {version} is unsupported (expected {IMAGE_VERSION})")]
    UnsupportedVersion {
        /// The rejected on-disk version.
        version: u32,
    },
    /// The trailing digest did not match the recomputed one.
    #[error("heap image integrity digest mismatch: expected {expected:#018x}, got {actual:#018x}")]
    IntegrityMismatch {
        /// The digest recomputed over the payload.
        expected: u64,
        /// The digest stored in the image trailer.
        actual: u64,
    },
    /// The stored domain was outside the valid Candidate-C domain range.
    #[error("heap image domain {raw} is not a valid Candidate-C reservation domain")]
    InvalidDomain {
        /// The rejected raw domain value.
        raw: u32,
    },
    /// The stored domain is still registered; the source reservation must be
    /// dropped before its image can be reloaded (domain-preservation invariant).
    #[error("heap image domain {domain} is still live; drop the source reservation before restore")]
    DomainAlreadyLive {
        /// The still-registered domain.
        domain: u32,
    },
    /// The restore mapping or registration failed.
    #[error(transparent)]
    Reservation(#[from] super::reservation::ReservedArenaError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::reservation_registry::reservation_containing_address;
    use crate::value::compressed::CandidateCScalarStore;

    /// Two wide integers that do not fit the inline `i32` payload, so each boxes
    /// a hash-consed cell in the reservation arena — giving the round trip real
    /// `(domain, index)` heap words to resolve.
    const WIDE_A: i64 = 1_000_000_000_000;
    const WIDE_B: i64 = -42_000_000_000;

    #[test]
    fn reservation_image_round_trip_is_address_free_and_value_equal() {
        let arena = SharedFlatStoreArena::new();
        if !arena.uses_reservation() {
            // The chunked fallback is not snapshottable; nothing to prove here.
            return;
        }

        let mut scalars = CandidateCScalarStore::new(arena.clone());
        let word_a = scalars.encode_int(WIDE_A).expect("boxes a wide integer");
        let word_b = scalars.encode_int(WIDE_B).expect("boxes a wide integer");
        let index_a = word_a.arena_index().expect("boxed word carries an index");
        let domain = arena.arena_domain_id().expect("reservation-backed arena");

        let image = capture_reservation(&arena).expect("captures the reservation");
        let bytes = image.to_bytes();

        // Drop the source reservation so its domain is free to re-register.
        drop(scalars);
        drop(arena);
        assert!(
            reservation_base(domain).is_none(),
            "dropping the source reservation withdraws its domain"
        );

        let reloaded = HeapImage::from_bytes(&bytes).expect("parses the serialized image");
        let restored = restore_reservation(&reloaded).expect("restores the reservation");
        assert_eq!(
            restored.arena_domain_id(),
            Some(domain),
            "restore preserves the original domain"
        );

        // Address-free resolution: the dumped word is untouched, and the
        // registry now rebinds its domain to the fresh base, so `domain + index`
        // names the reloaded mapping with no per-word rewrite.
        let base = reservation_base(domain).expect("restored domain is registered");
        assert_eq!(
            word_a.arena_domain(),
            Some(domain),
            "domain word is unchanged"
        );
        assert_eq!(
            word_a.arena_index(),
            Some(index_a),
            "index word is unchanged"
        );
        assert_eq!(
            reservation_containing_address(base + index_a.raw() as usize),
            Some((domain, base)),
            "the restored mapping owns the resolved address"
        );

        // Byte-identical arena round trip: re-capturing the restored arena
        // reproduces the exact used-lane bytes and metadata.
        let recaptured = capture_reservation(&restored).expect("re-captures the restored arena");
        assert_eq!(recaptured.low, image.low);
        assert_eq!(recaptured.high, image.high);
        assert_eq!(recaptured.domain, image.domain);
        assert_eq!(recaptured.capacity, image.capacity);

        // End-to-end value equality: a fresh scalar store over the restored
        // reservation decodes both boxed cells to their original integers.
        let mut restored_scalars = CandidateCScalarStore::new(restored.clone());
        restored_scalars.adopt_reloaded_regions();
        assert_eq!(
            restored_scalars.decode_int(word_a).expect("decodes a"),
            WIDE_A
        );
        assert_eq!(
            restored_scalars.decode_int(word_b).expect("decodes b"),
            WIDE_B
        );
    }

    #[test]
    fn from_bytes_rejects_a_corrupted_image() {
        let arena = SharedFlatStoreArena::new();
        if !arena.uses_reservation() {
            return;
        }
        let mut scalars = CandidateCScalarStore::new(arena.clone());
        scalars.encode_int(WIDE_A).expect("boxes a wide integer");
        let image = capture_reservation(&arena).expect("captures the reservation");
        let mut bytes = image.to_bytes();

        // Flip a payload byte; the trailing digest must catch it.
        let mid = HEADER_LEN + image.low.len() / 2;
        bytes[mid] ^= 0xff;
        assert!(matches!(
            HeapImage::from_bytes(&bytes),
            Err(SnapshotError::IntegrityMismatch { .. })
        ));

        // A short buffer is a clean truncation error, not a panic.
        assert!(matches!(
            HeapImage::from_bytes(&bytes[..HEADER_LEN]),
            Err(SnapshotError::Truncated { .. })
        ));
    }

    #[test]
    fn from_bytes_rejects_bad_magic_and_version() {
        let image = HeapImage {
            domain: 1,
            capacity: 0x1000,
            low: vec![1, 2, 3, 4],
            high: Vec::new(),
        };
        let good = image.to_bytes();

        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0xff;
        // Recompute the digest so magic is what fails, not integrity.
        fix_digest(&mut bad_magic);
        assert!(matches!(
            HeapImage::from_bytes(&bad_magic),
            Err(SnapshotError::BadMagic)
        ));

        let mut bad_version = good.clone();
        bad_version[8] = 0xff;
        fix_digest(&mut bad_version);
        assert!(matches!(
            HeapImage::from_bytes(&bad_version),
            Err(SnapshotError::UnsupportedVersion { .. })
        ));
    }

    /// Recomputes the trailing digest so a header-field mutation is exercised in
    /// isolation from the integrity check.
    fn fix_digest(bytes: &mut [u8]) {
        let len = bytes.len();
        let digest = xxh3_64(&bytes[..len - 8]);
        bytes[len - 8..].copy_from_slice(&digest.to_le_bytes());
    }
}
