//! Bounded canonical images of held hot-fork ring storage.

use super::{MappedSetupRegionAccessError, RegionLayout, ring_image_header_segments};
use crate::{
    ABI_VERSION, RING_HEADER_CONSUMER_STATE_OFFSET, RING_HEADER_PRODUCER_STATE_OFFSET,
    RING_HEADER_READ_IDX_OFFSET, RING_HEADER_WRITE_IDX_OFFSET, RegionConfig,
};
use thiserror::Error;

const HOT_FORK_RING_IMAGE_MAGIC: [u8; 8] = *b"CRHFRI01";
/// Current canonical hot-fork ring-image schema version.
pub const HOT_FORK_RING_IMAGE_SCHEMA_VERSION: u32 = 1;
pub(super) const HOT_FORK_RING_IMAGE_SEGMENT_COUNT: usize = 3;
const HOT_FORK_RING_IMAGE_FIXED_BYTES: usize = 8 + 4 + 4 + 8 + 4 + 4 + 4 + 4 + 32;
const HOT_FORK_RING_IMAGE_SEGMENT_METADATA_BYTES: usize = 16;
const HOT_FORK_RING_IMAGE_HELD_STATE: u64 = 1_u64 << 63;

/// One bounded transport image of every queue-backed shared-memory segment.
///
/// The image is operational transfer material, not configuration identity. It
/// retains complete ring backing ranges, including inactive slots, so a later
/// branch-private mapping can preserve exact cursors and queued bytes without
/// interpreting a queue between capture and restore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HotForkRingImage {
    pub(super) abi_version: u32,
    pub(super) region_size: u64,
    pub(super) vm_node_count: u32,
    pub(super) queue_capacity: u32,
    pub(super) icount_shift: u32,
    pub(super) fault_payload_arena_bytes: u32,
    pub(super) segments: [HotForkRingImageSegment; HOT_FORK_RING_IMAGE_SEGMENT_COUNT],
    pub(super) digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HotForkRingImageSegment {
    pub(super) offset: u64,
    pub(super) bytes: Vec<u8>,
}

impl HotForkRingImage {
    /// Returns the source shared-memory ABI version.
    #[must_use]
    pub const fn abi_version(&self) -> u32 {
        self.abi_version
    }

    /// Returns the exact source setup-region length.
    #[must_use]
    pub const fn region_size(&self) -> u64 {
        self.region_size
    }

    /// Returns the exact setup-region geometry carried by the image.
    ///
    /// A branch-private destination uses this value to construct fresh
    /// non-ring state before restoring the retained queue-backed segments.
    #[must_use]
    pub const fn region_config(&self) -> RegionConfig {
        RegionConfig {
            vm_node_count: self.vm_node_count,
            queue_capacity: self.queue_capacity,
            icount_shift: self.icount_shift,
            fault_payload_arena_bytes: self.fault_payload_arena_bytes,
        }
    }

    /// Returns the BLAKE3 transfer-integrity digest.
    ///
    /// This digest authenticates the complete operational image but does not
    /// enter campaign configuration identity.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the exact canonical byte length without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`HotForkRingImageError::LengthOverflow`] when the image length
    /// cannot be represented on this host.
    pub fn canonical_len(&self) -> Result<usize, HotForkRingImageError> {
        canonical_image_len(self.segments.iter().map(|segment| segment.bytes.len()))
    }

    /// Encodes the versioned operational image into canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HotForkRingImageError`] when the image is internally invalid,
    /// its encoded length overflows, or the exact output allocation fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HotForkRingImageError> {
        self.validate()?;
        let len = self.canonical_len()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_error| HotForkRingImageError::AllocationFailed { len })?;
        bytes.extend_from_slice(&HOT_FORK_RING_IMAGE_MAGIC);
        bytes.extend_from_slice(&HOT_FORK_RING_IMAGE_SCHEMA_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.abi_version.to_le_bytes());
        bytes.extend_from_slice(&self.region_size.to_le_bytes());
        bytes.extend_from_slice(&self.vm_node_count.to_le_bytes());
        bytes.extend_from_slice(&self.queue_capacity.to_le_bytes());
        bytes.extend_from_slice(&self.icount_shift.to_le_bytes());
        bytes.extend_from_slice(&self.fault_payload_arena_bytes.to_le_bytes());
        for segment in &self.segments {
            bytes.extend_from_slice(&segment.offset.to_le_bytes());
            let length = u64::try_from(segment.bytes.len())
                .map_err(|_error| HotForkRingImageError::LengthOverflow)?;
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(&segment.bytes);
        }
        bytes.extend_from_slice(&self.digest);
        debug_assert_eq!(bytes.len(), len);
        Ok(bytes)
    }

    /// Decodes and authenticates one bounded canonical operational image.
    ///
    /// `maximum_bytes` applies to the complete canonical body before any
    /// segment allocation.
    ///
    /// # Errors
    ///
    /// Returns [`HotForkRingImageError`] for an oversized, truncated,
    /// noncanonical, incompatible, or unauthenticated image, or when retaining
    /// the exact bounded segment bytes fails.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        maximum_bytes: usize,
    ) -> Result<Self, HotForkRingImageError> {
        if bytes.len() > maximum_bytes {
            return Err(HotForkRingImageError::ImageTooLarge {
                required: bytes.len(),
                maximum: maximum_bytes,
            });
        }
        let mut reader = HotForkRingImageReader::new(bytes);
        if reader.take(8)? != HOT_FORK_RING_IMAGE_MAGIC {
            return Err(HotForkRingImageError::InvalidCanonicalImage {
                reason: "hot-fork-ring-image-magic",
            });
        }
        if reader.u32()? != HOT_FORK_RING_IMAGE_SCHEMA_VERSION {
            return Err(HotForkRingImageError::InvalidCanonicalImage {
                reason: "hot-fork-ring-image-schema",
            });
        }
        let abi_version = reader.u32()?;
        let region_size = reader.u64()?;
        let vm_node_count = reader.u32()?;
        let queue_capacity = reader.u32()?;
        let icount_shift = reader.u32()?;
        let fault_payload_arena_bytes = reader.u32()?;
        let layout = image_layout(
            abi_version,
            region_size,
            vm_node_count,
            queue_capacity,
            icount_shift,
            fault_payload_arena_bytes,
        )?;
        let expected_ranges = ring_image_ranges(layout)?;

        let mut segments = Vec::new();
        segments
            .try_reserve_exact(HOT_FORK_RING_IMAGE_SEGMENT_COUNT)
            .map_err(|_error| HotForkRingImageError::AllocationFailed {
                len: HOT_FORK_RING_IMAGE_SEGMENT_COUNT,
            })?;
        for expected in expected_ranges {
            let offset = reader.u64()?;
            let length = reader.u64()?;
            if (offset, length) != expected {
                return Err(HotForkRingImageError::InvalidCanonicalImage {
                    reason: "hot-fork-ring-image-segment-geometry",
                });
            }
            let length =
                usize::try_from(length).map_err(|_error| HotForkRingImageError::LengthOverflow)?;
            let source = reader.take(length)?;
            let mut retained = Vec::new();
            retained
                .try_reserve_exact(length)
                .map_err(|_error| HotForkRingImageError::AllocationFailed { len: length })?;
            retained.extend_from_slice(source);
            segments.push(HotForkRingImageSegment {
                offset,
                bytes: retained,
            });
        }
        let digest = reader.array_32()?;
        if !reader.exhausted() {
            return Err(HotForkRingImageError::InvalidCanonicalImage {
                reason: "hot-fork-ring-image-trailing-bytes",
            });
        }
        let segments: [HotForkRingImageSegment; HOT_FORK_RING_IMAGE_SEGMENT_COUNT] = segments
            .try_into()
            .map_err(|_segments| HotForkRingImageError::InvalidCanonicalImage {
                reason: "hot-fork-ring-image-segment-count",
            })?;
        let image = Self {
            abi_version,
            region_size,
            vm_node_count,
            queue_capacity,
            icount_shift,
            fault_payload_arena_bytes,
            segments,
            digest,
        };
        image.validate()?;
        Ok(image)
    }

    pub(super) fn validate(&self) -> Result<RegionLayout, HotForkRingImageError> {
        let layout = image_layout(
            self.abi_version,
            self.region_size,
            self.vm_node_count,
            self.queue_capacity,
            self.icount_shift,
            self.fault_payload_arena_bytes,
        )?;
        let expected = ring_image_ranges(layout)?;
        for (segment, (offset, length)) in self.segments.iter().zip(expected) {
            let actual_length = u64::try_from(segment.bytes.len())
                .map_err(|_error| HotForkRingImageError::LengthOverflow)?;
            if segment.offset != offset || actual_length != length {
                return Err(HotForkRingImageError::InvalidCanonicalImage {
                    reason: "hot-fork-ring-image-segment-geometry",
                });
            }
        }
        validate_image_ring_headers(self, layout)?;
        if image_digest(self)? != self.digest {
            return Err(HotForkRingImageError::DigestMismatch);
        }
        Ok(layout)
    }
}

/// A failure to capture, encode, authenticate, or restore a hot-fork ring image.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HotForkRingImageError {
    /// The mapped setup region failed typed access or geometry validation.
    #[error("hot-fork ring image cannot access the mapped setup region")]
    RegionAccess {
        /// Underlying mapped-region access failure.
        source: MappedSetupRegionAccessError,
    },
    /// The source or destination ring set was not held and drained.
    #[error(
        "hot-fork ring image requires {held_rings}/{ring_count} held rings with zero admitted I/O; producers={producers_in_flight}, consumers={consumers_in_flight}"
    )]
    BarrierNotQuiescent {
        /// Exact ring count.
        ring_count: u64,
        /// Rings with both endpoints held.
        held_rings: u64,
        /// Producer operations admitted before the hold.
        producers_in_flight: u64,
        /// Consumer operations admitted before the hold.
        consumers_in_flight: u64,
    },
    /// The complete canonical image exceeds the caller's explicit bound.
    #[error("hot-fork ring image requires {required} bytes, above limit {maximum}")]
    ImageTooLarge {
        /// Exact required canonical bytes.
        required: usize,
        /// Caller-supplied maximum canonical bytes.
        maximum: usize,
    },
    /// Checked image length arithmetic overflowed.
    #[error("hot-fork ring image length overflowed")]
    LengthOverflow,
    /// Retaining an exact bounded image allocation failed.
    #[error("hot-fork ring image could not allocate {len} bytes")]
    AllocationFailed {
        /// Requested allocation size.
        len: usize,
    },
    /// Canonical input violated the closed image grammar or geometry.
    #[error("invalid canonical hot-fork ring image: {reason}")]
    InvalidCanonicalImage {
        /// Stable machine-readable rejection reason.
        reason: &'static str,
    },
    /// The transfer-integrity digest did not authenticate the image.
    #[error("hot-fork ring image digest mismatch")]
    DigestMismatch,
    /// Source and destination setup-region layouts differ.
    #[error("hot-fork ring image layout does not match destination")]
    LayoutMismatch,
}

pub(super) fn ring_image_ranges(
    layout: RegionLayout,
) -> Result<[(u64, u64); HOT_FORK_RING_IMAGE_SEGMENT_COUNT], HotForkRingImageError> {
    let bounds = [
        (layout.ring_hdr_off, layout.coverage_ring_hdr_off),
        (layout.coverage_ring_hdr_off, layout.fingerprint_sample_off),
        (layout.whitebox_marker_ring_hdr_off, layout.region_size),
    ];
    bounds
        .map(|(start, end)| {
            let length =
                end.checked_sub(start)
                    .ok_or(HotForkRingImageError::InvalidCanonicalImage {
                        reason: "hot-fork-ring-image-range-order",
                    })?;
            Ok((start, length))
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_ranges| HotForkRingImageError::InvalidCanonicalImage {
            reason: "hot-fork-ring-image-segment-count",
        })
}

pub(super) fn canonical_image_len(
    lengths: impl IntoIterator<Item = usize>,
) -> Result<usize, HotForkRingImageError> {
    let mut total = HOT_FORK_RING_IMAGE_FIXED_BYTES;
    for length in lengths {
        total = total
            .checked_add(HOT_FORK_RING_IMAGE_SEGMENT_METADATA_BYTES)
            .and_then(|value| value.checked_add(length))
            .ok_or(HotForkRingImageError::LengthOverflow)?;
    }
    Ok(total)
}

fn image_layout(
    abi_version: u32,
    region_size: u64,
    vm_node_count: u32,
    queue_capacity: u32,
    icount_shift: u32,
    fault_payload_arena_bytes: u32,
) -> Result<RegionLayout, HotForkRingImageError> {
    if abi_version != ABI_VERSION {
        return Err(HotForkRingImageError::InvalidCanonicalImage {
            reason: "hot-fork-ring-image-abi",
        });
    }
    let layout = RegionLayout::for_config(RegionConfig {
        vm_node_count,
        queue_capacity,
        icount_shift,
        fault_payload_arena_bytes,
    })
    .map_err(|_source| HotForkRingImageError::InvalidCanonicalImage {
        reason: "hot-fork-ring-image-layout",
    })?;
    if layout.region_size != region_size {
        return Err(HotForkRingImageError::InvalidCanonicalImage {
            reason: "hot-fork-ring-image-region-size",
        });
    }
    Ok(layout)
}

pub(super) fn image_digest(image: &HotForkRingImage) -> Result<[u8; 32], HotForkRingImageError> {
    let mut hasher = blake3::Hasher::new_derive_key("crucible.shmem.hot-fork-ring-image.v1");
    hasher.update(&HOT_FORK_RING_IMAGE_SCHEMA_VERSION.to_le_bytes());
    hasher.update(&image.abi_version.to_le_bytes());
    hasher.update(&image.region_size.to_le_bytes());
    hasher.update(&image.vm_node_count.to_le_bytes());
    hasher.update(&image.queue_capacity.to_le_bytes());
    hasher.update(&image.icount_shift.to_le_bytes());
    hasher.update(&image.fault_payload_arena_bytes.to_le_bytes());
    for segment in &image.segments {
        hasher.update(&segment.offset.to_le_bytes());
        let length = u64::try_from(segment.bytes.len())
            .map_err(|_error| HotForkRingImageError::LengthOverflow)?;
        hasher.update(&length.to_le_bytes());
        hasher.update(&segment.bytes);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn validate_image_ring_headers(
    image: &HotForkRingImage,
    layout: RegionLayout,
) -> Result<(), HotForkRingImageError> {
    for (_name, count, base, capacity) in ring_image_header_segments(layout) {
        for index in 0..count {
            let header = base
                .checked_add(
                    u64::from(index)
                        .checked_mul(crate::RING_HEADER_SIZE as u64)
                        .ok_or(HotForkRingImageError::LengthOverflow)?,
                )
                .ok_or(HotForkRingImageError::LengthOverflow)?;
            let read = image_u64(image, header, RING_HEADER_READ_IDX_OFFSET)?;
            let consumer = image_u64(image, header, RING_HEADER_CONSUMER_STATE_OFFSET)?;
            let write = image_u64(image, header, RING_HEADER_WRITE_IDX_OFFSET)?;
            let producer = image_u64(image, header, RING_HEADER_PRODUCER_STATE_OFFSET)?;
            if consumer != HOT_FORK_RING_IMAGE_HELD_STATE
                || producer != HOT_FORK_RING_IMAGE_HELD_STATE
            {
                return Err(HotForkRingImageError::InvalidCanonicalImage {
                    reason: "hot-fork-ring-image-open-or-active-header",
                });
            }
            if write.wrapping_sub(read) > u64::from(capacity) {
                return Err(HotForkRingImageError::InvalidCanonicalImage {
                    reason: "hot-fork-ring-image-cursor-capacity",
                });
            }
        }
    }
    Ok(())
}

fn image_u64(
    image: &HotForkRingImage,
    header_offset: u64,
    field_offset: usize,
) -> Result<u64, HotForkRingImageError> {
    let absolute = header_offset
        .checked_add(
            u64::try_from(field_offset).map_err(|_error| HotForkRingImageError::LengthOverflow)?,
        )
        .ok_or(HotForkRingImageError::LengthOverflow)?;
    let end = absolute
        .checked_add(8)
        .ok_or(HotForkRingImageError::LengthOverflow)?;
    for segment in &image.segments {
        let segment_length = u64::try_from(segment.bytes.len())
            .map_err(|_error| HotForkRingImageError::LengthOverflow)?;
        let segment_end = segment
            .offset
            .checked_add(segment_length)
            .ok_or(HotForkRingImageError::LengthOverflow)?;
        if absolute >= segment.offset && end <= segment_end {
            let local = usize::try_from(absolute - segment.offset)
                .map_err(|_error| HotForkRingImageError::LengthOverflow)?;
            let bytes: [u8; 8] = segment.bytes[local..local + 8]
                .try_into()
                .map_err(|_error| HotForkRingImageError::InvalidCanonicalImage {
                    reason: "hot-fork-ring-image-header-field",
                })?;
            return Ok(u64::from_le_bytes(bytes));
        }
    }
    Err(HotForkRingImageError::InvalidCanonicalImage {
        reason: "hot-fork-ring-image-header-range",
    })
}

struct HotForkRingImageReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> HotForkRingImageReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], HotForkRingImageError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(HotForkRingImageError::LengthOverflow)?;
        let value = self.bytes.get(self.offset..end).ok_or(
            HotForkRingImageError::InvalidCanonicalImage {
                reason: "hot-fork-ring-image-truncated",
            },
        )?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, HotForkRingImageError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_error| {
            HotForkRingImageError::InvalidCanonicalImage {
                reason: "hot-fork-ring-image-u32",
            }
        })?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, HotForkRingImageError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_error| {
            HotForkRingImageError::InvalidCanonicalImage {
                reason: "hot-fork-ring-image-u64",
            }
        })?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn array_32(&mut self) -> Result<[u8; 32], HotForkRingImageError> {
        self.take(32)?
            .try_into()
            .map_err(|_error| HotForkRingImageError::InvalidCanonicalImage {
                reason: "hot-fork-ring-image-digest",
            })
    }

    fn exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
