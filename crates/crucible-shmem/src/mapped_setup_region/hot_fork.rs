//! Aggregate hot-fork producer and consumer admission for mapped rings.

#[path = "hot_fork/image.rs"]
mod image;

pub use image::{HOT_FORK_RING_IMAGE_SCHEMA_VERSION, HotForkRingImage, HotForkRingImageError};

use super::*;
use crate::ABI_VERSION;
use image::{
    HOT_FORK_RING_IMAGE_SEGMENT_COUNT, HotForkRingImageSegment, canonical_image_len, image_digest,
    ring_image_ranges,
};

/// Exact aggregate state of every ring I/O barrier in one setup region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedRingIoBarrierSnapshot {
    ring_count: u64,
    held_rings: u64,
    producers_in_flight: u64,
    consumers_in_flight: u64,
}

/// Failure while changing whether a setup-region mapping survives `fork(2)`.
#[derive(Debug, Error)]
pub enum HotForkMappingDispositionError {
    /// The current operating system has no supported mapping-inheritance API.
    #[error("hot-fork mapping inheritance disposition is unsupported on this platform")]
    Unsupported,
    /// Linux rejected the requested mapping-inheritance transition.
    #[error("{operation} for the hot-fork setup-region mapping failed")]
    Madvise {
        /// Stable transition name.
        operation: &'static str,
        /// Underlying operating-system failure.
        #[source]
        source: std::io::Error,
    },
}

impl MappedRingIoBarrierSnapshot {
    /// Returns the exact number of ring headers in the validated region layout.
    #[must_use]
    pub const fn ring_count(self) -> u64 {
        self.ring_count
    }

    /// Returns the number of rings whose producer and consumer barriers are held.
    #[must_use]
    pub const fn held_rings(self) -> u64 {
        self.held_rings
    }

    /// Returns the checked aggregate of already-admitted producer operations.
    #[must_use]
    pub const fn producers_in_flight(self) -> u64 {
        self.producers_in_flight
    }

    /// Returns the checked aggregate of already-admitted consumer operations.
    #[must_use]
    pub const fn consumers_in_flight(self) -> u64 {
        self.consumers_in_flight
    }

    /// Returns whether every ring is held and every admitted I/O operation returned.
    #[must_use]
    pub const fn quiescent(self) -> bool {
        self.ring_count != 0
            && self.held_rings == self.ring_count
            && self.producers_in_flight == 0
            && self.consumers_in_flight == 0
    }
}

#[derive(Clone, Copy)]
enum BarrierAction {
    Hold,
    Query,
    Release,
}

impl MappedSetupRegion {
    /// Excludes this exact mapping from a future `fork(2)` child.
    ///
    /// The current process retains normal access. Callers must first stop every
    /// producer and consumer, retain the mapping owner until the matching
    /// release, and explicitly install an independently authenticated mapping
    /// in any child that continues execution.
    ///
    /// # Errors
    ///
    /// Returns [`HotForkMappingDispositionError`] when the platform does not
    /// support `MADV_DONTFORK` or the kernel rejects the transition.
    pub fn exclude_from_hot_fork_child(&self) -> Result<(), HotForkMappingDispositionError> {
        self.set_hot_fork_mapping_inheritance(false)
    }

    /// Restores ordinary inheritance for this exact mapping.
    ///
    /// This transition is intended for the retained template parent before
    /// ring producers and consumers reopen.
    ///
    /// # Errors
    ///
    /// Returns [`HotForkMappingDispositionError`] when the platform does not
    /// support `MADV_DOFORK` or the kernel rejects the transition.
    pub fn restore_hot_fork_parent_inheritance(
        &self,
    ) -> Result<(), HotForkMappingDispositionError> {
        self.set_hot_fork_mapping_inheritance(true)
    }

    #[cfg(target_os = "linux")]
    fn set_hot_fork_mapping_inheritance(
        &self,
        inherited: bool,
    ) -> Result<(), HotForkMappingDispositionError> {
        let (advice, operation) = if inherited {
            (libc::MADV_DOFORK, "MADV_DOFORK")
        } else {
            (libc::MADV_DONTFORK, "MADV_DONTFORK")
        };
        // SAFETY: `base_ptr` and `len` identify the live mapping owned by this
        // value. `madvise` changes only kernel inheritance metadata; it neither
        // transfers ownership nor permits access outside the mapped range.
        let status =
            unsafe { libc::madvise(self.base_ptr().cast::<libc::c_void>(), self.len, advice) };
        if status != 0 {
            return Err(HotForkMappingDispositionError::Madvise {
                operation,
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn set_hot_fork_mapping_inheritance(
        &self,
        _inherited: bool,
    ) -> Result<(), HotForkMappingDispositionError> {
        Err(HotForkMappingDispositionError::Unsupported)
    }

    /// Captures every queue-backed segment while both ring endpoints are held.
    ///
    /// `maximum_bytes` bounds the complete canonical image, including its
    /// fixed metadata and digest, before any segment allocation. The source
    /// remains held and unchanged after successful capture.
    ///
    /// # Errors
    ///
    /// Returns [`HotForkRingImageError`] when the mapped layout is invalid,
    /// any ring endpoint is open or still active, the image exceeds the caller
    /// bound, or exact bounded retention fails.
    pub fn capture_hot_fork_ring_image(
        &self,
        maximum_bytes: usize,
    ) -> Result<HotForkRingImage, HotForkRingImageError> {
        let before = self
            .hot_fork_ring_io_snapshot()
            .map_err(|source| HotForkRingImageError::RegionAccess { source })?;
        require_quiescent(before)?;
        let layout = self
            .layout()
            .map_err(|source| HotForkRingImageError::RegionAccess {
                source: MappedSetupRegionAccessError::Header { source },
            })?;
        let ranges = ring_image_ranges(layout)?;
        let lengths = ranges.map(|(_offset, length)| {
            usize::try_from(length).map_err(|_error| HotForkRingImageError::LengthOverflow)
        });
        let lengths = lengths.into_iter().collect::<Result<Vec<_>, _>>()?;
        let required = canonical_image_len(lengths.iter().copied())?;
        if required > maximum_bytes {
            return Err(HotForkRingImageError::ImageTooLarge {
                required,
                maximum: maximum_bytes,
            });
        }

        let mut retained = Vec::new();
        retained
            .try_reserve_exact(HOT_FORK_RING_IMAGE_SEGMENT_COUNT)
            .map_err(|_error| HotForkRingImageError::AllocationFailed {
                len: HOT_FORK_RING_IMAGE_SEGMENT_COUNT,
            })?;
        for ((offset, _length), length) in ranges.into_iter().zip(lengths) {
            let local_offset =
                usize::try_from(offset).map_err(|_error| HotForkRingImageError::LengthOverflow)?;
            let end = local_offset
                .checked_add(length)
                .ok_or(HotForkRingImageError::LengthOverflow)?;
            if end > self.len {
                return Err(HotForkRingImageError::InvalidCanonicalImage {
                    reason: "hot-fork-ring-image-source-range",
                });
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_error| HotForkRingImageError::AllocationFailed { len: length })?;
            // SAFETY: the validated range is inside the live mapping. Both
            // endpoints of every included ring are held and drained, so no
            // conforming producer or consumer can mutate these queue-backed
            // bytes until release. The copy completes before that release.
            let source =
                unsafe { core::slice::from_raw_parts(self.base_ptr().add(local_offset), length) };
            bytes.extend_from_slice(source);
            retained.push(HotForkRingImageSegment { offset, bytes });
        }
        let segments: [HotForkRingImageSegment; HOT_FORK_RING_IMAGE_SEGMENT_COUNT] = retained
            .try_into()
            .map_err(|_segments| HotForkRingImageError::InvalidCanonicalImage {
                reason: "hot-fork-ring-image-segment-count",
            })?;
        let mut image = HotForkRingImage {
            abi_version: ABI_VERSION,
            region_size: layout.region_size,
            vm_node_count: layout.vm_node_count,
            queue_capacity: layout.queue_capacity,
            icount_shift: layout.icount_shift,
            fault_payload_arena_bytes: layout.fault_payload_arena_bytes,
            segments,
            digest: [0; 32],
        };
        image.digest = image_digest(&image)?;

        let after = self
            .hot_fork_ring_io_snapshot()
            .map_err(|source| HotForkRingImageError::RegionAccess { source })?;
        require_quiescent(after)?;
        if after != before {
            return Err(HotForkRingImageError::InvalidCanonicalImage {
                reason: "hot-fork-ring-image-barrier-changed",
            });
        }
        Ok(image)
    }

    /// Restores one authenticated ring image into an inactive private mapping.
    ///
    /// The destination must have the identical ABI geometry and must already
    /// hold and drain both endpoints of every ring. Restored headers therefore
    /// remain held; callers release them only after the remaining child
    /// resources and host continuation are authenticated.
    ///
    /// # Errors
    ///
    /// Returns [`HotForkRingImageError`] when the image is invalid, source and
    /// destination layouts differ, a destination ring is open or active, or a
    /// restored barrier postcondition is inconsistent.
    pub fn restore_hot_fork_ring_image(
        &mut self,
        image: &HotForkRingImage,
    ) -> Result<(), HotForkRingImageError> {
        let image_layout = image.validate()?;
        let destination_layout =
            self.layout()
                .map_err(|source| HotForkRingImageError::RegionAccess {
                    source: MappedSetupRegionAccessError::Header { source },
                })?;
        if image_layout != destination_layout {
            return Err(HotForkRingImageError::LayoutMismatch);
        }
        let before = self
            .hot_fork_ring_io_snapshot()
            .map_err(|source| HotForkRingImageError::RegionAccess { source })?;
        require_quiescent(before)?;

        for segment in &image.segments {
            let offset = usize::try_from(segment.offset)
                .map_err(|_error| HotForkRingImageError::LengthOverflow)?;
            let end = offset
                .checked_add(segment.bytes.len())
                .ok_or(HotForkRingImageError::LengthOverflow)?;
            if end > self.len {
                return Err(HotForkRingImageError::InvalidCanonicalImage {
                    reason: "hot-fork-ring-image-destination-range",
                });
            }
            // SAFETY: `&mut self` provides exclusive Rust access to the live
            // mapping, the exact range was validated against the destination
            // layout, and the destination is an inactive private mapping whose
            // producer and consumer endpoints are held and drained.
            let destination = unsafe {
                core::slice::from_raw_parts_mut(self.base_ptr().add(offset), segment.bytes.len())
            };
            destination.copy_from_slice(&segment.bytes);
        }
        let after = self
            .hot_fork_ring_io_snapshot()
            .map_err(|source| HotForkRingImageError::RegionAccess { source })?;
        require_quiescent(after)?;
        Ok(())
    }

    /// Holds producer and consumer admission for every validated ring.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the live header or a ring
    /// segment no longer matches the mapped region's validated ABI geometry.
    pub fn hold_hot_fork_ring_io(
        &self,
    ) -> Result<MappedRingIoBarrierSnapshot, MappedSetupRegionAccessError> {
        self.apply_ring_io_barrier(BarrierAction::Hold)
    }

    /// Observes producer and consumer admission for every validated ring.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the live header or a ring
    /// segment no longer matches the mapped region's validated ABI geometry.
    pub fn hot_fork_ring_io_snapshot(
        &self,
    ) -> Result<MappedRingIoBarrierSnapshot, MappedSetupRegionAccessError> {
        self.apply_ring_io_barrier(BarrierAction::Query)
    }

    /// Releases consumer and producer admission for every validated ring.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the live header or a ring
    /// segment no longer matches the mapped region's validated ABI geometry.
    pub fn release_hot_fork_ring_io(
        &self,
    ) -> Result<MappedRingIoBarrierSnapshot, MappedSetupRegionAccessError> {
        self.apply_ring_io_barrier(BarrierAction::Release)
    }

    fn apply_ring_io_barrier(
        &self,
        action: BarrierAction,
    ) -> Result<MappedRingIoBarrierSnapshot, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        let segments = ring_header_segments(layout);

        // Validate the complete geometry before mutating the first barrier so
        // malformed shared header bytes cannot leave a partially held region.
        for &(segment, count, base) in &segments {
            if count != 0 {
                mapped_segment_offset(
                    segment,
                    count - 1,
                    base,
                    RING_HEADER_SIZE,
                    RING_HEADER_ALIGN,
                    self.len,
                )?;
            }
        }

        let mut ring_count = 0_u64;
        let mut held_rings = 0_u64;
        let mut producers_in_flight = 0_u64;
        let mut consumers_in_flight = 0_u64;
        for &(segment, count, base) in &segments {
            for index in 0..count {
                let offset = mapped_segment_offset(
                    segment,
                    index,
                    base,
                    RING_HEADER_SIZE,
                    RING_HEADER_ALIGN,
                    self.len,
                )?;
                // SAFETY: the complete segment geometry was validated before
                // any mutation and this immutable borrow uses only atomics.
                let ring = unsafe { &*self.base_ptr().add(offset).cast::<RingHeader>() };
                let (producer, consumer) = match action {
                    BarrierAction::Hold => (
                        ring.hold_hot_fork_producers(),
                        ring.hold_hot_fork_consumers(),
                    ),
                    BarrierAction::Query => (
                        ring.producer_barrier_snapshot(),
                        ring.consumer_barrier_snapshot(),
                    ),
                    BarrierAction::Release => {
                        // Reopen consumers first so already-queued content can
                        // drain before producers publish new entries.
                        let consumer = ring.release_hot_fork_consumers();
                        let producer = ring.release_hot_fork_producers();
                        (producer, consumer)
                    }
                };
                ring_count += 1;
                held_rings += u64::from(producer.held() && consumer.held());
                producers_in_flight = producers_in_flight
                    .checked_add(producer.in_flight())
                    .unwrap_or_else(|| std::process::abort());
                consumers_in_flight = consumers_in_flight
                    .checked_add(consumer.in_flight())
                    .unwrap_or_else(|| std::process::abort());
            }
        }

        Ok(MappedRingIoBarrierSnapshot {
            ring_count,
            held_rings,
            producers_in_flight,
            consumers_in_flight,
        })
    }
}

fn require_quiescent(snapshot: MappedRingIoBarrierSnapshot) -> Result<(), HotForkRingImageError> {
    if snapshot.quiescent() {
        return Ok(());
    }
    Err(HotForkRingImageError::BarrierNotQuiescent {
        ring_count: snapshot.ring_count(),
        held_rings: snapshot.held_rings(),
        producers_in_flight: snapshot.producers_in_flight(),
        consumers_in_flight: snapshot.consumers_in_flight(),
    })
}

type RingHeaderSegment = (&'static str, u32, u64);

const fn ring_header_segments(layout: RegionLayout) -> [RingHeaderSegment; 9] {
    [
        (
            "directed ring header",
            layout.ring_count,
            layout.ring_hdr_off,
        ),
        (
            "coverage ring header",
            layout.coverage_ring_count,
            layout.coverage_ring_hdr_off,
        ),
        (
            "white-box marker ring header",
            layout.whitebox_marker_ring_count,
            layout.whitebox_marker_ring_hdr_off,
        ),
        (
            "fault command ring header",
            layout.fault_command_ring_count,
            layout.fault_command_ring_hdr_off,
        ),
        (
            "fault result ring header",
            layout.fault_result_ring_count,
            layout.fault_result_ring_hdr_off,
        ),
        (
            "fault event ring header",
            layout.fault_event_ring_count,
            layout.fault_event_ring_hdr_off,
        ),
        (
            "guest introspection ring header",
            layout.guest_introspection_ring_count,
            layout.guest_introspection_ring_hdr_off,
        ),
        (
            "accelerator ring header",
            layout.accelerator_ring_count,
            layout.accelerator_ring_hdr_off,
        ),
        (
            "selectable reply ring header",
            layout.selectable_reply_ring_count,
            layout.selectable_reply_ring_hdr_off,
        ),
    ]
}

type RingImageHeaderSegment = (&'static str, u32, u64, u32);

const fn ring_image_header_segments(layout: RegionLayout) -> [RingImageHeaderSegment; 9] {
    [
        (
            "directed ring header",
            layout.ring_count,
            layout.ring_hdr_off,
            layout.queue_capacity,
        ),
        (
            "coverage ring header",
            layout.coverage_ring_count,
            layout.coverage_ring_hdr_off,
            layout.coverage_queue_capacity,
        ),
        (
            "white-box marker ring header",
            layout.whitebox_marker_ring_count,
            layout.whitebox_marker_ring_hdr_off,
            layout.whitebox_marker_queue_capacity,
        ),
        (
            "fault command ring header",
            layout.fault_command_ring_count,
            layout.fault_command_ring_hdr_off,
            layout.fault_command_queue_capacity,
        ),
        (
            "fault result ring header",
            layout.fault_result_ring_count,
            layout.fault_result_ring_hdr_off,
            layout.fault_result_queue_capacity,
        ),
        (
            "fault event ring header",
            layout.fault_event_ring_count,
            layout.fault_event_ring_hdr_off,
            layout.fault_event_queue_capacity,
        ),
        (
            "guest introspection ring header",
            layout.guest_introspection_ring_count,
            layout.guest_introspection_ring_hdr_off,
            layout.guest_introspection_queue_capacity,
        ),
        (
            "accelerator ring header",
            layout.accelerator_ring_count,
            layout.accelerator_ring_hdr_off,
            layout.accelerator_queue_capacity,
        ),
        (
            "selectable reply ring header",
            layout.selectable_reply_ring_count,
            layout.selectable_reply_ring_hdr_off,
            layout.selectable_reply_queue_capacity,
        ),
    ]
}
