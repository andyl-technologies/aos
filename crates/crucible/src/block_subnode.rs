//! Deterministic block sub-node copy-on-write overlay.
//!
//! The block sub-node presents a writable block device over an immutable,
//! content-addressed base image. Reads resolve each 4 KiB page from the overlay
//! first and then the base image; writes copy base pages into the overlay before
//! patching them there. Dirty pages are tracked in deterministic order for
//! checkpoint deltas.

use crate::{
    ContentAddressedBlobRef, ContentHash, Icount, IoSubNodeRequest, SchedulerNodeId,
    SchedulingNodeKind, Shift, SimDuration, TimeConversionError, VirtualInstant,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::Arc,
};

/// Size in bytes of every block overlay page.
pub const BLOCK_OVERLAY_PAGE_SIZE: usize = 4096;

const BLOCK_OVERLAY_PAGE_SIZE_U64: u64 = BLOCK_OVERLAY_PAGE_SIZE as u64;

/// A block request operation that participates in deterministic latency modeling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockSubNodeOperation {
    /// Read bytes from the block overlay/base stack.
    Read,
    /// Write bytes into the copy-on-write overlay.
    Write,
    /// Flush the simulated block device.
    Flush,
    /// Query the simulated block device length.
    GetLength,
}

/// Deterministic latency parameters for a block sub-node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BlockLatencyParameters {
    /// Fixed read-operation latency.
    pub read_base: SimDuration,
    /// Fixed write-operation latency.
    pub write_base: SimDuration,
    /// Fixed flush-operation latency.
    pub flush_base: SimDuration,
    /// Fixed get-length-operation latency.
    pub get_length_base: SimDuration,
    /// Additional latency per requested byte.
    pub per_byte: SimDuration,
}

impl BlockLatencyParameters {
    /// Builds deterministic block latency parameters.
    #[must_use]
    pub const fn new(
        read_base: SimDuration,
        write_base: SimDuration,
        flush_base: SimDuration,
        get_length_base: SimDuration,
        per_byte: SimDuration,
    ) -> Self {
        Self {
            read_base,
            write_base,
            flush_base,
            get_length_base,
            per_byte,
        }
    }

    /// Computes deterministic modeled latency for a block operation.
    ///
    /// # Errors
    ///
    /// Returns [`BlockCompletionError::LatencyOverflow`] when the fixed
    /// operation latency and per-byte latency cannot fit in `u64` nanoseconds.
    pub fn latency_for(
        self,
        operation: BlockSubNodeOperation,
        count: u32,
    ) -> Result<SimDuration, BlockCompletionError> {
        let base = match operation {
            BlockSubNodeOperation::Read => self.read_base,
            BlockSubNodeOperation::Write => self.write_base,
            BlockSubNodeOperation::Flush => self.flush_base,
            BlockSubNodeOperation::GetLength => self.get_length_base,
        };
        let variable = self
            .per_byte
            .nanos
            .checked_mul(u64::from(count))
            .ok_or(BlockCompletionError::LatencyOverflow { operation, count })?;
        let nanos = base
            .nanos
            .checked_add(variable)
            .ok_or(BlockCompletionError::LatencyOverflow { operation, count })?;
        Ok(SimDuration { nanos })
    }
}

/// A block request ready for deterministic completion planning.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockCompletionRequest {
    /// Device-local request sequence from the block ingress ring.
    pub sequence: u64,
    /// Disk sub-node that will produce the response.
    pub sub_node: SchedulerNodeId,
    /// VM scheduler node that will observe the response.
    pub requester: SchedulerNodeId,
    /// Block operation being modeled.
    pub operation: BlockSubNodeOperation,
    /// Requester's icount when the request became modeled input.
    pub request_icount: Icount,
    /// Operation byte count used by the deterministic latency model.
    pub count: u32,
    /// Deterministic response payload computed before visibility.
    pub payload: Vec<u8>,
}

impl BlockCompletionRequest {
    /// Computes the deterministic completion plan for this block request.
    ///
    /// # Errors
    ///
    /// Returns [`BlockCompletionError`] when the producer is not a disk
    /// sub-node, the requester is not a VM node, latency arithmetic overflows,
    /// or icount/virtual-time conversion fails.
    pub fn plan(
        self,
        shift: Shift,
        latency: BlockLatencyParameters,
    ) -> Result<BlockCompletionPlan, BlockCompletionError> {
        if self.sub_node.kind != SchedulingNodeKind::Disk {
            return Err(BlockCompletionError::InvalidNodeKind {
                kind: self.sub_node.kind,
            });
        }
        if self.requester.kind != SchedulingNodeKind::Vm {
            return Err(BlockCompletionError::InvalidRequesterKind {
                kind: self.requester.kind,
            });
        }
        let modeled_latency = latency.latency_for(self.operation, self.count)?;
        let delivery_icount = block_delivery_icount(shift, self.request_icount, modeled_latency)?;
        Ok(BlockCompletionPlan {
            sequence: self.sequence,
            sub_node: self.sub_node,
            requester: self.requester,
            operation: self.operation,
            request_icount: self.request_icount,
            count: self.count,
            modeled_latency,
            delivery_icount,
            payload: self.payload,
        })
    }
}

/// A deterministic completion selected for one block request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockCompletionPlan {
    /// Device-local request sequence from the block ingress ring.
    pub sequence: u64,
    /// Disk sub-node that will produce the response.
    pub sub_node: SchedulerNodeId,
    /// VM scheduler node that will observe the response.
    pub requester: SchedulerNodeId,
    /// Block operation being modeled.
    pub operation: BlockSubNodeOperation,
    /// Requester's icount when the request became modeled input.
    pub request_icount: Icount,
    /// Operation byte count used by the deterministic latency model.
    pub count: u32,
    /// Modeled latency added to `request_icount` in virtual time.
    pub modeled_latency: SimDuration,
    /// Icount at which the block response becomes visible to the requester.
    pub delivery_icount: Icount,
    /// Deterministic response payload computed before visibility.
    pub payload: Vec<u8>,
}

impl BlockCompletionPlan {
    /// Converts the plan into the uniform I/O sub-node request shape.
    #[must_use]
    pub fn into_io_request(self) -> IoSubNodeRequest {
        IoSubNodeRequest {
            sequence: self.sequence,
            expected_sub_node: Some(self.sub_node),
            requester: self.requester,
            request_icount: self.request_icount,
            modeled_latency: self.modeled_latency,
            expected_delivery_icount: Some(self.delivery_icount),
            rng_draw: None,
            payload: self.payload,
        }
    }
}

/// Sorts block completions in deterministic `(delivery_icount, src_node, seq)` order.
pub fn sort_block_completion_plans(plans: &mut [BlockCompletionPlan]) {
    plans.sort_by(block_completion_order);
}

/// An immutable, content-addressed base image for a block sub-node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBaseImage {
    content: ContentAddressedBlobRef,
    bytes: Arc<[u8]>,
    length: u64,
}

impl BlockBaseImage {
    /// Builds an immutable base image and computes its content address.
    ///
    /// # Errors
    ///
    /// Returns [`BlockOverlayError::BaseImageTooLarge`] if the byte length
    /// cannot be represented as a `u64`.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, BlockOverlayError> {
        let bytes = bytes.into();
        let content = ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(&bytes));
        Self::from_content_ref(content, bytes)
    }

    /// Builds an immutable base image from an expected content-addressed ref.
    ///
    /// # Errors
    ///
    /// Returns [`BlockOverlayError::BaseImageTooLarge`] if the byte length
    /// cannot be represented as a `u64`, or
    /// [`BlockOverlayError::ContentHashMismatch`] if `content` does not match
    /// the supplied bytes.
    pub fn from_content_ref(
        content: ContentAddressedBlobRef,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, BlockOverlayError> {
        let bytes = bytes.into();
        let length =
            u64::try_from(bytes.len()).map_err(|_| BlockOverlayError::BaseImageTooLarge {
                length: bytes.len(),
            })?;
        let actual = ContentHash::from_bytes(&bytes);
        if actual != content.hash() {
            return Err(BlockOverlayError::ContentHashMismatch {
                expected: content.hash(),
                actual,
            });
        }

        Ok(Self {
            content,
            bytes: Arc::<[u8]>::from(bytes),
            length,
        })
    }

    /// Returns the content-addressed reference for this base image.
    #[must_use]
    pub const fn content_ref(&self) -> ContentAddressedBlobRef {
        self.content
    }

    /// Returns the content hash for this base image.
    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content.hash()
    }

    /// Returns the total device length in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.length
    }

    /// Returns whether the base image has zero bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the immutable base bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn copy_page(&self, page_base: u64) -> BlockOverlayPage {
        let mut page = Box::new([0u8; BLOCK_OVERLAY_PAGE_SIZE]);
        if let Ok(start) = usize::try_from(page_base) {
            if start < self.bytes.len() {
                let end = start
                    .saturating_add(BLOCK_OVERLAY_PAGE_SIZE)
                    .min(self.bytes.len());
                page[..end - start].copy_from_slice(&self.bytes[start..end]);
            }
        }
        page
    }
}

/// One deterministic dirty overlay page captured for a checkpoint delta.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockDirtyPage {
    /// Page-aligned byte offset in the block device.
    pub page_base: u64,
    /// Whole 4 KiB overlay page bytes.
    pub bytes: Vec<u8>,
}

/// Dirty-page delta captured from a block sub-node overlay.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockOverlayDelta {
    /// Content-addressed base image over which this delta was captured.
    pub base: ContentAddressedBlobRef,
    /// Dirty pages in ascending `page_base` order.
    pub pages: Vec<BlockDirtyPage>,
}

impl BlockOverlayDelta {
    /// Computes a deterministic content hash for this dirty-page delta.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_bytes(&block_overlay_delta_bytes(self))
    }

    /// Returns whether the delta contains no dirty pages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }
}

/// A block-device copy-on-write overlay over an immutable base image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockSubNodeOverlay {
    base: BlockBaseImage,
    overlay: BTreeMap<u64, BlockOverlayPage>,
    dirty: BTreeSet<u64>,
}

impl BlockSubNodeOverlay {
    /// Builds an empty copy-on-write overlay over `base`.
    #[must_use]
    pub fn new(base: BlockBaseImage) -> Self {
        Self {
            base,
            overlay: BTreeMap::new(),
            dirty: BTreeSet::new(),
        }
    }

    /// Returns the immutable base image used by this overlay.
    #[must_use]
    pub const fn base(&self) -> &BlockBaseImage {
        &self.base
    }

    /// Returns the total block-device length in bytes.
    #[must_use]
    pub const fn get_length(&self) -> u64 {
        self.base.len()
    }

    /// Returns the number of live overlay pages.
    #[must_use]
    pub fn overlay_page_count(&self) -> usize {
        self.overlay.len()
    }

    /// Returns the number of pages dirtied since the last delta capture.
    #[must_use]
    pub fn dirty_page_count(&self) -> usize {
        self.dirty.len()
    }

    /// Returns dirty page offsets in deterministic ascending order.
    #[must_use]
    pub fn dirty_pages(&self) -> Vec<u64> {
        self.dirty.iter().copied().collect()
    }

    /// Reads `count` bytes at `offset`, resolving overlay pages before the base.
    ///
    /// # Errors
    ///
    /// Returns [`BlockOverlayError`] when the requested range overflows, exceeds
    /// platform allocation limits, or extends past the fixed base image length.
    pub fn read(&self, offset: u64, count: u64) -> Result<Vec<u8>, BlockOverlayError> {
        let count_usize = checked_count_usize(count)?;
        validate_range(offset, count, self.get_length())?;

        let mut output = vec![0u8; count_usize];
        let mut position = offset;
        let end = offset + count;
        let mut output_offset = 0usize;

        while position < end {
            let page_base = page_base(position);
            let page_offset = usize::try_from(position - page_base).map_err(|_| {
                BlockOverlayError::RangeTooLarge {
                    count: position - page_base,
                }
            })?;
            let chunk = (BLOCK_OVERLAY_PAGE_SIZE - page_offset).min(
                usize::try_from(end - position).map_err(|_| BlockOverlayError::RangeTooLarge {
                    count: end - position,
                })?,
            );

            if let Some(page) = self.overlay.get(&page_base) {
                output[output_offset..output_offset + chunk]
                    .copy_from_slice(&page[page_offset..page_offset + chunk]);
            } else {
                self.copy_base_range(position, &mut output[output_offset..output_offset + chunk]);
            }

            position += u64::try_from(chunk).map_err(|_| BlockOverlayError::RangeTooLarge {
                count: end - position,
            })?;
            output_offset += chunk;
        }

        Ok(output)
    }

    /// Writes `data` at `offset`, copying base pages into the overlay first.
    ///
    /// # Errors
    ///
    /// Returns [`BlockOverlayError`] when the written range overflows or extends
    /// past the fixed base image length.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), BlockOverlayError> {
        let count = u64::try_from(data.len())
            .map_err(|_| BlockOverlayError::RangeTooLarge { count: u64::MAX })?;
        validate_range(offset, count, self.get_length())?;

        let mut position = offset;
        let end = offset + count;
        let mut input_offset = 0usize;

        while position < end {
            let page_base = page_base(position);
            let page_offset = usize::try_from(position - page_base).map_err(|_| {
                BlockOverlayError::RangeTooLarge {
                    count: position - page_base,
                }
            })?;
            let chunk = (BLOCK_OVERLAY_PAGE_SIZE - page_offset).min(
                usize::try_from(end - position).map_err(|_| BlockOverlayError::RangeTooLarge {
                    count: end - position,
                })?,
            );

            let page = self
                .overlay
                .entry(page_base)
                .or_insert_with(|| self.base.copy_page(page_base));
            page[page_offset..page_offset + chunk]
                .copy_from_slice(&data[input_offset..input_offset + chunk]);
            self.dirty.insert(page_base);

            position += u64::try_from(chunk).map_err(|_| BlockOverlayError::RangeTooLarge {
                count: end - position,
            })?;
            input_offset += chunk;
        }

        Ok(())
    }

    /// Succeeds without changing overlay or base state.
    ///
    /// # Errors
    ///
    /// This operation currently never returns an error; it is modeled as a
    /// no-op success because the in-memory overlay is the simulation's durable
    /// block state.
    pub fn flush(&mut self) -> Result<(), BlockOverlayError> {
        Ok(())
    }

    /// Captures dirty overlay pages in deterministic order and clears dirtiness.
    #[must_use]
    pub fn capture_dirty_delta(&mut self) -> BlockOverlayDelta {
        let pages = self
            .dirty
            .iter()
            .filter_map(|page_base| {
                self.overlay.get(page_base).map(|page| BlockDirtyPage {
                    page_base: *page_base,
                    bytes: page.to_vec(),
                })
            })
            .collect();
        self.dirty.clear();
        BlockOverlayDelta {
            base: self.base.content_ref(),
            pages,
        }
    }

    /// Captures every live overlay page in deterministic order without clearing dirtiness.
    #[must_use]
    pub fn overlay_pages(&self) -> Vec<BlockDirtyPage> {
        self.overlay
            .iter()
            .map(|(page_base, page)| BlockDirtyPage {
                page_base: *page_base,
                bytes: page.to_vec(),
            })
            .collect()
    }

    fn copy_base_range(&self, offset: u64, output: &mut [u8]) {
        let Ok(start) = usize::try_from(offset) else {
            return;
        };
        if start >= self.base.bytes.len() {
            return;
        }
        let end = start
            .saturating_add(output.len())
            .min(self.base.bytes.len());
        output[..end - start].copy_from_slice(&self.base.bytes[start..end]);
    }
}

/// An error raised by the block sub-node overlay.
#[derive(Debug, PartialEq, Eq)]
pub enum BlockOverlayError {
    /// The supplied bytes were too large to represent as a block device.
    BaseImageTooLarge {
        /// Platform byte length that could not fit in `u64`.
        length: usize,
    },
    /// A supplied content-addressed reference did not match the base bytes.
    ContentHashMismatch {
        /// Expected content hash from the supplied reference.
        expected: ContentHash,
        /// Actual content hash computed from the bytes.
        actual: ContentHash,
    },
    /// A requested byte range overflowed `u64`.
    RangeOverflow {
        /// Requested byte offset.
        offset: u64,
        /// Requested byte count.
        count: u64,
    },
    /// A requested byte count cannot be represented by the host allocator.
    RangeTooLarge {
        /// Requested byte count.
        count: u64,
    },
    /// A read or write extended past the fixed block-device length.
    RangeOutOfBounds {
        /// Requested byte offset.
        offset: u64,
        /// Requested byte count.
        count: u64,
        /// Fixed block-device length.
        length: u64,
    },
}

impl fmt::Display for BlockOverlayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseImageTooLarge { length } => {
                write!(formatter, "base image length {length} does not fit in u64")
            }
            Self::ContentHashMismatch { expected, actual } => write!(
                formatter,
                "base image content hash mismatch: expected {}, got {}",
                expected.to_hex(),
                actual.to_hex()
            ),
            Self::RangeOverflow { offset, count } => write!(
                formatter,
                "block range at offset {offset} with count {count} overflows u64"
            ),
            Self::RangeTooLarge { count } => {
                write!(
                    formatter,
                    "block byte count {count} exceeds platform limits"
                )
            }
            Self::RangeOutOfBounds {
                offset,
                count,
                length,
            } => write!(
                formatter,
                "block range at offset {offset} with count {count} exceeds device length {length}"
            ),
        }
    }
}

impl Error for BlockOverlayError {}

/// An error raised while planning deterministic block completions.
#[derive(Debug, PartialEq, Eq)]
pub enum BlockCompletionError {
    /// The scheduler node kind is not a disk sub-node.
    InvalidNodeKind {
        /// Invalid node kind.
        kind: SchedulingNodeKind,
    },
    /// The completion requester is not a VM scheduler node.
    InvalidRequesterKind {
        /// Invalid requester kind.
        kind: SchedulingNodeKind,
    },
    /// The deterministic latency computation overflowed.
    LatencyOverflow {
        /// Operation whose latency overflowed.
        operation: BlockSubNodeOperation,
        /// Operation byte count that overflowed with the configured parameters.
        count: u32,
    },
    /// Completion virtual-time computation overflowed.
    CompletionTimeOverflow {
        /// Request icount that overflowed after projection and latency.
        request_icount: Icount,
        /// Modeled latency that could not be added.
        modeled_latency: SimDuration,
    },
    /// Virtual-time conversion failed.
    TimeConversion(TimeConversionError),
}

impl fmt::Display for BlockCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNodeKind { kind } => {
                write!(
                    formatter,
                    "scheduler node kind {kind:?} is not a disk sub-node"
                )
            }
            Self::InvalidRequesterKind { kind } => {
                write!(
                    formatter,
                    "block completion requester kind {kind:?} is not a VM node"
                )
            }
            Self::LatencyOverflow { operation, count } => write!(
                formatter,
                "block {operation:?} latency overflowed for count {count}"
            ),
            Self::CompletionTimeOverflow {
                request_icount,
                modeled_latency,
            } => write!(
                formatter,
                "block completion time overflow for request icount {} latency {}ns",
                request_icount.retired, modeled_latency.nanos
            ),
            Self::TimeConversion(source) => {
                write!(
                    formatter,
                    "block completion time conversion failed: {source}"
                )
            }
        }
    }
}

impl Error for BlockCompletionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TimeConversion(source) => Some(source),
            Self::InvalidNodeKind { .. }
            | Self::InvalidRequesterKind { .. }
            | Self::LatencyOverflow { .. }
            | Self::CompletionTimeOverflow { .. } => None,
        }
    }
}

impl From<TimeConversionError> for BlockCompletionError {
    fn from(source: TimeConversionError) -> Self {
        Self::TimeConversion(source)
    }
}

type BlockOverlayPage = Box<[u8; BLOCK_OVERLAY_PAGE_SIZE]>;

fn page_base(offset: u64) -> u64 {
    offset / BLOCK_OVERLAY_PAGE_SIZE_U64 * BLOCK_OVERLAY_PAGE_SIZE_U64
}

fn validate_range(offset: u64, count: u64, length: u64) -> Result<(), BlockOverlayError> {
    let end = offset
        .checked_add(count)
        .ok_or(BlockOverlayError::RangeOverflow { offset, count })?;
    if end > length {
        return Err(BlockOverlayError::RangeOutOfBounds {
            offset,
            count,
            length,
        });
    }
    Ok(())
}

fn checked_count_usize(count: u64) -> Result<usize, BlockOverlayError> {
    usize::try_from(count).map_err(|_| BlockOverlayError::RangeTooLarge { count })
}

fn block_delivery_icount(
    shift: Shift,
    request_icount: Icount,
    modeled_latency: SimDuration,
) -> Result<Icount, BlockCompletionError> {
    let request_time = request_icount.to_virtual(shift)?;
    let completion_time = request_time
        .nanos
        .checked_add(modeled_latency.nanos)
        .ok_or(BlockCompletionError::CompletionTimeOverflow {
            request_icount,
            modeled_latency,
        })?;
    Ok(VirtualInstant {
        nanos: completion_time,
    }
    .to_icount_ceil(shift)?)
}

fn block_completion_order(
    left: &BlockCompletionPlan,
    right: &BlockCompletionPlan,
) -> std::cmp::Ordering {
    left.delivery_icount
        .cmp(&right.delivery_icount)
        .then_with(|| left.sub_node.cmp(&right.sub_node))
        .then_with(|| left.sequence.cmp(&right.sequence))
}

fn block_overlay_delta_bytes(delta: &BlockOverlayDelta) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"crucible.block-overlay-delta.v1\n");
    bytes.extend_from_slice(delta.base.hash().to_hex().as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&(delta.pages.len() as u64).to_le_bytes());
    for page in &delta.pages {
        bytes.extend_from_slice(&page.page_base.to_le_bytes());
        bytes.extend_from_slice(&(page.bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&page.bytes);
    }
    bytes
}
