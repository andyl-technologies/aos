//! The block device sub-node: base + CoW overlay, wire ABI, completion model.
//!
//! This module assembles the block I/O sub-node of RFC-0010 §15.2 from three
//! focused submodules and re-exports their public surface:
//!
//! - [`codec`]: the versioned, little-endian, bounds-checked block wire ABI
//!   ([`BlockRequest`] / [`BlockResponse`], [IO-8], [IO-9]).
//! - [`overlay`]: the read-only [`BaseImage`] and its in-memory 4 KiB
//!   copy-on-write [`CowOverlay`] with dirty-page tracking and materialize
//!   ([IO-5], [IO-6], [IO-7], [IO-12]).
//! - [`device`]: the [`BlockDevice`] [`IoSubNode`](crate::subnode::IoSubNode)
//!   implementation, its [`BlockLatency`] completion model, and its
//!   [`BlockSnapshot`] device-half `MaterializedState` ([IO-10], [IO-11],
//!   [IO-22], [IO-23]).
//!
//! The block device composes the uniform [`IoCore`](crate::subnode::IoCore) of
//! the CS-IO-1 foundation for the clock, rings, in-flight queue, and
//! COMPUTE-then-DELIVER lifecycle; this module supplies only the block-specific
//! COMPUTE (serve a request against the overlay/base) and state (overlay, RNG
//! placeholder, base image).

pub mod codec;
pub mod device;
pub mod fault;
pub mod flash;
pub mod media;
pub mod overlay;
pub mod persistence;
pub mod service;

pub use codec::{
    BLOCK_ABI_VERSION, BlockCodecError, BlockErrorCode, BlockOp, BlockRequest,
    BlockRequestIdentity, BlockResponse, BlockStatus, BlockTransportPending,
    BlockTransportRequestIds, BlockTransportReset, BlockTransportResolved,
    BlockTransportUnadmitted, BlockTransportUndelivered, REQUEST_HEADER_LEN, RESPONSE_HEADER_LEN,
};
pub use device::{
    BlockDevice, BlockLatency, BlockSnapshot, BlockSnapshotCodecError, MAX_BLOCK_SNAPSHOT_BYTES,
    install_cross_device_misdirected_persistence,
};
pub use fault::*;
pub use flash::*;
pub use media::*;
pub use overlay::{BaseImage, CowOverlay, OverlayDelta, PAGE_SIZE};
pub use persistence::{
    BlockPersistenceGraph, BlockPersistenceNode, BlockPersistenceOrdering,
    BlockPersistenceReadyKey, BlockPersistenceTransformationEvidence, BlockWriteFragmentId,
    ResolvedBlockPersistenceTransform,
};
pub use service::*;

#[cfg(test)]
#[path = "block_lifecycle_test.rs"]
mod lifecycle_tests;
#[cfg(test)]
#[path = "block_overlay_codec_test.rs"]
mod overlay_codec_tests;
#[cfg(test)]
#[path = "block_service_test.rs"]
mod service_tests;
#[cfg(test)]
#[path = "block_snapshot_array_test.rs"]
mod snapshot_array_tests;
#[cfg(test)]
#[path = "block_test_support.rs"]
mod test_support;
