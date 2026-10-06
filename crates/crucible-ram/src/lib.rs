//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Implements portable logical RAM identities and independent observation epochs.
//!
//! The crate implements the canonical format's fixed 4096-byte logical pages, unkeyed
//! BLAKE3-256 domains, ordered region trees, and scoped topology commitments.
//! It contains no QEMU dependencies, callbacks, native addresses, or storage
//! authority. Both sides of the public process boundary may use its codecs.
//!
//! [`Topology`] validates byte ownership and scope membership. [`RegionTree`]
//! shares immutable subtrees and [`RamSnapshot`] freezes their logical identity.
//! [`RootRecord`] and [`PageProof`] carry checked portable evidence, while
//! [`DirtyTracker`] retains separate fingerprint, checkpoint, paging, and transfer
//! obligations. [`oracle`] independently reads all logical bytes and rebuilds
//! the canonical commitment without using the persistent tree or dirty tracker.
//!
//! Identity snapshots do not retain storage leases or establish a coherent
//! QEMU boundary. Callers must exclude writers while capturing bytes, retain
//! authoritative content, and publish complete continuation before execution.
//!
//! # Examples
//!
//! The following declares a region known to have been initialized to zero and
//! obtains a verified page proof. It does not map guest RAM or authorize resume.
//!
//! ```no_run
//! use crucible_ram::{
//!     Limits, MetadataBudget, RamSnapshot, RegionClass, RegionDescriptor,
//!     RegionTree, Scope, Topology,
//! };
//!
//! let budget = MetadataBudget::new(1024 * 1024);
//! let topology = Topology::new(
//!     vec![RegionDescriptor::new("machine.ram", RegionClass::MutableMain, 8192)?],
//!     Limits::default(),
//! )?;
//! let tree = RegionTree::zeroed(8192, &budget)?;
//! let proof = tree.proof("machine.ram", 0)?;
//! let snapshot = RamSnapshot::new(topology, vec![tree], &budget)?;
//! let record = snapshot.root_record(Scope::Exact)?;
//! proof.verify(&[0; 4096], &record, record.digest())?;
//! # Ok::<(), crucible_ram::RamError>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod budget;
mod codec;
mod digest;
mod dirty;
mod error;
pub mod oracle;
mod snapshot;
mod topology;
mod tree;

pub use budget::{MetadataBudget, MetadataReservation};
pub use codec::{PageProof, RootRecord};
pub use digest::{
    NodeDigest, PageDigest, RamRootDigest, RegionTreeDigest, TopologyDigest, empty_leaf_digest,
    inner_digest, leaf_digest, region_tree_digest,
};
pub use dirty::{
    Consumer, DirtyCapture, DirtyTracker, PageCoordinate, PageVersion, TrackingIncarnation,
    TrackingLimits,
};
pub use error::RamError;
pub use snapshot::RamSnapshot;
pub use topology::{Geometry, Limits, RegionClass, RegionDescriptor, Scope, Topology};
pub use tree::RegionTree;

/// The logical page size, independent of host and target page geometry.
pub const LOGICAL_PAGE_SIZE: u32 = 4096;

/// The current canonical logical digest edition.
pub const LOGICAL_ENCODING_EDITION: u32 = 1;

/// The closed hash algorithm name for this logical digest edition.
pub const HASH_ALGORITHM: &str = "blake3-256-unkeyed";
