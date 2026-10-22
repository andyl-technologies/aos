//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Defines typed canonical logical RAM commitments and their exact domain-separated preimages.
//!
//! ```text
//! PageDigest = BLAKE3("crucible.ram.page.v1\0" || U32(valid_length) || bytes)
//! InnerDigest = BLAKE3("crucible.ram.node.v1\0" || U32(height) || left || right)
//! ```

use crate::{Geometry, LOGICAL_PAGE_SIZE, RamError};
use std::fmt;

macro_rules! digest_type {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wraps exactly 32 raw digest bytes without claiming authenticity.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the raw digest bytes used inside canonical preimages.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

digest_type!(
    PageDigest,
    "Commits to a logical page's valid length and content."
);
digest_type!(
    NodeDigest,
    "Commits to a leaf, padding sentinel, or height-bound inner node."
);
digest_type!(
    RegionTreeDigest,
    "Commits to a region's exact geometry and ordered page tree."
);
digest_type!(
    TopologyDigest,
    "Commits to the complete canonical region inventory."
);
digest_type!(
    RamRootDigest,
    "Commits to a named scope, topology, and selected ordered region roots."
);

impl PageDigest {
    /// Hashes one logical page using the default unkeyed 32-byte BLAKE3 mode.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::InvalidLength`] unless the valid byte length is
    /// between one and 4096, inclusive.
    pub fn hash(bytes: &[u8]) -> Result<Self, RamError> {
        if bytes.is_empty() || bytes.len() > LOGICAL_PAGE_SIZE as usize {
            return Err(RamError::InvalidLength);
        }
        // Initialize the caller's hasher in place instead of returning its
        // large state through the tag factory's result slot.
        let mut hasher = blake3::Hasher::new();
        initialize_tag(&mut hasher, "page");
        hasher.update(&(bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
        Ok(Self(*hasher.finalize().as_bytes()))
    }
}

pub(crate) fn tagged(name: &str) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    initialize_tag(&mut hasher, name);
    hasher
}

fn initialize_tag(hasher: &mut blake3::Hasher, name: &str) {
    hasher.update(b"crucible.ram.");
    hasher.update(name.as_bytes());
    hasher.update(b".v1\0");
}

/// Wraps a page content commitment in the canonical leaf domain.
pub fn leaf_digest(page: PageDigest) -> NodeDigest {
    let mut preimage = [0; 53];
    preimage[..21].copy_from_slice(b"crucible.ram.leaf.v1\0");
    preimage[21..].copy_from_slice(page.as_bytes());
    NodeDigest(*blake3::hash(&preimage).as_bytes())
}

/// Returns the padding sentinel, which is distinct from every real zero page.
pub fn empty_leaf_digest() -> NodeDigest {
    NodeDigest(*blake3::hash(b"crucible.ram.empty.v1\0").as_bytes())
}

/// Hashes two ordered children at the declared parent height.
///
/// # Errors
///
/// Returns [`RamError::OutOfRange`] for heights outside one through 52.
pub fn inner_digest(
    height: u32,
    left: NodeDigest,
    right: NodeDigest,
) -> Result<NodeDigest, RamError> {
    if !(1..=52).contains(&height) {
        return Err(RamError::OutOfRange);
    }
    // The fixed preimage avoids retaining a streaming hasher while reducing
    // an authenticated proof path.
    let mut preimage = [0; 89];
    preimage[..21].copy_from_slice(b"crucible.ram.node.v1\0");
    preimage[21..25].copy_from_slice(&height.to_be_bytes());
    preimage[25..57].copy_from_slice(left.as_bytes());
    preimage[57..].copy_from_slice(right.as_bytes());
    Ok(NodeDigest(*blake3::hash(&preimage).as_bytes()))
}

/// Binds a reduced tree node to the region's checked length, count, and height.
pub fn region_tree_digest(geometry: Geometry, root: NodeDigest) -> RegionTreeDigest {
    let mut hasher = blake3::Hasher::new();
    initialize_tag(&mut hasher, "region-tree");
    hasher.update(&geometry.logical_length().to_be_bytes());
    hasher.update(&geometry.page_count().to_be_bytes());
    hasher.update(&geometry.height().to_be_bytes());
    hasher.update(root.as_bytes());
    RegionTreeDigest(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests;
