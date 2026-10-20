//! Names the existing fixed Controller Source proposal packet widths.
//!
//! These widths describe canonical wire DATA. They neither authenticate the
//! administrative issuer nor authorize a Source tree, epoch or native append.

/// Bounds the signed body of the initial Controller Source-tree proposal.
pub const CONTROLLER_SOURCE_TREE_SEED_BODY_BYTES_V1: usize = 160;

/// Bounds the exact proposal body followed by its existing Ed25519 signature.
pub const CONTROLLER_SOURCE_TREE_SEED_BYTES_V1: usize =
    CONTROLLER_SOURCE_TREE_SEED_BODY_BYTES_V1 + 64;
