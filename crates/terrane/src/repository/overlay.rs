//! Owns repository verbs for authenticated overlay layers and materialization.

use terrane_core::identity::Digest;

/// Identifies a signed input layer published for authenticated materialization.
///
/// An unreferenced input remains subject to the existing collection and grace
/// rules. Publishing an ordinary output with this input in its signed ancestry
/// establishes reachability; Original authentication alone supplies no GC root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedOverlayLayer {
    /// Exact newly signed input commit.
    pub commit: Digest,
    /// Canonical root of the authenticated input layer.
    pub root: Digest,
}
