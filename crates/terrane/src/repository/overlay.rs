//! Owns repository verbs for authenticated overlay layers and materialization.

use terrane_core::identity::Digest;

/// Identifies a signed input layer retained for later authenticated materialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedOverlayLayer {
    /// Exact newly signed input commit.
    pub commit: Digest,
    /// Canonical root of the authenticated input layer.
    pub root: Digest,
}
