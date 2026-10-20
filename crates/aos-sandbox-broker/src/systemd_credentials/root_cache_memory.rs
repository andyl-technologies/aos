//! Retains the fixed Root public deployed Cache physical memory ceiling through native posts.
//!
//! The actual R owner prepays this fixed recipe before construction. Borrowed
//! bytes remain configuration DATA; native capture cannot grant a new budget,
//! broker method, Source/Cache owner or independent currentness capability.

use aos_sandbox_core::ResourceVector;
use super::{ControllerNixPublicCredentialErrorV1, root_fixed_public::RootFixedPublicCredentialCustodyV1};

const NAMES: [&str; 1] = ["cache-signer-v2-memory-ceiling"];
const MAXIMUM_BYTES: [u64; 1] = [16];

/// Retains the same fixed public deployed Cache physical memory ceiling and actual native readbacks.
pub struct RootCurrentCacheMemoryCustodyV1 { native: RootFixedPublicCredentialCustodyV1<1> }

impl RootCurrentCacheMemoryCustodyV1 {
    /// Creates empty fixed native destinations without IO or authority.
    pub fn new() -> Self { Self { native: RootFixedPublicCredentialCustodyV1::new() } }

    /// Measures this exact fixed public recipe and every retained native prefix.
    pub fn dominant_demand() -> Option<ResourceVector> {
        RootFixedPublicCredentialCustodyV1::<1>::dominant_demand(&MAXIMUM_BYTES)
    }

    /// Captures this fixed artifact and its original native readback once.
    ///
    /// # Errors
    /// Refuses reentry, non-Root UID, unsafe names, wrong widths or native error.
    pub fn capture_once(&mut self) -> Result<(), ()> { self.native.capture_once(&NAMES, &MAXIMUM_BYTES) }

    /// Runs the independently owed same-name post after every entered outcome.
    ///
    /// # Errors
    /// Refuses absent entry, reentry, changed names/bytes or native failure.
    pub fn recheck_once(&mut self) -> Result<(), ()> { self.native.recheck_once(&NAMES, &MAXIMUM_BYTES) }

    /// Borrows only the actual captured artifact bytes without admitting them.
    pub fn bytes(&self) -> Option<&[u8]> { self.native.bytes(0) }

    /// Borrows the actual original capture or initial-post failure.
    pub fn capture_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> { self.native.capture_failure() }

    /// Borrows the actual independent final-post or reentry failure.
    pub fn post_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> { self.native.post_failure() }

    /// Borrows the same earliest retained original failure.
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> { self.native.failure() }
}
