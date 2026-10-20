//! Retains Root's independent Host, Mount and Network public session manifests.
//!
//! The same fixed public-credential reader captures these three configured
//! files and their independent native readbacks. The actual Root receiving
//! original must pay the complete demand before construction and capture.
//! Captured bytes are DATA: the Delete verifier still checks their canonical
//! formats, roles and trust context against its other genuine originals.

use aos_sandbox_core::ResourceVector;

use super::{
    ControllerNixPublicCredentialErrorV1, root_fixed_public::RootFixedPublicCredentialCustodyV1,
};

const NAMES: [&str; 3] = [
    "delete-host-session-manifest-v2",
    "delete-mount-session-manifest-v2",
    "delete-network-session-manifest-v2",
];
const MAXIMUM_BYTES: [u64; 3] = [920; 3];

/// Retains Root's three fixed public broker manifests and their native prefixes.
pub struct RootDeleteBrokerManifestsCustodyV2 {
    native: RootFixedPublicCredentialCustodyV1<3>,
}

impl RootDeleteBrokerManifestsCustodyV2 {
    /// Creates empty native destinations without reading or granting authority.
    #[must_use]
    pub fn new() -> Self {
        Self {
            native: RootFixedPublicCredentialCustodyV1::new(),
        }
    }

    /// Measures the complete fixed public-file buffers and native readbacks.
    #[must_use]
    pub fn dominant_demand() -> Option<ResourceVector> {
        RootFixedPublicCredentialCustodyV1::<3>::dominant_demand(&MAXIMUM_BYTES)
    }

    /// Captures the fixed manifests and their first native readback once.
    ///
    /// # Errors
    /// Retains refusal for reentry, a non-Root identity, unsafe or absent paths,
    /// a changed native file, an incorrect manifest width, or a native error.
    /// The original cause remains available through [`Self::capture_failure`].
    pub fn capture_once(&mut self) -> Result<(), ()> {
        self.native.capture_once(&NAMES, &MAXIMUM_BYTES)
    }

    /// Runs the independent final native readback after an entered capture.
    ///
    /// # Errors
    /// Retains refusal for missing entry, repeated observation, changed names
    /// or bytes, and native failures, including after an earlier capture error.
    pub fn recheck_once(&mut self) -> Result<(), ()> {
        self.native.recheck_once(&NAMES, &MAXIMUM_BYTES)
    }

    /// Borrows Root's captured public Host manifest without admitting it.
    #[must_use]
    pub fn host_bytes(&self) -> Option<&[u8]> {
        self.native.bytes(0)
    }

    /// Borrows Root's captured public Mount manifest without admitting it.
    #[must_use]
    pub fn mount_bytes(&self) -> Option<&[u8]> {
        self.native.bytes(1)
    }

    /// Borrows Root's captured public Network manifest without admitting it.
    #[must_use]
    pub fn network_bytes(&self) -> Option<&[u8]> {
        self.native.bytes(2)
    }

    /// Borrows the original capture or initial native readback failure.
    #[must_use]
    pub fn capture_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.native.capture_failure()
    }

    /// Borrows the independent final readback or reentry failure.
    #[must_use]
    pub fn post_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.native.post_failure()
    }

    /// Borrows the earliest retained native or state failure.
    #[must_use]
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.native.failure()
    }
}

impl Default for RootDeleteBrokerManifestsCustodyV2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Retains only the existing protected Host verification manifest.
///
/// Execution cleanup shares the same fixed credential and native reader as
/// Delete. It does not require unrelated broker manifests or an active
/// ownership lease to verify an already irreversible Host terminal marker.
pub struct RootCurrentHostManifestCustodyV2 {
    native: RootFixedPublicCredentialCustodyV1<1>,
}

impl RootCurrentHostManifestCustodyV2 {
    /// Creates empty native destinations without reading a file.
    #[must_use]
    pub fn new() -> Self {
        Self { native: RootFixedPublicCredentialCustodyV1::new() }
    }

    /// Measures the existing Host file buffers and both native readbacks.
    #[must_use]
    pub fn dominant_demand() -> Option<ResourceVector> {
        RootFixedPublicCredentialCustodyV1::<1>::dominant_demand(&[MAXIMUM_BYTES[0]])
    }

    /// Captures the existing Root-protected Host manifest once.
    ///
    /// # Errors
    /// Retains non-Root, unsafe-path, missing-file, width, currentness and
    /// native errors, and refuses repeated capture.
    pub fn capture_once(&mut self) -> Result<(), ()> {
        self.native.capture_once(&[NAMES[0]], &[MAXIMUM_BYTES[0]])
    }

    /// Runs the independently owed final native file readback once.
    ///
    /// # Errors
    /// Retains changed names or bytes, absent entry, reentry and native errors.
    pub fn recheck_once(&mut self) -> Result<(), ()> {
        self.native.recheck_once(&[NAMES[0]], &[MAXIMUM_BYTES[0]])
    }

    /// Borrows the original captured manifest bytes as comparison DATA.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> { self.native.bytes(0) }

    /// Borrows the actual first capture or initial readback failure.
    #[must_use]
    pub fn capture_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.native.capture_failure()
    }

    /// Borrows the independent final readback or reentry failure.
    #[must_use]
    pub fn post_failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.native.post_failure()
    }

    /// Borrows the earliest reached native failure without new observation.
    #[must_use]
    pub fn failure(&self) -> Option<&ControllerNixPublicCredentialErrorV1> {
        self.native.failure()
    }
}

impl Default for RootCurrentHostManifestCustodyV2 {
    fn default() -> Self { Self::new() }
}
