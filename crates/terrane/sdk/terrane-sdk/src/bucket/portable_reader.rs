//! Validates existing layout-two portable data without activating an Original.
//!
//! The native opener uses bounded, nofollow ordinary-data captures and the same
//! complete portable-copy validators as administrative copy admission. It returns
//! only immutable selected metadata. Complete pack bytes are transient validation
//! inputs, not a long-lived in-memory content store.
//!
//! A successful validation is not a host-layout, quota, freshness, publication,
//! lease or physical-deletion receipt. The native host adapter must independently
//! establish final custody at this same root. No `ContentStore` or `RefStore` is
//! implemented here; bounded live content serving remains a separate adapter.
//!
//! ```text
//! publication/PORTABLE -> publication/snapshots/<digest>
//!                     -> exact predecessor checkpoints
//!                     -> selected catalog, payload and retained-history closure
//! ```

#[cfg(all(feature = "tokio", unix))]
mod native;

#[cfg(all(feature = "tokio", unix))]
pub use native::validate_existing;

use crate::store::{Capabilities, CapabilityReport};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use terrane_format::{
    bucket::{BucketKey, GenerationManifest, StoreProfile},
    gc::publication::{PortableCurrent, SelectedHistory},
};

/// Bounds the work and retained inputs of one portable validation.
///
/// These are operator resource limits, not format maxima. Complete packs must
/// fit the per-file bound; larger valid buckets return capacity. The input bound
/// counts unique file bytes, while native closing recipes, validator decoding and
/// temporary copies require additional bounded memory. It is not an RSS limit.
#[derive(Clone, Copy, Debug)]
pub struct PortableReadLimits {
    /// Maximum bytes read from any one existing file.
    pub max_file_bytes: usize,
    /// Maximum sum of bytes in distinct input files.
    pub max_input_bytes: usize,
    /// Maximum number of distinct input files and retained native recipes.
    pub max_files: usize,
    /// Maximum selected key and value bytes retained by the returned snapshot.
    pub max_selected_bytes: usize,
}

impl Default for PortableReadLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 64 * 1024 * 1024,
            max_input_bytes: 256 * 1024 * 1024,
            max_files: 4096,
            max_selected_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Holds immutable metadata from a fully validated portable checkpoint.
///
/// Only the checked opener constructs this value. The root is a configured
/// pathname observation, not a retained native host binding. The snapshot is
/// point-in-time data: it does not authorize later reads from changed paths,
/// grant complete empty-inventory freshness, or import the origin's physical
/// ownership. In particular, selected ref records are data rather than local
/// ref authority. Revalidation is required for a later observation.
pub struct ValidatedPortableBucket {
    root: PathBuf,
    profile: StoreProfile,
    checkpoint: PortableCurrent,
    selected: BTreeMap<String, Option<Vec<u8>>>,
    history: SelectedHistory,
    manifest: GenerationManifest,
    capabilities: Capabilities,
}

impl ValidatedPortableBucket {
    /// Borrows the configured root whose existing data was validated.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Borrows the checked selected identity and chunk profile.
    pub fn profile(&self) -> &StoreProfile {
        &self.profile
    }

    /// Borrows the exact portable pointer checked against its snapshot bytes.
    pub fn checkpoint(&self) -> &PortableCurrent {
        &self.checkpoint
    }

    /// Borrows one selected logical value, preserving explicit absence.
    ///
    /// The outer `None` means the key was not in this projection. `Some(None)`
    /// is an explicitly absent selected value. Mutable physical cache bytes are
    /// never substituted for the selected value.
    pub fn selected_value(&self, key: &BucketKey) -> Option<Option<&[u8]>> {
        self.selected
            .get(key.as_str())
            .map(|value| value.as_deref())
    }

    /// Borrows complete checked retained branch-history data.
    ///
    /// Origin and selection fields do not establish destination authority.
    pub fn selected_history(&self) -> &SelectedHistory {
        &self.history
    }

    /// Borrows the checked selected inventory, exclusions and burn visibility.
    ///
    /// Physical age, lease and deletion ownership are not imported.
    pub fn generation_manifest(&self) -> &GenerationManifest {
        &self.manifest
    }
}

impl CapabilityReport for ValidatedPortableBucket {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg(all(feature = "tokio", unix))]
fn metadata_capabilities(locality: terrane_format::refs::Locality) -> Capabilities {
    use crate::store::{Durability, RangeCapability, RefCapability};

    Capabilities {
        refs: RefCapability::None,
        ranges: RangeCapability::WholeObjectOnly,
        presign: false,
        locality,
        durability: Durability::Local,
        sealed: false,
    }
}

#[cfg(all(test, feature = "tokio", unix))]
mod tests;
