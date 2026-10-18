//! Authenticated operational object profiles for immutable store graphs.
//!
//! A profile capability receives only an expected content identity and a
//! complete authenticated logical byte stream. It derives sensitivity,
//! reconstructibility, and retention classes from those bytes; callers cannot
//! attach or override a profile hint.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::Arc;

use super::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend, ObjectKind,
    PutReceipt, StoreError,
};

const MAX_PROFILE_POLICY_ID_BYTES: usize = 512;
const MAX_PROFILE_POLICY_SEGMENT_BYTES: usize = 255;

/// Closed operational sensitivity class derived from authenticated bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SensitivityClass {
    /// Campaign topology, policy, coordination, and other control metadata.
    Metadata,
    /// Measurements, observations, findings, logs, and reproduction evidence.
    Evidence,
    /// Exact guest RAM, disk, device, or configuration state.
    GuestState,
}

/// Closed reconstruction property derived from authenticated bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reconstructibility {
    /// The object is canonical retained input or evidence and cannot be dropped.
    Canonical,
    /// The object is a deterministic projection that may be rebuilt from roots.
    Rebuildable,
}

/// Closed operational retention role derived from authenticated bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetentionRole {
    /// Canonical campaign metadata retained through an owning closure.
    CampaignMetadata,
    /// Canonical execution or finding evidence retained through an owning closure.
    Evidence,
    /// Exact guest-state material retained through an owning manifest or artifact.
    ExactState,
    /// Replaceable acceleration data whose canonical inputs remain retained.
    ProjectionCache,
}

/// Authenticated operational classification of one logical content object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectProfile {
    kind: ObjectKind,
    logical_length: u64,
    sensitivity: SensitivityClass,
    reconstructibility: Reconstructibility,
    retention_role: RetentionRole,
}

impl ObjectProfile {
    /// Constructs a profile from values derived by a trusted profile capability.
    #[must_use]
    pub const fn new(
        kind: ObjectKind,
        logical_length: u64,
        sensitivity: SensitivityClass,
        reconstructibility: Reconstructibility,
        retention_role: RetentionRole,
    ) -> Self {
        Self {
            kind,
            logical_length,
            sensitivity,
            reconstructibility,
            retention_role,
        }
    }

    /// Returns the authenticated logical object kind.
    #[must_use]
    pub const fn kind(self) -> ObjectKind {
        self.kind
    }

    /// Returns the authenticated logical byte length.
    #[must_use]
    pub const fn logical_length(self) -> u64 {
        self.logical_length
    }

    /// Returns the derived sensitivity class.
    #[must_use]
    pub const fn sensitivity(self) -> SensitivityClass {
        self.sensitivity
    }

    /// Returns the derived reconstruction property.
    #[must_use]
    pub const fn reconstructibility(self) -> Reconstructibility {
        self.reconstructibility
    }

    /// Returns the derived retention role.
    #[must_use]
    pub const fn retention_role(self) -> RetentionRole {
        self.retention_role
    }
}

/// Validated non-secret identity of one operational object-profile policy.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreObjectProfilePolicyId(String);

impl StoreObjectProfilePolicyId {
    /// Validates one bounded slash-separated profile-policy identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the value is empty,
    /// exceeds 512 bytes, contains an empty, `.` or `..` segment, has a segment
    /// longer than 255 bytes, or uses characters outside ASCII letters,
    /// digits, `.`, `_`, and `-`.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_PROFILE_POLICY_ID_BYTES
            && value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.len() <= MAX_PROFILE_POLICY_SEGMENT_BYTES
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            });
        if !valid {
            return Err(StoreError::InvalidComposition {
                reason: "store object-profile policy identifier is invalid",
            });
        }
        Ok(Self(value))
    }

    /// Returns the validated policy identifier spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Operational capability that derives and validates one authenticated profile.
pub trait StoreObjectProfiler: Send + Sync {
    /// Derives the exact profile for a complete authenticated logical object.
    ///
    /// `source` has already been authenticated as `id` and is reopenable. The
    /// implementation must derive every semantic class from the canonical
    /// bytes or the content-ID kind, never from a caller-supplied claim.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Incompatible`] or [`StoreError::Corrupt`] when the
    /// object cannot be assigned its canonical profile, or another backend
    /// error when bounded derivation cannot complete safely.
    fn derive_profile(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<ObjectProfile, StoreError>;
}

/// External object-profile capabilities used while constructing a store graph.
#[derive(Default)]
pub struct StoreGraphObjectProfilers {
    profilers: BTreeMap<StoreObjectProfilePolicyId, Arc<dyn StoreObjectProfiler>>,
}

impl StoreGraphObjectProfilers {
    /// Creates an empty profile-capability collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            profilers: BTreeMap::new(),
        }
    }

    /// Inserts the capability for one exact operational profile policy.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the policy already has
    /// a capability in this collection.
    pub fn insert(
        &mut self,
        policy: StoreObjectProfilePolicyId,
        profiler: Arc<dyn StoreObjectProfiler>,
    ) -> Result<(), StoreError> {
        match self.profilers.entry(policy) {
            Entry::Vacant(entry) => {
                entry.insert(profiler);
                Ok(())
            }
            Entry::Occupied(_) => Err(StoreError::InvalidComposition {
                reason: "store object-profile capability collection contains a duplicate identifier",
            }),
        }
    }

    pub(super) fn resolve(
        &self,
        policy: &StoreObjectProfilePolicyId,
    ) -> Result<Arc<dyn StoreObjectProfiler>, StoreError> {
        self.profilers
            .get(policy)
            .cloned()
            .ok_or(StoreError::Unauthorized)
    }
}

/// Profile-validation facade bound to one exact operational policy.
pub(super) struct ProfileValidatedStore {
    name: String,
    child: Arc<dyn ImmutableBlobBackend>,
    profiler: Arc<dyn StoreObjectProfiler>,
}

impl ProfileValidatedStore {
    pub(super) fn new(
        name: impl Into<String>,
        child: Arc<dyn ImmutableBlobBackend>,
        profiler: Arc<dyn StoreObjectProfiler>,
    ) -> Self {
        Self {
            name: name.into(),
            child,
            profiler,
        }
    }

    fn authenticate_and_profile(
        &self,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<BlobHandle, StoreError> {
        let verified = source.verified_as(id)?;
        let profile = self.profiler.derive_profile(id, &verified)?;
        if profile.kind() != id.kind() || profile.logical_length() != verified.logical_length() {
            return Err(StoreError::Incompatible);
        }
        Ok(verified)
    }
}

impl ImmutableBlobBackend for ProfileValidatedStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        let mut capabilities = self.child.capabilities();
        // Profile derivation consumes the complete canonical source before a
        // range is returned, so range reads remain correct but are not cheap.
        capabilities.streaming_read = false;
        capabilities
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        match self.child.read(id, None) {
            Ok(source) => {
                self.authenticate_and_profile(id, &source)?;
                Ok(true)
            }
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        let source = self.child.read(id, None)?;
        self.authenticate_and_profile(id, &source)?.slice(range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let verified = self.authenticate_and_profile(id, source)?;
        self.child.put_if_absent(id, &verified)
    }
}
