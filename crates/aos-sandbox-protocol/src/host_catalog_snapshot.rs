//! Canonical sealed-memfd payload for Host launch-catalog publication.
//!
//! The unprivileged controller and root Host broker share this exact node-local
//! schema without sharing implementation code or live descriptors. The compact
//! JSON representation is intentionally strict:
//!
//! ```text
//! {
//!   "generation": 1,
//!   "workspaces": [...],
//!   "networks": [...],
//!   "attachment_anchors": [...],
//!   "retired_identity_allocations": [...]
//! }
//! ```
//!
//! Constructors validate individual records. [`HostCatalogSnapshot::encode`]
//! and [`HostCatalogSnapshot::decode_canonical`] validate the complete bounded,
//! strictly ordered snapshot and are the only supported wire encoders.

use aos_sandbox_core::ObjectDescriptor;
use serde::{Deserialize, Serialize};

use crate::host_catalog::MAXIMUM_HOST_CATALOG_BYTES;
use crate::{ValidatedAssignmentFence, ValidatedRuntimePlan};

/// Maximum number of entries in each complete catalog collection.
pub const MAXIMUM_HOST_CATALOG_ENTRIES: usize = 16_384;
/// Maximum number of attachment handles associated with one workspace.
pub const MAXIMUM_HOST_CATALOG_ATTACHMENTS: usize = 256;
/// Minimum subordinate identity range admitted by the Host backend.
pub const MINIMUM_HOST_IDENTITY_RANGE: u32 = 65_536;
/// Fixed root for root-owned published workspace pins.
pub const WORKSPACE_PIN_PREFIX: &str = "/run/aos/sandbox-pins/workspaces/";
/// Fixed root for root-owned published network-namespace pins.
pub const NETWORK_PIN_PREFIX: &str = "/run/aos/sandbox-pins/netns/";
/// Fixed Mount-owned root for namespace-generation attachment anchors.
pub const ATTACHMENT_ANCHOR_PIN_PREFIX: &str = "/run/aos/sandbox-mount-catalog/slots/";

/// Names an opaque broker resource in one Host launch catalog.
pub type HostCatalogHandle = [u8; 32];

/// Reports malformed, noncanonical, or oversized Host catalog data.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{message}")]
pub struct HostCatalogSnapshotError {
    message: String,
}

impl HostCatalogSnapshotError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Records one incarnation-bound, nonoverlapping subordinate identity range.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogIdentityAllocation {
    range_start: u32,
    range_size: u32,
    catalog_generation: u64,
}

impl CatalogIdentityAllocation {
    /// Constructs a catalog-backed private user-namespace allocation.
    ///
    /// # Errors
    ///
    /// Returns an error for host identity zero, fewer than 65,536 identities,
    /// range overflow, or missing allocation-generation evidence.
    pub fn new(
        range_start: u32,
        range_size: u32,
        catalog_generation: u64,
    ) -> Result<Self, HostCatalogSnapshotError> {
        let value = Self {
            range_start,
            range_size,
            catalog_generation,
        };
        value.validate()?;

        Ok(value)
    }

    /// Returns the first host identity mapped to guest identity zero.
    #[must_use]
    pub const fn range_start(self) -> u32 {
        self.range_start
    }

    /// Returns the number of mapped identities.
    #[must_use]
    pub const fn range_size(self) -> u32 {
        self.range_size
    }

    /// Returns the catalog generation that owns this allocation.
    #[must_use]
    pub const fn catalog_generation(self) -> u64 {
        self.catalog_generation
    }

    /// Reports whether this allocation matches an exact runtime plan.
    #[must_use]
    pub fn matches_runtime_plan(self, plan: &ValidatedRuntimePlan) -> bool {
        self.range_start == plan.uid_range_start() && self.range_size == plan.uid_range_size()
    }

    fn validate(self) -> Result<(), HostCatalogSnapshotError> {
        if self.range_start == 0
            || self.range_size < MINIMUM_HOST_IDENTITY_RANGE
            || self.range_start.checked_add(self.range_size).is_none()
            || self.catalog_generation == 0
        {
            return Err(HostCatalogSnapshotError::new(
                "catalog identity allocation is invalid",
            ));
        }

        Ok(())
    }

    fn end(self) -> u32 {
        self.range_start + self.range_size
    }
}

/// Binds one catalog entry to exact assignment semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogAssignment {
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
}

impl CatalogAssignment {
    /// Constructs an exact nonportable catalog assignment tuple.
    ///
    /// # Errors
    ///
    /// Returns an error when an identifier or digest is zero or a generation
    /// is zero.
    pub fn new(
        sandbox_id: [u8; 16],
        incarnation_id: [u8; 16],
        assignment_epoch: u64,
        desired_generation: u64,
        assignment_digest: [u8; 32],
    ) -> Result<Self, HostCatalogSnapshotError> {
        let value = Self {
            sandbox_id,
            incarnation_id,
            assignment_epoch,
            desired_generation,
            assignment_digest,
        };
        value.validate()?;

        Ok(value)
    }

    /// Returns the logical sandbox identity.
    #[must_use]
    pub const fn sandbox_id(&self) -> &[u8; 16] {
        &self.sandbox_id
    }

    /// Returns the assigned incarnation identity.
    #[must_use]
    pub const fn incarnation_id(&self) -> &[u8; 16] {
        &self.incarnation_id
    }

    /// Returns the monotonic assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(self) -> u64 {
        self.assignment_epoch
    }

    /// Returns the desired generation within the assignment epoch.
    #[must_use]
    pub const fn desired_generation(self) -> u64 {
        self.desired_generation
    }

    /// Returns the canonical assignment-manifest digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> &[u8; 32] {
        &self.assignment_digest
    }

    /// Reports whether this catalog assignment matches an exact request fence.
    #[must_use]
    pub fn matches_fence(self, fence: &ValidatedAssignmentFence) -> bool {
        self.sandbox_id == *fence.sandbox_id()
            && self.incarnation_id == *fence.incarnation_id()
            && self.assignment_epoch == fence.assignment_epoch()
            && self.desired_generation == fence.desired_generation()
            && self.assignment_digest == *fence.assignment_digest()
    }

    fn validate(self) -> Result<(), HostCatalogSnapshotError> {
        if self.sandbox_id == [0; 16]
            || self.incarnation_id == [0; 16]
            || self.assignment_epoch == 0
            || self.desired_generation == 0
            || self.assignment_digest == [0; 32]
        {
            return Err(HostCatalogSnapshotError::new(
                "catalog assignment contains a sentinel",
            ));
        }

        Ok(())
    }
}

/// Publishes one assembled workspace root and its installed attachments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceCatalogEntry {
    handle: HostCatalogHandle,
    assignment: CatalogAssignment,
    root_image: ObjectDescriptor,
    root_directory: String,
    device: u64,
    inode: u64,
    identity: CatalogIdentityAllocation,
    attachment_handles: Vec<HostCatalogHandle>,
}

impl WorkspaceCatalogEntry {
    /// Constructs one assignment-bound workspace catalog record.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero handle, unsafe path, missing physical
    /// identity, too many attachments, or noncanonical attachment handles.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor mirrors one closed serialized catalog record"
    )]
    pub fn new(
        handle: HostCatalogHandle,
        assignment: CatalogAssignment,
        root_image: ObjectDescriptor,
        root_directory: String,
        device: u64,
        inode: u64,
        identity: CatalogIdentityAllocation,
        attachment_handles: Vec<HostCatalogHandle>,
    ) -> Result<Self, HostCatalogSnapshotError> {
        let value = Self {
            handle,
            assignment,
            root_image,
            root_directory,
            device,
            inode,
            identity,
            attachment_handles,
        };
        value.validate()?;

        Ok(value)
    }

    /// Returns the opaque workspace handle.
    #[must_use]
    pub const fn handle(&self) -> &HostCatalogHandle {
        &self.handle
    }

    /// Returns the exact assignment bound to this workspace.
    #[must_use]
    pub const fn assignment(&self) -> CatalogAssignment {
        self.assignment
    }

    /// Returns the portable root-image descriptor.
    #[must_use]
    pub const fn root_image(&self) -> &ObjectDescriptor {
        &self.root_image
    }

    /// Returns the fixed-publisher workspace pin path.
    #[must_use]
    pub fn root_directory(&self) -> &str {
        &self.root_directory
    }

    /// Returns the catalogued workspace device identity.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the catalogued workspace inode identity.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the subordinate identity allocation carried by this workspace.
    #[must_use]
    pub const fn identity(&self) -> CatalogIdentityAllocation {
        self.identity
    }

    /// Returns the exact ordered attachment handles installed in this workspace.
    #[must_use]
    pub fn attachment_handles(&self) -> &[HostCatalogHandle] {
        &self.attachment_handles
    }

    fn validate(&self) -> Result<(), HostCatalogSnapshotError> {
        self.assignment.validate()?;
        validate_handle(self.handle, "workspace")?;
        validate_published_pin(&self.root_directory, WORKSPACE_PIN_PREFIX, "workspace root")?;
        if self.device == 0 || self.inode == 0 {
            return Err(HostCatalogSnapshotError::new(
                "workspace pin identity contains a sentinel",
            ));
        }
        self.identity.validate()?;
        if self.attachment_handles.len() > MAXIMUM_HOST_CATALOG_ATTACHMENTS
            || !strictly_ordered(&self.attachment_handles)
            || self.attachment_handles.contains(&[0; 32])
        {
            return Err(HostCatalogSnapshotError::new(
                "workspace attachment handles are not canonical",
            ));
        }

        Ok(())
    }
}

/// Publishes one prepared default-drop network namespace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCatalogEntry {
    handle: HostCatalogHandle,
    assignment: CatalogAssignment,
    namespace_path: String,
    device: u64,
    inode: u64,
}

impl NetworkCatalogEntry {
    /// Constructs one assignment-bound network catalog record.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero handle, unsafe namespace path, or missing
    /// physical identity.
    pub fn new(
        handle: HostCatalogHandle,
        assignment: CatalogAssignment,
        namespace_path: String,
        device: u64,
        inode: u64,
    ) -> Result<Self, HostCatalogSnapshotError> {
        let value = Self {
            handle,
            assignment,
            namespace_path,
            device,
            inode,
        };
        value.validate()?;

        Ok(value)
    }

    /// Returns the opaque network handle.
    #[must_use]
    pub const fn handle(&self) -> &HostCatalogHandle {
        &self.handle
    }

    /// Returns the exact assignment bound to this network.
    #[must_use]
    pub const fn assignment(&self) -> CatalogAssignment {
        self.assignment
    }

    /// Returns the fixed-publisher network namespace path.
    #[must_use]
    pub fn namespace_path(&self) -> &str {
        &self.namespace_path
    }

    /// Returns the catalogued namespace device identity.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the catalogued namespace inode identity.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    fn validate(&self) -> Result<(), HostCatalogSnapshotError> {
        self.assignment.validate()?;
        validate_handle(self.handle, "network")?;
        validate_published_pin(
            &self.namespace_path,
            NETWORK_PIN_PREFIX,
            "network namespace",
        )?;
        if self.device == 0 || self.inode == 0 {
            return Err(HostCatalogSnapshotError::new(
                "network pin identity contains a sentinel",
            ));
        }

        Ok(())
    }
}

/// Publishes one Mount-owned destination anchor for a payload generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentAnchorCatalogEntry {
    handle: HostCatalogHandle,
    assignment: CatalogAssignment,
    namespace_generation: u64,
    directory: String,
    device: u64,
    inode: u64,
    mount_id: u64,
}

impl AttachmentAnchorCatalogEntry {
    /// Constructs one assignment-bound attachment-anchor catalog record.
    ///
    /// The path must exactly reproduce Mount's namespace-generation anchor
    /// beneath its fixed private runtime root.
    ///
    /// # Errors
    ///
    /// Returns an error for a sentinel, a noncanonical path, or missing
    /// physical identity.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor mirrors one closed serialized catalog record"
    )]
    pub fn new(
        handle: HostCatalogHandle,
        assignment: CatalogAssignment,
        namespace_generation: u64,
        directory: String,
        device: u64,
        inode: u64,
        mount_id: u64,
    ) -> Result<Self, HostCatalogSnapshotError> {
        let value = Self {
            handle,
            assignment,
            namespace_generation,
            directory,
            device,
            inode,
            mount_id,
        };
        value.validate()?;

        Ok(value)
    }

    /// Returns the Mount-derived attachment-anchor handle.
    #[must_use]
    pub const fn handle(&self) -> &HostCatalogHandle {
        &self.handle
    }

    /// Returns the exact assignment bound to this anchor.
    #[must_use]
    pub const fn assignment(&self) -> CatalogAssignment {
        self.assignment
    }

    /// Returns the payload namespace generation served by this anchor.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.namespace_generation
    }

    /// Returns the fixed Mount-owned anchor directory.
    #[must_use]
    pub fn directory(&self) -> &str {
        &self.directory
    }

    /// Returns the catalogued anchor device identity.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the catalogued anchor inode identity.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the kernel-unique anchor mount identity.
    #[must_use]
    pub const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    fn validate(&self) -> Result<(), HostCatalogSnapshotError> {
        self.assignment.validate()?;
        validate_handle(self.handle, "attachment anchor")?;
        if self.namespace_generation == 0
            || self.device == 0
            || self.inode == 0
            || self.mount_id == 0
            || self.directory != self.expected_directory()
        {
            return Err(HostCatalogSnapshotError::new(
                "attachment-anchor catalog record is invalid",
            ));
        }
        validate_attachment_anchor_path(&self.directory)
    }

    fn expected_directory(&self) -> String {
        format!(
            "{ATTACHMENT_ANCHOR_PIN_PREFIX}{}/{}/{:016x}",
            encode_hex(&self.assignment.sandbox_id),
            encode_hex(&self.assignment.incarnation_id),
            self.namespace_generation,
        )
    }
}

/// Contains one atomic root-owned Host catalog generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCatalogSnapshot {
    generation: u64,
    workspaces: Vec<WorkspaceCatalogEntry>,
    networks: Vec<NetworkCatalogEntry>,
    #[serde(default)]
    attachment_anchors: Vec<AttachmentAnchorCatalogEntry>,
    retired_identity_allocations: Vec<CatalogIdentityAllocation>,
}

impl HostCatalogSnapshot {
    /// Constructs a canonical catalog snapshot for atomic publication.
    ///
    /// # Errors
    ///
    /// Returns an error for generation zero, excessive collections, invalid
    /// entries, or entries not strictly ordered by opaque handle.
    pub fn new(
        generation: u64,
        workspaces: Vec<WorkspaceCatalogEntry>,
        networks: Vec<NetworkCatalogEntry>,
    ) -> Result<Self, HostCatalogSnapshotError> {
        let value = Self {
            generation,
            workspaces,
            networks,
            attachment_anchors: Vec::new(),
            retired_identity_allocations: Vec::new(),
        };
        value.validate()?;

        Ok(value)
    }

    /// Adds the canonical Mount-owned attachment anchors in this generation.
    ///
    /// # Errors
    ///
    /// Returns an error for excessive, invalid, or unordered entries.
    pub fn with_attachment_anchors(
        mut self,
        anchors: Vec<AttachmentAnchorCatalogEntry>,
    ) -> Result<Self, HostCatalogSnapshotError> {
        self.attachment_anchors = anchors;
        self.validate()?;

        Ok(self)
    }

    /// Adds bounded publisher-asserted allocation tombstones that block reuse.
    ///
    /// # Errors
    ///
    /// Returns an error when a tombstone is invalid, newer than the snapshot,
    /// overlaps another tombstone, or overlaps a live allocation.
    pub fn with_retired_identity_allocations(
        mut self,
        allocations: Vec<CatalogIdentityAllocation>,
    ) -> Result<Self, HostCatalogSnapshotError> {
        self.retired_identity_allocations = allocations;
        self.validate()?;

        Ok(self)
    }

    /// Encodes the strict node-local snapshot for an atomic root-owned write.
    ///
    /// # Errors
    ///
    /// Returns an error when JSON encoding fails or exceeds sixteen MiB.
    pub fn encode(&self) -> Result<Vec<u8>, HostCatalogSnapshotError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| HostCatalogSnapshotError::new(error.to_string()))?;
        if bytes.len() > MAXIMUM_HOST_CATALOG_BYTES {
            return Err(HostCatalogSnapshotError::new(
                "encoded host catalog exceeds sixteen MiB",
            ));
        }

        Ok(bytes)
    }

    /// Decodes an exact canonical Host catalog encoding.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, unknown fields, invalid catalog
    /// semantics, an oversized encoding, or a noncanonical representation.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, HostCatalogSnapshotError> {
        if bytes.len() > MAXIMUM_HOST_CATALOG_BYTES {
            return Err(HostCatalogSnapshotError::new(
                "encoded host catalog exceeds sixteen MiB",
            ));
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| HostCatalogSnapshotError::new(error.to_string()))?;
        value.validate()?;
        let canonical = serde_json::to_vec(&value)
            .map_err(|error| HostCatalogSnapshotError::new(error.to_string()))?;
        if canonical != bytes {
            return Err(HostCatalogSnapshotError::new(
                "host catalog encoding is not canonical",
            ));
        }

        Ok(value)
    }

    /// Returns the nonzero publication generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the strictly handle-ordered workspace entries.
    #[must_use]
    pub fn workspaces(&self) -> &[WorkspaceCatalogEntry] {
        &self.workspaces
    }

    /// Returns the strictly handle-ordered network entries.
    #[must_use]
    pub fn networks(&self) -> &[NetworkCatalogEntry] {
        &self.networks
    }

    /// Returns the strictly handle-ordered Mount attachment anchors.
    #[must_use]
    pub fn attachment_anchors(&self) -> &[AttachmentAnchorCatalogEntry] {
        &self.attachment_anchors
    }

    /// Returns the canonical subordinate-identity tombstones.
    #[must_use]
    pub fn retired_identity_allocations(&self) -> &[CatalogIdentityAllocation] {
        &self.retired_identity_allocations
    }

    fn validate(&self) -> Result<(), HostCatalogSnapshotError> {
        if self.generation == 0
            || self.workspaces.len() > MAXIMUM_HOST_CATALOG_ENTRIES
            || self.networks.len() > MAXIMUM_HOST_CATALOG_ENTRIES
            || self.attachment_anchors.len() > MAXIMUM_HOST_CATALOG_ENTRIES
            || self.retired_identity_allocations.len() > MAXIMUM_HOST_CATALOG_ENTRIES
            || !strictly_ordered_by(&self.workspaces, |entry| entry.handle)
            || !strictly_ordered_by(&self.networks, |entry| entry.handle)
            || !strictly_ordered_by(&self.attachment_anchors, |entry| entry.handle)
            || !strictly_ordered(&self.retired_identity_allocations)
        {
            return Err(HostCatalogSnapshotError::new(
                "host catalog header or entry ordering is invalid",
            ));
        }
        for workspace in &self.workspaces {
            workspace.validate()?;
        }
        for network in &self.networks {
            network.validate()?;
        }
        for anchor in &self.attachment_anchors {
            anchor.validate()?;
        }

        let mut allocations = self
            .workspaces
            .iter()
            .map(|workspace| workspace.identity)
            .collect::<Vec<_>>();
        if allocations
            .iter()
            .any(|allocation| allocation.catalog_generation != self.generation)
        {
            return Err(HostCatalogSnapshotError::new(
                "catalog identity allocation has a stale generation",
            ));
        }
        for retired in &self.retired_identity_allocations {
            retired.validate()?;
            if retired.catalog_generation > self.generation {
                return Err(HostCatalogSnapshotError::new(
                    "retired identity allocation is from a future generation",
                ));
            }
        }
        allocations.extend(self.retired_identity_allocations.iter().copied());
        allocations.sort_unstable_by_key(|allocation| allocation.range_start);
        if allocations
            .windows(2)
            .any(|pair| pair[0].end() > pair[1].range_start)
        {
            return Err(HostCatalogSnapshotError::new(
                "catalog identity allocations overlap",
            ));
        }

        Ok(())
    }
}

fn validate_handle(handle: HostCatalogHandle, label: &str) -> Result<(), HostCatalogSnapshotError> {
    if handle == [0; 32] {
        return Err(HostCatalogSnapshotError::new(format!(
            "{label} handle is zero"
        )));
    }

    Ok(())
}

fn validate_published_pin(
    value: &str,
    prefix: &str,
    label: &str,
) -> Result<(), HostCatalogSnapshotError> {
    validate_absolute(value, label)?;
    let name = value.strip_prefix(prefix).ok_or_else(|| {
        HostCatalogSnapshotError::new(format!("{label} is outside its root-owned pin publisher"))
    })?;
    if name.is_empty() || name == "." || name.contains('/') {
        return Err(HostCatalogSnapshotError::new(format!(
            "{label} is not one exact published pin"
        )));
    }

    Ok(())
}

fn validate_attachment_anchor_path(value: &str) -> Result<(), HostCatalogSnapshotError> {
    validate_absolute(value, "attachment anchor")?;
    let components = value
        .strip_prefix(ATTACHMENT_ANCHOR_PIN_PREFIX)
        .map(|suffix| suffix.split('/').collect::<Vec<_>>());
    let valid = components.is_some_and(|components| {
        matches!(components.as_slice(), [sandbox, incarnation, generation]
            if canonical_hex(sandbox, 32)
                && canonical_hex(incarnation, 32)
                && canonical_hex(generation, 16))
    });
    if !valid {
        return Err(HostCatalogSnapshotError::new(
            "attachment anchor is not one exact namespace-generation pin",
        ));
    }

    Ok(())
}

fn validate_absolute(value: &str, label: &str) -> Result<(), HostCatalogSnapshotError> {
    if value.is_empty()
        || value.len() > 4096
        || !value.starts_with('/')
        || value.as_bytes().contains(&0)
        || value.strip_prefix('/').is_none_or(|tail| {
            tail.is_empty()
                || tail
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
        })
    {
        return Err(HostCatalogSnapshotError::new(format!(
            "{label} is not a bounded normalized absolute path"
        )));
    }

    Ok(())
}

fn canonical_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn strictly_ordered<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_ordered_by<T, K: Ord + Copy>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::{MediaType, ObjectDigest};

    use super::*;

    fn assignment() -> CatalogAssignment {
        CatalogAssignment::new([1; 16], [2; 16], 3, 4, [5; 32]).unwrap()
    }

    fn descriptor() -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new("application/octet-stream".to_owned()).unwrap(),
            ObjectDigest::from_bytes([6; 32]),
            7,
        )
    }

    fn workspace(generation: u64) -> WorkspaceCatalogEntry {
        WorkspaceCatalogEntry::new(
            [8; 32],
            assignment(),
            descriptor(),
            "/run/aos/sandbox-pins/workspaces/08".to_owned(),
            9,
            10,
            CatalogIdentityAllocation::new(65_536, 65_536, generation).unwrap(),
            vec![[11; 32]],
        )
        .unwrap()
    }

    fn network() -> NetworkCatalogEntry {
        NetworkCatalogEntry::new(
            [12; 32],
            assignment(),
            "/run/aos/sandbox-pins/netns/0c".to_owned(),
            13,
            14,
        )
        .unwrap()
    }

    fn anchor() -> AttachmentAnchorCatalogEntry {
        AttachmentAnchorCatalogEntry::new(
            [15; 32],
            assignment(),
            16,
            format!(
                "{ATTACHMENT_ANCHOR_PIN_PREFIX}{}/{}/{:016x}",
                encode_hex(&[1; 16]),
                encode_hex(&[2; 16]),
                16,
            ),
            17,
            18,
            19,
        )
        .unwrap()
    }

    #[test]
    fn canonical_round_trip_preserves_every_collection() {
        let snapshot = HostCatalogSnapshot::new(1, vec![workspace(1)], vec![network()])
            .unwrap()
            .with_attachment_anchors(vec![anchor()])
            .unwrap();
        let bytes = snapshot.encode().unwrap();
        let decoded = HostCatalogSnapshot::decode_canonical(&bytes).unwrap();

        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.workspaces().len(), 1);
        assert_eq!(decoded.networks().len(), 1);
        assert_eq!(decoded.attachment_anchors().len(), 1);
    }

    #[test]
    fn decoding_rejects_noncanonical_and_unknown_json() {
        let canonical = HostCatalogSnapshot::new(1, Vec::new(), Vec::new())
            .unwrap()
            .encode()
            .unwrap();
        let mut whitespace = canonical.clone();
        whitespace.push(b'\n');
        assert!(HostCatalogSnapshot::decode_canonical(&whitespace).is_err());

        let unknown = br#"{"generation":1,"workspaces":[],"networks":[],"attachment_anchors":[],"retired_identity_allocations":[],"unknown":true}"#;
        assert!(HostCatalogSnapshot::decode_canonical(unknown).is_err());
    }

    #[test]
    fn snapshot_rejects_noncanonical_handles_and_overlapping_allocations() {
        assert!(
            WorkspaceCatalogEntry::new(
                [0; 32],
                assignment(),
                descriptor(),
                "/run/aos/sandbox-pins/workspaces/zero".to_owned(),
                1,
                2,
                CatalogIdentityAllocation::new(65_536, 65_536, 1).unwrap(),
                Vec::new(),
            )
            .is_err()
        );

        let overlapping = WorkspaceCatalogEntry::new(
            [9; 32],
            assignment(),
            descriptor(),
            "/run/aos/sandbox-pins/workspaces/09".to_owned(),
            9,
            10,
            CatalogIdentityAllocation::new(98_304, 65_536, 1).unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert!(HostCatalogSnapshot::new(1, vec![workspace(1), overlapping], Vec::new()).is_err());
    }

    #[test]
    fn attachment_anchor_path_is_derived_from_assignment_and_generation() {
        let mut wrong = anchor();
        wrong.directory = format!(
            "{ATTACHMENT_ANCHOR_PIN_PREFIX}{}/{}/{:016x}",
            encode_hex(&[1; 16]),
            encode_hex(&[2; 16]),
            17,
        );

        assert!(wrong.validate().is_err());
    }
}
