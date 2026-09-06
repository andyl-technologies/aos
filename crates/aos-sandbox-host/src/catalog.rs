//! Assignment-bound root-owned launch catalog snapshots.
//!
//! A publisher atomically replaces `catalog.json` beneath a private directory.
//! Hostd opens that directory once, resolves the fixed filename with
//! `openat2`, reads at most sixteen MiB, strictly decodes one generation, and
//! resolves workspace, network, and attachment state from that same snapshot.
//!
//! Pin identity verification below is deliberately not launch authority yet:
//! a pathname can be replaced after verification. Production readiness stays
//! unconstructable until the pin publisher proves root ownership, immutable
//! parent and leaf entries for the complete verify-to-exec interval, and the
//! worker post-validates the identities after systemd starts the supervisor.

use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox_core::ObjectDescriptor;
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedRuntimePlan};
use serde::{Deserialize, Serialize};

use crate::plan::{
    ATTACHMENT_ANCHOR_PIN_PREFIX, HostCatalog, NETWORK_PIN_PREFIX, OpaqueHandle,
    ResolvedAttachmentAnchor, ResolvedIdentityAllocation, ResolvedLaunchResources, ResolvedNetwork,
    ResolvedWorkspace, WORKSPACE_PIN_PREFIX, validate_attachment_anchor_path,
    validate_published_pin,
};
use crate::{HostError, Result};

const CATALOG_FILE: &str = "catalog.json";
const MAXIMUM_CATALOG_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_ENTRIES: usize = 16_384;
const MAXIMUM_ATTACHMENTS: usize = 256;
const MINIMUM_IDENTITY_RANGE: u32 = 65_536;

/// Records one incarnation-bound, nonoverlapping subordinate identity range.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    pub fn new(range_start: u32, range_size: u32, catalog_generation: u64) -> Result<Self> {
        let value = Self {
            range_start,
            range_size,
            catalog_generation,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<()> {
        if self.range_start == 0
            || self.range_size < MINIMUM_IDENTITY_RANGE
            || self.range_start.checked_add(self.range_size).is_none()
            || self.catalog_generation == 0
        {
            return Err(HostError::Catalog(
                "catalog identity allocation is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    fn end(self) -> u32 {
        self.range_start + self.range_size
    }

    fn matches(self, plan: &ValidatedRuntimePlan) -> bool {
        self.range_start == plan.uid_range_start() && self.range_size == plan.uid_range_size()
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
    /// Returns [`HostError::Catalog`] when an identifier/digest is zero or a
    /// generation is zero.
    pub fn new(
        sandbox_id: [u8; 16],
        incarnation_id: [u8; 16],
        assignment_epoch: u64,
        desired_generation: u64,
        assignment_digest: [u8; 32],
    ) -> Result<Self> {
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

    fn validate(self) -> Result<()> {
        if self.sandbox_id == [0; 16]
            || self.incarnation_id == [0; 16]
            || self.assignment_epoch == 0
            || self.desired_generation == 0
            || self.assignment_digest == [0; 32]
        {
            return Err(HostError::Catalog(
                "catalog assignment contains a sentinel".to_owned(),
            ));
        }
        Ok(())
    }

    fn matches(self, fence: &ValidatedAssignmentFence) -> bool {
        self.sandbox_id == *fence.sandbox_id()
            && self.incarnation_id == *fence.incarnation_id()
            && self.assignment_epoch == fence.assignment_epoch()
            && self.desired_generation == fence.desired_generation()
            && self.assignment_digest == *fence.assignment_digest()
    }
}

/// Publishes one assembled workspace root and its installed attachments.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceCatalogEntry {
    handle: OpaqueHandle,
    assignment: CatalogAssignment,
    root_image: ObjectDescriptor,
    root_directory: String,
    device: u64,
    inode: u64,
    identity: CatalogIdentityAllocation,
    attachment_handles: Vec<OpaqueHandle>,
}

impl WorkspaceCatalogEntry {
    /// Constructs one assignment-bound workspace catalog record.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero handle, unsafe path, too many attachments,
    /// or attachment handles that are not strictly byte ordered.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor mirrors one closed, serialized catalog record"
    )]
    pub fn new(
        handle: OpaqueHandle,
        assignment: CatalogAssignment,
        root_image: ObjectDescriptor,
        root_directory: String,
        device: u64,
        inode: u64,
        identity: CatalogIdentityAllocation,
        attachment_handles: Vec<OpaqueHandle>,
    ) -> Result<Self> {
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

    fn validate(&self) -> Result<()> {
        self.assignment.validate()?;
        validate_handle(self.handle, "workspace")?;
        validate_published_pin(&self.root_directory, WORKSPACE_PIN_PREFIX, "workspace root")
            .map_err(|error| HostError::Catalog(error.to_string()))?;
        if self.device == 0 || self.inode == 0 {
            return Err(HostError::Catalog(
                "workspace pin identity contains a sentinel".to_owned(),
            ));
        }
        self.identity.validate()?;
        if self.attachment_handles.len() > MAXIMUM_ATTACHMENTS
            || !strictly_ordered(&self.attachment_handles)
            || self.attachment_handles.contains(&[0; 32])
        {
            return Err(HostError::Catalog(
                "workspace attachment handles are not canonical".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Publishes one prepared default-drop network namespace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCatalogEntry {
    handle: OpaqueHandle,
    assignment: CatalogAssignment,
    namespace_path: String,
    device: u64,
    inode: u64,
}

/// Publishes one Mount-owned destination anchor for a payload namespace generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentAnchorCatalogEntry {
    handle: OpaqueHandle,
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
    /// The path is not caller-selected. It must exactly reproduce Mount's
    /// namespace-generation anchor beneath its fixed private runtime root.
    ///
    /// # Errors
    ///
    /// Returns an error for a sentinel, a noncanonical path, or missing
    /// physical identity.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor mirrors one closed, serialized catalog record"
    )]
    pub fn new(
        handle: OpaqueHandle,
        assignment: CatalogAssignment,
        namespace_generation: u64,
        directory: String,
        device: u64,
        inode: u64,
        mount_id: u64,
    ) -> Result<Self> {
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

    fn validate(&self) -> Result<()> {
        self.assignment.validate()?;
        validate_handle(self.handle, "attachment anchor")?;
        if self.namespace_generation == 0
            || self.device == 0
            || self.inode == 0
            || self.mount_id == 0
            || self.directory != self.expected_directory()
        {
            return Err(HostError::Catalog(
                "attachment-anchor catalog record is invalid".to_owned(),
            ));
        }
        validate_attachment_anchor_path(&self.directory)
            .map_err(|error| HostError::Catalog(error.to_string()))
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

impl NetworkCatalogEntry {
    /// Constructs one assignment-bound network catalog record.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero handle or unsafe namespace path.
    pub fn new(
        handle: OpaqueHandle,
        assignment: CatalogAssignment,
        namespace_path: String,
        device: u64,
        inode: u64,
    ) -> Result<Self> {
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

    fn validate(&self) -> Result<()> {
        self.assignment.validate()?;
        validate_handle(self.handle, "network")?;
        validate_published_pin(
            &self.namespace_path,
            NETWORK_PIN_PREFIX,
            "network namespace",
        )
        .map_err(|error| HostError::Catalog(error.to_string()))?;
        if self.device == 0 || self.inode == 0 {
            return Err(HostError::Catalog(
                "network pin identity contains a sentinel".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Contains one atomic root-owned catalog generation.
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
    ) -> Result<Self> {
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

    /// Adds the canonical Mount-owned attachment anchors published in this generation.
    ///
    /// # Errors
    ///
    /// Returns an error for excessive, invalid, or unordered entries.
    pub fn with_attachment_anchors(
        mut self,
        anchors: Vec<AttachmentAnchorCatalogEntry>,
    ) -> Result<Self> {
        self.attachment_anchors = anchors;
        self.validate()?;
        Ok(self)
    }

    /// Adds bounded publisher-asserted allocation tombstones that block reuse.
    ///
    /// The catalog publisher, not this snapshot decoder, owns continuity with
    /// prior generations and removal only after cleanup is proven.
    ///
    /// # Errors
    ///
    /// Returns an error when a tombstone is invalid, newer than the snapshot,
    /// overlaps another tombstone, or overlaps a live allocation.
    pub fn with_retired_identity_allocations(
        mut self,
        allocations: Vec<CatalogIdentityAllocation>,
    ) -> Result<Self> {
        self.retired_identity_allocations = allocations;
        self.validate()?;
        Ok(self)
    }

    /// Encodes the strict node-local snapshot for an atomic root-owned write.
    ///
    /// # Errors
    ///
    /// Returns an error when JSON encoding fails or exceeds sixteen MiB.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|error| HostError::Catalog(error.to_string()))?;
        if bytes.len() > MAXIMUM_CATALOG_BYTES {
            return Err(HostError::Catalog(
                "encoded host catalog exceeds sixteen MiB".to_owned(),
            ));
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|error| HostError::Catalog(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.generation == 0
            || self.workspaces.len() > MAXIMUM_ENTRIES
            || self.networks.len() > MAXIMUM_ENTRIES
            || self.attachment_anchors.len() > MAXIMUM_ENTRIES
            || self.retired_identity_allocations.len() > MAXIMUM_ENTRIES
            || !strictly_ordered_by(&self.workspaces, |entry| entry.handle)
            || !strictly_ordered_by(&self.networks, |entry| entry.handle)
            || !strictly_ordered_by(&self.attachment_anchors, |entry| entry.handle)
        {
            return Err(HostError::Catalog(
                "host catalog header or entry ordering is invalid".to_owned(),
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
            return Err(HostError::Catalog(
                "catalog identity allocation has a stale generation".to_owned(),
            ));
        }
        for retired in &self.retired_identity_allocations {
            retired.validate()?;
            if retired.catalog_generation > self.generation {
                return Err(HostError::Catalog(
                    "retired identity allocation is from a future generation".to_owned(),
                ));
            }
        }
        allocations.extend(self.retired_identity_allocations.iter().copied());
        allocations.sort_unstable_by_key(|allocation| allocation.range_start);
        if allocations
            .windows(2)
            .any(|pair| pair[0].end() > pair[1].range_start)
        {
            return Err(HostError::Catalog(
                "catalog identity allocations overlap".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Resolves one fixed catalog file beneath a pre-opened private directory.
///
/// This reader verifies published metadata and attached directory pins. It
/// does not acquire the live detached mount required by nspawn's root transfer
/// role. A privileged workspace publisher and its assignment-bound descriptor
/// handoff remain required before this catalog can support production launch.
#[derive(Debug)]
pub struct FileHostCatalog {
    root: BeneathRoot,
}

impl FileHostCatalog {
    /// Constructs a catalog reader from a pre-opened private directory.
    #[must_use]
    pub const fn new(root: BeneathRoot) -> Self {
        Self { root }
    }

    /// Opens a root-owned catalog directory that is not group/other writable.
    ///
    /// This does not establish readiness of the separate workspace/network
    /// pin publisher; [`crate::plan::BackendReadiness`] remains unavailable.
    ///
    /// # Errors
    ///
    /// Returns an error for symlinks, non-directories, non-root ownership,
    /// writable group/other mode bits, or descriptor validation failures.
    pub fn open_root_owned(path: impl AsRef<Path>) -> Result<Self> {
        let fd = rustix::fs::open(
            path.as_ref(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| HostError::Catalog(error.to_string()))?;
        let metadata =
            rustix::fs::fstat(&fd).map_err(|error| HostError::Catalog(error.to_string()))?;
        if metadata.st_uid != 0 || metadata.st_mode & 0o022 != 0 {
            return Err(HostError::Catalog(
                "catalog root must be a root-owned non-writable real directory".to_owned(),
            ));
        }
        let root =
            BeneathRoot::from_owned(fd).map_err(|error| HostError::Catalog(error.to_string()))?;
        Ok(Self::new(root))
    }

    fn snapshot(&self) -> Result<HostCatalogSnapshot> {
        let bytes = self
            .root
            .open_regular(Path::new(CATALOG_FILE))
            .and_then(|file| file.read_bounded(MAXIMUM_CATALOG_BYTES))
            .map_err(|error| HostError::Catalog(error.to_string()))?;
        HostCatalogSnapshot::decode(&bytes)
    }
}

impl HostCatalog for FileHostCatalog {
    fn resolve(
        &self,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
    ) -> Result<ResolvedLaunchResources> {
        let snapshot = self.snapshot()?;
        let workspace = snapshot
            .workspaces
            .binary_search_by_key(plan.workspace_handle(), |entry| entry.handle)
            .ok()
            .map(|index| &snapshot.workspaces[index])
            .ok_or_else(|| HostError::Catalog("unknown workspace handle".to_owned()))?;
        let network = snapshot
            .networks
            .binary_search_by_key(plan.network_handle(), |entry| entry.handle)
            .ok()
            .map(|index| &snapshot.networks[index])
            .ok_or_else(|| HostError::Catalog("unknown network handle".to_owned()))?;
        if !workspace.assignment.matches(fence)
            || !network.assignment.matches(fence)
            || workspace.root_image != *plan.root_image()
            || workspace.attachment_handles != plan.attachment_handles()
            || !workspace.identity.matches(plan)
        {
            return Err(HostError::Catalog(
                "catalog resources do not bind the exact launch assignment".to_owned(),
            ));
        }
        let workspace_pin =
            verify_workspace_pin(&workspace.root_directory, workspace.device, workspace.inode)?;
        let network_pin =
            verify_network_pin(&network.namespace_path, network.device, network.inode)?;
        let attachment_anchor = plan
            .attachment_anchor_handle()
            .map(|handle| {
                let anchor = snapshot
                    .attachment_anchors
                    .binary_search_by_key(handle, |entry| entry.handle)
                    .ok()
                    .map(|index| &snapshot.attachment_anchors[index])
                    .ok_or_else(|| {
                        HostError::Catalog("unknown attachment-anchor handle".to_owned())
                    })?;
                if !anchor.assignment.matches(fence) {
                    return Err(HostError::Catalog(
                        "attachment anchor does not bind the exact launch assignment".to_owned(),
                    ));
                }
                let pin = verify_attachment_anchor_pin(
                    &anchor.directory,
                    anchor.device,
                    anchor.inode,
                    anchor.mount_id,
                )?;
                ResolvedAttachmentAnchor::from_pinned(
                    anchor.directory.clone(),
                    anchor.device,
                    anchor.inode,
                    anchor.mount_id,
                    pin,
                )
            })
            .transpose()?;
        Ok(ResolvedLaunchResources {
            workspace: ResolvedWorkspace::from_pinned(
                workspace.root_directory.clone(),
                workspace.device,
                workspace.inode,
                workspace_pin,
            )?,
            network: ResolvedNetwork::from_pinned(
                network.namespace_path.clone(),
                network.device,
                network.inode,
                network_pin,
            )?,
            identity: ResolvedIdentityAllocation {
                range_start: workspace.identity.range_start,
                range_size: workspace.identity.range_size,
                catalog_generation: workspace.identity.catalog_generation,
            },
            attachment_anchor,
        })
    }
}

fn validate_handle(handle: OpaqueHandle, label: &str) -> Result<()> {
    if handle == [0; 32] {
        return Err(HostError::Catalog(format!("{label} handle is zero")));
    }
    Ok(())
}

fn verify_workspace_pin(path: &str, device: u64, inode: u64) -> Result<std::os::fd::OwnedFd> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Catalog(error.to_string()))?;
    let stat = rustix::fs::fstat(&fd).map_err(|error| HostError::Catalog(error.to_string()))?;
    if stat.st_dev != device || stat.st_ino != inode {
        return Err(HostError::Catalog(
            "workspace pin identity changed".to_owned(),
        ));
    }
    Ok(fd)
}

fn verify_network_pin(
    path: &str,
    device: u64,
    inode: u64,
) -> Result<aos_sandbox_linux::pidfd::NamespaceFd> {
    use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind};

    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Catalog(error.to_string()))?;
    let namespace = NamespaceFd::from_owned(fd, NamespaceKind::Network)
        .map_err(|error| HostError::Catalog(error.to_string()))?;
    let identity = namespace.identity();
    if identity.device != device || identity.inode != inode {
        return Err(HostError::Catalog(
            "network namespace pin identity changed".to_owned(),
        ));
    }
    if current_network_namespace_identity()? == identity {
        return Err(HostError::Catalog(
            "network pin resolves to the host network namespace".to_owned(),
        ));
    }
    Ok(namespace)
}

fn verify_attachment_anchor_pin(
    path: &str,
    device: u64,
    inode: u64,
    mount_id: u64,
) -> Result<std::os::fd::OwnedFd> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Catalog(error.to_string()))?;
    let stat = rustix::fs::fstat(&fd).map_err(|error| HostError::Catalog(error.to_string()))?;
    let actual_mount_id = aos_sandbox_linux::inventory::MountId::from_fd(fd.as_fd())
        .map_err(|error| HostError::Catalog(error.to_string()))?;
    if stat.st_uid != 0
        || stat.st_mode & 0o7777 != 0o755
        || stat.st_dev != device
        || stat.st_ino != inode
        || actual_mount_id.get() != mount_id
    {
        return Err(HostError::Catalog(
            "attachment-anchor pin identity or protection changed".to_owned(),
        ));
    }
    Ok(fd)
}

fn current_network_namespace_identity() -> Result<aos_sandbox_linux::pidfd::NamespaceIdentity> {
    use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind};

    let host_fd = rustix::fs::open(
        "/proc/self/ns/net",
        // procfs namespace entries are kernel magic links. The path is fixed,
        // and NamespaceFd performs the authoritative nsfs/type check after
        // following it; O_NOFOLLOW would reject every valid comparison.
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Catalog(error.to_string()))?;
    let host = NamespaceFd::from_owned(host_fd, NamespaceKind::Network)
        .map_err(|error| HostError::Catalog(error.to_string()))?;
    Ok(host.identity())
}

fn strictly_ordered(values: &[OpaqueHandle]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_ordered_by<T>(values: &[T], key: impl Fn(&T) -> OpaqueHandle) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        ApplyRuntimeRequest, Audience, Feature, ResourceLimit, RuntimeAction,
    };
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_runtime_request};
    use buffa::Message as _;

    use super::*;

    fn request() -> Vec<u8> {
        let mut request = ApplyRuntimeRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 3;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 100;
        header.maximum_response_bytes = 4096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![2; 16];
        fence.incarnation_id = vec![3; 16];
        fence.assignment_epoch = 4;
        fence.desired_generation = 5;
        fence.assignment_digest = vec![6; 32];
        request.action = RuntimeAction::RUNTIME_ACTION_LAUNCH.into();
        let plan = request.launch_plan.get_or_insert_default();
        let root = plan.root_image.get_or_insert_default();
        root.media_type = "application/vnd.aos.sandbox.view.v1+cbor".to_owned();
        root.sha256 = vec![7; 32];
        root.encoded_size = 8;
        plan.workspace_handle = vec![9; 32];
        plan.network_handle = vec![10; 32];
        plan.uid_range_start = 65_536;
        plan.uid_range_size = 65_536;
        plan.limits = vec![
            ResourceLimit {
                dimension: 2,
                value: 64,
                ..Default::default()
            },
            ResourceLimit {
                dimension: 3,
                value: 1024,
                ..Default::default()
            },
            ResourceLimit {
                dimension: 4,
                value: 100,
                ..Default::default()
            },
        ];
        plan.attachment_handles.push(vec![11; 32]);
        plan.attachment_anchor_handle = vec![12; 32];
        plan.required_features.push(Feature {
            namespace: "aos.sandbox.runtime.linux-systemd".to_owned(),
            major: 1,
            minor: 0,
            ..Default::default()
        });
        request.encode_to_vec()
    }

    #[test]
    fn one_snapshot_atomically_binds_workspace_network_and_attachments() {
        let validated = decode_runtime_request(
            &request(),
            PeerCredentials {
                uid: 1,
                gid: 2,
                pid: Some(3),
            },
            PeerPolicy {
                uid: 1,
                gid: Some(2),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            1,
        )
        .unwrap();
        let fence = validated.fence();
        let plan = validated.launch_plan().unwrap();
        let assignment = CatalogAssignment::new([2; 16], [3; 16], 4, 5, [6; 32]).unwrap();
        let snapshot = HostCatalogSnapshot::new(
            1,
            vec![
                WorkspaceCatalogEntry::new(
                    [9; 32],
                    assignment,
                    plan.root_image().clone(),
                    "/run/aos/sandbox-pins/workspaces/root-a".to_owned(),
                    11,
                    12,
                    CatalogIdentityAllocation::new(65_536, 65_536, 1).unwrap(),
                    vec![[11; 32]],
                )
                .unwrap(),
            ],
            vec![
                NetworkCatalogEntry::new(
                    [10; 32],
                    assignment,
                    "/run/aos/sandbox-pins/netns/net-a".to_owned(),
                    13,
                    14,
                )
                .unwrap(),
            ],
        )
        .unwrap()
        .with_attachment_anchors(vec![
            AttachmentAnchorCatalogEntry::new(
                [12; 32],
                assignment,
                7,
                format!(
                    "/run/aos/sandbox-mount-catalog/slots/{}/{}/0000000000000007",
                    "02".repeat(16),
                    "03".repeat(16),
                ),
                15,
                16,
                17,
            )
            .unwrap(),
        ])
        .unwrap();
        let decoded = HostCatalogSnapshot::decode(&snapshot.encode().unwrap()).unwrap();
        assert_eq!(decoded, snapshot);
        assert!(decoded.workspaces[0].identity.matches(plan));
        assert!(decoded.workspaces[0].assignment.matches(fence));
        assert_eq!(decoded.attachment_anchors[0].handle, [12; 32]);
    }

    #[test]
    fn attachment_anchor_path_is_derived_from_assignment_and_generation() {
        let assignment = CatalogAssignment::new([2; 16], [3; 16], 4, 5, [6; 32]).unwrap();
        let path = format!(
            "/run/aos/sandbox-mount-catalog/slots/{}/{}/0000000000000007",
            "02".repeat(16),
            "03".repeat(16),
        );
        let anchor =
            AttachmentAnchorCatalogEntry::new([12; 32], assignment, 7, path, 15, 16, 17).unwrap();
        assert_eq!(anchor.expected_directory(), anchor.directory);

        assert!(
            AttachmentAnchorCatalogEntry::new(
                [12; 32],
                assignment,
                7,
                "/run/aos/sandbox-mount-catalog/slots/substituted".to_owned(),
                15,
                16,
                17,
            )
            .is_err()
        );
    }

    #[test]
    fn snapshot_rejects_duplicate_handles_before_publication() {
        let assignment = CatalogAssignment::new([2; 16], [3; 16], 4, 5, [6; 32]).unwrap();
        let descriptor = aos_sandbox_core::ObjectDescriptor::new(
            aos_sandbox_core::MediaType::new("application/vnd.aos.sandbox.view.v1+cbor".to_owned())
                .unwrap(),
            aos_sandbox_core::ObjectDigest::from_bytes([7; 32]),
            8,
        );
        let entry = WorkspaceCatalogEntry::new(
            [9; 32],
            assignment,
            descriptor,
            "/run/aos/sandbox-pins/workspaces/root-a".to_owned(),
            11,
            12,
            CatalogIdentityAllocation::new(65_536, 65_536, 1).unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert!(HostCatalogSnapshot::new(1, vec![entry.clone(), entry], Vec::new()).is_err());
    }

    #[test]
    fn identity_allocations_reject_host_ids_small_ranges_and_overflow() {
        assert!(CatalogIdentityAllocation::new(0, 65_536, 1).is_err());
        assert!(CatalogIdentityAllocation::new(65_536, 65_535, 1).is_err());
        assert!(CatalogIdentityAllocation::new(u32::MAX - 1, 65_536, 1).is_err());
        assert!(CatalogIdentityAllocation::new(65_536, 65_536, 0).is_err());
    }

    #[test]
    fn snapshot_rejects_overlapping_or_stale_identity_allocations() {
        let assignment = CatalogAssignment::new([2; 16], [3; 16], 4, 5, [6; 32]).unwrap();
        let descriptor = aos_sandbox_core::ObjectDescriptor::new(
            aos_sandbox_core::MediaType::new("application/vnd.aos.sandbox.view.v1+cbor".to_owned())
                .unwrap(),
            aos_sandbox_core::ObjectDigest::from_bytes([7; 32]),
            8,
        );
        let first = WorkspaceCatalogEntry::new(
            [8; 32],
            assignment,
            descriptor.clone(),
            "/run/aos/sandbox-pins/workspaces/first".to_owned(),
            11,
            12,
            CatalogIdentityAllocation::new(65_536, 65_536, 1).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let overlap = WorkspaceCatalogEntry::new(
            [9; 32],
            assignment,
            descriptor.clone(),
            "/run/aos/sandbox-pins/workspaces/second".to_owned(),
            13,
            14,
            CatalogIdentityAllocation::new(98_304, 65_536, 1).unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert!(HostCatalogSnapshot::new(1, vec![first.clone(), overlap], Vec::new()).is_err());

        let stale = WorkspaceCatalogEntry::new(
            [9; 32],
            assignment,
            descriptor,
            "/run/aos/sandbox-pins/workspaces/second".to_owned(),
            13,
            14,
            CatalogIdentityAllocation::new(131_072, 65_536, 2).unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert!(HostCatalogSnapshot::new(1, vec![first, stale], Vec::new()).is_err());
    }

    #[test]
    fn retired_identity_tombstone_prevents_range_reuse() {
        let assignment = CatalogAssignment::new([2; 16], [3; 16], 4, 5, [6; 32]).unwrap();
        let descriptor = aos_sandbox_core::ObjectDescriptor::new(
            aos_sandbox_core::MediaType::new("application/vnd.aos.sandbox.view.v1+cbor".to_owned())
                .unwrap(),
            aos_sandbox_core::ObjectDigest::from_bytes([7; 32]),
            8,
        );
        let live = WorkspaceCatalogEntry::new(
            [9; 32],
            assignment,
            descriptor,
            "/run/aos/sandbox-pins/workspaces/reused".to_owned(),
            11,
            12,
            CatalogIdentityAllocation::new(65_536, 65_536, 2).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let snapshot = HostCatalogSnapshot::new(2, vec![live], Vec::new()).unwrap();
        assert!(
            snapshot
                .with_retired_identity_allocations(vec![
                    CatalogIdentityAllocation::new(65_536, 65_536, 1).unwrap(),
                ])
                .is_err()
        );
    }

    #[test]
    fn workspace_pin_rejects_identity_change_and_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let stat = rustix::fs::stat(&target).unwrap();
        assert!(verify_workspace_pin(target.to_str().unwrap(), stat.st_dev, stat.st_ino).is_ok());
        assert!(
            verify_workspace_pin(target.to_str().unwrap(), stat.st_dev, stat.st_ino + 1).is_err()
        );

        let link = directory.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(verify_workspace_pin(link.to_str().unwrap(), stat.st_dev, stat.st_ino).is_err());
    }

    #[test]
    fn host_network_namespace_is_never_an_admissible_pin() {
        let stat = rustix::fs::stat("/proc/self/ns/net").unwrap();
        let identity = current_network_namespace_identity().unwrap();
        assert_eq!(identity.device, stat.st_dev);
        assert_eq!(identity.inode, stat.st_ino);
        assert!(verify_network_pin("/proc/self/ns/net", stat.st_dev, stat.st_ino).is_err());
    }
}
