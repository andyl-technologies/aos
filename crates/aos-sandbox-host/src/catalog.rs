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

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_protocol::host_catalog::MAXIMUM_HOST_CATALOG_BYTES;
pub use aos_sandbox_protocol::{
    AttachmentAnchorCatalogEntry, CatalogAssignment, CatalogIdentityAllocation,
    HostCatalogSnapshot, NetworkCatalogEntry, WorkspaceCatalogEntry,
};
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedRuntimePlan};

use crate::plan::{
    HostCatalog, OpaqueHandle, ResolvedAttachmentAnchor, ResolvedIdentityAllocation,
    ResolvedLaunchResources, ResolvedNetwork, ResolvedWorkspace,
};
use crate::{HostError, Result};

const CATALOG_FILE: &str = "catalog.json";
const CATALOG_NEXT_FILE: &str = "catalog.next";

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

/// Publishes complete Host launch catalogs beneath one protected root.
///
/// Publication holds an exclusive lock on the root directory, validates the
/// complete generation transition, and atomically replaces `catalog.json`.
/// The writer retains no authority to mint the entries it receives: trusted
/// reconciliation must still derive every opaque handle and physical identity.
#[derive(Debug)]
pub struct FileHostCatalogPublisher {
    root: BeneathRoot,
}

/// Reports whether an exact Host catalog generation was published or replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostCatalogPublicationOutcome {
    /// The supplied snapshot became the visible catalog generation.
    Published,
    /// The byte-equivalent snapshot was already visible.
    Replay,
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
        open_catalog_root(path).map(Self::new)
    }

    fn snapshot(&self) -> Result<HostCatalogSnapshot> {
        let bytes = self
            .root
            .open_regular(Path::new(CATALOG_FILE))
            .and_then(|file| file.read_bounded(MAXIMUM_HOST_CATALOG_BYTES))
            .map_err(|error| HostError::Catalog(error.to_string()))?;
        HostCatalogSnapshot::decode_canonical(&bytes).map_err(Into::into)
    }
}

impl FileHostCatalogPublisher {
    /// Constructs a catalog publisher from a pre-opened private directory.
    #[must_use]
    pub const fn new(root: BeneathRoot) -> Self {
        Self { root }
    }

    /// Opens a root-owned catalog directory that is not group/other writable.
    ///
    /// # Errors
    ///
    /// Returns an error for symlinks, non-directories, non-root ownership,
    /// writable group/other mode bits, or descriptor validation failures.
    pub fn open_root_owned(path: impl AsRef<Path>) -> Result<Self> {
        open_catalog_root(path).map(Self::new)
    }

    /// Durably publishes one complete catalog generation or accepts its replay.
    ///
    /// A successor must advance by exactly one generation. Every live identity
    /// range must either stay with the same workspace incarnation or become an
    /// exact tombstone, and every existing tombstone must remain present.
    ///
    /// # Errors
    ///
    /// Returns an error when another publisher holds the directory lock, the
    /// current or proposed catalog is invalid, the transition loses identity
    /// continuity, or atomic persistence and exact readback fail.
    pub fn publish(&self, snapshot: &HostCatalogSnapshot) -> Result<HostCatalogPublicationOutcome> {
        let encoded = snapshot.encode()?;
        let _publication_lock = lock_catalog_root(&self.root)?;
        let current = read_catalog_snapshot(&self.root)?;

        if let Some((current_snapshot, current_bytes)) = current.as_ref() {
            if current_snapshot.generation() == snapshot.generation() && current_bytes == &encoded {
                return Ok(HostCatalogPublicationOutcome::Replay);
            }
            validate_catalog_transition(current_snapshot, snapshot)?;
        }

        publish_catalog_bytes(&self.root, &encoded)?;
        let (_, visible_bytes) = read_catalog_snapshot(&self.root)?.ok_or_else(|| {
            HostError::Catalog("published host catalog disappeared during readback".to_owned())
        })?;
        if visible_bytes != encoded {
            return Err(HostError::Catalog(
                "published host catalog failed exact readback".to_owned(),
            ));
        }

        Ok(HostCatalogPublicationOutcome::Published)
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
            .workspaces()
            .binary_search_by_key(plan.workspace_handle(), |entry| *entry.handle())
            .ok()
            .map(|index| &snapshot.workspaces()[index])
            .ok_or_else(|| HostError::Catalog("unknown workspace handle".to_owned()))?;
        let network = snapshot
            .networks()
            .binary_search_by_key(plan.network_handle(), |entry| *entry.handle())
            .ok()
            .map(|index| &snapshot.networks()[index])
            .ok_or_else(|| HostError::Catalog("unknown network handle".to_owned()))?;
        if !workspace.assignment().matches_fence(fence)
            || !network.assignment().matches_fence(fence)
            || workspace.root_image() != plan.root_image()
            || workspace.attachment_handles() != plan.attachment_handles()
            || !workspace.identity().matches_runtime_plan(plan)
        {
            return Err(HostError::Catalog(
                "catalog resources do not bind the exact launch assignment".to_owned(),
            ));
        }
        let workspace_pin = verify_workspace_pin(
            workspace.root_directory(),
            workspace.device(),
            workspace.inode(),
        )?;
        let network_pin =
            verify_network_pin(network.namespace_path(), network.device(), network.inode())?;
        let attachment_anchor = plan
            .attachment_anchor_handle()
            .map(|handle| {
                let anchor = snapshot
                    .attachment_anchors()
                    .binary_search_by_key(handle, |entry| *entry.handle())
                    .ok()
                    .map(|index| &snapshot.attachment_anchors()[index])
                    .ok_or_else(|| {
                        HostError::Catalog("unknown attachment-anchor handle".to_owned())
                    })?;
                if !anchor.assignment().matches_fence(fence) {
                    return Err(HostError::Catalog(
                        "attachment anchor does not bind the exact launch assignment".to_owned(),
                    ));
                }
                let pin = verify_attachment_anchor_pin(
                    anchor.directory(),
                    anchor.device(),
                    anchor.inode(),
                    anchor.mount_id(),
                )?;
                ResolvedAttachmentAnchor::from_pinned(
                    anchor.directory().to_owned(),
                    anchor.device(),
                    anchor.inode(),
                    anchor.mount_id(),
                    pin,
                )
            })
            .transpose()?;
        Ok(ResolvedLaunchResources {
            workspace: ResolvedWorkspace::from_pinned(
                workspace.root_directory().to_owned(),
                workspace.device(),
                workspace.inode(),
                workspace_pin,
            )?,
            network: ResolvedNetwork::from_pinned(
                network.namespace_path().to_owned(),
                network.device(),
                network.inode(),
                network_pin,
            )?,
            identity: ResolvedIdentityAllocation {
                range_start: workspace.identity().range_start(),
                range_size: workspace.identity().range_size(),
                catalog_generation: workspace.identity().catalog_generation(),
            },
            attachment_anchor,
        })
    }
}

fn open_catalog_root(path: impl AsRef<Path>) -> Result<BeneathRoot> {
    let descriptor = rustix::fs::open(
        path.as_ref(),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(catalog_error)?;
    let metadata = rustix::fs::fstat(&descriptor).map_err(catalog_error)?;
    if metadata.st_uid != 0 || metadata.st_mode & 0o022 != 0 {
        return Err(HostError::Catalog(
            "catalog root must be a root-owned non-writable real directory".to_owned(),
        ));
    }

    BeneathRoot::from_owned(descriptor).map_err(|error| HostError::Catalog(error.to_string()))
}

fn lock_catalog_root(root: &BeneathRoot) -> Result<std::os::fd::OwnedFd> {
    // Opening `.` creates an independent open-file description, so flock also
    // serializes concurrent calls made through the same publisher instance.
    let descriptor = rustix::fs::openat(
        root.as_fd(),
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(catalog_error)?;
    let metadata = rustix::fs::fstat(&descriptor).map_err(catalog_error)?;
    if metadata.st_dev != root.identity().device || metadata.st_ino != root.identity().inode {
        return Err(HostError::Catalog(
            "catalog root identity changed before publication".to_owned(),
        ));
    }
    rustix::fs::flock(
        &descriptor,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::WOULDBLOCK {
            HostError::Catalog("another host catalog publisher holds the root lock".to_owned())
        } else {
            HostError::Catalog(error.to_string())
        }
    })?;
    Ok(descriptor)
}

fn read_catalog_snapshot(root: &BeneathRoot) -> Result<Option<(HostCatalogSnapshot, Vec<u8>)>> {
    let descriptor = match rustix::fs::openat(
        root.as_fd(),
        CATALOG_FILE,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(catalog_error(error)),
    };
    let metadata = rustix::fs::fstat(&descriptor).map_err(catalog_error)?;
    let root_metadata = rustix::fs::fstat(root.as_fd()).map_err(catalog_error)?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::RegularFile
        || metadata.st_uid != root_metadata.st_uid
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o7777 != 0o600
    {
        return Err(HostError::Catalog(
            "host catalog is not a protected owner-only regular file".to_owned(),
        ));
    }
    let declared_size = usize::try_from(metadata.st_size)
        .map_err(|_| HostError::Catalog("host catalog size is invalid".to_owned()))?;
    if declared_size == 0 || declared_size > MAXIMUM_HOST_CATALOG_BYTES {
        return Err(HostError::Catalog(
            "host catalog size is invalid".to_owned(),
        ));
    }

    let mut bytes = Vec::with_capacity(declared_size);
    File::from(descriptor)
        .take((MAXIMUM_HOST_CATALOG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| HostError::Catalog(error.to_string()))?;
    if bytes.len() != declared_size || bytes.len() > MAXIMUM_HOST_CATALOG_BYTES {
        return Err(HostError::Catalog(
            "host catalog changed while being read".to_owned(),
        ));
    }
    let snapshot = HostCatalogSnapshot::decode_canonical(&bytes)?;
    Ok(Some((snapshot, bytes)))
}

fn validate_catalog_transition(
    current: &HostCatalogSnapshot,
    proposed: &HostCatalogSnapshot,
) -> Result<()> {
    if proposed.generation() <= current.generation() {
        return Err(HostError::Catalog(
            "host catalog generation rolled back or equivocated".to_owned(),
        ));
    }
    if current.generation().checked_add(1) != Some(proposed.generation()) {
        return Err(HostError::Catalog(
            "host catalog generation skipped its immediate successor".to_owned(),
        ));
    }

    for retired in current.retired_identity_allocations() {
        if proposed
            .retired_identity_allocations()
            .binary_search(retired)
            .is_err()
        {
            return Err(HostError::Catalog(
                "host catalog discarded an identity allocation tombstone".to_owned(),
            ));
        }
    }
    let mut proposed_bindings = proposed
        .workspaces()
        .iter()
        .map(identity_binding)
        .collect::<Vec<_>>();
    proposed_bindings.sort_unstable();
    for workspace in current.workspaces() {
        let allocation = workspace.identity();
        let retained_by_same_incarnation = proposed_bindings
            .binary_search(&identity_binding(workspace))
            .is_ok();
        let retired_exactly = proposed
            .retired_identity_allocations()
            .binary_search(&allocation)
            .is_ok();
        if !retained_by_same_incarnation && !retired_exactly {
            return Err(HostError::Catalog(
                "host catalog lost continuity for a live identity allocation".to_owned(),
            ));
        }
    }
    Ok(())
}

fn identity_binding(
    workspace: &WorkspaceCatalogEntry,
) -> (u32, u32, OpaqueHandle, [u8; 16], [u8; 16]) {
    (
        workspace.identity().range_start(),
        workspace.identity().range_size(),
        *workspace.handle(),
        *workspace.assignment().sandbox_id(),
        *workspace.assignment().incarnation_id(),
    )
}

fn publish_catalog_bytes(root: &BeneathRoot, bytes: &[u8]) -> Result<()> {
    match rustix::fs::unlinkat(
        root.as_fd(),
        CATALOG_NEXT_FILE,
        rustix::fs::AtFlags::empty(),
    ) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(catalog_error(error)),
    }
    let descriptor = rustix::fs::openat(
        root.as_fd(),
        CATALOG_NEXT_FILE,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(catalog_error)?;
    let result = rustix::fs::fchmod(&descriptor, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
        .map_err(catalog_error)
        .and_then(|()| {
            let mut output = File::from(descriptor);
            output
                .write_all(bytes)
                .and_then(|()| output.sync_all())
                .map_err(|error| HostError::Catalog(error.to_string()))
        })
        .and_then(|()| {
            rustix::fs::renameat(root.as_fd(), CATALOG_NEXT_FILE, root.as_fd(), CATALOG_FILE)
                .map_err(catalog_error)
        })
        .and_then(|()| rustix::fs::fsync(root.as_fd()).map_err(catalog_error));
    if result.is_err() {
        let _ = rustix::fs::unlinkat(
            root.as_fd(),
            CATALOG_NEXT_FILE,
            rustix::fs::AtFlags::empty(),
        );
    }
    result
}

fn catalog_error(error: rustix::io::Errno) -> HostError {
    HostError::Catalog(error.to_string())
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

#[cfg(test)]
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
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

    use aos_proto::aos::sandbox::local::v1::{
        ApplyRuntimeRequest, Audience, Feature, ResourceLimit, RuntimeAction,
    };
    use aos_sandbox_core::ObjectDescriptor;
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_runtime_request};
    use buffa::Message as _;

    use super::*;

    fn publisher(directory: &tempfile::TempDir) -> FileHostCatalogPublisher {
        let descriptor = rustix::fs::open(
            directory.path(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        FileHostCatalogPublisher::new(BeneathRoot::from_owned(descriptor).unwrap())
    }

    fn empty_snapshot(generation: u64) -> HostCatalogSnapshot {
        HostCatalogSnapshot::new(generation, Vec::new(), Vec::new()).unwrap()
    }

    fn workspace_snapshot(
        generation: u64,
        handle_byte: u8,
        sandbox_byte: u8,
        incarnation_byte: u8,
        range_start: u32,
    ) -> HostCatalogSnapshot {
        let assignment = CatalogAssignment::new(
            [sandbox_byte; 16],
            [incarnation_byte; 16],
            4,
            generation,
            [6; 32],
        )
        .unwrap();
        let descriptor = ObjectDescriptor::new(
            aos_sandbox_core::MediaType::new("application/vnd.aos.sandbox.view.v1+cbor".to_owned())
                .unwrap(),
            aos_sandbox_core::ObjectDigest::from_bytes([7; 32]),
            8,
        );
        let workspace = WorkspaceCatalogEntry::new(
            [handle_byte; 32],
            assignment,
            descriptor,
            format!("/run/aos/sandbox-pins/workspaces/root-{handle_byte}"),
            11,
            12,
            CatalogIdentityAllocation::new(range_start, 65_536, generation).unwrap(),
            Vec::new(),
        )
        .unwrap();
        HostCatalogSnapshot::new(generation, vec![workspace], Vec::new()).unwrap()
    }

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
        let decoded = HostCatalogSnapshot::decode_canonical(&snapshot.encode().unwrap()).unwrap();
        assert_eq!(decoded, snapshot);
        assert!(
            decoded.workspaces()[0]
                .identity()
                .matches_runtime_plan(plan)
        );
        assert!(decoded.workspaces()[0].assignment().matches_fence(fence));
        assert_eq!(*decoded.attachment_anchors()[0].handle(), [12; 32]);
    }

    #[test]
    fn publisher_atomically_replaces_stale_staging_and_accepts_exact_replay() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(CATALOG_NEXT_FILE), b"interrupted").unwrap();
        let publisher = publisher(&directory);
        let snapshot = empty_snapshot(7);

        assert_eq!(
            publisher.publish(&snapshot).unwrap(),
            HostCatalogPublicationOutcome::Published
        );
        assert!(!directory.path().join(CATALOG_NEXT_FILE).exists());
        let metadata = std::fs::metadata(directory.path().join(CATALOG_FILE)).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(
            publisher.publish(&snapshot).unwrap(),
            HostCatalogPublicationOutcome::Replay
        );
        assert_eq!(
            std::fs::read(directory.path().join(CATALOG_FILE)).unwrap(),
            snapshot.encode().unwrap()
        );
    }

    #[test]
    fn wire_catalog_decode_requires_the_unique_canonical_encoding() {
        let snapshot = empty_snapshot(1);
        let canonical = snapshot.encode().unwrap();
        assert_eq!(
            HostCatalogSnapshot::decode_canonical(&canonical).unwrap(),
            snapshot
        );

        let mut whitespace_variant = canonical;
        whitespace_variant.push(b'\n');
        assert!(HostCatalogSnapshot::decode_canonical(&whitespace_variant).is_err());
    }

    #[test]
    fn publisher_rejects_generation_equivocation_rollback_and_skip() {
        let directory = tempfile::tempdir().unwrap();
        let publisher = publisher(&directory);
        publisher.publish(&empty_snapshot(3)).unwrap();
        let equivocation = empty_snapshot(3)
            .with_retired_identity_allocations(vec![
                CatalogIdentityAllocation::new(65_536, 65_536, 1).unwrap(),
            ])
            .unwrap();

        assert!(publisher.publish(&equivocation).is_err());
        assert!(publisher.publish(&empty_snapshot(2)).is_err());
        assert!(publisher.publish(&empty_snapshot(5)).is_err());
        assert_eq!(
            read_catalog_snapshot(&publisher.root).unwrap().unwrap().0,
            empty_snapshot(3)
        );
    }

    #[test]
    fn publisher_rejects_unprotected_or_redirected_current_catalogs() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().unwrap();
        let publisher = publisher(&directory);
        let catalog_path = directory.path().join(CATALOG_FILE);
        std::fs::write(&catalog_path, empty_snapshot(1).encode().unwrap()).unwrap();
        std::fs::set_permissions(&catalog_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(publisher.publish(&empty_snapshot(2)).is_err());

        std::fs::remove_file(&catalog_path).unwrap();
        let target = directory.path().join("redirected.json");
        std::fs::write(&target, empty_snapshot(1).encode().unwrap()).unwrap();
        symlink(&target, &catalog_path).unwrap();
        assert!(publisher.publish(&empty_snapshot(2)).is_err());
    }

    #[test]
    fn publisher_requires_live_ranges_to_stay_bound_or_become_tombstones() {
        let directory = tempfile::tempdir().unwrap();
        let publisher = publisher(&directory);
        let first = workspace_snapshot(1, 9, 2, 3, 65_536);
        let retained = workspace_snapshot(2, 9, 2, 3, 65_536);
        publisher.publish(&first).unwrap();
        publisher.publish(&retained).unwrap();

        let substituted = workspace_snapshot(3, 10, 2, 3, 65_536);
        assert!(publisher.publish(&substituted).is_err());
        let reassigned_sandbox = workspace_snapshot(3, 9, 4, 3, 65_536);
        assert!(publisher.publish(&reassigned_sandbox).is_err());
        let replaced_incarnation = workspace_snapshot(3, 9, 2, 4, 65_536);
        assert!(publisher.publish(&replaced_incarnation).is_err());
        let partial_overlap = workspace_snapshot(3, 10, 2, 3, 98_304);
        assert!(publisher.publish(&partial_overlap).is_err());

        let retired_allocation = retained.workspaces()[0].identity();
        let retired = empty_snapshot(3)
            .with_retired_identity_allocations(vec![retired_allocation])
            .unwrap();
        assert_eq!(
            publisher.publish(&retired).unwrap(),
            HostCatalogPublicationOutcome::Published
        );
        assert!(publisher.publish(&empty_snapshot(4)).is_err());

        let preserved = empty_snapshot(4)
            .with_retired_identity_allocations(vec![retired_allocation])
            .unwrap();
        assert_eq!(
            publisher.publish(&preserved).unwrap(),
            HostCatalogPublicationOutcome::Published
        );
    }

    #[test]
    fn publisher_serializes_calls_with_an_independent_directory_lock() {
        let directory = tempfile::tempdir().unwrap();
        let publisher = publisher(&directory);
        let held_lock = lock_catalog_root(&publisher.root).unwrap();

        assert!(publisher.publish(&empty_snapshot(1)).is_err());
        drop(held_lock);
        assert!(publisher.publish(&empty_snapshot(1)).is_ok());
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
            AttachmentAnchorCatalogEntry::new([12; 32], assignment, 7, path.clone(), 15, 16, 17)
                .unwrap();
        assert_eq!(anchor.directory(), path);

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
    fn retired_identity_tombstones_require_canonical_order() {
        let later = CatalogIdentityAllocation::new(131_072, 65_536, 1).unwrap();
        let earlier = CatalogIdentityAllocation::new(65_536, 65_536, 1).unwrap();

        assert!(
            empty_snapshot(2)
                .with_retired_identity_allocations(vec![later, earlier])
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
