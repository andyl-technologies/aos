//! Assignment-bound root-owned launch catalog snapshots.
//!
//! A publisher atomically replaces `catalog.json` beneath a private directory.
//! Hostd opens that directory once, resolves the fixed filename with
//! `openat2`, reads at most sixteen MiB, strictly decodes one generation, and
//! resolves workspace, network, and attachment state from that same snapshot.
//!
//! Pin identity verification and Storage export are only the resource-custody
//! part of launch. Backend readiness still requires independently verified
//! phase-0 filter and shifted-payload evidence before Host may advertise Apply.

mod pins;
mod launch;
mod publication_native;
pub(crate) mod publication;
pub use launch::HostLaunchCatalogOriginalV2;
pub use publication::{
    HostCatalogPublicationCallsiteV2, HostCatalogPublicationCompletedV2,
    HostCatalogPublicationFailureViewV2,
};

use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::mount::DetachedMount;
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_protocol::host_catalog::MAXIMUM_HOST_CATALOG_BYTES;
pub use aos_sandbox_protocol::{
    AttachmentAnchorCatalogEntry, CatalogAssignment, CatalogIdentityAllocation,
    HostCatalogSnapshot, NetworkCatalogEntry, WorkspaceCatalogEntry,
};
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedRuntimePlan};

use crate::live_agent::read_root_owned_credential;
use crate::plan::{
    HostCatalog, OpaqueHandle, ResolvedAttachmentAnchor, ResolvedIdentityAllocation,
    ResolvedLaunchResources, ResolvedNetwork, ResolvedWorkspace,
};
use crate::storage_root_export::StorageRootMountClientV1;
use crate::{HostError, Result};

const CATALOG_FILE: &str = "catalog.json";
const CATALOG_NEXT_FILE: &str = "catalog.next";
const GUEST_PACKAGE_BINDING_CREDENTIAL: &str = "guest-root-package-binding-v1";

/// Resolves one fixed catalog file beneath a pre-opened private directory.
///
/// This reader verifies published metadata and attached directory pins. When
/// configured with the cgroup-v2 anchor, it requests a fresh detached root
/// from the authenticated Storage service for each launch compilation.
#[derive(Debug)]
pub struct FileHostCatalog {
    root: BeneathRoot,
    root_export_cgroup: Option<CgroupV2Root>,
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

/// Classifies protected physical readback after an ambiguous publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostCatalogPublicationReadback {
    /// The exact intended canonical bytes are durably visible.
    Committed,
    /// The intended generation is absent and its transition remains admissible.
    Absent,
    /// Visible state conflicts with the intended generation or predecessor.
    Conflicting,
}

impl FileHostCatalog {
    // The actual production catalog donates its already-held fixed root. No
    // trait accepts a caller path, descriptor or fabricated Storage proof.
    pub(crate) fn capture_execution_storage_original_v2(
        &self, original: &mut crate::storage_existing_output::StorageExistingOutputOriginalV2,
    ) -> Result<()> {
        let root = self.root_export_cgroup.as_ref().ok_or_else(|| {
            HostError::Catalog("Storage root export cgroup is unavailable".to_owned())
        })?;
        original.capture_client_once(root)
    }

    pub(crate) fn capture_execution_capture_original_v3(
        &self,
        original: &mut crate::storage_existing_output::capture::StorageCaptureOriginalV2,
    ) -> Result<()> {
        let root = self.root_export_cgroup.as_ref().ok_or_else(|| {
            HostError::Catalog("Storage root export cgroup is unavailable".to_owned())
        })?;
        original.capture_client_once(root)
    }

    pub(crate) fn retain_canary_root_export_original(
        &self,
        owner: &mut crate::storage_root_export::HostCanaryRootExportOriginalV1,
    ) -> Result<()> {
        let root = self.root_export_cgroup.as_ref().ok_or_else(|| {
            HostError::Catalog("Storage root export cgroup is unavailable".to_owned())
        })?;
        owner.retain_catalog_original(root)
    }

    /// Constructs a catalog reader from a pre-opened private directory.
    #[must_use]
    pub const fn new(root: BeneathRoot) -> Self {
        Self {
            root,
            root_export_cgroup: None,
        }
    }

    /// Retains the live cgroup-v2 anchor used to authenticate Storage exports.
    #[must_use]
    pub fn with_root_export_cgroup(mut self, cgroup_root: CgroupV2Root) -> Self {
        self.root_export_cgroup = Some(cgroup_root);
        self
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
        let mut original = publication_native::PublicationNativeOriginal::default();
        original.publish(&self.root, snapshot, &mut publication_native::Receiving::Ordinary)
            .map_err(|_| original.ordinary_error())
    }

    /// Resolves an ambiguous publication through locked durable readback.
    ///
    /// The root directory is synchronized before observation, then the visible
    /// catalog is read twice while the publication lock is retained. `Absent`
    /// is returned only when retrying this exact snapshot remains a valid next
    /// transition; all other nonmatching visible state is `Conflicting`.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed root changes, cannot be synchronized,
    /// or does not produce two identical protected canonical observations.
    #[doc(hidden)]
    pub fn resolve_ambiguous_publication(
        &self,
        intended: &HostCatalogSnapshot,
    ) -> Result<HostCatalogPublicationReadback> {
        let mut original = publication_native::PublicationNativeOriginal::default();
        original.resolve(&self.root, intended, &mut publication_native::Receiving::Ordinary)
            .map_err(|_| original.ordinary_error())
    }
}

impl HostCatalog for FileHostCatalog {
    fn resolve(
        &self,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
    ) -> Result<ResolvedLaunchResources> {
        self.resolve_catalog_recipe_v2(fence, plan, &mut launch::CatalogResolutionDispositionV2::Ordinary)
    }

    fn resolve_launch_v2(
        &self,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
        receiving: &mut crate::plan::HostLaunchCatalogReceivingV2<'_, '_>,
        original: &mut HostLaunchCatalogOriginalV2,
    ) -> Result<ResolvedLaunchResources> {
        original.resolve_once(self, fence, plan, receiving)
    }

    fn export_root_mount_launch_v2(
        &self,
        workspace: &ResolvedWorkspace,
        receiving: &mut crate::plan::HostLaunchCatalogReceivingV2<'_, '_>,
        original: &mut HostLaunchCatalogOriginalV2,
    ) -> Result<DetachedMount> {
        let root = self.root_export_cgroup.as_ref().ok_or_else(||
            HostError::Catalog("Storage root export cgroup is unavailable".to_owned()))?;
        original.export_root_mount_once_v2(root, workspace, receiving)
    }

    fn export_root_mount(&self, workspace: &ResolvedWorkspace) -> Result<DetachedMount> {
        let root = self.root_export_cgroup.as_ref().ok_or_else(|| {
            HostError::Catalog("Storage root export cgroup is unavailable".to_owned())
        })?;
        let duplicate = root
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| HostError::Catalog(error.to_string()))?;
        let root = CgroupV2Root::from_owned(duplicate)
            .map_err(|error| HostError::Catalog(error.to_string()))?;
        StorageRootMountClientV1::new(root)?.export(workspace)
    }
}

impl FileHostCatalog {
    fn resolve_catalog_recipe_v2(
        &self,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
        disposition: &mut launch::CatalogResolutionDispositionV2<'_, '_, '_>,
    ) -> Result<ResolvedLaunchResources> {
        let snapshot = disposition.snapshot(self)?;
        let result = self.resolve_snapshot_recipe_v2(&snapshot, fence, plan, disposition);
        disposition.retain_snapshot(snapshot);
        result
    }

    fn resolve_snapshot_recipe_v2(
        &self,
        snapshot: &HostCatalogSnapshot,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
        disposition: &mut launch::CatalogResolutionDispositionV2<'_, '_, '_>,
    ) -> Result<ResolvedLaunchResources> {
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
        let publication = workspace.guest_root_publication().ok_or_else(|| {
            HostError::Catalog(
                "workspace lacks Storage-authenticated guest-root publication".to_owned(),
            )
        })?;
        let guest_root_proof = publication
            .proof()
            .map_err(|error| HostError::Catalog(error.to_string()))?;
        if guest_root_proof.package_binding != *disposition.package_binding()?.as_bytes() {
            return Err(HostError::Catalog(
                "guest-root proof differs from the deployed package binding".to_owned(),
            ));
        }

        let workspace_pin = disposition.workspace(workspace)?;
        let network_pin = disposition.network(network)?;
        let anchor = snapshot
            .attachment_anchors()
            .binary_search_by_key(plan.attachment_anchor_handle(), |entry| *entry.handle())
            .ok()
            .map(|index| &snapshot.attachment_anchors()[index])
            .ok_or_else(|| HostError::Catalog("unknown attachment-anchor handle".to_owned()))?;
        if !anchor.assignment().matches_fence(fence) {
            return Err(HostError::Catalog(
                "attachment anchor does not bind the exact launch assignment".to_owned(),
            ));
        }
        let pin = disposition.anchor(anchor)?;
        disposition.construct_resources(workspace, network, anchor, guest_root_proof,
            workspace_pin, network_pin, pin)
    }
}

fn protected_guest_package_binding() -> Result<ObjectDigest> {
    let bytes = read_root_owned_credential(GUEST_PACKAGE_BINDING_CREDENTIAL, 65, 65)
        .map_err(|()| HostError::Catalog("protected guest package binding is absent".to_owned()))?;
    decode_guest_package_binding(&bytes)
}

fn decode_guest_package_binding(bytes: &[u8]) -> Result<ObjectDigest> {
    if bytes.len() != 65 || bytes[64] != b'\n' {
        return Err(HostError::Catalog(
            "protected guest package binding is malformed".to_owned(),
        ));
    }

    let mut digest = [0_u8; 32];
    for (index, pair) in bytes[..64].chunks_exact(2).enumerate() {
        let high = lowercase_hex_digit(pair[0])?;
        let low = lowercase_hex_digit(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    if digest == [0; 32] {
        return Err(HostError::Catalog(
            "protected guest package binding is a sentinel".to_owned(),
        ));
    }
    Ok(ObjectDigest::from_bytes(digest))
}

fn lowercase_hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(HostError::Catalog(
            "protected guest package binding is not lowercase hex".to_owned(),
        )),
    }
}

fn open_catalog_root(path: impl AsRef<Path>) -> Result<BeneathRoot> {
    let descriptor = open_catalog_root_descriptor(path.as_ref()).map_err(catalog_error)?;
    let metadata = rustix::fs::fstat(&descriptor).map_err(catalog_error)?;
    require_catalog_root_protection(&metadata)?;

    BeneathRoot::from_owned(descriptor).map_err(|error| HostError::Catalog(error.to_string()))
}

// Both ordinary acquisition and selected name observations use these exact
// flags and protection checks. A selected observation retains the raw prefix.
fn open_catalog_root_descriptor(path: &Path) -> rustix::io::Result<std::os::fd::OwnedFd> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
}

fn require_catalog_root_protection(metadata: &rustix::fs::Stat) -> Result<()> {
    if metadata.st_uid != 0 || metadata.st_mode & 0o022 != 0 {
        return Err(HostError::Catalog(
            "catalog root must be a root-owned non-writable real directory".to_owned(),
        ));
    }
    Ok(())
}

fn read_catalog_snapshot(root: &BeneathRoot) -> Result<Option<(HostCatalogSnapshot, Vec<u8>)>> {
    let mut original = publication_native::ReadOriginal::default();
    original.observe(root, &mut publication_native::Receiving::Ordinary)
        .map_err(|_| publication_native::ordinary_error(original.failure()))?;
    original.take_value()
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


fn catalog_error(error: rustix::io::Errno) -> HostError {
    HostError::Catalog(error.to_string())
}

fn verify_workspace_pin(path: &str, device: u64, inode: u64) -> Result<std::os::fd::OwnedFd> {
    let mut original = pins::CatalogPinOriginalV2::new();
    if original.workspace_once(path, device, inode).is_err() {
        return Err(original.into_ordinary_error());
    }
    original.take_raw().ok_or_else(pins::closed)
}

fn verify_network_pin(
    path: &str,
    device: u64,
    inode: u64,
) -> Result<aos_sandbox_linux::pidfd::NamespaceFd> {
    let mut original = pins::CatalogPinOriginalV2::new();
    if original.network_once(path, device, inode).is_err() {
        return Err(original.into_ordinary_error());
    }
    original.take_namespace().ok_or_else(pins::closed)
}

fn verify_attachment_anchor_pin(
    path: &str,
    device: u64,
    inode: u64,
    mount_id: u64,
) -> Result<std::os::fd::OwnedFd> {
    let mut original = pins::CatalogPinOriginalV2::new();
    if original.anchor_once(path, device, inode, mount_id).is_err() {
        return Err(original.into_ordinary_error());
    }
    original.take_raw().ok_or_else(pins::closed)
}

fn current_network_namespace_identity() -> Result<aos_sandbox_linux::pidfd::NamespaceIdentity> {
    let mut original = pins::CatalogPinOriginalV2::new();
    if original.capture_host_current().is_err() {
        return Err(original.into_ordinary_error());
    }
    original.current_network_identity().ok_or_else(pins::closed)
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
    use aos_sandbox_protocol::decode_runtime_template_v1;
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

    #[test]
    fn protected_guest_package_binding_requires_exact_lowercase_digest_line() {
        let line = format!("{}\n", "ab".repeat(32));
        assert_eq!(
            decode_guest_package_binding(line.as_bytes()).unwrap(),
            ObjectDigest::from_bytes([0xab; 32])
        );
        assert!(decode_guest_package_binding(line.trim_end().as_bytes()).is_err());
        assert!(decode_guest_package_binding(line.to_uppercase().as_bytes()).is_err());
        assert!(decode_guest_package_binding(format!("{}\n", "00".repeat(32)).as_bytes()).is_err());
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
        header.protocol_minor = 0;
        header.request_id = vec![1; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 0;
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
        let validated = decode_runtime_template_v1(&request()).unwrap();
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
        let mut held_lock = publication_native::LockOriginal::default();
        held_lock.acquire(&publisher.root).unwrap();

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
