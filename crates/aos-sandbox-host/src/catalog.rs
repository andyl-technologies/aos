//! Assignment-bound root-owned launch catalog snapshots.
//!
//! A publisher atomically replaces `catalog.json` beneath a private directory.
//! Hostd opens that directory once, resolves the fixed filename with
//! `openat2`, reads at most sixteen MiB, strictly decodes one generation, and
//! resolves workspace, network, and attachment state from that same snapshot.

use std::path::Path;

use aos_sandbox_core::ObjectDescriptor;
use aos_sandbox_linux::path::BeneathRoot;
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedRuntimePlan};
use serde::{Deserialize, Serialize};

use crate::plan::{
    HostCatalog, OpaqueHandle, ResolvedLaunchResources, ResolvedNetwork, ResolvedWorkspace,
};
use crate::{HostError, Result};

const CATALOG_FILE: &str = "catalog.json";
const MAXIMUM_CATALOG_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_ENTRIES: usize = 16_384;
const MAXIMUM_ATTACHMENTS: usize = 256;

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
    attachment_handles: Vec<OpaqueHandle>,
}

impl WorkspaceCatalogEntry {
    /// Constructs one assignment-bound workspace catalog record.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero handle, unsafe path, too many attachments,
    /// or attachment handles that are not strictly byte ordered.
    pub fn new(
        handle: OpaqueHandle,
        assignment: CatalogAssignment,
        root_image: ObjectDescriptor,
        root_directory: String,
        attachment_handles: Vec<OpaqueHandle>,
    ) -> Result<Self> {
        let value = Self {
            handle,
            assignment,
            root_image,
            root_directory,
            attachment_handles,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        self.assignment.validate()?;
        validate_handle(self.handle, "workspace")?;
        validate_absolute(&self.root_directory, "workspace root")?;
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
    ) -> Result<Self> {
        let value = Self {
            handle,
            assignment,
            namespace_path,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        self.assignment.validate()?;
        validate_handle(self.handle, "network")?;
        validate_absolute(&self.namespace_path, "network namespace")
    }
}

/// Contains one atomic root-owned catalog generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCatalogSnapshot {
    generation: u64,
    workspaces: Vec<WorkspaceCatalogEntry>,
    networks: Vec<NetworkCatalogEntry>,
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
        };
        value.validate()?;
        Ok(value)
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
            || !strictly_ordered_by(&self.workspaces, |entry| entry.handle)
            || !strictly_ordered_by(&self.networks, |entry| entry.handle)
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
        Ok(())
    }
}

/// Resolves one fixed catalog file beneath a pre-opened private directory.
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
        {
            return Err(HostError::Catalog(
                "catalog resources do not bind the exact launch assignment".to_owned(),
            ));
        }
        Ok(ResolvedLaunchResources {
            workspace: ResolvedWorkspace {
                root_directory: workspace.root_directory.clone(),
            },
            network: ResolvedNetwork {
                namespace_path: network.namespace_path.clone(),
            },
        })
    }
}

fn validate_handle(handle: OpaqueHandle, label: &str) -> Result<()> {
    if handle == [0; 32] {
        return Err(HostError::Catalog(format!("{label} handle is zero")));
    }
    Ok(())
}

fn validate_absolute(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 4096
        || !value.starts_with('/')
        || value.as_bytes().contains(&0)
        || value.split('/').any(|component| component == "..")
    {
        return Err(HostError::Catalog(format!(
            "{label} is not a bounded normalized absolute path"
        )));
    }
    Ok(())
}

fn strictly_ordered(values: &[OpaqueHandle]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_ordered_by<T>(values: &[T], key: impl Fn(&T) -> OpaqueHandle) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::File;
    use std::os::fd::OwnedFd;

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
                    "/var/lib/aos/root".to_owned(),
                    vec![[11; 32]],
                )
                .unwrap(),
            ],
            vec![
                NetworkCatalogEntry::new(
                    [10; 32],
                    assignment,
                    "/run/aos/netns/assigned".to_owned(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join(CATALOG_FILE),
            snapshot.encode().unwrap(),
        )
        .unwrap();
        let fd: OwnedFd = File::open(directory.path()).unwrap().into();
        let catalog = FileHostCatalog::new(BeneathRoot::from_owned(fd).unwrap());
        let resolved = catalog.resolve(fence, plan).unwrap();
        assert_eq!(resolved.workspace.root_directory, "/var/lib/aos/root");
        assert_eq!(resolved.network.namespace_path, "/run/aos/netns/assigned");
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
            "/var/lib/aos/root".to_owned(),
            Vec::new(),
        )
        .unwrap();
        assert!(HostCatalogSnapshot::new(1, vec![entry.clone(), entry], Vec::new()).is_err());
    }
}
