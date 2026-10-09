//! Static namespace-inspector deployment contract and digest.
//!
//! The contract names immutable artifacts by protected canonical path, content
//! digest, and expected metadata. It intentionally excludes boot-local device,
//! inode, mount, pidfd, process, and cgroup observations because copied guest
//! filesystem objects do not have builder-predictable inode identities. The
//! protected loader authenticates canonical credential bytes and separately
//! pins and revalidates every live artifact descriptor.
//!
//! An artifact descriptor authenticates only that ELF file. Deployment still
//! requires SBX-P0-09 to authenticate each physical executable together with
//! its complete `PT_INTERP` and `DT_NEEDED` closure; descriptor-backed helper
//! execution does not satisfy that prerequisite by itself.
//!
//! ```text
//! AOSNIMC1 | version:u16 | kind:u8 | reserved:u8 | total:u32
//! fixed paths and ordered argv | static environment-name sets
//! ordered artifact roles/path/content-digest/expected metadata
//! static-property-count:u16 | static properties in descriptor-table order
//! ```

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::manager_query::codec::{self, Decoder, Encoder};
use super::manager_query::{
    CanonicalManagerPropertyValueV1, ManagerPropertyObservationV1,
    NamespaceInspectorManagerQueryError, validate_property_sequence,
};

const CONTRACT_MAGIC: &[u8; 8] = b"AOSNIMC1";
const CONTRACT_KIND: u8 = 1;
const CONTRACT_DIGEST_DOMAIN: &[u8] = b"AOS-NETWORK-NAMESPACE-INSPECTOR-DEPLOYMENT-CONTRACT-V1\0";
const MAXIMUM_PATH_BYTES: usize = 512;
const MAXIMUM_UNIT_NAME_BYTES: usize = 256;
const MAXIMUM_ARGUMENTS: usize = 16;
const MAXIMUM_ENVIRONMENT_NAMES: usize = 64;
const ARTIFACT_COUNT: usize = 4;
const MAXIMUM_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;
const MAXIMUM_AGGREGATE_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const ARTIFACT_HASH_BUFFER_BYTES: usize = 64 * 1024;

/// Identifies the static deployment digest without interchanging it with
/// lifecycle-worker object or launch-contract digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceInspectorDeploymentDigestV1([u8; 32]);

impl NamespaceInspectorDeploymentDigestV1 {
    pub(super) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Identifies one immutable artifact role in the static deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NamespaceInspectorArtifactRoleV1 {
    /// The namespace-inspector executable started by the service unit.
    InspectorExecutable,
    /// The one-shot libsystemd query helper executable.
    ManagerQueryHelperExecutable,
    /// The immutable inspector service template fragment.
    InspectorServiceFragment,
    /// The immutable inspector socket-unit fragment.
    InspectorSocketFragment,
}

impl NamespaceInspectorArtifactRoleV1 {
    const fn code(self) -> u8 {
        match self {
            Self::InspectorExecutable => 1,
            Self::ManagerQueryHelperExecutable => 2,
            Self::InspectorServiceFragment => 3,
            Self::InspectorSocketFragment => 4,
        }
    }

    fn from_code(code: u8) -> Result<Self, NamespaceInspectorManagerQueryError> {
        match code {
            1 => Ok(Self::InspectorExecutable),
            2 => Ok(Self::ManagerQueryHelperExecutable),
            3 => Ok(Self::InspectorServiceFragment),
            4 => Ok(Self::InspectorSocketFragment),
            _ => Err(NamespaceInspectorManagerQueryError::InvalidContract),
        }
    }
}

/// Names one immutable source artifact without predicting its runtime inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceInspectorArtifactExpectationV1 {
    role: NamespaceInspectorArtifactRoleV1,
    canonical_path: String,
    content_digest: [u8; 32],
    expected_mode: u32,
    expected_uid: u32,
    expected_gid: u32,
}

/// Reports failure to load or revalidate protected deployment artifacts.
#[derive(Debug, Error)]
pub(crate) enum ProtectedNamespaceInspectorDeploymentContractError {
    /// A bounded file or descriptor operation failed.
    #[error("namespace-inspector protected deployment read failed during {operation}: {source}")]
    Io {
        /// Names the bounded operation which failed.
        operation: &'static str,
        /// Preserves the operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Canonical contract decoding failed.
    #[error(transparent)]
    Model(#[from] NamespaceInspectorManagerQueryError),
    /// Protected file metadata, identity, or content did not match policy.
    #[error("namespace-inspector protected deployment artifact did not match policy")]
    Mismatch,
}

impl NamespaceInspectorArtifactExpectationV1 {
    fn validate(&self) -> Result<(), NamespaceInspectorManagerQueryError> {
        if !absolute_path_is_valid(&self.canonical_path)
            || self.content_digest == [0; 32]
            || self.expected_mode & !0o7777 != 0
        {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }
        Ok(())
    }
}

/// Holds decoded static deployment bytes without claiming protected origin.
///
/// Ordered vectors retain semantics for argv, fragment/drop-in search order,
/// and path policy. Environment-name collections are canonical unordered sets.
/// Runtime manager environment values and all boot-local identities are absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceInspectorDeploymentContractV1 {
    inspector_arguments: Vec<String>,
    helper_arguments: Vec<String>,
    service_unit_template: String,
    socket_unit: String,
    control_socket_path: String,
    manager_socket_path: String,
    service_drop_in_paths: Vec<String>,
    socket_drop_in_paths: Vec<String>,
    read_only_paths: Vec<String>,
    read_write_paths: Vec<String>,
    inaccessible_paths: Vec<String>,
    allowed_environment_names: Vec<String>,
    forbidden_environment_names: Vec<String>,
    artifacts: Vec<NamespaceInspectorArtifactExpectationV1>,
    static_properties: Vec<ManagerPropertyObservationV1>,
}

/// Retains a deployment contract admitted by protected provisioning.
///
/// This move-only wrapper is the authority input to the manager-query session.
/// Construction is available only through the protected credential loader,
/// which retains all four checked artifact descriptors.
#[derive(Debug)]
pub(crate) struct ProtectedNamespaceInspectorDeploymentContractV1 {
    contract: NamespaceInspectorDeploymentContractV1,
    digest: NamespaceInspectorDeploymentDigestV1,
    artifacts: Vec<RetainedNamespaceInspectorArtifactV1>,
}

#[derive(Debug)]
struct RetainedNamespaceInspectorArtifactV1 {
    expectation: NamespaceInspectorArtifactExpectationV1,
    descriptor: OwnedFd,
    device: u64,
    inode: u64,
    length: u64,
}

impl ProtectedNamespaceInspectorDeploymentContractV1 {
    /// Loads canonical contract bytes from a root-only credential and pins all artifacts.
    ///
    /// The credential must be a root-owned, single-link, regular `0400` file.
    /// Every artifact is opened without following a final symlink and checked
    /// against its exact content digest, mode, owner, and group before any
    /// authority-bearing wrapper is returned.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe credential, an oversized or noncanonical
    /// contract, or any missing, mutable, aliased, or mismatched artifact.
    pub(crate) fn load(
        path: &Path,
    ) -> Result<Self, ProtectedNamespaceInspectorDeploymentContractError> {
        let descriptor = open_regular_nofollow(path, "open deployment contract")?;
        let metadata = descriptor
            .metadata()
            .map_err(|source| protected_io("inspect deployment contract", source))?;
        if metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o400
            || metadata.nlink() != 1
        {
            return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
        }

        let bytes = read_bounded(
            descriptor,
            codec::MAXIMUM_MANAGER_QUERY_FRAME_BYTES,
            "read deployment contract",
        )?;
        let contract = NamespaceInspectorDeploymentContractV1::decode_untrusted(&bytes)?;
        let digest = contract.digest()?;
        let mut artifacts = Vec::with_capacity(contract.artifacts.len());
        let mut aggregate_bytes = 0_u64;
        for expectation in &contract.artifacts {
            let artifact = RetainedNamespaceInspectorArtifactV1::open(expectation.clone())?;
            aggregate_bytes = checked_aggregate_artifact_bytes(aggregate_bytes, artifact.length)?;
            artifacts.push(artifact);
        }
        for (index, artifact) in artifacts.iter().enumerate() {
            if artifacts[..index]
                .iter()
                .any(|prior| prior.device == artifact.device && prior.inode == artifact.inode)
            {
                return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
            }
        }

        Ok(Self {
            contract,
            digest,
            artifacts,
        })
    }

    pub(super) const fn contract(&self) -> &NamespaceInspectorDeploymentContractV1 {
        &self.contract
    }

    pub(super) const fn digest(&self) -> NamespaceInspectorDeploymentDigestV1 {
        self.digest
    }

    /// Duplicates the pinned descriptor for one closed artifact role.
    ///
    /// # Errors
    ///
    /// Returns an error if the role is absent or descriptor duplication fails.
    pub(crate) fn duplicate_artifact(
        &self,
        role: NamespaceInspectorArtifactRoleV1,
    ) -> Result<OwnedFd, ProtectedNamespaceInspectorDeploymentContractError> {
        let artifact = self
            .artifacts
            .iter()
            .find(|artifact| artifact.expectation.role == role)
            .ok_or(ProtectedNamespaceInspectorDeploymentContractError::Mismatch)?;
        artifact
            .descriptor
            .as_fd()
            .try_clone_to_owned()
            .map_err(|source| protected_io("duplicate deployment artifact", source))
    }

    /// Verifies one descriptor against a pinned deployment artifact.
    ///
    /// The artifact's retained content, metadata, and current pathname are
    /// revalidated before its device and inode are compared with `descriptor`.
    ///
    /// # Errors
    ///
    /// Returns an error when the role is absent, retained policy changed, or
    /// the supplied descriptor does not name the pinned artifact inode.
    pub(crate) fn verify_artifact_descriptor(
        &self,
        role: NamespaceInspectorArtifactRoleV1,
        descriptor: BorrowedFd<'_>,
    ) -> Result<(), ProtectedNamespaceInspectorDeploymentContractError> {
        let artifact = self
            .artifacts
            .iter()
            .find(|artifact| artifact.expectation.role == role)
            .ok_or(ProtectedNamespaceInspectorDeploymentContractError::Mismatch)?;
        artifact.revalidate()?;

        let observed = rustix::fs::fstat(descriptor).map_err(|source| {
            protected_io("inspect deployment artifact descriptor", source.into())
        })?;
        if observed.st_dev as u64 != artifact.device || observed.st_ino as u64 != artifact.inode {
            return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
        }
        Ok(())
    }

    /// Reopens every protected pathname and checks retained identity and content.
    ///
    /// # Errors
    ///
    /// Returns an error if any pathname no longer resolves to the exact pinned
    /// artifact or if retained metadata or content differs from the contract.
    pub(crate) fn revalidate(
        &self,
    ) -> Result<(), ProtectedNamespaceInspectorDeploymentContractError> {
        for artifact in &self.artifacts {
            artifact.revalidate()?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn for_test(
        contract: NamespaceInspectorDeploymentContractV1,
    ) -> Result<Self, NamespaceInspectorManagerQueryError> {
        let digest = contract.digest()?;
        Ok(Self {
            contract,
            digest,
            artifacts: Vec::new(),
        })
    }

    #[cfg(test)]
    pub(super) fn for_test_with_helper(
        mut contract: NamespaceInspectorDeploymentContractV1,
        helper: &Path,
    ) -> Result<Self, ProtectedNamespaceInspectorDeploymentContractError> {
        let canonical_path = helper
            .to_str()
            .ok_or(ProtectedNamespaceInspectorDeploymentContractError::Mismatch)?
            .to_owned();
        let descriptor = open_regular_nofollow(helper, "open test helper artifact")?;
        let metadata = descriptor
            .metadata()
            .map_err(|source| protected_io("inspect test helper artifact", source))?;
        let expectation = NamespaceInspectorArtifactExpectationV1 {
            role: NamespaceInspectorArtifactRoleV1::ManagerQueryHelperExecutable,
            canonical_path: canonical_path.clone(),
            content_digest: hash_artifact(
                &descriptor,
                metadata.len(),
                "hash test helper artifact",
            )?,
            expected_mode: metadata.mode() & 0o7777,
            expected_uid: metadata.uid(),
            expected_gid: metadata.gid(),
        };
        let helper_artifact = RetainedNamespaceInspectorArtifactV1::open(expectation.clone())?;

        contract.helper_arguments = vec![canonical_path];
        contract.artifacts[1] = expectation;
        let digest = contract.digest()?;
        Ok(Self {
            contract,
            digest,
            artifacts: vec![helper_artifact],
        })
    }
}

impl RetainedNamespaceInspectorArtifactV1 {
    fn open(
        expectation: NamespaceInspectorArtifactExpectationV1,
    ) -> Result<Self, ProtectedNamespaceInspectorDeploymentContractError> {
        let descriptor = open_regular_nofollow(
            Path::new(&expectation.canonical_path),
            "open deployment artifact",
        )?;
        let metadata = descriptor
            .metadata()
            .map_err(|source| protected_io("inspect deployment artifact", source))?;
        validate_artifact_metadata(&expectation, &metadata)?;
        let digest = hash_artifact(&descriptor, metadata.len(), "hash deployment artifact")?;
        if digest != expectation.content_digest {
            return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
        }

        let descriptor = open_regular_nofollow(
            Path::new(&expectation.canonical_path),
            "reopen deployment artifact",
        )?;
        let final_metadata = descriptor
            .metadata()
            .map_err(|source| protected_io("reinspect deployment artifact", source))?;
        validate_artifact_metadata(&expectation, &final_metadata)?;
        if metadata.dev() != final_metadata.dev()
            || metadata.ino() != final_metadata.ino()
            || metadata.len() != final_metadata.len()
        {
            return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
        }
        let final_digest = hash_artifact(
            &descriptor,
            final_metadata.len(),
            "rehash deployment artifact",
        )?;
        let stable_metadata = descriptor
            .metadata()
            .map_err(|source| protected_io("reinspect hashed deployment artifact", source))?;
        if final_digest != expectation.content_digest
            || final_metadata.len() != stable_metadata.len()
            || final_metadata.dev() != stable_metadata.dev()
            || final_metadata.ino() != stable_metadata.ino()
        {
            return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
        }

        Ok(Self {
            expectation,
            descriptor: descriptor.into(),
            device: final_metadata.dev(),
            inode: final_metadata.ino(),
            length: final_metadata.len(),
        })
    }

    fn revalidate(&self) -> Result<(), ProtectedNamespaceInspectorDeploymentContractError> {
        let retained = File::from(
            self.descriptor
                .as_fd()
                .try_clone_to_owned()
                .map_err(|source| protected_io("duplicate retained deployment artifact", source))?,
        );
        let retained_metadata = retained
            .metadata()
            .map_err(|source| protected_io("reinspect retained deployment artifact", source))?;
        validate_artifact_metadata(&self.expectation, &retained_metadata)?;
        if retained_metadata.dev() != self.device
            || retained_metadata.ino() != self.inode
            || retained_metadata.len() != self.length
        {
            return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
        }
        let retained_digest = hash_artifact(
            &retained,
            retained_metadata.len(),
            "rehash retained deployment artifact",
        )?;
        let stable_metadata = retained.metadata().map_err(|source| {
            protected_io("reinspect hashed retained deployment artifact", source)
        })?;
        if retained_digest != self.expectation.content_digest
            || retained_metadata.len() != stable_metadata.len()
            || retained_metadata.dev() != stable_metadata.dev()
            || retained_metadata.ino() != stable_metadata.ino()
        {
            return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
        }

        let current = open_regular_nofollow(
            Path::new(&self.expectation.canonical_path),
            "reopen current deployment artifact",
        )?;
        let current_metadata = current
            .metadata()
            .map_err(|source| protected_io("reinspect current deployment artifact", source))?;
        validate_artifact_metadata(&self.expectation, &current_metadata)?;
        if current_metadata.dev() != self.device || current_metadata.ino() != self.inode {
            return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
        }
        Ok(())
    }
}

fn open_regular_nofollow(
    path: &Path,
    operation: &'static str,
) -> Result<File, ProtectedNamespaceInspectorDeploymentContractError> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| protected_io(operation, source.into()))?;
    let file = File::from(descriptor);
    if !file
        .metadata()
        .map_err(|source| protected_io(operation, source))?
        .file_type()
        .is_file()
    {
        return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
    }
    Ok(file)
}

fn read_bounded(
    file: File,
    maximum: usize,
    operation: &'static str,
) -> Result<Vec<u8>, ProtectedNamespaceInspectorDeploymentContractError> {
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| protected_io(operation, source))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
    }
    Ok(bytes)
}

fn hash_artifact(
    file: &File,
    length: u64,
    operation: &'static str,
) -> Result<[u8; 32], ProtectedNamespaceInspectorDeploymentContractError> {
    if length == 0 || length > MAXIMUM_ARTIFACT_BYTES {
        return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
    }

    let mut digest = Sha256::new();
    let mut buffer = [0; ARTIFACT_HASH_BUFFER_BYTES];
    let mut offset = 0_u64;
    while offset < length {
        let remaining = length - offset;
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| ProtectedNamespaceInspectorDeploymentContractError::Mismatch)?;
        file.read_exact_at(&mut buffer[..count], offset)
            .map_err(|source| protected_io(operation, source))?;
        digest.update(&buffer[..count]);
        offset = offset
            .checked_add(count as u64)
            .ok_or(ProtectedNamespaceInspectorDeploymentContractError::Mismatch)?;
    }
    Ok(digest.finalize().into())
}

fn checked_aggregate_artifact_bytes(
    current: u64,
    next: u64,
) -> Result<u64, ProtectedNamespaceInspectorDeploymentContractError> {
    let total = current
        .checked_add(next)
        .ok_or(ProtectedNamespaceInspectorDeploymentContractError::Mismatch)?;
    if total > MAXIMUM_AGGREGATE_ARTIFACT_BYTES {
        return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
    }
    Ok(total)
}

fn validate_artifact_metadata(
    expectation: &NamespaceInspectorArtifactExpectationV1,
    metadata: &std::fs::Metadata,
) -> Result<(), ProtectedNamespaceInspectorDeploymentContractError> {
    let mode = metadata.mode() & 0o7777;
    let executable_role = matches!(
        expectation.role,
        NamespaceInspectorArtifactRoleV1::InspectorExecutable
            | NamespaceInspectorArtifactRoleV1::ManagerQueryHelperExecutable
    );
    if metadata.uid() != expectation.expected_uid
        || metadata.gid() != expectation.expected_gid
        || mode != expectation.expected_mode
        || mode & 0o222 != 0
        || executable_role != (mode & 0o111 != 0)
        || metadata.len() == 0
        || metadata.len() > MAXIMUM_ARTIFACT_BYTES
    {
        return Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch);
    }
    Ok(())
}

fn protected_io(
    operation: &'static str,
    source: std::io::Error,
) -> ProtectedNamespaceInspectorDeploymentContractError {
    ProtectedNamespaceInspectorDeploymentContractError::Io { operation, source }
}

impl NamespaceInspectorDeploymentContractV1 {
    /// Decodes bounded canonical bytes without authenticating their source.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceInspectorManagerQueryError`] when the record is
    /// oversized, malformed, noncanonical, truncated, or violates the closed
    /// artifact and static-property tables.
    pub(crate) fn decode_untrusted(
        bytes: &[u8],
    ) -> Result<Self, NamespaceInspectorManagerQueryError> {
        codec::decode_contract(bytes)
    }

    /// Encodes the canonical static deployment record.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceInspectorManagerQueryError`] when this value violates
    /// a structural limit or a closed table.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, NamespaceInspectorManagerQueryError> {
        self.validate()?;
        codec::encode_contract(self)
    }

    /// Computes the domain-separated digest of the canonical contract bytes.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceInspectorManagerQueryError`] when the contract cannot
    /// be canonically encoded.
    pub(crate) fn digest(
        &self,
    ) -> Result<NamespaceInspectorDeploymentDigestV1, NamespaceInspectorManagerQueryError> {
        let bytes = self.encode()?;
        let mut digest = Sha256::new();
        digest.update(CONTRACT_DIGEST_DOMAIN);
        digest.update(bytes);
        Ok(NamespaceInspectorDeploymentDigestV1::from_bytes(
            digest.finalize().into(),
        ))
    }

    pub(super) fn static_properties(&self) -> &[ManagerPropertyObservationV1] {
        &self.static_properties
    }

    pub(super) fn inspector_arguments(&self) -> &[String] {
        &self.inspector_arguments
    }

    pub(super) fn manager_query_helper(&self) -> Option<&str> {
        match self.helper_arguments.as_slice() {
            [helper] => Some(helper),
            _ => None,
        }
    }

    pub(super) fn service_unit_for_instance(
        &self,
        instance: &str,
    ) -> Result<String, NamespaceInspectorManagerQueryError> {
        if instance.is_empty()
            || !instance.is_ascii()
            || instance.len() > MAXIMUM_UNIT_NAME_BYTES
            || instance
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-'))
        {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }
        let Some(stem) = self.service_unit_template.strip_suffix("@.service") else {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        };
        let unit = format!("{stem}@{instance}.service");
        if unit.len() > MAXIMUM_UNIT_NAME_BYTES {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }
        Ok(unit)
    }

    pub(super) fn socket_unit(&self) -> &str {
        &self.socket_unit
    }

    pub(super) fn manager_socket_path(&self) -> &str {
        &self.manager_socket_path
    }

    pub(super) fn control_socket_path(&self) -> &str {
        &self.control_socket_path
    }

    pub(super) fn validate(&self) -> Result<(), NamespaceInspectorManagerQueryError> {
        validate_ordered_text(
            &self.inspector_arguments,
            MAXIMUM_ARGUMENTS,
            MAXIMUM_PATH_BYTES,
        )?;
        validate_ordered_text(
            &self.helper_arguments,
            MAXIMUM_ARGUMENTS,
            MAXIMUM_PATH_BYTES,
        )?;
        if self.inspector_arguments.is_empty()
            || self.helper_arguments.is_empty()
            || !absolute_path_is_valid(&self.inspector_arguments[0])
            || !absolute_path_is_valid(&self.helper_arguments[0])
            || !service_template_is_valid(&self.service_unit_template)
            || !socket_unit_is_valid(&self.socket_unit)
            || !absolute_path_is_valid(&self.control_socket_path)
            || !absolute_path_is_valid(&self.manager_socket_path)
        {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }

        validate_ordered_paths(&self.service_drop_in_paths)?;
        validate_ordered_paths(&self.socket_drop_in_paths)?;
        validate_ordered_paths(&self.read_only_paths)?;
        validate_ordered_paths(&self.read_write_paths)?;
        validate_ordered_paths(&self.inaccessible_paths)?;
        codec::validate_sorted_text_set(
            &self.allowed_environment_names,
            MAXIMUM_ENVIRONMENT_NAMES,
        )?;
        codec::validate_sorted_text_set(
            &self.forbidden_environment_names,
            MAXIMUM_ENVIRONMENT_NAMES,
        )?;
        for name in self
            .allowed_environment_names
            .iter()
            .chain(&self.forbidden_environment_names)
        {
            codec::validate_environment_name(name)?;
        }
        if self
            .allowed_environment_names
            .iter()
            .any(|name| self.forbidden_environment_names.binary_search(name).is_ok())
        {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }

        if self.artifacts.len() != ARTIFACT_COUNT {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }
        for (index, artifact) in self.artifacts.iter().enumerate() {
            artifact.validate()?;
            if usize::from(artifact.role.code()) != index + 1 {
                return Err(NamespaceInspectorManagerQueryError::InvalidContract);
            }
        }
        if self.artifacts[0].canonical_path != self.inspector_arguments[0]
            || self.artifacts[1].canonical_path != self.helper_arguments[0]
        {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }

        validate_property_sequence(&self.static_properties, true)?;
        self.validate_property_cross_links()
    }

    fn validate_property_cross_links(&self) -> Result<(), NamespaceInspectorManagerQueryError> {
        require_scalar_text_property(
            &self.static_properties,
            7,
            &self.artifacts[2].canonical_path,
        )?;
        require_ordered_text_property(&self.static_properties, 9, &self.service_drop_in_paths)?;
        require_fixed_exec_property(&self.static_properties, 34, &self.inspector_arguments)?;
        require_ordered_text_property(&self.static_properties, 74, &self.read_write_paths)?;
        require_ordered_text_property(&self.static_properties, 75, &self.read_only_paths)?;
        require_ordered_text_property(&self.static_properties, 76, &self.inaccessible_paths)?;
        require_scalar_text_property(
            &self.static_properties,
            99,
            &self.artifacts[3].canonical_path,
        )?;
        require_ordered_text_property(&self.static_properties, 101, &self.socket_drop_in_paths)?;
        require_socket_listener_property(&self.static_properties, 107, &self.control_socket_path)
    }

    pub(super) fn manager_environment_is_allowed(&self, elements: &[Vec<u8>]) -> bool {
        elements.iter().all(|element| {
            let Ok(value) = std::str::from_utf8(element) else {
                return false;
            };
            let Some((name, _)) = value.split_once('=') else {
                return false;
            };
            self.allowed_environment_names
                .binary_search_by(|candidate| candidate.as_str().cmp(name))
                .is_ok()
                && self
                    .forbidden_environment_names
                    .binary_search_by(|candidate| candidate.as_str().cmp(name))
                    .is_err()
        })
    }
}

fn static_property(
    properties: &[ManagerPropertyObservationV1],
    descriptor_id: u16,
) -> Result<&CanonicalManagerPropertyValueV1, NamespaceInspectorManagerQueryError> {
    properties
        .iter()
        .find(|property| property.descriptor_id == descriptor_id)
        .map(|property| &property.value)
        .ok_or(NamespaceInspectorManagerQueryError::InvalidContract)
}

fn require_scalar_text_property(
    properties: &[ManagerPropertyObservationV1],
    descriptor_id: u16,
    expected: &str,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    let CanonicalManagerPropertyValueV1::Scalar(observed) =
        static_property(properties, descriptor_id)?
    else {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    };
    if observed != expected.as_bytes() {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    }
    Ok(())
}

fn require_ordered_text_property(
    properties: &[ManagerPropertyObservationV1],
    descriptor_id: u16,
    expected: &[String],
) -> Result<(), NamespaceInspectorManagerQueryError> {
    let CanonicalManagerPropertyValueV1::OrderedArray(observed) =
        static_property(properties, descriptor_id)?
    else {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    };
    if !observed
        .iter()
        .map(Vec::as_slice)
        .eq(expected.iter().map(String::as_bytes))
    {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    }
    Ok(())
}

fn require_fixed_exec_property(
    properties: &[ManagerPropertyObservationV1],
    descriptor_id: u16,
    expected_arguments: &[String],
) -> Result<(), NamespaceInspectorManagerQueryError> {
    let CanonicalManagerPropertyValueV1::OrderedArray(commands) =
        static_property(properties, descriptor_id)?
    else {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    };
    let [command] = commands.as_slice() else {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    };
    let (executable, arguments, ignore_failure) =
        codec::decode_fixed_exec_command_projection(command)?;
    if ignore_failure
        || executable != expected_arguments[0]
        || !arguments
            .iter()
            .copied()
            .eq(expected_arguments.iter().map(String::as_str))
    {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    }
    Ok(())
}

fn require_socket_listener_property(
    properties: &[ManagerPropertyObservationV1],
    descriptor_id: u16,
    expected_path: &str,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    let CanonicalManagerPropertyValueV1::OrderedArray(listeners) =
        static_property(properties, descriptor_id)?
    else {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    };
    let [listener] = listeners.as_slice() else {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    };
    let (kind, path) = codec::decode_string_pair(listener)?;
    if kind != "SequentialPacket" || path != expected_path {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    }
    Ok(())
}

fn absolute_path_is_valid(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    !path.is_empty()
        && path.len() <= MAXIMUM_PATH_BYTES
        && path.starts_with('/')
        && !path.ends_with('/')
        && !path.as_bytes().contains(&0)
        && path[1..]
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn unit_stem_is_valid(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= MAXIMUM_UNIT_NAME_BYTES
        && unit.is_ascii()
        && !unit.as_bytes().contains(&0)
        && unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'-'))
}

fn service_template_is_valid(unit: &str) -> bool {
    unit.len() <= MAXIMUM_UNIT_NAME_BYTES
        && unit
            .strip_suffix("@.service")
            .is_some_and(unit_stem_is_valid)
}

fn socket_unit_is_valid(unit: &str) -> bool {
    unit.len() <= MAXIMUM_UNIT_NAME_BYTES
        && unit.strip_suffix(".socket").is_some_and(unit_stem_is_valid)
}

fn validate_ordered_paths(paths: &[String]) -> Result<(), NamespaceInspectorManagerQueryError> {
    if paths.len() > codec::MAXIMUM_COLLECTION_ELEMENTS
        || paths.iter().any(|path| !absolute_path_is_valid(path))
    {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    }
    Ok(())
}

fn validate_ordered_text(
    values: &[String],
    maximum_elements: usize,
    maximum_bytes: usize,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    if values.len() > maximum_elements {
        return Err(NamespaceInspectorManagerQueryError::FieldTooLarge);
    }
    for value in values {
        if value.is_empty() || value.len() > maximum_bytes {
            return Err(NamespaceInspectorManagerQueryError::InvalidText);
        }
        codec::validate_text(value)?;
    }
    Ok(())
}

pub(super) fn encode_contract_body(
    contract: &NamespaceInspectorDeploymentContractV1,
    encoder: &mut Encoder,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    encoder.strings(&contract.inspector_arguments)?;
    encoder.strings(&contract.helper_arguments)?;
    encoder.text(&contract.service_unit_template)?;
    encoder.text(&contract.socket_unit)?;
    encoder.text(&contract.control_socket_path)?;
    encoder.text(&contract.manager_socket_path)?;
    encoder.strings(&contract.service_drop_in_paths)?;
    encoder.strings(&contract.socket_drop_in_paths)?;
    encoder.strings(&contract.read_only_paths)?;
    encoder.strings(&contract.read_write_paths)?;
    encoder.strings(&contract.inaccessible_paths)?;
    encoder.strings(&contract.allowed_environment_names)?;
    encoder.strings(&contract.forbidden_environment_names)?;

    encoder.count(contract.artifacts.len())?;
    for artifact in &contract.artifacts {
        encoder.u8(artifact.role.code());
        encoder.text(&artifact.canonical_path)?;
        encoder.bytes(&artifact.content_digest);
        encoder.u32(artifact.expected_mode);
        encoder.u32(artifact.expected_uid);
        encoder.u32(artifact.expected_gid);
    }
    encoder.properties(&contract.static_properties)?;
    Ok(())
}

pub(super) fn decode_contract_body(
    decoder: &mut Decoder<'_>,
) -> Result<NamespaceInspectorDeploymentContractV1, NamespaceInspectorManagerQueryError> {
    let inspector_arguments = decoder.strings(MAXIMUM_ARGUMENTS, MAXIMUM_PATH_BYTES)?;
    let helper_arguments = decoder.strings(MAXIMUM_ARGUMENTS, MAXIMUM_PATH_BYTES)?;
    let service_unit_template = decoder.text(MAXIMUM_UNIT_NAME_BYTES)?;
    let socket_unit = decoder.text(MAXIMUM_UNIT_NAME_BYTES)?;
    let control_socket_path = decoder.text(MAXIMUM_PATH_BYTES)?;
    let manager_socket_path = decoder.text(MAXIMUM_PATH_BYTES)?;
    let service_drop_in_paths =
        decoder.strings(codec::MAXIMUM_COLLECTION_ELEMENTS, MAXIMUM_PATH_BYTES)?;
    let socket_drop_in_paths =
        decoder.strings(codec::MAXIMUM_COLLECTION_ELEMENTS, MAXIMUM_PATH_BYTES)?;
    let read_only_paths =
        decoder.strings(codec::MAXIMUM_COLLECTION_ELEMENTS, MAXIMUM_PATH_BYTES)?;
    let read_write_paths =
        decoder.strings(codec::MAXIMUM_COLLECTION_ELEMENTS, MAXIMUM_PATH_BYTES)?;
    let inaccessible_paths =
        decoder.strings(codec::MAXIMUM_COLLECTION_ELEMENTS, MAXIMUM_PATH_BYTES)?;
    let allowed_environment_names =
        decoder.strings(MAXIMUM_ENVIRONMENT_NAMES, codec::MAXIMUM_TEXT_BYTES)?;
    let forbidden_environment_names =
        decoder.strings(MAXIMUM_ENVIRONMENT_NAMES, codec::MAXIMUM_TEXT_BYTES)?;

    let artifact_count = decoder.count(ARTIFACT_COUNT)?;
    if artifact_count != ARTIFACT_COUNT {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    }
    let mut artifacts = Vec::with_capacity(artifact_count);
    for _ in 0..artifact_count {
        artifacts.push(NamespaceInspectorArtifactExpectationV1 {
            role: NamespaceInspectorArtifactRoleV1::from_code(decoder.u8()?)?,
            canonical_path: decoder.text(MAXIMUM_PATH_BYTES)?,
            content_digest: decoder.array()?,
            expected_mode: decoder.u32()?,
            expected_uid: decoder.u32()?,
            expected_gid: decoder.u32()?,
        });
    }
    let static_properties = decoder.properties(true)?;

    let contract = NamespaceInspectorDeploymentContractV1 {
        inspector_arguments,
        helper_arguments,
        service_unit_template,
        socket_unit,
        control_socket_path,
        manager_socket_path,
        service_drop_in_paths,
        socket_drop_in_paths,
        read_only_paths,
        read_write_paths,
        inaccessible_paths,
        allowed_environment_names,
        forbidden_environment_names,
        artifacts,
        static_properties,
    };
    contract.validate()?;
    Ok(contract)
}

pub(super) const fn contract_magic() -> &'static [u8; 8] {
    CONTRACT_MAGIC
}

pub(super) const fn contract_kind() -> u8 {
    CONTRACT_KIND
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::namespace_inspector::manager_query::codec::test_properties;
    use std::io::{Seek as _, Write as _};

    pub(in crate::namespace_inspector) fn contract() -> NamespaceInspectorDeploymentContractV1 {
        let inspector = "/bin/aos-sandbox-network-namespace-inspector";
        let service_fragment = "/etc/systemd/system/inspector-service.conf";
        let socket_fragment = "/etc/systemd/system/inspector-socket.conf";
        let control_socket = "/run/aos/sandbox-network-namespace-inspector/control.sock";
        let service_drop_ins = vec!["/etc/systemd/system/inspector-service.conf".into()];
        let socket_drop_ins = vec!["/etc/systemd/system/inspector-socket.conf".into()];
        let read_only_paths =
            vec!["/var/lib/aos/sandbox-network/namespace-inspector/expected-final".into()];
        let read_write_paths = vec![
            "/var/lib/aos/sandbox-network/namespace-inspector/spent-staging".into(),
            "/var/lib/aos/sandbox-network/namespace-inspector/spent-final".into(),
        ];
        let inaccessible_paths = vec![
            "/var/lib/aos/sandbox-network/broker-state".into(),
            "/var/lib/aos/sandbox-network/namespace-inspector/expected-staging".into(),
        ];
        let mut static_properties = test_properties(true);
        set_property_scalar(&mut static_properties, 7, service_fragment);
        set_property_strings(&mut static_properties, 9, &service_drop_ins);
        set_property_elements(
            &mut static_properties,
            34,
            vec![encode_exec_projection(inspector, &[inspector], false)],
        );
        set_property_strings(&mut static_properties, 74, &read_write_paths);
        set_property_strings(&mut static_properties, 75, &read_only_paths);
        set_property_strings(&mut static_properties, 76, &inaccessible_paths);
        set_property_scalar(&mut static_properties, 99, socket_fragment);
        set_property_strings(&mut static_properties, 101, &socket_drop_ins);
        set_property_elements(
            &mut static_properties,
            107,
            vec![encode_text_pair("SequentialPacket", control_socket)],
        );

        NamespaceInspectorDeploymentContractV1 {
            inspector_arguments: vec![inspector.into()],
            helper_arguments: vec!["/bin/aos-systemd-manager-query".into()],
            service_unit_template: "aos-sandbox-network-namespace-inspector@.service".into(),
            socket_unit: "aos-sandbox-network-namespace-inspector.socket".into(),
            control_socket_path: control_socket.into(),
            manager_socket_path: "/run/systemd/private".into(),
            service_drop_in_paths: service_drop_ins,
            socket_drop_in_paths: socket_drop_ins,
            read_only_paths,
            read_write_paths,
            inaccessible_paths,
            allowed_environment_names: vec!["LANG".into(), "PATH".into()],
            forbidden_environment_names: vec![
                "LD_AUDIT".into(),
                "LD_LIBRARY_PATH".into(),
                "LD_PRELOAD".into(),
            ],
            artifacts: vec![
                NamespaceInspectorArtifactExpectationV1 {
                    role: NamespaceInspectorArtifactRoleV1::InspectorExecutable,
                    canonical_path: inspector.into(),
                    content_digest: [1; 32],
                    expected_mode: 0o555,
                    expected_uid: 0,
                    expected_gid: 0,
                },
                NamespaceInspectorArtifactExpectationV1 {
                    role: NamespaceInspectorArtifactRoleV1::ManagerQueryHelperExecutable,
                    canonical_path: "/bin/aos-systemd-manager-query".into(),
                    content_digest: [2; 32],
                    expected_mode: 0o555,
                    expected_uid: 0,
                    expected_gid: 0,
                },
                NamespaceInspectorArtifactExpectationV1 {
                    role: NamespaceInspectorArtifactRoleV1::InspectorServiceFragment,
                    canonical_path: service_fragment.into(),
                    content_digest: [3; 32],
                    expected_mode: 0o444,
                    expected_uid: 0,
                    expected_gid: 0,
                },
                NamespaceInspectorArtifactExpectationV1 {
                    role: NamespaceInspectorArtifactRoleV1::InspectorSocketFragment,
                    canonical_path: socket_fragment.into(),
                    content_digest: [4; 32],
                    expected_mode: 0o444,
                    expected_uid: 0,
                    expected_gid: 0,
                },
            ],
            static_properties,
        }
    }

    fn property_mut(
        properties: &mut [ManagerPropertyObservationV1],
        descriptor_id: u16,
    ) -> &mut CanonicalManagerPropertyValueV1 {
        &mut properties
            .iter_mut()
            .find(|property| property.descriptor_id == descriptor_id)
            .unwrap()
            .value
    }

    fn set_property_scalar(
        properties: &mut [ManagerPropertyObservationV1],
        descriptor_id: u16,
        value: &str,
    ) {
        *property_mut(properties, descriptor_id) =
            CanonicalManagerPropertyValueV1::Scalar(value.as_bytes().to_vec());
    }

    fn set_property_strings(
        properties: &mut [ManagerPropertyObservationV1],
        descriptor_id: u16,
        values: &[String],
    ) {
        *property_mut(properties, descriptor_id) = CanonicalManagerPropertyValueV1::OrderedArray(
            values
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect(),
        );
    }

    fn set_property_elements(
        properties: &mut [ManagerPropertyObservationV1],
        descriptor_id: u16,
        values: Vec<Vec<u8>>,
    ) {
        *property_mut(properties, descriptor_id) =
            CanonicalManagerPropertyValueV1::OrderedArray(values);
    }

    fn encode_text(buffer: &mut Vec<u8>, value: &str) {
        buffer.extend_from_slice(&(value.len() as u16).to_le_bytes());
        buffer.extend_from_slice(value.as_bytes());
    }

    fn encode_exec_projection(executable: &str, arguments: &[&str], ignore: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        encode_text(&mut bytes, executable);
        bytes.extend_from_slice(&(arguments.len() as u16).to_le_bytes());
        for argument in arguments {
            encode_text(&mut bytes, argument);
        }
        bytes.push(u8::from(ignore));
        bytes
    }

    fn encode_text_pair(first: &str, second: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        encode_text(&mut bytes, first);
        encode_text(&mut bytes, second);
        bytes
    }

    #[test]
    fn contract_round_trip_and_digest_are_canonical() {
        let expected = contract();
        let bytes = expected.encode().unwrap();
        let decoded = NamespaceInspectorDeploymentContractV1::decode_untrusted(&bytes).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(
            *decoded.digest().unwrap().as_bytes(),
            [
                155, 205, 137, 39, 81, 3, 52, 193, 119, 41, 133, 60, 53, 225, 135, 241, 165, 76,
                174, 1, 119, 153, 87, 92, 217, 85, 214, 59, 70, 27, 44, 251,
            ]
        );
    }

    #[test]
    fn artifact_hashing_streams_the_maximum_sparse_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large-sparse-artifact");
        let file = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.set_len(MAXIMUM_ARTIFACT_BYTES).unwrap();

        assert_ne!(
            hash_artifact(&file, MAXIMUM_ARTIFACT_BYTES, "hash sparse test artifact").unwrap(),
            [0; 32]
        );
    }

    #[test]
    fn artifact_hashing_rejects_truncation_and_observes_content_change() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mutable-artifact");
        let mut file = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.write_all(b"original").unwrap();
        let original = hash_artifact(&file, 8, "hash original test artifact").unwrap();

        file.rewind().unwrap();
        file.write_all(b"changed!").unwrap();
        let changed = hash_artifact(&file, 8, "hash changed test artifact").unwrap();
        assert_ne!(changed, original);

        file.set_len(0).unwrap();
        assert!(hash_artifact(&file, 8, "hash truncated test artifact").is_err());
    }

    #[test]
    fn artifact_size_budgets_are_independent_and_aggregate() {
        assert_eq!(MAXIMUM_ARTIFACT_BYTES, 32 * 1024 * 1024);
        assert_eq!(MAXIMUM_AGGREGATE_ARTIFACT_BYTES, 2 * MAXIMUM_ARTIFACT_BYTES);

        let accepted = [16_u64, 16, 16, 16]
            .into_iter()
            .map(|mebibytes| mebibytes * 1024 * 1024)
            .try_fold(0_u64, checked_aggregate_artifact_bytes)
            .unwrap();
        assert_eq!(accepted, MAXIMUM_AGGREGATE_ARTIFACT_BYTES);

        assert!(checked_aggregate_artifact_bytes(accepted, 1).is_err());
        assert!(checked_aggregate_artifact_bytes(u64::MAX, 1).is_err());
    }

    #[test]
    fn path_and_argv_order_are_digest_significant() {
        let expected = contract();
        let expected_digest = expected.digest().unwrap();

        let mut reordered_paths = expected.clone();
        reordered_paths.read_write_paths.swap(0, 1);
        let reordered = reordered_paths.read_write_paths.clone();
        set_property_strings(&mut reordered_paths.static_properties, 74, &reordered);
        assert_ne!(reordered_paths.digest().unwrap(), expected_digest);

        let mut extended_argv = expected.clone();
        extended_argv.inspector_arguments.push("unexpected".into());
        set_property_elements(
            &mut extended_argv.static_properties,
            34,
            vec![encode_exec_projection(
                "/bin/aos-sandbox-network-namespace-inspector",
                &["/bin/aos-sandbox-network-namespace-inspector", "unexpected"],
                false,
            )],
        );
        assert_ne!(extended_argv.digest().unwrap(), expected_digest);
    }

    #[test]
    fn redundant_policy_fields_must_match_manager_properties() {
        for descriptor_id in [7, 99] {
            let mut wrong_fragment = contract();
            set_property_scalar(
                &mut wrong_fragment.static_properties,
                descriptor_id,
                "/wrong/fragment",
            );
            assert_eq!(
                wrong_fragment.encode(),
                Err(NamespaceInspectorManagerQueryError::InvalidContract)
            );
        }

        for descriptor_id in [9, 74, 75, 76, 101] {
            let mut wrong_paths = contract();
            set_property_strings(&mut wrong_paths.static_properties, descriptor_id, &[]);
            assert_eq!(
                wrong_paths.encode(),
                Err(NamespaceInspectorManagerQueryError::InvalidContract)
            );
        }

        let mut wrong_exec = contract();
        set_property_elements(
            &mut wrong_exec.static_properties,
            34,
            vec![encode_exec_projection(
                "/wrong/inspector",
                &["/wrong/inspector"],
                false,
            )],
        );
        assert_eq!(
            wrong_exec.encode(),
            Err(NamespaceInspectorManagerQueryError::InvalidContract)
        );

        let mut wrong_listener = contract();
        set_property_elements(
            &mut wrong_listener.static_properties,
            107,
            vec![encode_text_pair("SequentialPacket", "/wrong/socket")],
        );
        assert_eq!(
            wrong_listener.encode(),
            Err(NamespaceInspectorManagerQueryError::InvalidContract)
        );
    }

    #[test]
    fn manager_environment_policy_is_a_closed_name_allowlist() {
        let expected = contract();
        assert!(
            expected.manager_environment_is_allowed(&[b"LANG=C".to_vec(), b"PATH=/bin".to_vec(),])
        );
        assert!(!expected.manager_environment_is_allowed(&[b"HOME=/root".to_vec()]));
        assert!(!expected.manager_environment_is_allowed(&[b"LD_PRELOAD=x".to_vec()]));
    }

    #[test]
    fn environment_name_sets_require_canonical_order() {
        let mut expected = contract();
        expected.forbidden_environment_names.swap(0, 1);
        assert_eq!(
            expected.encode(),
            Err(NamespaceInspectorManagerQueryError::NoncanonicalSet)
        );
    }

    #[test]
    fn artifact_roles_are_closed_and_ordered() {
        let mut expected = contract();
        expected.artifacts.swap(0, 1);
        assert_eq!(
            expected.encode(),
            Err(NamespaceInspectorManagerQueryError::InvalidContract)
        );
    }

    #[test]
    fn paths_are_absolute_and_lexically_canonical() {
        for path in [
            "relative/path",
            "/trailing/",
            "/repeated//separator",
            "/current/./entry",
            "/parent/../entry",
        ] {
            let mut expected = contract();
            expected.control_socket_path = path.into();
            assert_eq!(
                expected.encode(),
                Err(NamespaceInspectorManagerQueryError::InvalidContract)
            );
        }
    }

    #[test]
    fn unit_names_use_fixed_template_and_socket_grammars() {
        for service in [
            "inspector.service",
            "inspector@instance.service",
            "inspector @.service",
            "path/inspector@.service",
        ] {
            let mut expected = contract();
            expected.service_unit_template = service.into();
            assert_eq!(
                expected.encode(),
                Err(NamespaceInspectorManagerQueryError::InvalidContract)
            );
        }
        for socket in ["inspector@.socket", "inspector.socket/", "inspector socket"] {
            let mut expected = contract();
            expected.socket_unit = socket.into();
            assert_eq!(
                expected.encode(),
                Err(NamespaceInspectorManagerQueryError::InvalidContract)
            );
        }

        let mut expected = contract();
        expected.service_unit_template = format!(
            "{}@.service",
            "a".repeat(MAXIMUM_UNIT_NAME_BYTES - "@.service".len() + 1)
        );
        assert_eq!(
            expected.encode(),
            Err(NamespaceInspectorManagerQueryError::InvalidContract)
        );

        let mut expected = contract();
        expected.socket_unit = format!(
            "{}.socket",
            "a".repeat(MAXIMUM_UNIT_NAME_BYTES - ".socket".len() + 1)
        );
        assert_eq!(
            expected.encode(),
            Err(NamespaceInspectorManagerQueryError::InvalidContract)
        );
    }

    #[test]
    fn environment_policy_names_use_variable_grammar() {
        for name in ["1BAD", "BAD-NAME", "BAD=VALUE"] {
            let mut expected = contract();
            expected.allowed_environment_names = vec![name.into()];
            assert_eq!(
                expected.encode(),
                Err(NamespaceInspectorManagerQueryError::InvalidText)
            );
        }
    }

    #[test]
    fn static_digest_has_no_runtime_identity_fields() {
        let fields = format!("{:#?}", contract());
        for forbidden in [
            "device_id",
            "inode",
            "pidfd",
            "control_group_id",
            "invocation_id",
            "accepted_socket_cookie",
        ] {
            assert!(!fields.contains(forbidden));
        }
    }
}
