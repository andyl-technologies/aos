//! Trusted catalog resolution and fixed nspawn launch compilation.
//!
//! Phase-0 backend readiness claims may be ingested from a root-owned systemd
//! credential. Its bounded JSON schema is intentionally node-local rather than
//! a controller protocol:
//!
//! ```text
//! {
//!   "schema": "aos.sandbox.host-backend-readiness.v1",
//!   "publisher_generation": 42,
//!   "boot_id": [16 bytes],
//!   "nspawn_store_path": "/nix/store/.../bin/systemd-nspawn",
//!   "nspawn_device": 1,
//!   "nspawn_inode": 2,
//!   "probe_digest": [32 bytes],
//!   "supervisor_profile_digest": [32 bytes],
//!   "payload_filter_digest": [32 bytes]
//! }
//! ```
//!
//! When the optional credential is present, the last accepted generation and
//! exact artifact digest are atomically persisted in
//! `backend-readiness-watermark.json`. The generation is global across boots,
//! so a publisher must increment it before publishing evidence for a new boot.
//! The protected digests remain publisher claims until independent runtime
//! checks verify what they name. Ingestion is therefore necessary but
//! deliberately insufficient to create [`BackendReadiness`].

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::pidfd::NamespaceFd;
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedRuntimePlan};
use aos_systemd::{
    SandboxDescriptorPath, SandboxResolvedPaths, SandboxResources, SandboxUnitName, SandboxUnitSpec,
};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{HostError, Result};

#[cfg(all(test, feature = "kernel-tests"))]
mod kernel_tests;

const PROCESSES: u8 = 2;
const MEMORY: u8 = 3;
const CPU_WEIGHT: u8 = 4;
const CPU_QUOTA: u8 = 5;
const IO_WEIGHT: u8 = 6;
const OPEN_FILES: u8 = 9;
const MICROS_PER_SECOND: u64 = 1_000_000;
const READINESS_CREDENTIAL_FILE: &str = "backend-readiness.json";
const READINESS_SCHEMA: &str = "aos.sandbox.host-backend-readiness.v1";
const MAXIMUM_READINESS_BYTES: usize = 16 * 1024;
const READINESS_WATERMARK_FILE: &str = "backend-readiness-watermark.json";
const READINESS_WATERMARK_NEXT: &str = "backend-readiness-watermark.next";
const READINESS_WATERMARK_SCHEMA: &str = "aos.sandbox.host-backend-readiness-watermark.v1";
const MAXIMUM_WATERMARK_BYTES: usize = 4096;
pub(crate) const WORKSPACE_PIN_PREFIX: &str = "/run/aos/sandbox-pins/workspaces/";
pub(crate) const NETWORK_PIN_PREFIX: &str = "/run/aos/sandbox-pins/netns/";
const SUPPORTED_BACKEND_FEATURES: &[(&str, u32, u32)] = &[
    ("aos.sandbox.runtime.linux-systemd", 1, 0),
    ("aos.sandbox.identity.posix32", 1, 0),
    ("aos.sandbox.enforcement.cgroup-v2", 1, 0),
    ("aos.sandbox.enforcement.broker-ledger", 1, 0),
];

/// Names an opaque catalog handle carried only inside the local protocol.
pub type OpaqueHandle = [u8; 32];

/// Describes a broker-catalogued private root after identity verification.
#[derive(Debug)]
pub struct ResolvedWorkspace {
    /// Absolute directory containing the assembled private sandbox root.
    pub root_directory: String,
    /// Device identity verified against the publisher record.
    pub device: u64,
    /// Inode identity verified against the publisher record.
    pub inode: u64,
    pin: OwnedFd,
}

impl ResolvedWorkspace {
    /// Constructs a workspace only when its descriptor has the catalogued identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor cannot be inspected or its device
    /// and inode differ from the trusted catalog record.
    pub fn from_pinned(
        root_directory: String,
        device: u64,
        inode: u64,
        pin: OwnedFd,
    ) -> Result<Self> {
        let identity =
            rustix::fs::fstat(&pin).map_err(|error| HostError::Catalog(error.to_string()))?;
        if identity.st_dev != device || identity.st_ino != inode {
            return Err(HostError::Catalog(
                "workspace descriptor identity changed".to_owned(),
            ));
        }
        Ok(Self {
            root_directory,
            device,
            inode,
            pin,
        })
    }
}

/// Describes a broker-catalogued prepared network namespace.
#[derive(Debug)]
pub struct ResolvedNetwork {
    /// Absolute path to a host-owned pinned network namespace descriptor.
    pub namespace_path: String,
    /// Nsfs device identity verified against the publisher record.
    pub device: u64,
    /// Namespace inode identity verified against the publisher record.
    pub inode: u64,
    pin: NamespaceFd,
}

impl ResolvedNetwork {
    /// Constructs a network resource from its type-checked namespace pin.
    ///
    /// # Errors
    ///
    /// Returns an error when the namespace identity differs from the trusted
    /// catalog record.
    pub fn from_pinned(
        namespace_path: String,
        device: u64,
        inode: u64,
        pin: NamespaceFd,
    ) -> Result<Self> {
        let identity = pin.identity();
        if identity.device != device || identity.inode != inode {
            return Err(HostError::Catalog(
                "network descriptor identity changed".to_owned(),
            ));
        }
        Ok(Self {
            namespace_path,
            device,
            inode,
            pin,
        })
    }
}

/// Describes an incarnation-bound subordinate UID/GID allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedIdentityAllocation {
    /// First host identity mapped to guest identity zero.
    pub range_start: u32,
    /// Number of mapped identities.
    pub range_size: u32,
    /// Catalog generation that allocated this nonoverlapping range.
    pub catalog_generation: u64,
}

/// Carries one assignment-bound, atomically resolved launch resource tuple.
#[derive(Debug)]
pub struct ResolvedLaunchResources {
    /// Private assembled runtime root.
    pub workspace: ResolvedWorkspace,
    /// Prepared default-drop network namespace.
    pub network: ResolvedNetwork,
    /// Incarnation-bound private user-namespace allocation.
    pub identity: ResolvedIdentityAllocation,
}

/// Retains the exact workspace and network objects resolved for one launch.
///
/// Holding these descriptors prevents the underlying objects from disappearing
/// while a launch is in flight. It does not by itself authorize reopening the
/// catalog paths; production readiness additionally requires a descriptor-based
/// handoff to systemd and post-launch identity verification.
#[derive(Debug)]
pub struct LaunchPins {
    executable: Arc<OwnedFd>,
    workspace: OwnedFd,
    network: NamespaceFd,
}

impl LaunchPins {
    /// Returns the pinned nspawn executable descriptor.
    #[must_use]
    pub fn executable(&self) -> BorrowedFd<'_> {
        self.executable.as_fd()
    }

    /// Returns the pinned workspace directory descriptor.
    #[must_use]
    pub fn workspace(&self) -> BorrowedFd<'_> {
        self.workspace.as_fd()
    }

    /// Returns the pinned prepared network namespace descriptor.
    #[must_use]
    pub fn network(&self) -> &NamespaceFd {
        &self.network
    }

    #[cfg(test)]
    pub(crate) fn for_tests(executable: OwnedFd, workspace: OwnedFd, network: NamespaceFd) -> Self {
        Self {
            executable: Arc::new(executable),
            workspace,
            network,
        }
    }
}

/// Couples a fixed systemd unit specification to its kernel object pins.
#[derive(Debug)]
pub struct PreparedLaunch {
    spec: SandboxUnitSpec,
    pins: LaunchPins,
}

impl PreparedLaunch {
    /// Returns the fixed transient-unit specification.
    #[must_use]
    pub const fn spec(&self) -> &SandboxUnitSpec {
        &self.spec
    }

    pub(crate) fn into_parts(self) -> (SandboxUnitSpec, LaunchPins) {
        (self.spec, self.pins)
    }
}

/// Resolves only broker-minted node-local handles into privileged resources.
pub trait HostCatalog {
    /// Resolves and verifies one atomic workspace/network/attachment snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown, stale, mismatched, or unready handle.
    fn resolve(
        &self,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
    ) -> Result<ResolvedLaunchResources>;
}

/// Proves that the exact node-local nspawn backend passed all executable gates.
///
/// The type intentionally has no production constructor yet. Protected phase-0
/// evidence is represented by [`ProtectedBackendReadinessEvidence`]. The
/// closed unit compiler now supplies a root-continuity policy witness, and the
/// worker verifies point-in-time payload-root identity, but the artifact still
/// does not independently bind the deployed profile or prove pidfd namespace
/// access to a user-namespace-shifted payload. Until those checks can be
/// combined mechanically, hostd cannot construct this token and does not
/// advertise runtime launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendReadiness {
    executable: String,
    executable_device: u64,
    executable_inode: u64,
    probe_generation: u64,
    mac_policy_digest: [u8; 32],
    supervisor_profile_digest: [u8; 32],
    payload_filter_digest: [u8; 32],
}

/// Names runtime proofs which protected phase-0 evidence cannot establish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendReadinessBlocker {
    /// No trusted implementation has verified the declared probe and profile digests.
    Phase0ClaimVerification,
    /// Self-inspection does not prove ptrace access to a user-namespace-shifted payload.
    ShiftedPayloadPidfdNamespaceInspection,
    /// The compiled root policy is not yet bound to independently verified deployment evidence.
    PayloadRootPolicyDeploymentVerification,
}

/// Holds protected, boot-bound phase-0 publisher claims without authorizing launch.
///
/// Protection establishes the artifact's local source and exact bytes; it does
/// not independently verify the probe, profile, or filter named by its digests.
/// The type deliberately offers no conversion into [`BackendReadiness`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedBackendReadinessEvidence {
    publisher_generation: u64,
    boot_id: [u8; 16],
    executable: String,
    executable_device: u64,
    executable_inode: u64,
    probe_digest: [u8; 32],
    supervisor_profile_digest: [u8; 32],
    payload_filter_digest: [u8; 32],
}

impl ProtectedBackendReadinessEvidence {
    /// Loads and rollback-protects one systemd-provisioned readiness artifact.
    ///
    /// The loader reads the fixed `backend-readiness.json` child of a private,
    /// root-owned systemd credential directory. It binds the artifact to the
    /// current boot and exact configured store executable, then atomically
    /// advances a private publisher-generation watermark in `state_directory`.
    /// An equal generation is accepted only for byte-identical restart replay.
    /// Generations are global, not reset by a boot, so new-boot publication
    /// must use a generation greater than the durable prior watermark.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, oversized, symlinked, multiply linked,
    /// publicly writable, stale, equivocated, malformed, wrong-boot, or
    /// executable-identity-mismatched evidence, or when its durable watermark
    /// cannot be read or synchronized.
    pub fn load_protected(
        credential_directory: impl AsRef<Path>,
        state_directory: impl AsRef<Path>,
        expected_executable: &str,
    ) -> Result<Self> {
        Self::load_protected_optional(credential_directory, state_directory, expected_executable)?
            .ok_or_else(|| HostError::State("backend readiness credential is absent".to_owned()))
    }

    /// Loads optional protected claims without gating observation-only service.
    ///
    /// Absence returns `None`, allowing non-authorizing Observe and Inventory
    /// methods to remain available. A present credential receives the same
    /// fail-closed validation and rollback protection as
    /// [`Self::load_protected`].
    ///
    /// # Errors
    ///
    /// Returns an error when the directory is unprotected or a present artifact
    /// is invalid, stale, equivocated, or cannot advance its durable watermark.
    pub fn load_protected_optional(
        credential_directory: impl AsRef<Path>,
        state_directory: impl AsRef<Path>,
        expected_executable: &str,
    ) -> Result<Option<Self>> {
        validate_fixed_nspawn_path(expected_executable)?;
        let Some(artifact_bytes) = read_protected_artifact_optional(credential_directory.as_ref())?
        else {
            return Ok(None);
        };
        let artifact_digest: [u8; 32] = Sha256::digest(&artifact_bytes).into();
        let wire: BackendReadinessArtifact = serde_json::from_slice(&artifact_bytes)
            .map_err(|_| HostError::State("backend readiness artifact is malformed".to_owned()))?;
        let current_boot_id = KernelBootId::current()
            .map_err(|error| HostError::State(error.to_string()))?
            .into_bytes();
        let evidence = verify_readiness(wire, current_boot_id, expected_executable)?;

        persist_readiness_watermark(
            state_directory.as_ref(),
            ReadinessWatermark {
                schema: READINESS_WATERMARK_SCHEMA.to_owned(),
                publisher_generation: evidence.publisher_generation,
                boot_id: evidence.boot_id,
                artifact_sha256: artifact_digest,
            },
        )?;
        Ok(Some(evidence))
    }

    /// Returns the monotonic publisher generation accepted at startup.
    #[must_use]
    pub const fn publisher_generation(&self) -> u64 {
        self.publisher_generation
    }

    /// Returns the current blockers which keep phase-0 evidence from authorizing launch.
    #[must_use]
    pub const fn runtime_blockers(&self) -> [BackendReadinessBlocker; 3] {
        [
            BackendReadinessBlocker::Phase0ClaimVerification,
            BackendReadinessBlocker::ShiftedPayloadPidfdNamespaceInspection,
            BackendReadinessBlocker::PayloadRootPolicyDeploymentVerification,
        ]
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendReadinessArtifact {
    schema: String,
    publisher_generation: u64,
    boot_id: [u8; 16],
    nspawn_store_path: String,
    nspawn_device: u64,
    nspawn_inode: u64,
    probe_digest: [u8; 32],
    supervisor_profile_digest: [u8; 32],
    payload_filter_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReadinessWatermark {
    schema: String,
    publisher_generation: u64,
    boot_id: [u8; 16],
    artifact_sha256: [u8; 32],
}

fn verify_readiness(
    artifact: BackendReadinessArtifact,
    current_boot_id: [u8; 16],
    expected_executable: &str,
) -> Result<ProtectedBackendReadinessEvidence> {
    let executable = open_executable_pin(expected_executable)?;
    let identity = fstat(&executable).map_err(|error| HostError::State(error.to_string()))?;
    verify_readiness_identity(
        artifact,
        current_boot_id,
        expected_executable,
        identity.st_dev,
        identity.st_ino,
    )
}

fn verify_readiness_identity(
    artifact: BackendReadinessArtifact,
    current_boot_id: [u8; 16],
    expected_executable: &str,
    executable_device: u64,
    executable_inode: u64,
) -> Result<ProtectedBackendReadinessEvidence> {
    if artifact.schema != READINESS_SCHEMA
        || artifact.publisher_generation == 0
        || artifact.boot_id == [0; 16]
        || artifact.boot_id != current_boot_id
        || artifact.nspawn_store_path != expected_executable
        || artifact.nspawn_device == 0
        || artifact.nspawn_inode == 0
        || artifact.probe_digest == [0; 32]
        || artifact.supervisor_profile_digest == [0; 32]
        || artifact.payload_filter_digest == [0; 32]
    {
        return Err(HostError::State(
            "backend readiness artifact contradicts required deployment evidence".to_owned(),
        ));
    }
    if executable_device != artifact.nspawn_device || executable_inode != artifact.nspawn_inode {
        return Err(HostError::State(
            "backend readiness executable identity changed".to_owned(),
        ));
    }
    Ok(ProtectedBackendReadinessEvidence {
        publisher_generation: artifact.publisher_generation,
        boot_id: artifact.boot_id,
        executable: artifact.nspawn_store_path,
        executable_device: artifact.nspawn_device,
        executable_inode: artifact.nspawn_inode,
        probe_digest: artifact.probe_digest,
        supervisor_profile_digest: artifact.supervisor_profile_digest,
        payload_filter_digest: artifact.payload_filter_digest,
    })
}

fn read_protected_artifact_optional(directory_path: &Path) -> Result<Option<Vec<u8>>> {
    let directory = open(
        directory_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| HostError::State(error.to_string()))?;
    validate_protected_directory(&directory, "credential directory")?;
    match openat(
        &directory,
        READINESS_CREDENTIAL_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => read_protected_descriptor(
            descriptor,
            READINESS_CREDENTIAL_FILE,
            MAXIMUM_READINESS_BYTES,
        )
        .map(Some),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(HostError::State(error.to_string())),
    }
}

fn validate_protected_directory(directory: &OwnedFd, label: &str) -> Result<()> {
    let metadata = fstat(directory).map_err(|error| HostError::State(error.to_string()))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != 0
        || !protected_directory_permissions(metadata.st_mode)
    {
        return Err(HostError::State(format!(
            "backend readiness {label} is not a protected root-owned directory"
        )));
    }
    Ok(())
}

#[cfg(test)]
fn read_protected_file(
    directory: &OwnedFd,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<Vec<u8>> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| HostError::State(error.to_string()))?;
    read_protected_descriptor(descriptor, name, maximum_bytes)
}

fn read_protected_descriptor(
    descriptor: OwnedFd,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<Vec<u8>> {
    let metadata = fstat(&descriptor).map_err(|error| HostError::State(error.to_string()))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != 0
        || metadata.st_nlink != 1
        || !protected_file_permissions(metadata.st_mode)
    {
        return Err(HostError::State(format!(
            "backend readiness {name} is not a protected root-owned file"
        )));
    }
    let declared_size = usize::try_from(metadata.st_size)
        .map_err(|_| HostError::State(format!("backend readiness {name} is oversized")))?;
    if declared_size == 0 || declared_size > maximum_bytes {
        return Err(HostError::State(format!(
            "backend readiness {name} has an invalid size"
        )));
    }
    let mut bytes = Vec::with_capacity(declared_size);
    File::from(descriptor)
        .take((maximum_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| HostError::State(error.to_string()))?;
    if bytes.len() != declared_size || bytes.len() > maximum_bytes {
        return Err(HostError::State(format!(
            "backend readiness {name} changed while being read"
        )));
    }
    Ok(bytes)
}

fn persist_readiness_watermark(directory_path: &Path, proposed: ReadinessWatermark) -> Result<()> {
    let directory = open(
        directory_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| HostError::State(error.to_string()))?;
    validate_protected_directory(&directory, "state directory")?;
    let current = match openat(
        &directory,
        READINESS_WATERMARK_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => {
            let bytes = read_protected_descriptor(
                descriptor,
                READINESS_WATERMARK_FILE,
                MAXIMUM_WATERMARK_BYTES,
            )?;
            Some(
                serde_json::from_slice::<ReadinessWatermark>(&bytes).map_err(|_| {
                    HostError::State("backend readiness watermark is malformed".to_owned())
                })?,
            )
        }
        Err(rustix::io::Errno::NOENT) => None,
        Err(error) => return Err(HostError::State(error.to_string())),
    };
    validate_watermark_transition(current.as_ref(), &proposed)?;
    if current.as_ref() == Some(&proposed) {
        return Ok(());
    }

    let bytes = serde_json::to_vec(&proposed)
        .map_err(|_| HostError::State("backend readiness watermark cannot encode".to_owned()))?;
    match rustix::fs::unlinkat(
        &directory,
        READINESS_WATERMARK_NEXT,
        rustix::fs::AtFlags::empty(),
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(HostError::State(error.to_string())),
    }
    let descriptor = openat(
        &directory,
        READINESS_WATERMARK_NEXT,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| HostError::State(error.to_string()))?;
    let mut output = File::from(descriptor);
    let result = output
        .write_all(&bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| HostError::State(error.to_string()))
        .and_then(|()| {
            rustix::fs::renameat(
                &directory,
                READINESS_WATERMARK_NEXT,
                &directory,
                READINESS_WATERMARK_FILE,
            )
            .map_err(|error| HostError::State(error.to_string()))
        })
        .and_then(|()| {
            rustix::fs::fsync(&directory).map_err(|error| HostError::State(error.to_string()))
        });
    if result.is_err() {
        let _ = rustix::fs::unlinkat(
            &directory,
            READINESS_WATERMARK_NEXT,
            rustix::fs::AtFlags::empty(),
        );
    }
    result
}

fn validate_watermark_transition(
    current: Option<&ReadinessWatermark>,
    proposed: &ReadinessWatermark,
) -> Result<()> {
    if proposed.schema != READINESS_WATERMARK_SCHEMA
        || proposed.publisher_generation == 0
        || proposed.boot_id == [0; 16]
        || proposed.artifact_sha256 == [0; 32]
    {
        return Err(HostError::State(
            "backend readiness watermark is invalid".to_owned(),
        ));
    }
    let Some(current) = current else {
        return Ok(());
    };
    if current.schema != READINESS_WATERMARK_SCHEMA
        || current.publisher_generation == 0
        || current.boot_id == [0; 16]
        || current.artifact_sha256 == [0; 32]
    {
        return Err(HostError::State(
            "backend readiness watermark is invalid".to_owned(),
        ));
    }
    if proposed.publisher_generation < current.publisher_generation
        || (proposed.publisher_generation == current.publisher_generation && proposed != current)
    {
        return Err(HostError::State(
            "backend readiness publisher generation rolled back or equivocated".to_owned(),
        ));
    }
    Ok(())
}

fn validate_fixed_nspawn_path(executable: &str) -> Result<()> {
    validate_absolute(executable, "nspawn executable")?;
    if !executable.starts_with("/nix/store/") || !executable.ends_with("/bin/systemd-nspawn") {
        return Err(HostError::InvalidPlan(
            "nspawn executable is not the fixed AOS store binary".to_owned(),
        ));
    }
    Ok(())
}

const fn protected_directory_permissions(mode: u32) -> bool {
    matches!(mode & 0o7777, 0o500 | 0o700)
}

const fn protected_file_permissions(mode: u32) -> bool {
    matches!(mode & 0o7777, 0o400 | 0o600)
}

/// Stores node-owned constants used to compile a launch request.
#[derive(Debug)]
pub struct NspawnConfig {
    executable_pin: Arc<OwnedFd>,
    timeout_start: Duration,
    timeout_stop: Duration,
}

impl NspawnConfig {
    /// Constructs an immutable host launch profile.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::InvalidPlan`] for nonabsolute/unnormalized paths,
    /// an invalid `SELinux` context token, or zero timeouts.
    pub fn from_readiness(
        readiness: BackendReadiness,
        timeout_start: Duration,
        timeout_stop: Duration,
    ) -> Result<Self> {
        let executable = readiness.executable;
        validate_fixed_nspawn_path(&executable)?;
        if readiness.executable_device == 0
            || readiness.executable_inode == 0
            || readiness.probe_generation == 0
            || readiness.mac_policy_digest == [0; 32]
            || readiness.supervisor_profile_digest == [0; 32]
            || readiness.payload_filter_digest == [0; 32]
        {
            return Err(HostError::InvalidPlan(
                "nspawn backend readiness evidence is incomplete".to_owned(),
            ));
        }
        if timeout_start.is_zero() || timeout_stop.is_zero() {
            return Err(HostError::InvalidPlan(
                "systemd operation timeouts must be nonzero".to_owned(),
            ));
        }
        let executable_pin = open_executable_pin(&executable)?;
        let executable_identity = rustix::fs::fstat(&executable_pin)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        if executable_identity.st_dev != readiness.executable_device
            || executable_identity.st_ino != readiness.executable_inode
        {
            return Err(HostError::InvalidPlan(
                "nspawn executable identity changed".to_owned(),
            ));
        }
        Ok(Self {
            executable_pin: Arc::new(executable_pin),
            timeout_start,
            timeout_stop,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests(executable: impl Into<String>) -> Result<Self> {
        let _configured_executable = executable.into();
        let executable =
            std::env::current_exe().map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let executable_pin = rustix::fs::open(
            &executable,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        Ok(Self {
            executable_pin: Arc::new(executable_pin),
            timeout_start: Duration::from_secs(30),
            timeout_stop: Duration::from_secs(10),
        })
    }

    /// Resolves opaque resources and compiles the sole accepted nspawn argv.
    ///
    /// # Errors
    ///
    /// Returns an error when catalog resolution fails, mandatory cgroup limits
    /// are missing or invalid, or a trusted catalog returns an unsafe path.
    pub fn compile<C: HostCatalog>(
        &self,
        catalog: &C,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
    ) -> Result<PreparedLaunch> {
        let resolved = catalog.resolve(fence, plan)?;
        self.compile_resolved(fence, plan, resolved)
    }

    /// Compiles a launch from the exact resources admitted by the caller.
    ///
    /// Keeping resolution outside this method lets the broker resolve the
    /// controller-authorized opaque handles exactly once for local compilation.
    /// Kernel identities remain node-local checks and never enter the portable
    /// signed request semantics.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported features, invalid required resources,
    /// unsafe resolved paths, or a contradictory identity allocation.
    pub(crate) fn compile_resolved(
        &self,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
        resolved: ResolvedLaunchResources,
    ) -> Result<PreparedLaunch> {
        validate_backend_features(plan)?;
        let workspace = resolved.workspace;
        let network = resolved.network;
        validate_resolved_identity(&resolved.identity, plan)?;
        validate_published_pin(
            &workspace.root_directory,
            WORKSPACE_PIN_PREFIX,
            "workspace root",
        )?;
        validate_published_pin(
            &network.namespace_path,
            NETWORK_PIN_PREFIX,
            "network namespace",
        )?;

        let memory_max = required_limit(plan, MEMORY, "memory")?;
        let memory_high = memory_max.saturating_sub(memory_max / 10).max(1);
        let tasks_max = required_limit(plan, PROCESSES, "process")?;
        let cpu_weight = required_limit(plan, CPU_WEIGHT, "CPU weight")?;
        let mut resources = SandboxResources::new(memory_high, memory_max, tasks_max, cpu_weight)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        resources = resources
            .with_open_file_limit(required_limit(plan, OPEN_FILES, "open-file")?)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        if let Some(quota) = optional_limit(plan, CPU_QUOTA) {
            if quota == 0 || quota > MICROS_PER_SECOND {
                return Err(HostError::InvalidPlan(
                    "CPU quota must be in 1..=1000000 microseconds".to_owned(),
                ));
            }
            resources = resources
                .with_cpu_quota(Duration::from_micros(quota))
                .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        }
        if let Some(weight) = optional_limit(plan, IO_WEIGHT) {
            resources = resources
                .with_io_weight(weight)
                .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        }

        let executable_path =
            SandboxDescriptorPath::for_current_process(self.executable_pin.as_fd())
                .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let root_path = SandboxDescriptorPath::for_current_process(workspace.pin.as_fd())
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let network_path = SandboxDescriptorPath::for_current_process(network.pin.as_fd())
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let command = aos_systemd::SandboxNspawnCommand::private_user_descriptor_v1(
            executable_path,
            *fence.incarnation_id(),
            resolved.identity.range_start,
            resolved.identity.range_size,
        )
        .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let paths = SandboxResolvedPaths::from_descriptors(root_path, network_path);
        let spec = SandboxUnitSpec::new_nspawn(
            SandboxUnitName::from_incarnation(*fence.incarnation_id()),
            command,
            paths,
            resources,
            self.timeout_start,
            self.timeout_stop,
        )
        .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        Ok(PreparedLaunch {
            spec,
            pins: LaunchPins {
                executable: Arc::clone(&self.executable_pin),
                workspace: workspace.pin,
                network: network.pin,
            },
        })
    }
}

fn open_executable_pin(path: &str) -> Result<OwnedFd> {
    let pin = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
    let identity =
        rustix::fs::fstat(&pin).map_err(|error| HostError::InvalidPlan(error.to_string()))?;
    if rustix::fs::FileType::from_raw_mode(identity.st_mode) != rustix::fs::FileType::RegularFile
        || identity.st_uid != 0
        || identity.st_mode & 0o111 == 0
        || identity.st_mode & 0o022 != 0
    {
        return Err(HostError::InvalidPlan(
            "nspawn executable pin is not a protected executable".to_owned(),
        ));
    }
    Ok(pin)
}

fn validate_resolved_identity(
    identity: &ResolvedIdentityAllocation,
    plan: &ValidatedRuntimePlan,
) -> Result<()> {
    if identity.range_start == 0
        || identity.range_size < 65_536
        || identity
            .range_start
            .checked_add(identity.range_size)
            .is_none()
        || identity.catalog_generation == 0
        || identity.range_start != plan.uid_range_start()
        || identity.range_size != plan.uid_range_size()
    {
        return Err(HostError::InvalidPlan(
            "runtime identity request does not match its catalog allocation".to_owned(),
        ));
    }
    Ok(())
}

fn validate_backend_features(plan: &ValidatedRuntimePlan) -> Result<()> {
    for feature in plan.required_features() {
        if !backend_supports_feature(feature.namespace(), feature.major(), feature.minor()) {
            return Err(HostError::InvalidPlan(format!(
                "nspawn backend does not implement required feature {} version {}.{}",
                feature.namespace(),
                feature.major(),
                feature.minor()
            )));
        }
    }
    Ok(())
}

fn backend_supports_feature(namespace: &str, major: u32, minor: u32) -> bool {
    SUPPORTED_BACKEND_FEATURES
        .iter()
        .any(|candidate| candidate == &(namespace, major, minor))
}

fn required_limit(plan: &ValidatedRuntimePlan, dimension: u8, label: &str) -> Result<u64> {
    let value = optional_limit(plan, dimension)
        .ok_or_else(|| HostError::InvalidPlan(format!("mandatory {label} limit is absent")))?;
    if value == 0 {
        return Err(HostError::InvalidPlan(format!(
            "mandatory {label} limit is zero"
        )));
    }
    Ok(value)
}

fn optional_limit(plan: &ValidatedRuntimePlan, dimension: u8) -> Option<u64> {
    plan.limits()
        .iter()
        .find(|limit| limit.dimension() == dimension)
        .map(|limit| limit.value())
}

fn validate_absolute(value: &str, label: &str) -> Result<()> {
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
        return Err(HostError::InvalidPlan(format!(
            "{label} is not a bounded normalized absolute path"
        )));
    }
    Ok(())
}

pub(crate) fn validate_published_pin(value: &str, prefix: &str, label: &str) -> Result<()> {
    validate_absolute(value, label)?;
    let name = value.strip_prefix(prefix).ok_or_else(|| {
        HostError::InvalidPlan(format!("{label} is outside its root-owned pin publisher"))
    })?;
    if name.is_empty() || name == "." || name.contains('/') {
        return Err(HostError::InvalidPlan(format!(
            "{label} is not one exact published pin"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::symlink;

    use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind};

    use super::*;

    fn readiness_artifact(path: String, boot_id: [u8; 16]) -> BackendReadinessArtifact {
        BackendReadinessArtifact {
            schema: READINESS_SCHEMA.to_owned(),
            publisher_generation: 7,
            boot_id,
            nspawn_store_path: path,
            nspawn_device: 17,
            nspawn_inode: 19,
            probe_digest: [1; 32],
            supervisor_profile_digest: [2; 32],
            payload_filter_digest: [3; 32],
        }
    }

    fn watermark(generation: u64, boot_id: [u8; 16], digest: [u8; 32]) -> ReadinessWatermark {
        ReadinessWatermark {
            schema: READINESS_WATERMARK_SCHEMA.to_owned(),
            publisher_generation: generation,
            boot_id,
            artifact_sha256: digest,
        }
    }

    #[test]
    fn backend_feature_admission_is_an_exact_allowlist() {
        assert!(backend_supports_feature(
            "aos.sandbox.runtime.linux-systemd",
            1,
            0
        ));
        assert!(!backend_supports_feature(
            "aos.sandbox.storage.zfs-held-snapshot",
            1,
            0
        ));
        assert!(!backend_supports_feature(
            "aos.sandbox.runtime.linux-systemd",
            1,
            1
        ));
    }

    #[test]
    fn publisher_pin_paths_reject_root_dot_and_nested_names() {
        assert!(validate_published_pin("/", WORKSPACE_PIN_PREFIX, "workspace").is_err());
        assert!(
            validate_published_pin(
                "/run/aos/sandbox-pins/workspaces/.",
                WORKSPACE_PIN_PREFIX,
                "workspace"
            )
            .is_err()
        );
        assert!(
            validate_published_pin(
                "/run/aos/sandbox-pins/workspaces/a/b",
                WORKSPACE_PIN_PREFIX,
                "workspace"
            )
            .is_err()
        );
        assert!(
            validate_published_pin(
                "/run/aos/sandbox-pins/workspaces/a",
                WORKSPACE_PIN_PREFIX,
                "workspace"
            )
            .is_ok()
        );
    }

    #[test]
    fn resolved_resources_reject_descriptor_identity_substitution() {
        let workspace = rustix::fs::open(
            "/",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let identity = rustix::fs::fstat(&workspace).unwrap();
        assert!(
            ResolvedWorkspace::from_pinned(
                "/run/aos/sandbox-pins/workspaces/test".to_owned(),
                identity.st_dev,
                identity.st_ino.wrapping_add(1),
                workspace,
            )
            .is_err()
        );

        let network = rustix::fs::open(
            "/proc/self/ns/net",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let network = NamespaceFd::from_owned(network, NamespaceKind::Network).unwrap();
        let identity = network.identity();
        assert!(
            ResolvedNetwork::from_pinned(
                "/run/aos/sandbox-pins/netns/test".to_owned(),
                identity.device,
                identity.inode.wrapping_add(1),
                network,
            )
            .is_err()
        );
    }

    #[test]
    fn readiness_binds_boot_path_identity_and_nonzero_digests() {
        let executable = "/nix/store/test-systemd/bin/systemd-nspawn".to_owned();
        let boot_id = [4; 16];
        let valid = readiness_artifact(executable.clone(), boot_id);
        let evidence = verify_readiness_identity(valid, boot_id, &executable, 17, 19).unwrap();
        assert_eq!(evidence.publisher_generation(), 7);
        assert_eq!(
            evidence.runtime_blockers(),
            [
                BackendReadinessBlocker::Phase0ClaimVerification,
                BackendReadinessBlocker::ShiftedPayloadPidfdNamespaceInspection,
                BackendReadinessBlocker::PayloadRootPolicyDeploymentVerification,
            ]
        );

        let wrong_boot = readiness_artifact(executable.clone(), [5; 16]);
        assert!(verify_readiness_identity(wrong_boot, boot_id, &executable, 17, 19).is_err());
        let mut wrong_identity = readiness_artifact(executable.clone(), boot_id);
        wrong_identity.nspawn_inode = wrong_identity.nspawn_inode.wrapping_add(1);
        assert!(verify_readiness_identity(wrong_identity, boot_id, &executable, 17, 19).is_err());
        let mut incomplete = readiness_artifact(executable.clone(), boot_id);
        incomplete.payload_filter_digest = [0; 32];
        assert!(verify_readiness_identity(incomplete, boot_id, &executable, 17, 19).is_err());
        let other = readiness_artifact(executable.clone(), boot_id);
        assert!(
            verify_readiness_identity(other, boot_id, "/different/executable", 17, 19).is_err()
        );
    }

    #[test]
    fn watermark_rejects_rollback_and_same_generation_equivocation() {
        let current = watermark(9, [1; 16], [2; 32]);
        assert!(validate_watermark_transition(Some(&current), &current).is_ok());
        assert!(
            validate_watermark_transition(Some(&current), &watermark(8, [1; 16], [2; 32])).is_err()
        );
        assert!(
            validate_watermark_transition(Some(&current), &watermark(9, [1; 16], [3; 32])).is_err()
        );
        assert!(
            validate_watermark_transition(Some(&current), &watermark(9, [3; 16], [2; 32])).is_err()
        );
        assert!(
            validate_watermark_transition(Some(&current), &watermark(10, [3; 16], [4; 32])).is_ok()
        );
    }

    #[test]
    fn protected_readiness_modes_reject_special_and_public_bits() {
        assert!(protected_directory_permissions(0o040700));
        assert!(protected_directory_permissions(0o040500));
        assert!(!protected_directory_permissions(0o041700));
        assert!(!protected_directory_permissions(0o040710));
        assert!(protected_file_permissions(0o100600));
        assert!(protected_file_permissions(0o100400));
        assert!(!protected_file_permissions(0o104600));
        assert!(!protected_file_permissions(0o100604));
    }

    #[test]
    fn protected_readiness_reader_never_follows_final_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        std::fs::write(&target, b"protected-looking bytes").unwrap();
        symlink(&target, temporary.path().join(READINESS_CREDENTIAL_FILE)).unwrap();
        let directory = open(
            temporary.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();

        assert!(
            read_protected_file(
                &directory,
                READINESS_CREDENTIAL_FILE,
                MAXIMUM_READINESS_BYTES,
            )
            .is_err()
        );
    }

    #[test]
    fn readiness_schema_rejects_unknown_fields() {
        let bytes = br#"{
            "schema":"aos.sandbox.host-backend-readiness.v1",
            "publisher_generation":1,
            "boot_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
            "nspawn_store_path":"/nix/store/example/bin/systemd-nspawn",
            "nspawn_device":1,
            "nspawn_inode":2,
            "probe_digest":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
            "supervisor_profile_digest":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
            "payload_filter_digest":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
            "unexpected":true
        }"#;
        assert!(serde_json::from_slice::<BackendReadinessArtifact>(bytes).is_err());
    }
}
