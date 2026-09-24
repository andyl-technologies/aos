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

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1;
use aos_sandbox_linux::mount::DetachedMount;
use aos_sandbox_linux::pidfd::NamespaceFd;
use aos_sandbox_protocol::{ValidatedAssignmentFence, ValidatedRuntimePlan};
use aos_systemd::{
    GuardianCredentialDescriptors, GuardianExecutableDescriptor, GuardianExecutableSnapshot,
    GuardianUnitSpec, SandboxDescriptorPath, SandboxResolvedPaths, SandboxResources,
    SandboxUnitName, SandboxUnitSpec,
};
use rustix::fs::fstat;
#[cfg(all(test, feature = "kernel-tests"))]
use rustix::fs::{Mode, OFlags, open};

use crate::state::transition::{PayloadLaunchSnapshot, PinnedObjectSnapshot};
use crate::{HostError, Result};

mod deployment;
#[cfg(all(test, feature = "kernel-tests"))]
mod kernel_tests;
mod readiness;
mod selinux_policy;

pub use deployment::{
    VerifiedPhase0ClaimV1, verify_optional_backend_deployment_v1, verify_optional_phase0_claim_v1,
};
pub use readiness::{
    BackendReadiness, BackendReadinessBlocker, ProtectedBackendReadinessEvidence,
    VerifiedCompiledSupervisorProfileV1, VerifiedPackagedRuntimeV1,
    verified_packaged_nspawn_digest,
};
pub use selinux_policy::VerifiedLiveSelinuxPolicyV1;

const PROCESSES: u8 = 2;
const MEMORY: u8 = 3;
const CPU_WEIGHT: u8 = 4;
const CPU_QUOTA: u8 = 5;
const IO_WEIGHT: u8 = 6;
const OPEN_FILES: u8 = 9;
const MICROS_PER_SECOND: u64 = 1_000_000;
pub(crate) const WORKSPACE_PIN_PREFIX: &str = "/run/aos/sandbox-pins/workspaces/";
pub(crate) const NETWORK_PIN_PREFIX: &str = "/run/aos/sandbox-pins/netns/";
pub(crate) const ATTACHMENT_ANCHOR_PIN_PREFIX: &str = "/run/aos/sandbox-mount-catalog/slots/";
#[cfg(test)]
const TEST_NSPAWN_PATH: &str =
    "/nix/store/00000000000000000000000000000000-aos-readiness-absent/bin/systemd-nspawn";
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
    guest_root_publication: Option<GuestRootPublicationProofV1>,
    pin: OwnedFd,
}

impl ResolvedWorkspace {
    /// Constructs a workspace only when its descriptor has the catalogued identity.
    ///
    /// Identity validation does not prove mount transferability. For launch,
    /// the privileged Storage owner must export a detached mount of this root;
    /// nspawn rejects an attached directory from another mount namespace.
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
            guest_root_publication: None,
            pin,
        })
    }

    /// Returns the Storage-authenticated guest-root proof retained for launch.
    #[must_use]
    pub const fn guest_root_publication(&self) -> Option<GuestRootPublicationProofV1> {
        self.guest_root_publication
    }

    #[cfg(test)]
    pub(crate) fn pin(&self) -> BorrowedFd<'_> {
        self.pin.as_fd()
    }

    pub(crate) fn with_guest_root_publication(
        mut self,
        proof: GuestRootPublicationProofV1,
    ) -> Self {
        self.guest_root_publication = Some(proof);
        self
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

/// Describes one broker-owned destination anchor for a payload namespace generation.
#[derive(Debug)]
pub struct ResolvedAttachmentAnchor {
    /// Absolute broker-derived directory containing the declared destination slots.
    pub directory: String,
    /// Device identity verified against the publisher record.
    pub device: u64,
    /// Inode identity verified against the publisher record.
    pub inode: u64,
    /// Kernel-unique mount identity verified against the publisher record.
    pub mount_id: u64,
    pin: OwnedFd,
}

impl ResolvedAttachmentAnchor {
    /// Constructs an anchor only when its descriptor has the catalogued identity.
    ///
    /// # Errors
    ///
    /// Returns an error when descriptor inspection fails or any physical identity
    /// differs from the trusted catalog record.
    pub fn from_pinned(
        directory: String,
        device: u64,
        inode: u64,
        mount_id: u64,
        pin: OwnedFd,
    ) -> Result<Self> {
        let identity =
            rustix::fs::fstat(&pin).map_err(|error| HostError::Catalog(error.to_string()))?;
        let actual_mount_id = aos_sandbox_linux::inventory::MountId::from_fd(pin.as_fd())
            .map_err(|error| HostError::Catalog(error.to_string()))?;
        if identity.st_dev != device
            || identity.st_ino != inode
            || actual_mount_id.get() != mount_id
        {
            return Err(HostError::Catalog(
                "attachment-anchor descriptor identity changed".to_owned(),
            ));
        }
        Ok(Self {
            directory,
            device,
            inode,
            mount_id,
            pin,
        })
    }
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
    /// Broker-owned destination anchor, required by Host 1.0 launches.
    pub attachment_anchor: ResolvedAttachmentAnchor,
}

/// Retains the exact workspace source, exported root, and network for a launch.
///
/// The source workspace has a stable mount identity across replay. Storage's
/// detached export receives a new mount ID for each transfer and is held until
/// the systemd handoff and post-launch payload-root verification complete.
#[derive(Debug)]
pub struct LaunchPins {
    executable: Arc<OwnedFd>,
    workspace: OwnedFd,
    transferred_root: OwnedFd,
    network: NamespaceFd,
    attachment_anchor: OwnedFd,
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

    /// Returns the Storage-exported root mount retained through launch proof.
    #[must_use]
    pub fn transferred_root(&self) -> BorrowedFd<'_> {
        self.transferred_root.as_fd()
    }

    /// Returns the pinned prepared network namespace descriptor.
    #[must_use]
    pub fn network(&self) -> &NamespaceFd {
        &self.network
    }

    /// Returns the pinned attachment-anchor descriptor.
    #[must_use]
    pub fn attachment_anchor(&self) -> BorrowedFd<'_> {
        self.attachment_anchor.as_fd()
    }

    #[cfg(test)]
    pub(crate) fn for_tests(
        executable: OwnedFd,
        workspace: OwnedFd,
        network: NamespaceFd,
        attachment_anchor: OwnedFd,
    ) -> Self {
        let transferred_root = workspace.try_clone().expect("test workspace clone");
        Self {
            executable: Arc::new(executable),
            workspace,
            transferred_root,
            network,
            attachment_anchor,
        }
    }
}

/// Couples a fixed systemd unit specification to its kernel object pins.
#[derive(Debug)]
pub struct PreparedLaunch {
    spec: SandboxUnitSpec,
    pins: LaunchPins,
    snapshot: PayloadLaunchSnapshot,
    guest_package_binding: Option<[u8; 32]>,
    guest_feature_mask: Option<u16>,
}

/// Stores the fixed executable and timeout used for Guardian starts.
#[derive(Clone, Debug)]
pub struct GuardianConfig {
    executable: GuardianExecutableDescriptor,
    executable_path: String,
    timeout_start: Duration,
}

impl GuardianConfig {
    /// Pins one fixed AOS Guardian store executable.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-store path, wrong executable name, zero
    /// timeout, or an executable that fails the protected descriptor contract.
    pub fn new(path: &str, timeout_start: Duration) -> Result<Self> {
        validate_absolute(path, "guardian executable")?;
        if !path.starts_with("/nix/store/") || !path.ends_with("/bin/aos-sandbox-guardian") {
            return Err(HostError::InvalidPlan(
                "guardian executable is not the fixed AOS store binary".to_owned(),
            ));
        }
        if timeout_start.is_zero() {
            return Err(HostError::InvalidPlan(
                "guardian start timeout must be nonzero".to_owned(),
            ));
        }
        let descriptor = open_executable_pin(path)?;
        let executable = GuardianExecutableDescriptor::from_descriptor(descriptor.as_fd())
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        Ok(Self {
            executable,
            executable_path: path.to_owned(),
            timeout_start,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Result<Self> {
        let path =
            std::env::current_exe().map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let descriptor = rustix::fs::open(
            &path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let executable = GuardianExecutableDescriptor::from_descriptor(descriptor.as_fd())
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        Ok(Self {
            executable,
            executable_path: path.to_string_lossy().into_owned(),
            timeout_start: Duration::from_secs(30),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test_descriptor(descriptor: BorrowedFd<'_>) -> Result<Self> {
        let executable = GuardianExecutableDescriptor::from_descriptor(descriptor)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        Ok(Self {
            executable,
            executable_path: "/invalid-test-guardian".to_owned(),
            timeout_start: Duration::from_secs(30),
        })
    }

    /// Returns the exact executable identity bound into durable launch evidence.
    #[must_use]
    pub const fn executable_snapshot(&self) -> GuardianExecutableSnapshot {
        self.executable.snapshot()
    }

    /// Revalidates the protected Guardian executable pinned by this profile.
    ///
    /// # Errors
    ///
    /// Returns an error if its retained descriptor, metadata, or exact content
    /// no longer matches the profile admitted at construction.
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.executable
            .revalidate()
            .map_err(|error| HostError::InvalidPlan(error.to_string()))
    }

    /// Constructs the sole fixed Guardian unit from an exact descriptor set.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor set or unit contract is invalid.
    pub(crate) fn prepare(
        &self,
        incarnation_id: [u8; 16],
        credentials: GuardianCredentialDescriptors,
        binding: [u8; 32],
    ) -> Result<GuardianUnitSpec> {
        GuardianUnitSpec::new(
            SandboxUnitName::from_incarnation(incarnation_id),
            self.executable.clone(),
            self.executable_path.clone(),
            credentials,
            binding,
            self.timeout_start,
        )
        .map_err(|error| HostError::InvalidPlan(error.to_string()))
    }
}

impl PreparedLaunch {
    /// Returns the fixed transient-unit specification.
    #[must_use]
    pub const fn spec(&self) -> &SandboxUnitSpec {
        &self.spec
    }

    pub(crate) const fn guest_package_binding(&self) -> Option<[u8; 32]> {
        self.guest_package_binding
    }

    pub(crate) const fn guest_feature_mask(&self) -> Option<u16> {
        self.guest_feature_mask
    }

    pub(crate) fn with_guest_agent_descriptors(
        mut self,
        claim: &aos_sandbox::runtime_execution::DormantRuntimeExecutionClaimV1<'_>,
        assignment: &ValidatedAssignmentFence,
        guest: &crate::live_agent::HostAgentGuestLaunchDescriptorsV1,
    ) -> std::result::Result<Self, crate::live_agent::HostAgentLiveErrorV1> {
        self.spec = guest.bind_unit_spec(claim, assignment, self.spec)?;
        // The descriptor role is a launch-semantic input. Update the durable
        // snapshot before Guardian binds and commits this payload attempt.
        self.snapshot.spec_semantic_digest = self.spec.semantic_digest_v1();
        self.snapshot.agent_required = true;
        Ok(self)
    }

    pub(crate) fn into_parts(self) -> (SandboxUnitSpec, LaunchPins) {
        (self.spec, self.pins)
    }

    pub(crate) fn snapshot(&self) -> &PayloadLaunchSnapshot {
        &self.snapshot
    }

    pub(crate) const fn pins(&self) -> &LaunchPins {
        &self.pins
    }

    pub(crate) fn bind(mut self, binding: [u8; 32]) -> Result<Self> {
        self.spec = self
            .spec
            .into_bound(binding)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        Ok(self)
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

    /// Exports the exact resolved workspace as a transferable detached mount.
    ///
    /// # Errors
    ///
    /// Returns an error when the privileged Storage owner cannot authenticate
    /// or export the resolved workspace.
    fn export_root_mount(&self, _workspace: &ResolvedWorkspace) -> Result<DetachedMount> {
        Err(HostError::Catalog(
            "workspace detached root-mount export is unavailable".to_owned(),
        ))
    }
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

/// Retains verified backend readiness and node-owned launch timeouts.
#[derive(Debug)]
pub struct NspawnConfig {
    readiness: BackendReadiness,
    timeout_start: Duration,
    timeout_stop: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NspawnExecutableSnapshot {
    device: u64,
    inode: u64,
    bytes: i64,
    uid: u32,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl NspawnConfig {
    /// Constructs an immutable host launch profile.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::State`] when the current kernel boot identity
    /// cannot be read. Returns [`HostError::InvalidPlan`] for zero timeouts, an
    /// invalid executable path, incomplete readiness evidence, an admitted boot
    /// or binding mismatch, or retained executable metadata or content drift.
    pub fn from_readiness(
        readiness: BackendReadiness,
        timeout_start: Duration,
        timeout_stop: Duration,
    ) -> Result<Self> {
        if timeout_start.is_zero() || timeout_stop.is_zero() {
            return Err(HostError::InvalidPlan(
                "systemd operation timeouts must be nonzero".to_owned(),
            ));
        }

        let readiness = readiness.into_nspawn_readiness()?;
        Ok(Self {
            readiness,
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
        let readiness = readiness::backend_readiness_for_tests(TEST_NSPAWN_PATH, executable_pin)?;
        Self::from_readiness(readiness, Duration::from_secs(30), Duration::from_secs(10))
    }

    /// Pins the real packaged nspawn for explicit kernel qualification.
    #[cfg(all(test, feature = "kernel-tests"))]
    pub(crate) fn for_kernel_test(
        executable: &str,
        timeout_start: Duration,
        timeout_stop: Duration,
    ) -> Result<Self> {
        validate_fixed_nspawn_path(executable)?;
        if timeout_start.is_zero() || timeout_stop.is_zero() {
            return Err(HostError::InvalidPlan(
                "systemd operation timeouts must be nonzero".to_owned(),
            ));
        }
        let executable_pin = open_executable_pin(executable)?;

        let readiness = readiness::backend_readiness_for_tests(executable, executable_pin)?;
        Self::from_readiness(readiness, timeout_start, timeout_stop)
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        self.readiness.revalidate_for_nspawn()
    }

    /// Resolves opaque resources and compiles the sole accepted nspawn argv.
    ///
    /// # Errors
    ///
    /// Returns an error when catalog resolution fails, backend readiness
    /// changed, mandatory cgroup limits are missing or invalid, or a trusted
    /// catalog returns an unsafe path.
    pub fn compile<C: HostCatalog>(
        &self,
        catalog: &C,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
    ) -> Result<PreparedLaunch> {
        let resolved = catalog.resolve(fence, plan)?;
        let root_mount = catalog.export_root_mount(&resolved.workspace)?;
        self.compile_resolved(fence, plan, resolved, root_mount)
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
    /// Returns an error when backend readiness changed, or for unsupported
    /// features, invalid required resources, unsafe resolved paths, or a
    /// contradictory identity allocation.
    pub(crate) fn compile_resolved(
        &self,
        fence: &ValidatedAssignmentFence,
        plan: &ValidatedRuntimePlan,
        resolved: ResolvedLaunchResources,
        root_mount: DetachedMount,
    ) -> Result<PreparedLaunch> {
        self.revalidate()?;
        validate_backend_features(plan)?;
        let workspace = resolved.workspace;
        let guest_package_binding = workspace
            .guest_root_publication()
            .map(|proof| proof.package_binding);
        let guest_feature_mask = workspace
            .guest_root_publication()
            .map(|proof| proof.feature_mask);
        let network = resolved.network;
        let attachment_anchor = resolved.attachment_anchor;
        let root_identity =
            fstat(root_mount.as_fd()).map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        if (root_identity.st_dev, root_identity.st_ino) != (workspace.device, workspace.inode) {
            return Err(HostError::InvalidPlan(
                "exported root mount differs from the resolved workspace".to_owned(),
            ));
        }
        // Build the systemd descriptor path from the owned FD retained in
        // LaunchPins, not the temporary export wrapper dropped on return.
        let transferred_root = root_mount
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
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
            SandboxDescriptorPath::for_current_process(self.readiness.executable_pin())
                .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let root_path = SandboxDescriptorPath::for_current_process(transferred_root.as_fd())
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
        validate_attachment_anchor_path(&attachment_anchor.directory)?;
        let attachment_anchor_path =
            SandboxDescriptorPath::for_current_process(attachment_anchor.pin.as_fd())
                .map_err(|error| HostError::InvalidPlan(error.to_string()))?;

        // The anchor is attached in this mount namespace. Pass that exact
        // namespace alongside it so nspawn can clone the validated mount in a
        // short-lived child without granting mount authority to Host itself.
        let attachment_anchor_namespace = rustix::fs::open(
            "/proc/self/ns/mnt",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let attachment_anchor_namespace = NamespaceFd::from_owned(
            attachment_anchor_namespace,
            aos_sandbox_linux::pidfd::NamespaceKind::Mount,
        )
        .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let attachment_anchor_namespace_path =
            SandboxDescriptorPath::for_current_process(attachment_anchor_namespace.as_fd())
                .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let paths = SandboxResolvedPaths::from_descriptors(root_path, network_path)
            .with_attachment_anchor(attachment_anchor_path, attachment_anchor_namespace_path);
        let spec = SandboxUnitSpec::new_nspawn(
            SandboxUnitName::from_incarnation(*fence.incarnation_id()),
            command,
            paths,
            resources,
            self.timeout_start,
            self.timeout_stop,
        )
        .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let nspawn_identity = fstat(self.readiness.executable_pin())
            .map_err(|error| HostError::InvalidPlan(error.to_string()))?;
        let nspawn_mount_id =
            aos_sandbox_linux::inventory::MountId::from_fd(self.readiness.executable_pin())
                .map_err(|error| HostError::InvalidPlan(error.to_string()))?
                .get();
        // A detached clone receives a new mount ID on each export. Durable
        // replay must bind the stable catalog source, while the exact exported
        // descriptor stays live in the transient launch specification.
        let workspace_mount_id =
            aos_sandbox_linux::inventory::MountId::from_fd(workspace.pin.as_fd())
                .map_err(|error| HostError::InvalidPlan(error.to_string()))?
                .get();
        let snapshot = PayloadLaunchSnapshot {
            nspawn: PinnedObjectSnapshot {
                device: nspawn_identity.st_dev,
                inode: nspawn_identity.st_ino,
                mount_id: nspawn_mount_id,
            },
            workspace: PinnedObjectSnapshot {
                device: workspace.device,
                inode: workspace.inode,
                mount_id: workspace_mount_id,
            },
            network_device: network.device,
            network_inode: network.inode,
            identity_range_start: resolved.identity.range_start,
            identity_range_size: resolved.identity.range_size,
            identity_catalog_generation: resolved.identity.catalog_generation,
            attachment_anchor: PinnedObjectSnapshot {
                device: attachment_anchor.device,
                inode: attachment_anchor.inode,
                mount_id: attachment_anchor.mount_id,
            },
            spec_semantic_digest: spec.semantic_digest_v1(),
            agent_required: false,
        };
        Ok(PreparedLaunch {
            spec,
            snapshot,
            guest_package_binding,
            guest_feature_mask,
            pins: LaunchPins {
                executable: Arc::clone(self.readiness.executable_pin_arc()),
                workspace: workspace.pin,
                transferred_root,
                network: network.pin,
                attachment_anchor: attachment_anchor.pin,
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

fn nspawn_executable_snapshot(descriptor: BorrowedFd<'_>) -> Result<NspawnExecutableSnapshot> {
    let identity =
        rustix::fs::fstat(descriptor).map_err(|error| HostError::InvalidPlan(error.to_string()))?;
    Ok(NspawnExecutableSnapshot {
        device: identity.st_dev,
        inode: identity.st_ino,
        bytes: identity.st_size,
        uid: identity.st_uid,
        mode: identity.st_mode,
        modified_seconds: identity.st_mtime,
        modified_nanoseconds: identity.st_mtime_nsec,
        changed_seconds: identity.st_ctime,
        changed_nanoseconds: identity.st_ctime_nsec,
    })
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

pub(crate) fn validate_attachment_anchor_path(value: &str) -> Result<()> {
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
        return Err(HostError::InvalidPlan(
            "attachment anchor is not one exact namespace-generation pin".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, OwnedFd};
    use std::path::Path;

    use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind};

    use super::*;

    fn readiness_with_pin(executable_pin: OwnedFd) -> BackendReadiness {
        readiness_with_path_and_pin(TEST_NSPAWN_PATH, executable_pin)
    }

    fn readiness_with_path_and_pin(
        executable_path: &str,
        executable_pin: OwnedFd,
    ) -> BackendReadiness {
        readiness::backend_readiness_for_tests(executable_path, executable_pin).unwrap()
    }

    fn readiness_with_path(executable_path: &str) -> BackendReadiness {
        let executable = std::env::current_exe().unwrap();
        let executable_pin = rustix::fs::open(
            executable,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();

        readiness_with_path_and_pin(executable_path, executable_pin)
    }

    fn readiness() -> BackendReadiness {
        readiness_with_path(TEST_NSPAWN_PATH)
    }

    #[test]
    fn nspawn_readiness_transfers_the_exact_pin_without_reopening_its_path() {
        assert!(!Path::new(TEST_NSPAWN_PATH).exists());
        let readiness = readiness();
        let admitted_descriptor = readiness.binding.executable_pin.as_raw_fd();
        let admitted_snapshot = readiness.binding.executable_snapshot;
        let admitted_executable_sha256 = readiness.binding.executable_sha256;

        let config = NspawnConfig::from_readiness(
            readiness,
            Duration::from_secs(30),
            Duration::from_secs(10),
        )
        .unwrap();

        assert_eq!(
            config.readiness.binding.executable_pin.as_raw_fd(),
            admitted_descriptor
        );
        assert_eq!(
            config.readiness.binding.executable_snapshot,
            admitted_snapshot
        );
        assert_eq!(
            config.readiness.binding.executable_sha256,
            admitted_executable_sha256
        );
        config.revalidate().unwrap();
    }

    #[test]
    fn nspawn_readiness_rejects_each_incomplete_binding_or_claim() {
        let remove_claims: [fn(&mut BackendReadiness); 6] = [
            |readiness| readiness.binding.executable_snapshot.device = 0,
            |readiness| readiness.binding.executable_snapshot.inode = 0,
            |readiness| readiness.binding.artifact_sha256 = [0; 32],
            |readiness| readiness.mac_policy_digest = [0; 32],
            |readiness| readiness.supervisor_profile_digest = [0; 32],
            |readiness| readiness.payload_filter_digest = [0; 32],
        ];

        for remove_claim in remove_claims {
            let mut readiness = readiness();
            remove_claim(&mut readiness);

            assert!(
                NspawnConfig::from_readiness(
                    readiness,
                    Duration::from_secs(30),
                    Duration::from_secs(10),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn nspawn_readiness_rejects_invalid_path_and_zero_timeouts() {
        let invalid_path = readiness_with_path("/tmp/systemd-nspawn");
        let error = NspawnConfig::from_readiness(
            invalid_path,
            Duration::from_secs(30),
            Duration::from_secs(10),
        );
        assert!(matches!(
            error,
            Err(HostError::InvalidPlan(message))
                if message == "nspawn executable is not the fixed AOS store binary"
        ));

        assert!(
            NspawnConfig::from_readiness(readiness(), Duration::ZERO, Duration::from_secs(10),)
                .is_err()
        );
        assert!(
            NspawnConfig::from_readiness(readiness(), Duration::from_secs(30), Duration::ZERO,)
                .is_err()
        );
    }

    #[test]
    fn nspawn_readiness_rejects_declared_descriptor_identity_substitution() {
        let mut changed_device = readiness();
        changed_device.binding.executable_snapshot.device = changed_device
            .binding
            .executable_snapshot
            .device
            .wrapping_add(1);
        assert!(
            NspawnConfig::from_readiness(
                changed_device,
                Duration::from_secs(30),
                Duration::from_secs(10),
            )
            .is_err()
        );

        let mut changed_inode = readiness();
        changed_inode.binding.executable_snapshot.inode = changed_inode
            .binding
            .executable_snapshot
            .inode
            .wrapping_add(1);
        assert!(
            NspawnConfig::from_readiness(
                changed_inode,
                Duration::from_secs(30),
                Duration::from_secs(10),
            )
            .is_err()
        );
    }

    #[test]
    fn nspawn_readiness_revalidates_every_executable_snapshot_field() {
        let change_fields: [fn(&mut NspawnExecutableSnapshot); 9] = [
            |snapshot| snapshot.device = snapshot.device.wrapping_add(1),
            |snapshot| snapshot.inode = snapshot.inode.wrapping_add(1),
            |snapshot| snapshot.bytes = snapshot.bytes.wrapping_add(1),
            |snapshot| snapshot.uid = snapshot.uid.wrapping_add(1),
            |snapshot| snapshot.mode ^= 0o100,
            |snapshot| {
                snapshot.modified_seconds = snapshot.modified_seconds.wrapping_add(1);
            },
            |snapshot| {
                snapshot.modified_nanoseconds = snapshot.modified_nanoseconds.wrapping_add(1);
            },
            |snapshot| {
                snapshot.changed_seconds = snapshot.changed_seconds.wrapping_add(1);
            },
            |snapshot| {
                snapshot.changed_nanoseconds = snapshot.changed_nanoseconds.wrapping_add(1);
            },
        ];

        for change_field in change_fields {
            let mut readiness = readiness();
            change_field(&mut readiness.binding.executable_snapshot);

            assert!(
                NspawnConfig::from_readiness(
                    readiness,
                    Duration::from_secs(30),
                    Duration::from_secs(10),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn nspawn_readiness_rejects_metadata_drift_on_the_retained_file() {
        let mut executable = tempfile::tempfile().unwrap();
        executable.write_all(b"admitted executable").unwrap();
        let executable_pin = OwnedFd::from(executable.try_clone().unwrap());
        let readiness = readiness_with_pin(executable_pin);

        executable.set_len(128).unwrap();

        assert!(
            NspawnConfig::from_readiness(
                readiness,
                Duration::from_secs(30),
                Duration::from_secs(10),
            )
            .is_err()
        );
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
}
