//! Installed native candidate preparation separated from node execution authority.
//!
//! [`KvmInstalledCandidate`] authenticates bounded installation files. Its
//! stopped preparation opens the real native KVM API and creates a kernel VM,
//! but creates no vCPU, RAM, device, child process or run thread. Genuine
//! component observations cannot construct a `SimulationNode`, advertise a
//! capability profile, or pass an all-owner world readiness barrier.

mod artifact;
mod policy;

use crucible_node_contract::{ContentRef, HashRef, canonical};
use serde::Serialize;

use super::{KvmArchitecture, KvmNativePreparation, KvmProfileError, prepare_native_kvm};
use artifact::PinnedArtifact;

pub use policy::{
    KvmCandidateArtifactPolicy, KvmCandidateArtifactRole, KvmCandidatePolicy,
    MAX_KVM_CANDIDATE_POLICY_BYTES,
};

/// Bounds each installed file while authentication streams through finite buffers.
pub const MAX_KVM_CANDIDATE_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Bounds the complete installed file roster independently of native resource use.
pub const MAX_KVM_CANDIDATE_TOTAL_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024 * 1024;

const KVM_CAP_CONTROLLER_CLOCK_V1: u32 = 0xa025;
const KVM_CAP_CONTROLLER_CLOCK_V2: u32 = 0xa026;
const KVM_CAP_CONTROLLER_CLOCK_V3: u32 = 0xa027;

/// Classifies local candidate refusal without manufacturing native qualification.
#[derive(Debug, thiserror::Error)]
pub enum KvmCandidateError {
    /// A bounded closed local policy failed before native allocation.
    #[error("installed KVM candidate policy refused: {reason}")]
    Policy {
        /// Explains the failed structural or finite-resource requirement.
        reason: &'static str,
    },
    /// An actual installed file could not be opened or read.
    #[error("installed KVM {role:?} artifact I/O failed: {source}")]
    ArtifactIo {
        /// Identifies the independently installed artifact role.
        role: KvmCandidateArtifactRole,
        /// Retains the operating-system failure without guest effects.
        #[source]
        source: std::io::Error,
    },
    /// An installed file disagrees with independently expected bytes or file type.
    #[error("installed KVM {role:?} artifact identity changed")]
    ArtifactIdentity {
        /// Identifies the mismatched independently installed artifact.
        role: KvmCandidateArtifactRole,
    },
    /// The actual native kernel/device or component path refused preparation.
    #[error("installed KVM native preparation failed: {0}")]
    Native(#[from] KvmProfileError),
    /// The private policy or portable reference failed its closed schema.
    #[error("installed KVM candidate schema failed: {0}")]
    Schema(#[from] crucible_node_contract::ContractError),
}

impl KvmCandidateError {
    /// Reports an actual absent or inaccessible host device independently of coverage.
    pub fn environment_unavailable(&self) -> bool {
        matches!(
            self,
            Self::Native(KvmProfileError::DeviceUnavailable { .. })
        )
    }
}

/// Reports real stopped-VM component capabilities without executing a guest.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KvmStoppedComponentInventory {
    /// Names the actual native ISA checked against both kernel and compilation host.
    pub architecture: KvmArchitecture,
    /// Records the authentic running kernel release as observation, not a source hash.
    pub kernel_release: String,
    /// Records the native system API version, currently twelve.
    pub api_version: i32,
    /// Records the actual system limit; per-machine vCPU qualification remains absent.
    pub maximum_vcpus: u32,
    /// Reports this stopped VM's original TSC/read-write/RUN-owner component bitmap.
    pub clock_v1_components: u32,
    /// Reports this stopped VM's architecture-specific second-stage component bitmap.
    pub clock_v2_components: u32,
    /// Reports this stopped VM's automatic-ceiling component bitmap, or zero if refused.
    pub clock_v3_components: u32,
}

/// Owns measured candidate files without executable profile or activation authority.
#[derive(Debug)]
pub struct KvmInstalledCandidate {
    policy: KvmCandidatePolicy,
    identity: HashRef,
    artifacts: Vec<PinnedArtifact>,
}

impl KvmInstalledCandidate {
    /// Authenticates the independently selected installed artifact roster.
    ///
    /// No emulator or guest is started. Source artifact authentication is not
    /// evidence that the running kernel was built from those source bytes.
    ///
    /// # Errors
    /// Refuses invalid local policy, symlink/nonregular or changed files,
    /// nonexecutable QEMU, or failed bounded streaming authentication.
    pub fn open(policy: KvmCandidatePolicy) -> Result<Self, KvmCandidateError> {
        policy.validate()?;
        let identity = canonical::json_hash("crucible.kvm.installed-candidate.v1", &policy)?;
        let artifacts = policy
            .artifacts
            .iter()
            .cloned()
            .map(PinnedArtifact::open)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            policy,
            identity,
            artifacts,
        })
    }

    /// Returns the original local policy identity, including its operational paths.
    ///
    /// This is not a backend implementation/source identity or native execution seal.
    pub fn identity(&self) -> &HashRef {
        &self.identity
    }

    /// Borrows the immutable original local candidate policy.
    pub fn policy(&self) -> &KvmCandidatePolicy {
        &self.policy
    }

    /// Iterates independently authenticated installed opaque artifact identities.
    pub fn artifact_identities(&self) -> impl Iterator<Item = &ContentRef> {
        self.artifacts
            .iter()
            .map(|artifact| &artifact.policy.expected)
    }

    pub(super) fn original_qemu_descriptor(&self) -> Result<std::fs::File, KvmCandidateError> {
        let artifact = self
            .artifacts
            .iter()
            .find(|artifact| artifact.policy.role == KvmCandidateArtifactRole::Qemu)
            .ok_or(KvmCandidateError::Policy {
                reason: "original QEMU installation absent",
            })?;
        artifact.clone_descriptor()
    }

    /// Prepares a genuine stopped kernel VM and probes its component inventory.
    ///
    /// The returned object retains the actual system/VM descriptors. No vCPU,
    /// guest RAM, device, run thread, child process, input delivery or publication
    /// is allocated. Rechecking pinned artifact bytes precedes kernel allocation.
    ///
    /// # Errors
    /// Returns changed artifact identity, architecture mismatch, actual device
    /// absence/permissions, failed native VM construction or capability queries,
    /// or a requested vCPU bound exceeding the actual system limit.
    pub fn prepare_stopped_component(&self) -> Result<KvmCandidatePreparation, KvmCandidateError> {
        for artifact in &self.artifacts {
            artifact.verify()?;
        }
        let native = prepare_native_kvm(self.policy.architecture)?;
        if self.policy.vcpus.get() > u64::from(native.host().maximum_vcpus()) {
            return Err(KvmCandidateError::Policy {
                reason: "requested vCPU count exceeds actual native system capability",
            });
        }
        let components = |extension| {
            u32::try_from(native.check_vm_extension(extension)?).map_err(|_| {
                KvmProfileError::MissingMediation {
                    requirement: "negative native VM component bitmap".into(),
                }
            })
        };
        let inventory = KvmStoppedComponentInventory {
            architecture: native.host().architecture(),
            kernel_release: rustix::system::uname()
                .release()
                .to_string_lossy()
                .into_owned(),
            api_version: native.host().api_version(),
            maximum_vcpus: native.host().maximum_vcpus(),
            clock_v1_components: components(KVM_CAP_CONTROLLER_CLOCK_V1)?,
            clock_v2_components: components(KVM_CAP_CONTROLLER_CLOCK_V2)?,
            clock_v3_components: components(KVM_CAP_CONTROLLER_CLOCK_V3)?,
        };
        Ok(KvmCandidatePreparation {
            candidate: self.identity.clone(),
            native,
            inventory,
        })
    }

    /// Attempts native quantized preparation without stock KVM or TCG fallback.
    ///
    /// This exercises the real kernel preparation path. This source edition then
    /// refuses the missing whole-domain emulator/device/output mediation before
    /// any vCPU, child, guest input or native RUN can exist. Component offsets,
    /// clock caps or a successful ordinary QMP stop cannot bypass the refusal.
    ///
    /// # Errors
    /// Reports genuine hardware/environment failure separately from incomplete
    /// controller component coverage and missing whole-domain implementation.
    /// This edition never returns executable qualification.
    pub fn prepare_quantized(&self) -> Result<(), KvmCandidateError> {
        let prepared = self.prepare_stopped_component()?;
        prepared.require_whole_domain()
    }
}

/// Retains real inactive kernel descriptors and their authentic observed inventory.
///
/// The constructor is private and no raw descriptor, activation token or run
/// method is exposed. Dropping this no-vCPU object closes its owned kernel
/// handles; there is no autonomous process to abandon or physically stop.
#[derive(Debug)]
pub struct KvmCandidatePreparation {
    candidate: HashRef,
    native: KvmNativePreparation,
    inventory: KvmStoppedComponentInventory,
}

impl KvmCandidatePreparation {
    /// Returns the original independently measured local candidate identity.
    pub fn candidate_identity(&self) -> &HashRef {
        &self.candidate
    }

    /// Returns the genuine stopped VM's observed component capabilities.
    pub fn inventory(&self) -> &KvmStoppedComponentInventory {
        &self.inventory
    }

    /// Queries another VM-specific extension without granting execution authority.
    ///
    /// # Errors
    /// Returns the actual VM capability failure while retaining both descriptors.
    pub fn check_vm_extension(&self, extension: u32) -> Result<i32, KvmCandidateError> {
        Ok(self.native.check_vm_extension(extension)?)
    }

    fn require_whole_domain(&self) -> Result<(), KvmCandidateError> {
        let requirement = match self.inventory.architecture {
            KvmArchitecture::X86_64 if self.inventory.clock_v1_components != 7 => {
                "actual stopped VM lacks the exact original controller-clock component ABI"
            }
            KvmArchitecture::Aarch64 if self.inventory.clock_v3_components == 0 => {
                "native ARM event-stream enforcement remains unsupported by the controller ABI"
            }
            _ => {
                "native all-vCPU/exit/device/IRQ/input/output custody and stopped-clock qualification are incomplete"
            }
        };
        Err(KvmProfileError::MissingMediation {
            requirement: requirement.into(),
        }
        .into())
    }
}

#[cfg(test)]
mod tests;
