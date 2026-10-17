//! Closed local installation policy for native KVM component preparation.
//!
//! ```json
//! {"format":"crucible.kvm-installed-candidate","version":1,
//!  "architecture":"x86_64","vcpus":"1","quantum_ps":"1000000",
//!  "host_budget_ns":"1000000","artifacts":[
//!    {"role":"qemu","path":"/installed/qemu","expected":{}}
//!  ]}
//! ```
//!
//! The abbreviated content reference is illustrative. Actual references must
//! authenticate complete bytes independently selected by the local operator.
//! This policy has no execution, stopping, capture or replay qualification field.

use std::path::PathBuf;

use crucible_node_contract::{ContentRef, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

use super::{KvmArchitecture, KvmCandidateError};

/// Bounds a complete local candidate policy before parsing or allocation.
pub const MAX_KVM_CANDIDATE_POLICY_BYTES: usize = 64 * 1024;

/// Identifies the measured artifact's role without granting native authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KvmCandidateArtifactRole {
    /// Names the actual QEMU executable selected for a later guarded launch.
    Qemu,
    /// Names the QEMU source archive whose build correspondence remains unqualified.
    QemuSource,
    /// Names the source-built kernel mediation patch or complete source archive.
    KernelSource,
}

/// Binds an installed file to independently expected complete content.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvmCandidateArtifactPolicy {
    /// Names the artifact's unique role in the installed roster.
    pub role: KvmCandidateArtifactRole,
    /// Locates a local regular file independently of its artifact byte identity.
    pub path: PathBuf,
    /// Authenticates the file's exact opaque bytes, rather than its pathname.
    pub expected: ContentRef,
}

/// Describes an operator-installed native candidate without executable guarantees.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvmCandidatePolicy {
    /// Names the closed candidate policy format.
    pub format: String,
    /// Selects edition one of the local candidate policy.
    pub version: u16,
    /// Selects the native host ISA; cross-architecture TCG fallback is forbidden.
    pub architecture: KvmArchitecture,
    /// Bounds the eventual native vCPU roster before any vCPU is created.
    pub vcpus: U64,
    /// Declares a fixed simulated window, in whole nanoseconds expressed as ps.
    pub quantum_ps: U64,
    /// Bounds operational native work, in nanoseconds, independently of guest time.
    pub host_budget_ns: U64,
    /// Names exactly one QEMU, QEMU source and kernel source artifact, in role order.
    pub artifacts: Vec<KvmCandidateArtifactPolicy>,
}

impl KvmCandidatePolicy {
    /// Decodes bounded duplicate-strict policy without allocating native resources.
    ///
    /// # Errors
    /// Refuses malformed JSON, duplicate or unknown fields, unsupported formats,
    /// absent source artifacts, invalid references, or unrepresentable timing.
    pub fn from_json(bytes: &[u8]) -> Result<Self, KvmCandidateError> {
        let value = canonical::parse_json(bytes, MAX_KVM_CANDIDATE_POLICY_BYTES)?;
        let policy: Self =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Checks finite preparation parameters and the complete installed roster.
    ///
    /// # Errors
    /// Refuses unknown editions, duplicate/missing artifacts, nonabsolute paths,
    /// more than 4096 vCPUs, subnanosecond component coordinates, zero/excessive
    /// budgets, or files exceeding the finite candidate measurement limits.
    pub fn validate(&self) -> Result<(), KvmCandidateError> {
        if self.format != "crucible.kvm-installed-candidate"
            || self.version != 1
            || !(1..=4096).contains(&self.vcpus.get())
            || self.quantum_ps.get() == 0
            || !self.quantum_ps.get().is_multiple_of(1000)
            || self.quantum_ps.get() / 1000 > i64::MAX as u64
            || !(1..=5_000_000_000).contains(&self.host_budget_ns.get())
        {
            return Err(KvmCandidateError::Policy {
                reason: "unsupported candidate edition or native window bounds",
            });
        }
        let roles = [
            KvmCandidateArtifactRole::Qemu,
            KvmCandidateArtifactRole::QemuSource,
            KvmCandidateArtifactRole::KernelSource,
        ];
        if self.artifacts.len() != roles.len() {
            return Err(KvmCandidateError::Policy {
                reason: "candidate requires exactly three installed artifact roles",
            });
        }
        let mut total = 0u64;
        for (artifact, role) in self.artifacts.iter().zip(roles) {
            artifact.expected.validate()?;
            if artifact.role != role
                || !artifact.path.is_absolute()
                || artifact.expected.length.get() == 0
                || artifact.expected.length.get() > super::MAX_KVM_CANDIDATE_ARTIFACT_BYTES
                || artifact.expected.hash.domain != "cnp.blob.v1"
            {
                return Err(KvmCandidateError::Policy {
                    reason: "candidate artifact role, path or finite content bound is invalid",
                });
            }
            total = total.checked_add(artifact.expected.length.get()).ok_or(
                KvmCandidateError::Policy {
                    reason: "candidate artifact total overflows",
                },
            )?;
        }
        if total > super::MAX_KVM_CANDIDATE_TOTAL_ARTIFACT_BYTES {
            return Err(KvmCandidateError::Policy {
                reason: "candidate artifact total exceeds installed measurement allowance",
            });
        }
        Ok(())
    }
}
