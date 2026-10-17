//! Operator-installed KVM candidate preparation without executable profile promotion.
//!
//! The local caller supplies independently authenticated installation policy.
//! These helpers measure actual files and reach the real native device path;
//! they cannot add a KVM `InstalledNodeKind`, publish a node descriptor, prepare
//! an admitted world, or convert a component bitmap into native run authority.

use crucible_qemu::kvm_profile::{KvmCandidateError, KvmCandidatePolicy, KvmInstalledCandidate};

pub use crucible_qemu::kvm_profile::MAX_KVM_CANDIDATE_POLICY_BYTES;

/// Measures a strict independently selected native candidate policy.
///
/// # Errors
/// Refuses unknown policy/qualification fields, invalid bounds, missing source
/// artifacts, or changed installed bytes. No native resource is created here.
pub fn load_installed_kvm_candidate(
    bytes: &[u8],
) -> Result<KvmInstalledCandidate, KvmCandidateError> {
    KvmInstalledCandidate::open(KvmCandidatePolicy::from_json(bytes)?)
}

/// Attempts real stopped native preparation and refuses incomplete execution paths.
///
/// This is an operational installed-backend entry point, not a conformance
/// witness. Actual device absence returns an environment failure; an available
/// unqualified kernel/emulator path returns missing mediation. No guest or
/// emulator child can execute and no TCG fallback is selected.
///
/// # Errors
/// Reports malformed or changed installation, actual KVM device/VM failure,
/// architecture mismatch, or incomplete whole-domain native mediation. This
/// source edition never returns an executable profile.
pub fn prepare_installed_kvm_candidate(bytes: &[u8]) -> Result<(), KvmCandidateError> {
    load_installed_kvm_candidate(bytes)?.prepare_quantized()
}
