//! Offline sandbox-root builder seams for dormant and concrete guest agents.
//!
//! Each builder materializes exact package-pinned executables and a protected
//! agent credential into a caller-provided staging root. Neither installs
//! OpenSSH route trust material or activates the guest transport.

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

const EXECUTABLE_RELATIVE_PATH: &str = "usr/libexec/aos-sandbox-agent";
const CREDENTIAL_RELATIVE_PATH: &str = "run/credentials/aos-sandbox-agent/guest-executable-v1";
const CONCRETE_AGENT_PATH: &str = "usr/libexec/aos-sandbox-guest-agent";
const CONCRETE_HELPER_PATH: &str = "usr/libexec/aos-sandbox-guest-exec";
const CONCRETE_GATE_PATH: &str = "usr/libexec/aos-sandbox-exec-gate";
const SSHD_SESSION_PATH: &str = "usr/libexec/sshd-session";

/// Pins one executable source to its expected package content digest.
pub struct GuestExecutableInputV1 {
    /// Absolute path to an AOS-built executable.
    pub source: PathBuf,
    /// SHA-256 of its complete executable bytes.
    pub digest: ObjectDigest,
}

/// Names all binaries required by the concrete guest process and attach owner.
pub struct ConcreteGuestRootBuildPlanV1 {
    /// Offline staging root, not an active guest filesystem.
    pub staging_root: PathBuf,
    /// Protected agent executable installed at its fixed libexec path.
    pub agent: GuestExecutableInputV1,
    /// Admission-only child launcher installed beside the agent.
    pub helper: GuestExecutableInputV1,
    /// Forced-command gate executable installed at its fixed path.
    pub gate: GuestExecutableInputV1,
    /// AOS OpenSSH session helper used for peer ancestry verification.
    pub sshd_session: GuestExecutableInputV1,
    /// Protected package binding carried by agent provisioning.
    pub credential_binding: ObjectDigest,
}

/// Materializes exact package-pinned guest binaries into an offline root.
///
/// This does not install route-specific OpenSSH keys or configuration. The
/// attach gate remains unavailable until a separate authenticated installer
/// supplies those files and a physical readback verifies them.
///
/// # Errors
///
/// Returns an error for invalid source commitments, substituted executable
/// bytes, or occupied destination paths.
pub fn build_concrete_guest_root_v1(
    plan: &ConcreteGuestRootBuildPlanV1,
) -> Result<(), DormantGuestRootBuildErrorV1> {
    if !plan.staging_root.is_absolute() || plan.credential_binding.as_bytes() == &[0; 32] {
        return Err(DormantGuestRootBuildErrorV1::InvalidPlan);
    }

    for (input, relative_path) in [
        (&plan.agent, CONCRETE_AGENT_PATH),
        (&plan.helper, CONCRETE_HELPER_PATH),
        (&plan.gate, CONCRETE_GATE_PATH),
        (&plan.sshd_session, SSHD_SESSION_PATH),
    ] {
        if !input.source.is_absolute() || input.digest.as_bytes() == &[0; 32] {
            return Err(DormantGuestRootBuildErrorV1::InvalidPlan);
        }
        let bytes = read_bounded(&input.source)?;
        if content_digest(&bytes) != input.digest {
            return Err(DormantGuestRootBuildErrorV1::ExecutableMismatch);
        }
        write_new_file(&plan.staging_root.join(relative_path), 0o500, &bytes)?;
    }

    write_credential(
        &plan.staging_root,
        plan.agent.digest,
        plan.credential_binding,
    )
}

/// Describes exact offline inputs for one dormant guest root.
pub struct DormantGuestRootBuildPlanV1 {
    staging_root: PathBuf,
    executable_source: PathBuf,
    executable_digest: ObjectDigest,
    credential_binding: ObjectDigest,
}

impl DormantGuestRootBuildPlanV1 {
    /// Constructs one fixed-layout root build plan.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuestRootBuildErrorV1::InvalidPlan`] for a nonabsolute
    /// staging root/source or sentinel commitment.
    pub fn new(
        staging_root: PathBuf,
        executable_source: PathBuf,
        executable_digest: ObjectDigest,
        credential_binding: ObjectDigest,
    ) -> Result<Self, DormantGuestRootBuildErrorV1> {
        if !staging_root.is_absolute()
            || !executable_source.is_absolute()
            || executable_digest.as_bytes() == &[0; 32]
            || credential_binding.as_bytes() == &[0; 32]
        {
            return Err(DormantGuestRootBuildErrorV1::InvalidPlan);
        }
        Ok(Self {
            staging_root,
            executable_source,
            executable_digest,
            credential_binding,
        })
    }
}

/// Materializes the dormant guest-agent files into an offline staging root.
///
/// # Errors
///
/// Returns [`DormantGuestRootBuildErrorV1`] for unavailable filesystem access,
/// substituted executable content, or a nonempty destination file.
pub fn build_dormant_guest_root_v1(
    plan: &DormantGuestRootBuildPlanV1,
) -> Result<(), DormantGuestRootBuildErrorV1> {
    let executable_bytes = read_bounded(&plan.executable_source)?;
    if content_digest(&executable_bytes) != plan.executable_digest {
        return Err(DormantGuestRootBuildErrorV1::ExecutableMismatch);
    }

    let executable_target = plan.staging_root.join(EXECUTABLE_RELATIVE_PATH);
    write_new_file(&executable_target, 0o500, &executable_bytes)?;

    write_credential(
        &plan.staging_root,
        plan.executable_digest,
        plan.credential_binding,
    )
}

fn write_credential(
    staging_root: &Path,
    executable_digest: ObjectDigest,
    credential_binding: ObjectDigest,
) -> Result<(), DormantGuestRootBuildErrorV1> {
    let mut credential = Vec::with_capacity(104);
    credential.extend_from_slice(b"AOSGEX01");
    credential.extend_from_slice(executable_digest.as_bytes());
    credential.extend_from_slice(credential_binding.as_bytes());
    let checksum = content_digest(&credential);
    credential.extend_from_slice(checksum.as_bytes());
    write_new_file(
        &staging_root.join(CREDENTIAL_RELATIVE_PATH),
        0o400,
        &credential,
    )
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, DormantGuestRootBuildErrorV1> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 128 * 1_048_576 {
        return Err(DormantGuestRootBuildErrorV1::InvalidPlan);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write_new_file(
    path: &Path,
    mode: u32,
    bytes: &[u8],
) -> Result<(), DormantGuestRootBuildErrorV1> {
    let parent = path
        .parent()
        .ok_or(DormantGuestRootBuildErrorV1::InvalidPlan)?;
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn content_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

/// Reports offline dormant-root construction failure.
#[derive(Debug, thiserror::Error)]
pub enum DormantGuestRootBuildErrorV1 {
    /// A path or commitment violates the fixed build contract.
    #[error("dormant guest root build plan is invalid")]
    InvalidPlan,
    /// The executable source does not match its package commitment.
    #[error("dormant guest executable does not match its package commitment")]
    ExecutableMismatch,
    /// Offline staging filesystem access failed.
    #[error("dormant guest root filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
}
