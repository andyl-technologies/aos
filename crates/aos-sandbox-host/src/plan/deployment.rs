//! Non-authorizing startup verification of deployed Host backend evidence.
//!
//! Both Host entrypoints call this shared gate. A missing optional phase-0
//! credential preserves observation-only service; a present invalid credential
//! or independent probe report fails startup. Successful partial verification
//! never constructs `NspawnConfig`.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_sandbox_linux::boot::KernelBootId;
use aos_systemd::SystemdClient;
use ed25519_dalek::VerifyingKey;
use rustix::fs::{Mode, OFlags, open};

use super::readiness::verified_packaged_nspawn_digest;
use super::{
    BackendReadinessBlocker, ProtectedBackendReadinessEvidence, VerifiedLiveSelinuxPolicyV1,
};
use crate::phase0_probe::{
    PHASE0_PROBE_RECORD_BYTES, SignedPhase0ProbeRecordV1, verified_packaged_hostd_digest,
};
use crate::{HostError, Result};

const PROBE_DIRECTORY: &str = "/var/lib/aos/sandbox-host-phase0";
const PROBE_RECORD: &str = "probe-v1";
const PROBE_PUBLIC_KEY: &str = "phase0-probe-public-key-v1";

/// Verifies every currently implemented, non-authorizing deployment check.
///
/// The protected phase-0 credential is optional because Host observation must
/// remain available before the independent filter and full shifted-payload
/// producers exist. A separately configured signed shifted-target probe is
/// always verified, even when this credential is absent.
///
/// # Errors
///
/// Rejects a malformed or stale credential, packaged executable mismatch,
/// foreign PID 1/service policy, non-enforcing or foreign SELinux policy,
/// missing/invalid signed probe evidence, or an unexpected launch-blocker set.
pub async fn verify_optional_backend_deployment_v1(
    credential_directory: &Path,
    state_root: &Path,
    nspawn_executable: &str,
    selinux_policy: &str,
) -> Result<()> {
    let probe_digest = verify_optional_protected_phase0_probe(
        credential_directory,
        nspawn_executable,
        selinux_policy,
    )?;
    let Some(readiness) = ProtectedBackendReadinessEvidence::load_protected_optional(
        credential_directory,
        state_root,
        nspawn_executable,
    )?
    else {
        return Ok(());
    };

    let packaged = readiness.verify_packaged_runtime()?;
    let live_mac = VerifiedLiveSelinuxPolicyV1::verify(selinux_policy)?;
    let systemd = SystemdClient::connect()
        .await
        .map_err(|error| HostError::State(format!("PID 1 bus unavailable: {error}")))?;
    packaged
        .verify_live_pid1_service(&readiness, &systemd)
        .await?;
    live_mac.revalidate(selinux_policy)?;
    if probe_digest != Some(readiness.phase0_probe_claim()) {
        return Err(HostError::State(
            "protected phase-0 probe claim differs from signed readback".to_owned(),
        ));
    }

    if readiness.runtime_blockers()
        != [
            BackendReadinessBlocker::Phase0ClaimVerification,
            BackendReadinessBlocker::ShiftedPayloadPidfdNamespaceInspection,
            BackendReadinessBlocker::PayloadRootPolicyDeploymentVerification,
        ]
    {
        return Err(HostError::State(
            "host backend readiness boundary changed without launch wiring".to_owned(),
        ));
    }
    Ok(())
}

fn verify_optional_protected_phase0_probe(
    credential_directory: &Path,
    nspawn_executable: &str,
    selinux_policy: &str,
) -> Result<Option<[u8; 32]>> {
    let public_path = credential_directory.join(PROBE_PUBLIC_KEY);
    match public_path.symlink_metadata() {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(HostError::State(format!(
                "cannot inspect phase-0 verifier pin: {error}"
            )));
        }
    }
    let public = read_protected_exact(&public_path, 32)?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| HostError::State("phase-0 probe verifier key has wrong length".to_owned()))?;
    let key = VerifyingKey::from_bytes(&public)
        .map_err(|_| HostError::State("phase-0 probe verifier key is invalid".to_owned()))?;

    let directory = Path::new(PROBE_DIRECTORY);
    let metadata = directory
        .symlink_metadata()
        .map_err(|error| HostError::State(format!("phase-0 probe root is absent: {error}")))?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(HostError::State(
            "phase-0 probe root is not protected".to_owned(),
        ));
    }
    let bytes = read_protected_exact(&directory.join(PROBE_RECORD), PHASE0_PROBE_RECORD_BYTES)?;
    let boot_id = KernelBootId::current()
        .map(KernelBootId::into_bytes)
        .map_err(|error| HostError::State(error.to_string()))?;
    let nspawn_sha256 = verified_packaged_nspawn_digest(nspawn_executable)?;
    let hostd_path = std::env::current_exe().map_err(|error| {
        HostError::State(format!("cannot resolve running Host daemon: {error}"))
    })?;
    let hostd_sha256 = verified_packaged_hostd_digest(&hostd_path)?;
    let selinux_policy_sha256 = VerifiedLiveSelinuxPolicyV1::verify(selinux_policy)?.digest();
    let report = SignedPhase0ProbeRecordV1::verify(
        &bytes,
        &key,
        boot_id,
        nspawn_sha256,
        hostd_sha256,
        selinux_policy_sha256,
    )?;
    Ok(Some(report.digest()))
}

fn read_protected_exact(path: &Path, length: usize) -> Result<Vec<u8>> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| HostError::State(format!("protected phase-0 input is absent: {error}")))?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|error| {
        HostError::State(format!("cannot stat protected phase-0 input: {error}"))
    })?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() != length as u64
    {
        return Err(HostError::State(
            "protected phase-0 input has invalid metadata".to_owned(),
        ));
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).map_err(|error| {
        HostError::State(format!("cannot read protected phase-0 input: {error}"))
    })?;
    let mut trailing = [0];
    if file.read(&mut trailing).map_err(|error| {
        HostError::State(format!("cannot recheck protected phase-0 input: {error}"))
    })? != 0
    {
        return Err(HostError::State(
            "protected phase-0 input has trailing bytes".to_owned(),
        ));
    }
    Ok(bytes)
}
