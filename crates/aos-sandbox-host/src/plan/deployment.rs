//! Non-authorizing startup verification of deployed Host backend evidence.
//!
//! A missing optional phase-0 credential preserves observation-only service;
//! a present invalid credential or independent probe report fails startup.
//! Successful partial verification retains a revalidatable proof but never
//! constructs `NspawnConfig`.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::pidfd::{NamespaceKind, PidFd};
use aos_systemd::SystemdClient;
use ed25519_dalek::VerifyingKey;
use rustix::fs::{Mode, OFlags, open};

use super::readiness::verified_packaged_nspawn_digest;
use super::{
    BackendReadinessBlocker, ProtectedBackendReadinessEvidence, VerifiedLiveSelinuxPolicyV1,
    VerifiedPackagedRuntimeV1,
};
use crate::phase0_probe::{
    PHASE0_PROBE_RECORD_BYTES, Phase0ProbeObservationV2, SignedPhase0ProbeRecordV2,
    verified_packaged_hostd_digest, verified_packaged_inspector_digest,
};
use crate::{HostError, Result};

const PROBE_DIRECTORY: &str = "/var/lib/aos/sandbox-host-phase0";
const PROBE_RECORD: &str = "probe-v2";
const PROBE_PUBLIC_KEY: &str = "phase0-probe-public-key-v1";
const PROBE_TARGET_SERVICE: &str = "aos-sandbox-host-phase0-target.service";

/// Retains an independently verified, boot-local phase-0 deployment claim.
///
/// The protected readiness credential alone cannot construct this value. Its
/// package and PID 1 identity, active SELinux policy, signed shifted-target
/// probe, and a fresh zero-capability Host readback have all matched. This is
/// not backend launch readiness: shifted payload inspection and payload-root
/// deployment remain separate blockers.
pub struct VerifiedPhase0ClaimV1 {
    readiness: ProtectedBackendReadinessEvidence,
    packaged: VerifiedPackagedRuntimeV1,
    probe_digest: [u8; 32],
    observation: Phase0ProbeObservationV2,
    policy_digest: [u8; 32],
}

impl VerifiedPhase0ClaimV1 {
    /// Returns the exact signed probe commitment matched to protected readiness.
    #[must_use]
    pub const fn probe_digest(&self) -> [u8; 32] {
        self.probe_digest
    }

    /// Returns the two proofs still required before backend launch is possible.
    #[must_use]
    pub const fn remaining_blockers(&self) -> [BackendReadinessBlocker; 2] {
        [
            BackendReadinessBlocker::ShiftedPayloadPidfdNamespaceInspection,
            BackendReadinessBlocker::PayloadRootPolicyDeploymentVerification,
        ]
    }

    /// Repeats package, PID 1, policy, signed probe, and live target readback.
    ///
    /// # Errors
    ///
    /// Rejects an absent or changed protected claim, package, boot, PID 1,
    /// policy, signer, probe, or shifted target. Revalidation cannot authorize
    /// launch and never constructs `NspawnConfig`.
    pub async fn revalidate(
        &self,
        credential_directory: &Path,
        state_root: &Path,
        nspawn_executable: &str,
        selinux_policy: &str,
    ) -> Result<()> {
        let fresh = verify_optional_phase0_claim_v1(
            credential_directory,
            state_root,
            nspawn_executable,
            selinux_policy,
        )
        .await?
        .ok_or_else(|| HostError::State("phase-0 claim disappeared".to_owned()))?;
        self.packaged.revalidate(&fresh.readiness)?;
        if self.readiness.publisher_generation() != fresh.readiness.publisher_generation()
            || self.probe_digest != fresh.probe_digest
            || self.observation != fresh.observation
            || self.policy_digest != fresh.policy_digest
        {
            return Err(HostError::State(
                "phase-0 claim changed after verification".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Verifies every currently implemented, non-authorizing deployment check.
///
/// This compatibility entry point drops the typed proof after verification.
/// The protected phase-0 credential is optional because Host observation must
/// remain available before independent shifted-payload and payload-root
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
    let _phase0 = verify_optional_phase0_claim_v1(
        credential_directory,
        state_root,
        nspawn_executable,
        selinux_policy,
    )
    .await?;
    Ok(())
}

/// Produces a non-authorizing proof of the installed phase-0 claim.
///
/// The optional protected readiness credential permits observation-only Host
/// service when absent. A present claim requires exact independent readback
/// and returns an owned proof that can be revalidated without trusting the
/// original publisher. The remaining blockers still prohibit `NspawnConfig`.
///
/// # Errors
///
/// Rejects malformed or stale protected evidence, changed package or process
/// identity, absent or mismatched signed probe, or failed live kernel readback.
pub async fn verify_optional_phase0_claim_v1(
    credential_directory: &Path,
    state_root: &Path,
    nspawn_executable: &str,
    selinux_policy: &str,
) -> Result<Option<VerifiedPhase0ClaimV1>> {
    let probe = verify_optional_protected_phase0_probe(
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
        return Ok(None);
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
    let (probe_digest, observation) = matching_signed_probe(readiness.phase0_probe_claim(), probe)?;
    verify_host_shifted_target_access(&systemd, observation).await?;
    packaged.revalidate(&readiness)?;
    let policy_digest = live_mac.digest();
    live_mac.revalidate(selinux_policy)?;

    // Bracket the live readback with fresh protected-file reads. Neither a
    // signed report nor an admitted credential may be swapped mid-probe.
    let final_readiness = ProtectedBackendReadinessEvidence::load_protected(
        credential_directory,
        state_root,
        nspawn_executable,
    )?;
    packaged.revalidate(&final_readiness)?;
    let final_probe = verify_optional_protected_phase0_probe(
        credential_directory,
        nspawn_executable,
        selinux_policy,
    )?;
    let (final_probe_digest, final_observation) =
        matching_signed_probe(final_readiness.phase0_probe_claim(), final_probe)?;
    if final_readiness.publisher_generation() != readiness.publisher_generation()
        || final_probe_digest != probe_digest
        || final_observation != observation
    {
        return Err(HostError::State(
            "phase-0 claim changed during live readback".to_owned(),
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
    Ok(Some(VerifiedPhase0ClaimV1 {
        readiness,
        packaged,
        probe_digest,
        observation,
        policy_digest,
    }))
}

fn matching_signed_probe(
    claimed_digest: [u8; 32],
    probe: Option<([u8; 32], Phase0ProbeObservationV2)>,
) -> Result<([u8; 32], Phase0ProbeObservationV2)> {
    // The optional probe has already passed the independent key, package,
    // boot, and policy checks in verify_optional_protected_phase0_probe.
    let (digest, observation) = probe.ok_or_else(|| {
        HostError::State("protected phase-0 probe claim has no signed readback".to_owned())
    })?;
    if claimed_digest == [0; 32] || digest != claimed_digest {
        return Err(HostError::State(
            "protected phase-0 probe claim differs from signed readback".to_owned(),
        ));
    }
    Ok((digest, observation))
}

fn verify_optional_protected_phase0_probe(
    credential_directory: &Path,
    nspawn_executable: &str,
    selinux_policy: &str,
) -> Result<Option<([u8; 32], Phase0ProbeObservationV2)>> {
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
    let inspector_path = hostd_path
        .parent()
        .ok_or_else(|| HostError::State("running Host package has no binary directory".to_owned()))?
        .join("aos-sandbox-host-phase0-probe");
    let inspector_sha256 = verified_packaged_inspector_digest(&inspector_path)?;
    let selinux_policy_sha256 = VerifiedLiveSelinuxPolicyV1::verify(selinux_policy)?.digest();
    let report = SignedPhase0ProbeRecordV2::verify(
        &bytes,
        &key,
        boot_id,
        nspawn_sha256,
        hostd_sha256,
        inspector_sha256,
        selinux_policy_sha256,
    )?;
    Ok(Some((report.digest(), *report.observation())))
}

async fn verify_host_shifted_target_access(
    systemd: &SystemdClient,
    expected: Phase0ProbeObservationV2,
) -> Result<()> {
    verify_zero_capability_host_status()?;

    let service = systemd
        .observe_service_control_group(PROBE_TARGET_SERVICE)
        .await
        .map_err(|error| HostError::State(format!("shifted target readback failed: {error}")))?;
    verify_shifted_service_pid(expected.target_pid, service.main_pid.get())?;

    let target = PidFd::open(service.main_pid)
        .map_err(|error| HostError::State(format!("shifted target pidfd failed: {error}")))?;
    let before = target
        .info()
        .map_err(|error| HostError::State(format!("shifted target identity failed: {error}")))?;
    verify_shifted_process_identity(
        expected.target_pid,
        before.pid(),
        before.thread_group_id(),
        before.parent_pid(),
    )?;

    let root = open(
        "/sys/fs/cgroup",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| HostError::State(format!("cgroup root unavailable: {error}")))?;
    let root = CgroupV2Root::from_owned(root)
        .map_err(|error| HostError::State(format!("cgroup root invalid: {error}")))?;
    let relative = service
        .control_group
        .strip_prefix('/')
        .ok_or_else(|| HostError::State("shifted target cgroup is not absolute".to_owned()))?;
    let anchor = root
        .resolve(Path::new(relative))
        .map_err(|error| HostError::State(format!("shifted cgroup unavailable: {error}")))?;
    let membership = anchor
        .verify_exact_membership(&target)
        .map_err(|error| HostError::State(format!("shifted cgroup mismatch: {error}")))?;
    if membership.cgroup_id() != Some(expected.cgroup_id) {
        return Err(HostError::State(
            "shifted target cgroup differs from the signed probe".to_owned(),
        ));
    }

    for (kind, identity) in [
        (NamespaceKind::User, expected.user),
        (NamespaceKind::Mount, expected.mount),
        (NamespaceKind::Network, expected.network),
        (NamespaceKind::Pid, expected.pid),
    ] {
        let namespace = target.namespace(kind).map_err(|error| {
            HostError::State(format!(
                "zero-capability shifted pidfd access failed: {error}"
            ))
        })?;
        if namespace.identity() != identity {
            return Err(HostError::State(
                "shifted namespace differs from the signed probe".to_owned(),
            ));
        }
    }

    let after = target
        .info()
        .map_err(|error| HostError::State(format!("shifted target recheck failed: {error}")))?;
    if before != after
        || anchor
            .verify_exact_membership(&target)
            .map_err(|error| HostError::State(format!("shifted cgroup recheck failed: {error}")))?
            != membership
        || !target
            .is_alive()
            .map_err(|error| HostError::State(format!("shifted target liveness failed: {error}")))?
        || systemd
            .observe_service_control_group(PROBE_TARGET_SERVICE)
            .await
            .map_err(|error| HostError::State(format!("shifted service recheck failed: {error}")))?
            != service
    {
        return Err(HostError::State(
            "shifted target changed during Host pidfd inspection".to_owned(),
        ));
    }
    Ok(())
}

fn verify_zero_capability_host_status() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| HostError::State(format!("Host status unavailable: {error}")))?;
    verify_zero_capability_status(&status)
}

fn verify_shifted_service_pid(expected: u32, observed: u32) -> Result<()> {
    if observed != expected {
        return Err(HostError::State(
            "shifted target PID differs from the signed probe".to_owned(),
        ));
    }
    Ok(())
}

fn verify_shifted_process_identity(
    expected: u32,
    observed_pid: u32,
    observed_thread_group: u32,
    observed_parent: u32,
) -> Result<()> {
    if observed_pid != expected || observed_thread_group != expected || observed_parent != 1 {
        return Err(HostError::State(
            "shifted target is not PID 1's pinned service leader".to_owned(),
        ));
    }
    Ok(())
}

fn verify_zero_capability_status(status: &str) -> Result<()> {
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        if status_field(status, name) != Some("0000000000000000") {
            return Err(HostError::State(format!(
                "Host {name} is not zero during shifted-target inspection"
            )));
        }
    }
    if status_field(status, "NoNewPrivs") != Some("1")
        || status_field(status, "Seccomp") != Some("2")
    {
        return Err(HostError::State(
            "Host NNP or seccomp is absent during shifted-target inspection".to_owned(),
        ));
    }
    Ok(())
}

fn status_field<'a>(status: &'a str, name: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key == name).then(|| value.trim())
    })
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

#[cfg(test)]
mod tests {
    use super::{
        matching_signed_probe, verify_shifted_process_identity, verify_shifted_service_pid,
        verify_zero_capability_status,
    };
    use crate::phase0_probe::Phase0ProbeObservationV2;
    use aos_sandbox_linux::pidfd::NamespaceIdentity;

    const ZERO_CAPABILITY_STATUS: &str = "\
CapInh:\t0000000000000000\n\
CapPrm:\t0000000000000000\n\
CapEff:\t0000000000000000\n\
CapBnd:\t0000000000000000\n\
CapAmb:\t0000000000000000\n\
NoNewPrivs:\t1\n\
Seccomp:\t2\n";

    fn probe_observation() -> Phase0ProbeObservationV2 {
        let namespace = NamespaceIdentity {
            device: 1,
            inode: 2,
        };
        Phase0ProbeObservationV2 {
            boot_id: [1; 16],
            nspawn_sha256: [2; 32],
            hostd_sha256: [3; 32],
            inspector_sha256: [4; 32],
            selinux_policy_sha256: [5; 32],
            target_pid: 41,
            host_uid_start: 100_000,
            host_gid_start: 100_000,
            mapping_count: 65_536,
            cgroup_id: 8,
            user: namespace,
            mount: namespace,
            network: namespace,
            pid: namespace,
        }
    }

    #[test]
    fn phase0_claim_requires_the_exact_signed_probe_digest() {
        let observation = probe_observation();
        let probe = Some(([7; 32], observation));

        assert_eq!(
            matching_signed_probe([7; 32], probe).unwrap(),
            ([7; 32], observation)
        );
        assert!(matching_signed_probe([7; 32], None).is_err());
        assert!(matching_signed_probe([8; 32], probe).is_err());
        assert!(matching_signed_probe([0; 32], Some(([0; 32], observation))).is_err());
    }

    #[test]
    fn shifted_target_access_requires_zero_capabilities_and_active_hardening() {
        assert!(verify_zero_capability_status(ZERO_CAPABILITY_STATUS).is_ok());

        for changed in [
            ZERO_CAPABILITY_STATUS
                .replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
            ZERO_CAPABILITY_STATUS
                .replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001"),
            ZERO_CAPABILITY_STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            ZERO_CAPABILITY_STATUS.replace("Seccomp:\t2", "Seccomp:\t0"),
        ] {
            assert!(verify_zero_capability_status(&changed).is_err());
        }
    }

    #[test]
    fn shifted_target_rejects_service_and_pidfd_identity_substitution() {
        assert!(verify_shifted_service_pid(41, 41).is_ok());
        assert!(verify_shifted_service_pid(41, 42).is_err());
        assert!(verify_shifted_process_identity(41, 41, 41, 1).is_ok());
        assert!(verify_shifted_process_identity(41, 42, 41, 1).is_err());
        assert!(verify_shifted_process_identity(41, 41, 42, 1).is_err());
        assert!(verify_shifted_process_identity(41, 41, 41, 2).is_err());
    }
}
