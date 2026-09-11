//! Protected backend-readiness claims and rollback-safe persistence.
//!
//! This module owns the bounded credential and watermark codecs, protected
//! filesystem loading, deployment-identity validation, and monotonic publisher
//! watermark updates used by the host launch planner.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_linux::boot::KernelBootId;
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{NspawnExecutableSnapshot, validate_fixed_nspawn_path};
use crate::{HostError, Result};

const READINESS_CREDENTIAL_FILE: &str = "backend-readiness.json";
const READINESS_SCHEMA: &str = "aos.sandbox.host-backend-readiness.v1";
const MAXIMUM_READINESS_BYTES: usize = 16 * 1024;
const READINESS_WATERMARK_FILE: &str = "backend-readiness-watermark.json";
const READINESS_WATERMARK_NEXT: &str = "backend-readiness-watermark.next";
const READINESS_WATERMARK_SCHEMA: &str = "aos.sandbox.host-backend-readiness-watermark.v1";
const MAXIMUM_WATERMARK_BYTES: usize = 4096;

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
#[derive(Debug)]
pub struct BackendReadiness {
    pub(super) executable: String,
    pub(super) executable_device: u64,
    pub(super) executable_inode: u64,
    pub(super) executable_pin: OwnedFd,
    pub(super) executable_snapshot: NspawnExecutableSnapshot,
    pub(super) probe_generation: u64,
    pub(super) mac_policy_digest: [u8; 32],
    pub(super) supervisor_profile_digest: [u8; 32],
    pub(super) payload_filter_digest: [u8; 32],
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
    let executable = super::open_executable_pin(expected_executable)?;
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

const fn protected_directory_permissions(mode: u32) -> bool {
    matches!(mode & 0o7777, 0o500 | 0o700)
}

const fn protected_file_permissions(mode: u32) -> bool {
    matches!(mode & 0o7777, 0o400 | 0o600)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::symlink;

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
