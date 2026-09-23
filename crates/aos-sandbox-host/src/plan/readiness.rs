//! Protected backend-readiness claims and rollback-safe persistence.
//!
//! This module owns the bounded credential and watermark codecs, protected
//! filesystem loading, deployment-identity validation, and monotonic publisher
//! watermark updates used by the host launch planner.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::num::NonZeroU64;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::boot::KernelBootId;
use aos_systemd::PayloadRootContinuityPolicyV1;
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{NspawnExecutableSnapshot, nspawn_executable_snapshot, validate_fixed_nspawn_path};
use crate::{HostError, Result};

const READINESS_CREDENTIAL_FILE: &str = "backend-readiness.json";
const READINESS_SCHEMA: &str = "aos.sandbox.host-backend-readiness.v1";
const MAXIMUM_READINESS_BYTES: usize = 16 * 1024;
const READINESS_WATERMARK_FILE: &str = "backend-readiness-watermark.json";
const READINESS_WATERMARK_NEXT: &str = "backend-readiness-watermark.next";
const READINESS_WATERMARK_SCHEMA: &str = "aos.sandbox.host-backend-readiness-watermark.v1";
const MAXIMUM_WATERMARK_BYTES: usize = 4096;
const MAXIMUM_NSPAWN_EXECUTABLE_BYTES: i64 = 256 * 1024 * 1024;
const BACKEND_POLICY_ARTIFACT: &str = "share/aos/backend-policy-artifact-v1";
const BACKEND_POLICY_ARTIFACT_BYTES: usize = 9 + 65 * 3;
const BACKEND_POLICY_MAGIC: &[u8; 9] = b"AOSBPA01\n";
const EXECUTABLE_HASH_BUFFER_BYTES: usize = 64 * 1024;
const READINESS_BINDING_DOMAIN: &[u8] = b"aos.sandbox.host-readiness-binding.v1\0";

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
    pub(super) binding: ReadinessBindingV1,
    pub(super) mac_policy_digest: [u8; 32],
    pub(super) supervisor_profile_digest: [u8; 32],
    pub(super) payload_filter_digest: [u8; 32],
}

impl BackendReadiness {
    pub(super) fn into_nspawn_readiness(self) -> Result<Self> {
        self.revalidate_for_nspawn()?;
        Ok(self)
    }

    pub(super) fn revalidate_for_nspawn(&self) -> Result<()> {
        validate_fixed_nspawn_path(&self.binding.executable_path)?;
        if self.mac_policy_digest == [0; 32]
            || self.supervisor_profile_digest == [0; 32]
            || self.payload_filter_digest == [0; 32]
        {
            return Err(HostError::InvalidPlan(
                "nspawn backend readiness evidence is incomplete".to_owned(),
            ));
        }

        let current_boot_id = current_boot_id()?;
        self.binding
            .revalidate(current_boot_id)
            .map_err(|error| HostError::InvalidPlan(error.to_string()))
    }

    pub(super) fn executable_pin(&self) -> BorrowedFd<'_> {
        self.binding.executable_pin.as_fd()
    }

    pub(super) fn executable_pin_arc(&self) -> &Arc<OwnedFd> {
        &self.binding.executable_pin
    }
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
#[derive(Debug)]
pub struct ProtectedBackendReadinessEvidence {
    binding: ReadinessBindingV1,
    claims: UntrustedPhase0ClaimsV1,
}

/// Proves that one protected readiness claim matches the compiled supervisor policy.
///
/// The proof is bound to the admitted boot, publisher generation, artifact,
/// canonical executable path, descriptor snapshot, and executable content. It
/// verifies only the sealed compiler-policy digest. It does not attest a live
/// systemd deployment, a probe result, a payload filter, a MAC policy, or
/// shifted-payload inspection, and cannot create [`BackendReadiness`].
pub struct VerifiedCompiledSupervisorProfileV1 {
    binding_identity: ReadinessBindingIdentityV1,
    policy_digest: [u8; 32],
}

/// Proves the packaged policy and final binaries against live PID 1.
///
/// This is a partial phase-0 proof. It does not verify the installed unit
/// property program, the protected probe result, or shifted-payload access,
/// and therefore cannot construct [`BackendReadiness`].
pub struct VerifiedPackagedRuntimeV1 {
    binding_identity: ReadinessBindingIdentityV1,
    pid1_snapshot: NspawnExecutableSnapshot,
    pid1_digest: [u8; 32],
    policy_digest: [u8; 32],
}

impl VerifiedPackagedRuntimeV1 {
    /// Rechecks the same protected claim, package, and live PID 1 generation.
    ///
    /// # Errors
    ///
    /// Returns an error after a boot, executable, package, or PID 1 change.
    pub fn revalidate(&self, evidence: &ProtectedBackendReadinessEvidence) -> Result<()> {
        let current = evidence.verify_packaged_runtime()?;
        if current.binding_identity != self.binding_identity
            || current.pid1_snapshot != self.pid1_snapshot
            || current.pid1_digest != self.pid1_digest
            || current.policy_digest != self.policy_digest
        {
            return Err(HostError::State(
                "packaged backend proof changed after verification".to_owned(),
            ));
        }
        Ok(())
    }
}

struct BackendPolicyArtifactV1 {
    pid1_digest: [u8; 32],
    nspawn_digest: [u8; 32],
    policy_digest: [u8; 32],
}

fn read_backend_policy_artifact(nspawn_path: &str) -> Result<BackendPolicyArtifactV1> {
    let package_root = Path::new(nspawn_path)
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| HostError::State("nspawn package root is invalid".to_owned()))?;
    let artifact_path = package_root.join(BACKEND_POLICY_ARTIFACT);
    let descriptor = open(
        &artifact_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| HostError::State(error.to_string()))?;
    let bytes = read_protected_descriptor(
        descriptor,
        BACKEND_POLICY_ARTIFACT,
        BACKEND_POLICY_ARTIFACT_BYTES,
    )?;
    parse_backend_policy_artifact(&bytes)
}

fn parse_backend_policy_artifact(bytes: &[u8]) -> Result<BackendPolicyArtifactV1> {
    if bytes.len() != BACKEND_POLICY_ARTIFACT_BYTES || !bytes.starts_with(BACKEND_POLICY_MAGIC) {
        return Err(HostError::State(
            "packaged backend policy artifact is malformed".to_owned(),
        ));
    }
    let digest = |offset| -> Result<[u8; 32]> {
        let line = bytes.get(offset..offset + 65).ok_or_else(|| {
            HostError::State("packaged backend policy artifact is truncated".to_owned())
        })?;
        if line[64] != b'\n' {
            return Err(HostError::State(
                "packaged backend policy digest is malformed".to_owned(),
            ));
        }
        let text = std::str::from_utf8(&line[..64]).map_err(|_| {
            HostError::State("packaged backend policy digest is not UTF-8".to_owned())
        })?;
        let digest = format!("sha256:{text}")
            .parse::<ObjectDigest>()
            .map_err(|_| {
                HostError::State("packaged backend policy digest is invalid".to_owned())
            })?;
        if digest.as_bytes() == &[0; 32] {
            return Err(HostError::State(
                "packaged backend policy digest is a sentinel".to_owned(),
            ));
        }
        Ok(*digest.as_bytes())
    };

    Ok(BackendPolicyArtifactV1 {
        pid1_digest: digest(9)?,
        nspawn_digest: digest(74)?,
        policy_digest: digest(139)?,
    })
}

impl std::fmt::Debug for VerifiedCompiledSupervisorProfileV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedCompiledSupervisorProfileV1")
            .field("binding_identity", &self.binding_identity)
            .field("policy_digest", &self.policy_digest)
            .finish()
    }
}

#[derive(Debug)]
pub(super) struct ReadinessBindingV1 {
    pub(super) publisher_generation: NonZeroU64,
    pub(super) boot_id: [u8; 16],
    pub(super) artifact_sha256: [u8; 32],
    pub(super) executable_path: String,
    pub(super) executable_pin: Arc<OwnedFd>,
    pub(super) executable_snapshot: NspawnExecutableSnapshot,
    pub(super) executable_sha256: [u8; 32],
    identity: ReadinessBindingIdentityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadinessBindingIdentityV1([u8; 32]);

#[derive(Debug, Eq, PartialEq)]
struct UntrustedPhase0ClaimsV1 {
    probe_digest: [u8; 32],
    supervisor_profile_digest: [u8; 32],
    payload_filter_digest: [u8; 32],
}

impl ReadinessBindingV1 {
    fn new(
        publisher_generation: NonZeroU64,
        boot_id: [u8; 16],
        artifact_sha256: [u8; 32],
        executable_path: String,
        executable_pin: OwnedFd,
        executable_snapshot: NspawnExecutableSnapshot,
        executable_sha256: [u8; 32],
    ) -> Result<Self> {
        let identity = readiness_binding_identity(
            publisher_generation,
            boot_id,
            artifact_sha256,
            &executable_path,
            executable_snapshot,
            executable_sha256,
        )?;

        Ok(Self {
            publisher_generation,
            boot_id,
            artifact_sha256,
            executable_path,
            executable_pin: Arc::new(executable_pin),
            executable_snapshot,
            executable_sha256,
            identity,
        })
    }

    fn revalidate(&self, current_boot_id: [u8; 16]) -> Result<()> {
        if current_boot_id != self.boot_id
            || self.artifact_sha256 == [0; 32]
            || self.executable_sha256 == [0; 32]
            || readiness_binding_identity(
                self.publisher_generation,
                self.boot_id,
                self.artifact_sha256,
                &self.executable_path,
                self.executable_snapshot,
                self.executable_sha256,
            )? != self.identity
        {
            return Err(HostError::State(
                "backend readiness binding identity changed".to_owned(),
            ));
        }

        let (current_snapshot, current_sha256) =
            snapshot_and_hash_executable(self.executable_pin.as_fd())?;
        if current_snapshot != self.executable_snapshot || current_sha256 != self.executable_sha256
        {
            return Err(HostError::State(
                "backend readiness executable changed after admission".to_owned(),
            ));
        }
        Ok(())
    }
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
        let current_boot_id = current_boot_id()?;
        let evidence =
            verify_readiness(wire, current_boot_id, artifact_digest, expected_executable)?;

        persist_readiness_watermark(
            state_directory.as_ref(),
            ReadinessWatermark {
                schema: READINESS_WATERMARK_SCHEMA.to_owned(),
                publisher_generation: evidence.binding.publisher_generation.get(),
                boot_id: evidence.binding.boot_id,
                artifact_sha256: artifact_digest,
            },
        )?;
        Ok(Some(evidence))
    }

    /// Returns the monotonic publisher generation accepted at startup.
    #[must_use]
    pub const fn publisher_generation(&self) -> u64 {
        self.binding.publisher_generation.get()
    }

    /// Verifies that the protected supervisor-profile claim names the sealed policy.
    ///
    /// This check freshly binds the proof to the current boot and revalidates
    /// every snapshot field and the streamed SHA-256 of the exact descriptor
    /// retained during admission. It then computes the sealed policy digest
    /// independently before comparing the publisher's untrusted claim.
    ///
    /// # Errors
    ///
    /// Returns an error when the boot changed, the admitted binding or retained
    /// executable drifted, hashing fails, or the claim differs from the compiled
    /// policy digest.
    pub fn verify_compiled_supervisor_profile(
        &self,
        policy: PayloadRootContinuityPolicyV1,
    ) -> Result<VerifiedCompiledSupervisorProfileV1> {
        self.verify_compiled_supervisor_profile_for_boot(policy, current_boot_id()?)
    }

    /// Verifies the deployed package artifact and live PID 1 executable.
    ///
    /// The artifact is opened beside the exact Nix-store nspawn selected by
    /// the protected readiness credential. Its policy digest must equal the
    /// sealed compiler projection, and its two binary digests must match the
    /// retained nspawn pin and the current PID 1 executable. This check does
    /// not authorize launch or discharge the remaining runtime blockers.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or malformed package evidence, changed
    /// protected currentness, an unrecognized policy, or foreign PID 1 bytes.
    pub fn verify_packaged_runtime(&self) -> Result<VerifiedPackagedRuntimeV1> {
        let policy = PayloadRootContinuityPolicyV1::fixed();
        let compiler = self.verify_compiled_supervisor_profile(policy)?;
        let artifact = read_backend_policy_artifact(&self.binding.executable_path)?;
        if artifact.nspawn_digest != self.binding.executable_sha256
            || artifact.policy_digest != compiler.policy_digest
        {
            return Err(HostError::State(
                "packaged backend policy differs from protected readiness".to_owned(),
            ));
        }

        let pid1 = open(
            "/proc/1/exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| HostError::State(error.to_string()))?;
        let pid1_stat = fstat(&pid1).map_err(|error| HostError::State(error.to_string()))?;
        if FileType::from_raw_mode(pid1_stat.st_mode) != FileType::RegularFile
            || pid1_stat.st_uid != 0
            || pid1_stat.st_mode & 0o022 != 0
        {
            return Err(HostError::State(
                "live PID 1 executable is not a protected binary".to_owned(),
            ));
        }
        let (pid1_snapshot, pid1_digest) = snapshot_and_hash_executable(pid1.as_fd())?;
        if pid1_digest != artifact.pid1_digest {
            return Err(HostError::State(
                "live PID 1 differs from the packaged backend policy".to_owned(),
            ));
        }
        self.binding.revalidate(current_boot_id()?)?;

        Ok(VerifiedPackagedRuntimeV1 {
            binding_identity: compiler.binding_identity,
            pid1_snapshot,
            pid1_digest,
            policy_digest: compiler.policy_digest,
        })
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

    fn verify_compiled_supervisor_profile_for_boot(
        &self,
        policy: PayloadRootContinuityPolicyV1,
        current_boot_id: [u8; 16],
    ) -> Result<VerifiedCompiledSupervisorProfileV1> {
        self.binding.revalidate(current_boot_id)?;
        let policy_digest = policy.digest();
        if self.claims.supervisor_profile_digest != policy_digest {
            return Err(HostError::State(
                "backend readiness supervisor-profile claim is unverified".to_owned(),
            ));
        }

        Ok(VerifiedCompiledSupervisorProfileV1 {
            binding_identity: self.binding.identity,
            policy_digest,
        })
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
    artifact_sha256: [u8; 32],
    expected_executable: &str,
) -> Result<ProtectedBackendReadinessEvidence> {
    let executable_pin = super::open_executable_pin(expected_executable)?;
    verify_readiness_with_pin(
        artifact,
        current_boot_id,
        artifact_sha256,
        expected_executable,
        executable_pin,
    )
}

fn verify_readiness_with_pin(
    artifact: BackendReadinessArtifact,
    current_boot_id: [u8; 16],
    artifact_sha256: [u8; 32],
    expected_executable: &str,
    executable_pin: OwnedFd,
) -> Result<ProtectedBackendReadinessEvidence> {
    let Some(publisher_generation) = NonZeroU64::new(artifact.publisher_generation) else {
        return Err(HostError::State(
            "backend readiness artifact contradicts required deployment evidence".to_owned(),
        ));
    };
    if artifact.schema != READINESS_SCHEMA
        || artifact.boot_id == [0; 16]
        || artifact.boot_id != current_boot_id
        || artifact_sha256 == [0; 32]
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

    let (executable_snapshot, executable_sha256) =
        snapshot_and_hash_executable(executable_pin.as_fd())?;
    if executable_snapshot.device != artifact.nspawn_device
        || executable_snapshot.inode != artifact.nspawn_inode
    {
        return Err(HostError::State(
            "backend readiness executable identity changed".to_owned(),
        ));
    }

    let binding = ReadinessBindingV1::new(
        publisher_generation,
        artifact.boot_id,
        artifact_sha256,
        artifact.nspawn_store_path,
        executable_pin,
        executable_snapshot,
        executable_sha256,
    )?;
    Ok(ProtectedBackendReadinessEvidence {
        binding,
        claims: UntrustedPhase0ClaimsV1 {
            probe_digest: artifact.probe_digest,
            supervisor_profile_digest: artifact.supervisor_profile_digest,
            payload_filter_digest: artifact.payload_filter_digest,
        },
    })
}

fn current_boot_id() -> Result<[u8; 16]> {
    KernelBootId::current()
        .map(KernelBootId::into_bytes)
        .map_err(|error| HostError::State(error.to_string()))
}

fn snapshot_and_hash_executable(
    descriptor: BorrowedFd<'_>,
) -> Result<(NspawnExecutableSnapshot, [u8; 32])> {
    snapshot_and_hash_executable_with_progress(descriptor, |_| {})
}

fn snapshot_and_hash_executable_with_progress<F>(
    descriptor: BorrowedFd<'_>,
    mut after_chunk: F,
) -> Result<(NspawnExecutableSnapshot, [u8; 32])>
where
    F: FnMut(u64),
{
    let before = nspawn_executable_snapshot(descriptor)?;
    if !(1..=MAXIMUM_NSPAWN_EXECUTABLE_BYTES).contains(&before.bytes) {
        return Err(HostError::State(
            "backend readiness executable has an invalid size".to_owned(),
        ));
    }

    let expected_bytes = u64::try_from(before.bytes).map_err(|_| {
        HostError::State("backend readiness executable has an invalid size".to_owned())
    })?;
    let mut hash = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; EXECUTABLE_HASH_BUFFER_BYTES];
    while offset < expected_bytes {
        let remaining = expected_bytes - offset;
        let limit = usize::try_from(remaining)
            .map_err(|_| HostError::State("backend readiness executable is oversized".to_owned()))?
            .min(buffer.len());
        let read = rustix::io::pread(descriptor, &mut buffer[..limit], offset)
            .map_err(|error| HostError::State(error.to_string()))?;
        if read == 0 {
            return Err(HostError::State(
                "backend readiness executable ended while being hashed".to_owned(),
            ));
        }

        hash.update(&buffer[..read]);
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| {
                HostError::State("backend readiness executable is oversized".to_owned())
            })?)
            .ok_or_else(|| {
                HostError::State("backend readiness executable is oversized".to_owned())
            })?;
        // The generic no-op monomorphizes away in production. Tests use this
        // point to exercise mutation handling without timing or global state.
        after_chunk(offset);
    }

    let after = nspawn_executable_snapshot(descriptor)?;
    if after != before {
        return Err(HostError::State(
            "backend readiness executable metadata changed while being hashed".to_owned(),
        ));
    }
    Ok((before, hash.finalize().into()))
}

fn readiness_binding_identity(
    publisher_generation: NonZeroU64,
    boot_id: [u8; 16],
    artifact_sha256: [u8; 32],
    executable_path: &str,
    executable_snapshot: NspawnExecutableSnapshot,
    executable_sha256: [u8; 32],
) -> Result<ReadinessBindingIdentityV1> {
    let mut hash = Sha256::new();
    hash.update(READINESS_BINDING_DOMAIN);
    update_binding_field(&mut hash, 1, &publisher_generation.get().to_be_bytes())?;
    update_binding_field(&mut hash, 2, &boot_id)?;
    update_binding_field(&mut hash, 3, &artifact_sha256)?;
    update_binding_field(&mut hash, 4, executable_path.as_bytes())?;
    update_binding_field(&mut hash, 5, &executable_snapshot.device.to_be_bytes())?;
    update_binding_field(&mut hash, 6, &executable_snapshot.inode.to_be_bytes())?;
    update_binding_field(&mut hash, 7, &executable_snapshot.bytes.to_be_bytes())?;
    update_binding_field(&mut hash, 8, &executable_snapshot.uid.to_be_bytes())?;
    update_binding_field(&mut hash, 9, &executable_snapshot.mode.to_be_bytes())?;
    update_binding_field(
        &mut hash,
        10,
        &executable_snapshot.modified_seconds.to_be_bytes(),
    )?;
    update_binding_field(
        &mut hash,
        11,
        &executable_snapshot.modified_nanoseconds.to_be_bytes(),
    )?;
    update_binding_field(
        &mut hash,
        12,
        &executable_snapshot.changed_seconds.to_be_bytes(),
    )?;
    update_binding_field(
        &mut hash,
        13,
        &executable_snapshot.changed_nanoseconds.to_be_bytes(),
    )?;
    update_binding_field(&mut hash, 14, &executable_sha256)?;
    Ok(ReadinessBindingIdentityV1(hash.finalize().into()))
}

fn update_binding_field(hash: &mut Sha256, tag: u16, value: &[u8]) -> Result<()> {
    let length = u64::try_from(value.len())
        .map_err(|_| HostError::State("backend readiness binding field is too large".to_owned()))?;
    hash.update(tag.to_be_bytes());
    hash.update(length.to_be_bytes());
    hash.update(value);
    Ok(())
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
pub(super) fn backend_readiness_for_tests(
    executable_path: &str,
    executable_pin: OwnedFd,
) -> Result<BackendReadiness> {
    let (executable_snapshot, executable_sha256) =
        snapshot_and_hash_executable(executable_pin.as_fd())?;
    let binding = ReadinessBindingV1::new(
        NonZeroU64::MIN,
        current_boot_id()?,
        [4; 32],
        executable_path.to_owned(),
        executable_pin,
        executable_snapshot,
        executable_sha256,
    )?;

    Ok(BackendReadiness {
        binding,
        mac_policy_digest: [1; 32],
        supervisor_profile_digest: [2; 32],
        payload_filter_digest: [3; 32],
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::{Seek as _, SeekFrom};
    use std::os::unix::fs::symlink;
    use std::time::Duration;

    use aos_systemd::{
        SandboxDescriptorPath, SandboxNspawnCommand, SandboxResolvedPaths, SandboxResources,
        SandboxUnitName, SandboxUnitSpec,
    };

    use super::*;

    #[test]
    fn packaged_policy_artifact_rejects_substitution_and_noncanonical_digests() {
        let mut bytes = Vec::from(BACKEND_POLICY_MAGIC.as_slice());
        for byte in [b'a', b'b', b'c'] {
            bytes.extend(std::iter::repeat_n(byte, 64));
            bytes.push(b'\n');
        }
        let artifact = parse_backend_policy_artifact(&bytes).unwrap();
        assert_eq!(artifact.pid1_digest, [0xaa; 32]);
        assert_eq!(artifact.nspawn_digest, [0xbb; 32]);
        assert_eq!(artifact.policy_digest, [0xcc; 32]);

        bytes[75] = b'B';
        assert!(parse_backend_policy_artifact(&bytes).is_err());
        bytes[75] = b'b';
        bytes[203] = b' ';
        assert!(parse_backend_policy_artifact(&bytes).is_err());
        bytes.pop();
        assert!(parse_backend_policy_artifact(&bytes).is_err());
    }

    fn readiness_artifact(
        path: String,
        boot_id: [u8; 16],
        snapshot: NspawnExecutableSnapshot,
    ) -> BackendReadinessArtifact {
        BackendReadinessArtifact {
            schema: READINESS_SCHEMA.to_owned(),
            publisher_generation: 7,
            boot_id,
            nspawn_store_path: path,
            nspawn_device: snapshot.device,
            nspawn_inode: snapshot.inode,
            probe_digest: [1; 32],
            supervisor_profile_digest: [2; 32],
            payload_filter_digest: [3; 32],
        }
    }

    fn admitted_evidence(
        contents: &[u8],
        supervisor_profile_digest: [u8; 32],
    ) -> (File, ProtectedBackendReadinessEvidence) {
        admitted_evidence_for_boot(contents, supervisor_profile_digest, [4; 16])
    }

    fn admitted_evidence_for_boot(
        contents: &[u8],
        supervisor_profile_digest: [u8; 32],
        boot_id: [u8; 16],
    ) -> (File, ProtectedBackendReadinessEvidence) {
        let mut executable = tempfile::tempfile().unwrap();
        executable.write_all(contents).unwrap();
        executable.flush().unwrap();
        let executable_pin = OwnedFd::from(executable.try_clone().unwrap());
        let snapshot = nspawn_executable_snapshot(executable_pin.as_fd()).unwrap();
        let path = "/nix/store/test-systemd/bin/systemd-nspawn";
        let mut artifact = readiness_artifact(path.to_owned(), boot_id, snapshot);
        artifact.supervisor_profile_digest = supervisor_profile_digest;
        let evidence =
            verify_readiness_with_pin(artifact, boot_id, [5; 32], path, executable_pin).unwrap();

        (executable, evidence)
    }

    fn compiled_policy() -> PayloadRootContinuityPolicyV1 {
        let executable = File::open("/proc/self/exe").unwrap();
        let root = File::open("/").unwrap();
        let network = File::open("/proc/self/ns/net").unwrap();
        let command = SandboxNspawnCommand::private_user_descriptor_v1(
            SandboxDescriptorPath::for_current_process(executable.as_fd()).unwrap(),
            [1; 16],
            65_536,
            65_536,
        )
        .unwrap();
        let paths = SandboxResolvedPaths::from_descriptors(
            SandboxDescriptorPath::for_current_process(root.as_fd()).unwrap(),
            SandboxDescriptorPath::for_current_process(network.as_fd()).unwrap(),
        );
        SandboxUnitSpec::new_nspawn(
            SandboxUnitName::from_incarnation([1; 16]),
            command,
            paths,
            SandboxResources::new(1, 1, 1, 1).unwrap(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap()
        .payload_root_continuity_policy()
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
    fn readiness_binds_boot_path_identity_and_nonzero_claims() {
        let executable = "/nix/store/test-systemd/bin/systemd-nspawn".to_owned();
        let boot_id = [4; 16];
        let file = tempfile::tempfile().unwrap();
        file.set_len(1).unwrap();
        let pin = OwnedFd::from(file.try_clone().unwrap());
        let snapshot = nspawn_executable_snapshot(pin.as_fd()).unwrap();
        let valid = readiness_artifact(executable.clone(), boot_id, snapshot);
        let evidence =
            verify_readiness_with_pin(valid, boot_id, [5; 32], &executable, pin).unwrap();
        assert_eq!(evidence.publisher_generation(), 7);
        assert_eq!(
            evidence.runtime_blockers(),
            [
                BackendReadinessBlocker::Phase0ClaimVerification,
                BackendReadinessBlocker::ShiftedPayloadPidfdNamespaceInspection,
                BackendReadinessBlocker::PayloadRootPolicyDeploymentVerification,
            ]
        );

        let pin = OwnedFd::from(file.try_clone().unwrap());
        let wrong_boot = readiness_artifact(executable.clone(), [5; 16], snapshot);
        assert!(verify_readiness_with_pin(wrong_boot, boot_id, [5; 32], &executable, pin).is_err());
        let pin = OwnedFd::from(file.try_clone().unwrap());
        let mut zero_generation = readiness_artifact(executable.clone(), boot_id, snapshot);
        zero_generation.publisher_generation = 0;
        assert!(
            verify_readiness_with_pin(zero_generation, boot_id, [5; 32], &executable, pin,)
                .is_err()
        );
        let pin = OwnedFd::from(file.try_clone().unwrap());
        let zero_artifact_digest = readiness_artifact(executable.clone(), boot_id, snapshot);
        assert!(
            verify_readiness_with_pin(zero_artifact_digest, boot_id, [0; 32], &executable, pin,)
                .is_err()
        );
        let pin = OwnedFd::from(file.try_clone().unwrap());
        let mut wrong_identity = readiness_artifact(executable.clone(), boot_id, snapshot);
        wrong_identity.nspawn_inode = wrong_identity.nspawn_inode.wrapping_add(1);
        assert!(
            verify_readiness_with_pin(wrong_identity, boot_id, [5; 32], &executable, pin).is_err()
        );
        let pin = OwnedFd::from(file.try_clone().unwrap());
        let mut incomplete = readiness_artifact(executable.clone(), boot_id, snapshot);
        incomplete.payload_filter_digest = [0; 32];
        assert!(verify_readiness_with_pin(incomplete, boot_id, [5; 32], &executable, pin).is_err());
        let pin = OwnedFd::from(file.try_clone().unwrap());
        let other = readiness_artifact(executable.clone(), boot_id, snapshot);
        assert!(
            verify_readiness_with_pin(other, boot_id, [5; 32], "/different/executable", pin,)
                .is_err()
        );
    }

    #[test]
    fn readiness_binding_identity_covers_every_bound_field() {
        let file = tempfile::tempfile().unwrap();
        file.set_len(17).unwrap();
        let snapshot = nspawn_executable_snapshot(file.as_fd()).unwrap();
        let generation = NonZeroU64::new(7).unwrap();
        let boot_id = [1; 16];
        let artifact_sha256 = [2; 32];
        let path = "/nix/store/test-systemd/bin/systemd-nspawn";
        let executable_sha256 = [3; 32];
        let identity = readiness_binding_identity(
            generation,
            boot_id,
            artifact_sha256,
            path,
            snapshot,
            executable_sha256,
        )
        .unwrap();
        let compute = |candidate_generation,
                       candidate_boot,
                       candidate_artifact,
                       candidate_path: &str,
                       candidate_snapshot,
                       candidate_executable| {
            readiness_binding_identity(
                candidate_generation,
                candidate_boot,
                candidate_artifact,
                candidate_path,
                candidate_snapshot,
                candidate_executable,
            )
            .unwrap()
        };

        assert_ne!(
            identity,
            compute(
                NonZeroU64::new(8).unwrap(),
                boot_id,
                artifact_sha256,
                path,
                snapshot,
                executable_sha256,
            )
        );
        assert_ne!(
            identity,
            compute(
                generation,
                [4; 16],
                artifact_sha256,
                path,
                snapshot,
                executable_sha256,
            )
        );
        assert_ne!(
            identity,
            compute(
                generation,
                boot_id,
                [5; 32],
                path,
                snapshot,
                executable_sha256,
            )
        );
        assert_ne!(
            identity,
            compute(
                generation,
                boot_id,
                artifact_sha256,
                "/nix/store/other-systemd/bin/systemd-nspawn",
                snapshot,
                executable_sha256,
            )
        );
        assert_ne!(
            identity,
            compute(
                generation,
                boot_id,
                artifact_sha256,
                path,
                snapshot,
                [6; 32],
            )
        );

        let change_snapshot_fields: [fn(&mut NspawnExecutableSnapshot); 9] = [
            |value| value.device = value.device.wrapping_add(1),
            |value| value.inode = value.inode.wrapping_add(1),
            |value| value.bytes = value.bytes.wrapping_add(1),
            |value| value.uid = value.uid.wrapping_add(1),
            |value| value.mode ^= 0o100,
            |value| value.modified_seconds = value.modified_seconds.wrapping_add(1),
            |value| value.modified_nanoseconds = value.modified_nanoseconds.wrapping_add(1),
            |value| value.changed_seconds = value.changed_seconds.wrapping_add(1),
            |value| value.changed_nanoseconds = value.changed_nanoseconds.wrapping_add(1),
        ];
        for change_snapshot in change_snapshot_fields {
            let mut changed = snapshot;
            change_snapshot(&mut changed);

            assert_ne!(
                identity,
                compute(
                    generation,
                    boot_id,
                    artifact_sha256,
                    path,
                    changed,
                    executable_sha256,
                )
            );
        }
    }

    #[test]
    fn readiness_binding_v1_matches_the_canonical_golden_vector() {
        let snapshot = NspawnExecutableSnapshot {
            device: 0x1112_1314_1516_1718,
            inode: 0x2122_2324_2526_2728,
            bytes: 0x3132_3334_3536_3738,
            uid: 0x4142_4344,
            mode: 0x5152_5354,
            modified_seconds: -0x0102_0304_0506_0708,
            modified_nanoseconds: 0x6162_6364_6566_6768,
            changed_seconds: 0x7172_7374_7576_7778,
            changed_nanoseconds: 0x8182_8384_8586_8788,
        };
        let identity = readiness_binding_identity(
            NonZeroU64::new(0x0102_0304_0506_0708).unwrap(),
            [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ],
            [
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
                0x3c, 0x3d, 0x3e, 0x3f,
            ],
            "/nix/store/golden-systemd/bin/systemd-nspawn",
            snapshot,
            [
                0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
                0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
                0xbc, 0xbd, 0xbe, 0xbf,
            ],
        )
        .unwrap();

        // Independently encoded as a 374-byte stream: the NUL-terminated
        // domain, ordered u16-BE tags, u64-BE lengths, and BE scalar values.
        assert_eq!(
            identity.0,
            [
                0xee, 0x39, 0xb5, 0x4a, 0x00, 0x3f, 0x28, 0xd4, 0x4f, 0x09, 0xa9, 0x45, 0x3d, 0xac,
                0x54, 0xce, 0x37, 0x23, 0xa3, 0x68, 0x8b, 0xf8, 0x1b, 0x5f, 0x2c, 0x52, 0x23, 0x5b,
                0x70, 0xd2, 0x14, 0xab,
            ]
        );
    }

    #[test]
    fn executable_hash_rejects_sizes_outside_the_fixed_bound() {
        let file = tempfile::tempfile().unwrap();
        let zero_size = snapshot_and_hash_executable(file.as_fd());
        assert!(matches!(
            zero_size,
            Err(HostError::State(message))
                if message == "backend readiness executable has an invalid size"
        ));

        file.set_len(u64::try_from(MAXIMUM_NSPAWN_EXECUTABLE_BYTES).unwrap() + 1)
            .unwrap();
        let oversized = snapshot_and_hash_executable(file.as_fd());
        assert!(matches!(
            oversized,
            Err(HostError::State(message))
                if message == "backend readiness executable has an invalid size"
        ));
    }

    #[test]
    fn executable_hash_streams_multiple_buffers_without_moving_the_cursor() {
        let mut file = tempfile::tempfile().unwrap();
        let contents: Vec<u8> = (0..(EXECUTABLE_HASH_BUFFER_BYTES * 2 + 137))
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        file.write_all(&contents).unwrap();
        file.seek(SeekFrom::Start(31)).unwrap();

        let (_, digest) = snapshot_and_hash_executable(file.as_fd()).unwrap();

        assert_eq!(file.stream_position().unwrap(), 31);
        assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&contents)));
    }

    #[test]
    fn executable_hash_rejects_premature_eof_without_a_timing_race() {
        let file = tempfile::tempfile().unwrap();
        file.set_len(u64::try_from(EXECUTABLE_HASH_BUFFER_BYTES * 2 + 1).unwrap())
            .unwrap();
        let mut truncated = false;

        let result = snapshot_and_hash_executable_with_progress(file.as_fd(), |offset| {
            if !truncated {
                file.set_len(offset).unwrap();
                truncated = true;
            }
        });

        assert!(truncated);
        assert!(matches!(
            result,
            Err(HostError::State(message))
                if message == "backend readiness executable ended while being hashed"
        ));
    }

    #[test]
    fn executable_hash_rejects_final_snapshot_mismatch_without_a_timing_race() {
        let file = tempfile::tempfile().unwrap();
        let admitted_bytes = u64::try_from(EXECUTABLE_HASH_BUFFER_BYTES + 1).unwrap();
        file.set_len(admitted_bytes).unwrap();
        let mut grown = false;

        let result = snapshot_and_hash_executable_with_progress(file.as_fd(), |_| {
            if !grown {
                file.set_len(admitted_bytes + 1).unwrap();
                grown = true;
            }
        });

        assert!(grown);
        assert!(matches!(
            result,
            Err(HostError::State(message))
                if message
                    == "backend readiness executable metadata changed while being hashed"
        ));
    }

    #[test]
    fn readiness_retains_the_original_descriptor_after_path_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let executable_path = temporary.path().join("systemd-nspawn");
        std::fs::write(&executable_path, b"admitted executable").unwrap();
        let executable_pin = open(
            &executable_path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let snapshot = nspawn_executable_snapshot(executable_pin.as_fd()).unwrap();
        let path = executable_path.to_str().unwrap();
        let artifact = readiness_artifact(path.to_owned(), [4; 16], snapshot);
        let evidence =
            verify_readiness_with_pin(artifact, [4; 16], [5; 32], path, executable_pin).unwrap();

        std::fs::rename(&executable_path, temporary.path().join("retained")).unwrap();
        std::fs::write(&executable_path, b"replacement executable").unwrap();
        let replacement = File::open(&executable_path).unwrap();
        let retained = fstat(evidence.binding.executable_pin.as_fd()).unwrap();
        let replacement = fstat(&replacement).unwrap();
        let (_, retained_sha256) =
            snapshot_and_hash_executable(evidence.binding.executable_pin.as_fd()).unwrap();

        assert_eq!(retained.st_ino, evidence.binding.executable_snapshot.inode);
        assert_ne!(retained.st_ino, replacement.st_ino);
        assert_eq!(retained_sha256, evidence.binding.executable_sha256);
    }

    #[test]
    fn readiness_revalidation_rejects_snapshot_and_content_drift() {
        let (growth_file, growth_evidence) = admitted_evidence(b"snapshot drift", [2; 32]);
        growth_file.set_len(128).unwrap();
        assert!(growth_evidence.binding.revalidate([4; 16]).is_err());

        let (truncation_file, truncation_evidence) =
            admitted_evidence(b"truncate this executable", [2; 32]);
        truncation_file.set_len(4).unwrap();
        assert!(truncation_evidence.binding.revalidate([4; 16]).is_err());

        let (mut content_file, mut content_evidence) =
            admitted_evidence(b"original bytes", [2; 32]);
        content_file.seek(SeekFrom::Start(0)).unwrap();
        content_file.write_all(b"mutated! bytes").unwrap();
        content_file.flush().unwrap();
        content_evidence.binding.executable_snapshot =
            nspawn_executable_snapshot(content_evidence.binding.executable_pin.as_fd()).unwrap();
        content_evidence.binding.identity = readiness_binding_identity(
            content_evidence.binding.publisher_generation,
            content_evidence.binding.boot_id,
            content_evidence.binding.artifact_sha256,
            &content_evidence.binding.executable_path,
            content_evidence.binding.executable_snapshot,
            content_evidence.binding.executable_sha256,
        )
        .unwrap();

        assert!(content_evidence.binding.revalidate([4; 16]).is_err());
    }

    #[test]
    fn nspawn_config_retains_and_rehashes_the_full_readiness_binding() {
        let mut executable = tempfile::tempfile().unwrap();
        executable.write_all(b"original bytes").unwrap();
        executable.flush().unwrap();
        let executable_pin = OwnedFd::from(executable.try_clone().unwrap());
        let readiness = backend_readiness_for_tests(
            "/nix/store/test-systemd/bin/systemd-nspawn",
            executable_pin,
        )
        .unwrap();
        let admitted_identity = readiness.binding.identity;
        let mut config = super::super::NspawnConfig::from_readiness(
            readiness,
            Duration::from_secs(30),
            Duration::from_secs(10),
        )
        .unwrap();

        assert_eq!(config.readiness.binding.identity, admitted_identity);
        executable.seek(SeekFrom::Start(0)).unwrap();
        executable.write_all(b"mutated! bytes").unwrap();
        executable.flush().unwrap();
        config.readiness.binding.executable_snapshot =
            nspawn_executable_snapshot(config.readiness.binding.executable_pin.as_fd()).unwrap();
        config.readiness.binding.identity = readiness_binding_identity(
            config.readiness.binding.publisher_generation,
            config.readiness.binding.boot_id,
            config.readiness.binding.artifact_sha256,
            &config.readiness.binding.executable_path,
            config.readiness.binding.executable_snapshot,
            config.readiness.binding.executable_sha256,
        )
        .unwrap();

        assert!(config.revalidate().is_err());
    }

    #[test]
    fn compiled_supervisor_profile_proof_rechecks_binding_and_exact_digest() {
        let policy = compiled_policy();
        let policy_digest = policy.digest();
        let boot_id = current_boot_id().unwrap();
        let (_file, evidence) =
            admitted_evidence_for_boot(b"profile executable", policy_digest, boot_id);
        let proof = evidence.verify_compiled_supervisor_profile(policy).unwrap();

        assert_eq!(proof.binding_identity, evidence.binding.identity);
        assert_eq!(proof.policy_digest, policy_digest);
        let mut other_boot = boot_id;
        other_boot[0] ^= 1;
        assert!(
            evidence
                .verify_compiled_supervisor_profile_for_boot(policy, other_boot)
                .is_err()
        );

        let mut changed_digest = policy_digest;
        changed_digest[0] ^= 1;
        let (_file, changed) =
            admitted_evidence_for_boot(b"profile executable", changed_digest, boot_id);
        assert!(changed.verify_compiled_supervisor_profile(policy).is_err());
    }

    #[test]
    fn unrelated_phase0_claims_have_no_compiled_profile_authority() {
        let policy = compiled_policy();
        let (_file, mut evidence) = admitted_evidence(b"profile executable", policy.digest());
        evidence.claims.probe_digest = [17; 32];
        evidence.claims.payload_filter_digest = [23; 32];

        assert!(
            evidence
                .verify_compiled_supervisor_profile_for_boot(policy, [4; 16])
                .is_ok()
        );
        assert_eq!(
            evidence.runtime_blockers(),
            [
                BackendReadinessBlocker::Phase0ClaimVerification,
                BackendReadinessBlocker::ShiftedPayloadPidfdNamespaceInspection,
                BackendReadinessBlocker::PayloadRootPolicyDeploymentVerification,
            ]
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
