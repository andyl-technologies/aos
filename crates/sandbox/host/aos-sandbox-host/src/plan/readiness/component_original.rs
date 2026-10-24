//! Retains the real credential, executable and package observations of phase 0.
//!
//! The enclosing Control borrower pays these destinations before entry and
//! independently completes its source, process and clock posts. These owners
//! provide deployment DATA and never construct backend readiness.

use std::error::Error;
use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1;

use super::watermark_original::{
    ProtectedReadOriginalV2, ReadinessWatermarkOriginalV2, validate_directory_metadata_v2,
};
use super::*;

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("retained phase-0 deployment observation is incomplete or closed")]
pub(crate) struct ComponentReadinessClosedV2;

/// Measures only the fixed package's executable and declared policy DATA.
pub(crate) struct PackagedNspawnOriginalV2 {
    artifact_open: Option<rustix::io::Result<OwnedFd>>,
    artifact_read: ProtectedReadOriginalV2,
    artifact: Option<Result<BackendPolicyArtifactV2>>,
    executable: crate::phase0_probe::ProtectedPackagedExecutableHashOriginalV2,
    primary: Option<std::result::Result<(), crate::phase0_probe::PackagedExecutableHashClosedV2>>,
    after: Option<std::result::Result<(), crate::phase0_probe::PackagedExecutableHashClosedV2>>,
    completion: Option<Result<[u8; 32]>>,
    entered: bool,
    refused: bool,
}

impl PackagedNspawnOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            artifact_open: None,
            artifact_read: ProtectedReadOriginalV2::new(),
            artifact: None,
            executable: crate::phase0_probe::ProtectedPackagedExecutableHashOriginalV2::new(),
            primary: None,
            after: None,
            completion: None,
            entered: false,
            refused: false,
        }
    }

    pub(crate) fn receiving_demand_v2(executable: &str) -> Option<ResourceVector> {
        let path = Path::new(executable);
        let hash =
            crate::phase0_probe::ProtectedPackagedExecutableHashOriginalV2::receiving_shape_v2(
                path,
            )?;
        let package_root = path.parent()?.parent()?;
        let path_bytes = package_root
            .as_os_str()
            .len()
            .checked_add(1)?
            .checked_add(BACKEND_POLICY_ARTIFACT.len())?;
        let own = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(path_bytes.checked_mul(2)?)?;
        let read = ProtectedReadOriginalV2::receiving_demand_v2(
            BACKEND_POLICY_ARTIFACT_BYTES,
            BACKEND_POLICY_ARTIFACT.len(),
        )?;
        ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                u64::try_from(own).ok()?.checked_add(hash.memory_bytes)?,
            )
            .with(D::OpenFiles, hash.open_files)
            .with(D::OutputBytes, crate::phase0_probe::ProtectedPackagedExecutableHashOriginalV2::maximum_requested_read_bytes_v2())
            .with(D::MetadataEntries, hash.namespace_entries.checked_add(1)?)
            .checked_add(read)
            .ok()
    }

    pub(crate) fn observe_once_v2(
        &mut self,
        executable: &str,
    ) -> std::result::Result<(), ComponentReadinessClosedV2> {
        if self.entered {
            self.refused = true;
            return Err(ComponentReadinessClosedV2);
        }
        self.entered = true;
        self.completion = Some(self.observe(executable));
        if self.digest_v2().is_some() {
            Ok(())
        } else {
            Err(ComponentReadinessClosedV2)
        }
    }

    fn observe(&mut self, executable: &str) -> Result<[u8; 32]> {
        validate_fixed_nspawn_path(executable)?;
        let root = Path::new(executable)
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| HostError::State("nspawn package root is invalid".to_owned()))?;
        self.artifact_open = Some(open(
            root.join(BACKEND_POLICY_ARTIFACT),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ));
        native(self.artifact_open.as_ref())?;
        let Some(Ok(file)) = self.artifact_open.take() else {
            return Err(closed());
        };
        self.artifact_read
            .observe_packaged_once_v2(file, BACKEND_POLICY_ARTIFACT, BACKEND_POLICY_ARTIFACT_BYTES)
            .map_err(|_| closed())?;
        self.artifact = Some(parse_backend_policy_artifact(
            self.artifact_read.bytes_v2().ok_or_else(closed)?,
        ));
        let artifact = self
            .artifact
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(closed)?;
        self.primary = Some(self.executable.observe_once_v2(Path::new(executable)));
        // A reached executable phase owes its own independent descriptor and
        // named-path posts even when its primary measurement refused.
        self.after = Some(self.executable.observe_after_owed_once_v2());
        if !matches!(self.primary, Some(Ok(()))) || !matches!(self.after, Some(Ok(()))) {
            return Err(closed());
        }
        let actual = self.executable.digest_v2().ok_or_else(closed)?;
        if actual != artifact.nspawn_digest {
            return Err(HostError::State(
                "packaged nspawn digest differs from the live executable".to_owned(),
            ));
        }
        Ok(actual)
    }

    pub(crate) fn digest_v2(&self) -> Option<[u8; 32]> {
        if self.refused {
            return None;
        }
        self.completion.as_ref()?.as_ref().ok().copied()
    }

    pub(crate) fn snapshot_v2(&self) -> Option<&rustix::fs::Stat> {
        self.digest_v2()?;
        self.executable.snapshot_v2()
    }

    pub(crate) fn pid1_digest_v2(&self) -> Option<[u8; 32]> {
        self.digest_v2()?;
        Some(self.artifact.as_ref()?.as_ref().ok()?.pid1_digest)
    }

    pub(crate) fn supervisor_profile_digest_v2(&self) -> Option<[u8; 32]> {
        self.digest_v2()?;
        Some(self.artifact.as_ref()?.as_ref().ok()?.policy_digest)
    }

    pub(crate) fn payload_filter_digest_v2(&self) -> Option<[u8; 32]> {
        self.digest_v2()?;
        Some(self.artifact.as_ref()?.as_ref().ok()?.payload_filter_digest)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.artifact_open
            .as_ref()
            .and_then(|r| r.as_ref().err())
            .map(|e| e as _)
            .or_else(|| self.artifact_read.failure())
            .or_else(|| self.artifact.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.executable.failure_v2())
            .or_else(|| self.completion.as_ref()?.as_ref().err().map(|e| e as _))
    }

    pub(super) fn into_ordinary_result_v2(mut self) -> Result<[u8; 32]> {
        self.completion.take().unwrap_or_else(|| Err(closed()))
    }
}

/// Owns the optional credential read and its actual rollback watermark write.
pub(in crate::plan) struct ReadinessLoadOriginalV2 {
    directory: Option<rustix::io::Result<OwnedFd>>,
    directory_metadata: Option<rustix::io::Result<rustix::fs::Stat>>,
    credential: Option<rustix::io::Result<OwnedFd>>,
    read: ProtectedReadOriginalV2,
    decoded: Option<std::result::Result<BackendReadinessArtifact, serde_json::Error>>,
    boot: RootOriginalKernelBootIdAttemptV1,
    executable: Option<rustix::io::Result<OwnedFd>>,
    executable_metadata: Option<rustix::io::Result<rustix::fs::Stat>>,
    measurement: NspawnRevalidationOriginalV2,
    watermark: ReadinessWatermarkOriginalV2,
    pending_evidence: Option<ProtectedBackendReadinessEvidence>,
    completion: Option<Result<Option<ProtectedBackendReadinessEvidence>>>,
    entered: bool,
    refused: bool,
}

impl ReadinessLoadOriginalV2 {
    pub(in crate::plan) fn new() -> Self {
        Self {
            directory: None,
            directory_metadata: None,
            credential: None,
            read: ProtectedReadOriginalV2::new(),
            decoded: None,
            boot: RootOriginalKernelBootIdAttemptV1::new(),
            executable: None,
            executable_metadata: None,
            measurement: NspawnRevalidationOriginalV2::new(),
            watermark: ReadinessWatermarkOriginalV2::new(),
            pending_evidence: None,
            completion: None,
            entered: false,
            refused: false,
        }
    }

    pub(in crate::plan) fn receiving_demand_v2(path_bytes: usize) -> Option<ResourceVector> {
        let reader = ProtectedReadOriginalV2::receiving_demand_v2(
            MAXIMUM_READINESS_BYTES,
            READINESS_CREDENTIAL_FILE.len(),
        )?;
        let watermark = ReadinessWatermarkOriginalV2::receiving_demand_v2(path_bytes)?;
        // The decoded JSON is bounded by the admitted wire. Its strings,
        // decoder scratch and the retained successful binding coexist with it.
        let memory = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(MAXIMUM_READINESS_BYTES.checked_mul(4)?)?
            .checked_add(path_bytes.checked_mul(4)?)?
            .checked_add(NspawnRevalidationOriginalV2::requested_bytes_v2()?)?
            .checked_add(RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?)?;
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            // Directory, credential, boot and executable remain resident even
            // when a subsequent parse, hash or watermark operation refuses.
            .with(D::OpenFiles, 4)
            .with(
                D::OutputBytes,
                NspawnRevalidationOriginalV2::maximum_requested_read_bytes_v2().checked_add(
                    u64::try_from(
                        RootOriginalKernelBootIdAttemptV1::maximum_requested_read_bytes_v2(),
                    )
                    .ok()?,
                )?,
            )
            .with(D::MetadataEntries, 4);
        own.checked_add(reader).ok()?.checked_add(watermark).ok()
    }

    pub(in crate::plan) fn load_once_v2(
        &mut self,
        credentials: &Path,
        state: &Path,
        executable: &str,
    ) -> std::result::Result<(), ComponentReadinessClosedV2> {
        self.load_with_preparation_v1(credentials, state, executable, None)
    }

    pub(in crate::plan) fn load_with_boot_preparation_once_v1(
        &mut self,
        credentials: &Path,
        state: &Path,
        executable: &str,
        preparation: &super::boot_preparation_original::HostBootPreparationOriginalV1,
    ) -> std::result::Result<(), ComponentReadinessClosedV2> {
        self.load_with_preparation_v1(credentials, state, executable, Some(preparation))
    }

    fn load_with_preparation_v1(
        &mut self,
        credentials: &Path,
        state: &Path,
        executable: &str,
        preparation: Option<&super::boot_preparation_original::HostBootPreparationOriginalV1>,
    ) -> std::result::Result<(), ComponentReadinessClosedV2> {
        if self.entered {
            self.refused = true;
            return Err(ComponentReadinessClosedV2);
        }
        self.entered = true;
        self.completion = Some(self.load(credentials, state, executable, preparation));
        if matches!(self.completion, Some(Ok(_))) {
            Ok(())
        } else {
            Err(ComponentReadinessClosedV2)
        }
    }

    fn load(
        &mut self,
        credentials: &Path,
        state: &Path,
        executable: &str,
        preparation: Option<&super::boot_preparation_original::HostBootPreparationOriginalV1>,
    ) -> Result<Option<ProtectedBackendReadinessEvidence>> {
        validate_fixed_nspawn_path(executable)?;
        self.directory = Some(open(
            credentials,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let directory = native(self.directory.as_ref())?;
        self.directory_metadata = Some(fstat(directory));
        validate_directory_metadata_v2(
            native(self.directory_metadata.as_ref())?,
            "credential directory",
        )?;

        self.credential = Some(openat(
            directory,
            READINESS_CREDENTIAL_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ));
        if matches!(self.credential, Some(Err(rustix::io::Errno::NOENT))) {
            return Ok(None);
        }
        native(self.credential.as_ref())?;
        let Some(Ok(credential)) = self.credential.take() else {
            return Err(closed());
        };
        self.read
            .observe_once_v2(
                credential,
                READINESS_CREDENTIAL_FILE,
                MAXIMUM_READINESS_BYTES,
            )
            .map_err(|_| closed())?;
        let bytes = self.read.bytes_v2().ok_or_else(closed)?;
        let artifact_digest = Sha256::digest(bytes).into();
        self.decoded = Some(serde_json::from_slice(bytes));
        if let Some(Err(_)) = self.decoded {
            return Err(HostError::State(
                "backend readiness artifact is malformed".to_owned(),
            ));
        }
        let boot = self.boot.observe_once().map_err(|_| closed())?.into_bytes();
        let artifact = self
            .decoded
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(closed)?;
        validate_readiness_fields_v2(artifact, boot, artifact_digest, executable)?;

        // A visible JSON file can outlive a failed publisher. Bind it to the
        // successful current publisher invocation before advancing rollback
        // state; ordinary and Canary callers retain their existing boundary.
        if let Some(preparation) = preparation {
            preparation
                .require_readiness_binding_v1(artifact_digest, artifact.publisher_generation, boot)
                .map_err(|_| closed())?;
        }

        self.executable = Some(open(
            executable,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ));
        let pin = native(self.executable.as_ref())?;
        self.executable_metadata = Some(fstat(pin));
        require_executable_metadata_v2(native(self.executable_metadata.as_ref())?)?;
        let measured = snapshot_and_hash_executable_engine_v2(
            pin.as_fd(),
            |_| {},
            Some(&mut self.measurement),
        )?;
        // The exact descriptor moves into the successful binding. Failed
        // measurement leaves it in this original; failed semantic validation
        // must do so too, hence validation precedes the move.
        let artifact = self
            .decoded
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(closed)?;
        let parts =
            readiness_measurement_parts_v2(artifact, boot, artifact_digest, executable, measured)?;
        let Some(Ok(artifact)) = self.decoded.take() else {
            return Err(closed());
        };
        let Some(Ok(pin)) = self.executable.take() else {
            return Err(closed());
        };
        self.pending_evidence = Some(readiness_from_verified_parts_v2(
            artifact,
            artifact_digest,
            pin,
            measured,
            parts,
        ));
        let evidence = self.pending_evidence.as_ref().ok_or_else(closed)?;
        self.watermark
            .persist_once_v2(
                state,
                ReadinessWatermark {
                    schema: READINESS_WATERMARK_SCHEMA.to_owned(),
                    publisher_generation: evidence.binding.publisher_generation.get(),
                    boot_id: evidence.binding.boot_id,
                    artifact_sha256: artifact_digest,
                },
            )
            .map_err(|_| closed())?;
        Ok(self.pending_evidence.take())
    }

    pub(in crate::plan) fn evidence_v2(
        &self,
    ) -> Result<Option<&ProtectedBackendReadinessEvidence>> {
        if self.refused {
            return Err(closed());
        }
        match self.completion.as_ref() {
            Some(Ok(evidence)) => Ok(evidence.as_ref()),
            _ => Err(closed()),
        }
    }

    pub(in crate::plan) fn take_evidence_v2(
        &mut self,
    ) -> Result<Option<ProtectedBackendReadinessEvidence>> {
        self.evidence_v2()?;
        match self.completion.take() {
            Some(Ok(evidence)) => Ok(evidence),
            _ => Err(closed()),
        }
    }

    pub(super) fn into_ordinary_result_v2(
        mut self,
    ) -> Result<Option<ProtectedBackendReadinessEvidence>> {
        self.completion.take().unwrap_or_else(|| Err(closed()))
    }

    pub(in crate::plan) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.directory
            .as_ref()
            .and_then(|r| r.as_ref().err())
            .map(|e| e as _)
            .or_else(|| {
                self.directory_metadata
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|e| e as _)
            })
            .or_else(|| {
                self.credential
                    .as_ref()?
                    .as_ref()
                    .err()
                    .filter(|e| **e != rustix::io::Errno::NOENT)
                    .map(|e| e as _)
            })
            .or_else(|| self.read.failure())
            .or_else(|| self.decoded.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.boot.failure())
            .or_else(|| self.executable.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| {
                self.executable_metadata
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|e| e as _)
            })
            .or_else(|| self.measurement.failure())
            .or_else(|| self.watermark.failure())
            .or_else(|| self.completion.as_ref()?.as_ref().err().map(|e| e as _))
    }
}

/// Keeps package reads and all three same-executable hash originals together.
pub(in crate::plan) struct PackagedRuntimeOriginalV2 {
    binding: [NspawnRevalidationOriginalV2; 2],
    artifact_open: Option<rustix::io::Result<OwnedFd>>,
    artifact_read: ProtectedReadOriginalV2,
    artifact: Option<Result<BackendPolicyArtifactV2>>,
    source_open: Option<rustix::io::Result<OwnedFd>>,
    source_read: ProtectedReadOriginalV2,
    pid1_open: Option<rustix::io::Result<OwnedFd>>,
    pid1_stat: Option<rustix::io::Result<rustix::fs::Stat>>,
    pid1_measurement: NspawnRevalidationOriginalV2,
    completion: Option<Result<VerifiedPackagedRuntimeV1>>,
    entered: bool,
    refused: bool,
}

impl PackagedRuntimeOriginalV2 {
    pub(in crate::plan) fn new() -> Self {
        Self {
            binding: std::array::from_fn(|_| NspawnRevalidationOriginalV2::new()),
            artifact_open: None,
            artifact_read: ProtectedReadOriginalV2::new(),
            artifact: None,
            source_open: None,
            source_read: ProtectedReadOriginalV2::new(),
            pid1_open: None,
            pid1_stat: None,
            pid1_measurement: NspawnRevalidationOriginalV2::new(),
            completion: None,
            entered: false,
            refused: false,
        }
    }

    pub(in crate::plan) fn receiving_demand_v2(path_bytes: usize) -> Option<ResourceVector> {
        let artifact = ProtectedReadOriginalV2::receiving_demand_v2(
            BACKEND_POLICY_ARTIFACT_BYTES,
            BACKEND_POLICY_ARTIFACT.len(),
        )?;
        let source = ProtectedReadOriginalV2::receiving_demand_v2(
            MAXIMUM_PAYLOAD_FILTER_SOURCE_BYTES,
            PAYLOAD_FILTER_SOURCE.len(),
        )?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(path_bytes.checked_mul(3)?)?
            .checked_add(
                3_usize.checked_mul(NspawnRevalidationOriginalV2::requested_bytes_v2()?)?,
            )?;
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?)
            // Two boot reads; the optional ordinary PID1 open is counted too.
            .with(D::OpenFiles, 3)
            .with(
                D::OutputBytes,
                NspawnRevalidationOriginalV2::maximum_requested_read_bytes_v2()
                    .checked_mul(3)?
                    .checked_add(
                        u64::try_from(
                            RootOriginalKernelBootIdAttemptV1::maximum_requested_read_bytes_v2(),
                        )
                        .ok()?
                        .checked_mul(2)?,
                    )?,
            )
            .with(D::MetadataEntries, 3);
        own.checked_add(artifact).ok()?.checked_add(source).ok()
    }

    pub(in crate::plan) fn capture_component_once_v2(
        &mut self,
        evidence: &ProtectedBackendReadinessEvidence,
        pid1: BorrowedFd<'_>,
    ) -> std::result::Result<(), ComponentReadinessClosedV2> {
        self.capture_once_v2(evidence, Pid1PackageOriginV1::ComponentPinned(pid1))
    }

    pub(super) fn capture_once_v2(
        &mut self,
        evidence: &ProtectedBackendReadinessEvidence,
        origin: Pid1PackageOriginV1<'_>,
    ) -> std::result::Result<(), ComponentReadinessClosedV2> {
        if self.entered {
            self.refused = true;
            return Err(ComponentReadinessClosedV2);
        }
        self.entered = true;
        self.completion = Some(self.capture(evidence, origin));
        if matches!(self.completion, Some(Ok(_))) {
            Ok(())
        } else {
            Err(ComponentReadinessClosedV2)
        }
    }

    fn capture(
        &mut self,
        evidence: &ProtectedBackendReadinessEvidence,
        origin: Pid1PackageOriginV1<'_>,
    ) -> Result<VerifiedPackagedRuntimeV1> {
        observe_binding_v2(evidence, &mut self.binding[0])?;
        let policy = PayloadRootContinuityPolicyV1::fixed();
        if evidence.claims.supervisor_profile_digest != policy.digest() {
            return Err(HostError::State(
                "backend readiness supervisor-profile claim is unverified".to_owned(),
            ));
        }
        let package_root = Path::new(&evidence.binding.executable_path)
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| HostError::State("nspawn package root is invalid".to_owned()))?;

        self.artifact_open = Some(open(
            package_root.join(BACKEND_POLICY_ARTIFACT),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ));
        native(self.artifact_open.as_ref())?;
        let Some(Ok(file)) = self.artifact_open.take() else {
            return Err(closed());
        };
        self.artifact_read
            .observe_packaged_once_v2(file, BACKEND_POLICY_ARTIFACT, BACKEND_POLICY_ARTIFACT_BYTES)
            .map_err(|_| closed())?;
        self.artifact = Some(parse_backend_policy_artifact(
            self.artifact_read.bytes_v2().ok_or_else(closed)?,
        ));
        let artifact = self
            .artifact
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(closed)?;

        self.source_open = Some(open(
            package_root.join(PAYLOAD_FILTER_SOURCE),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ));
        native(self.source_open.as_ref())?;
        let Some(Ok(file)) = self.source_open.take() else {
            return Err(closed());
        };
        self.source_read
            .observe_packaged_once_v2(
                file,
                PAYLOAD_FILTER_SOURCE,
                MAXIMUM_PAYLOAD_FILTER_SOURCE_BYTES,
            )
            .map_err(|_| closed())?;
        let payload_filter_digest = verify_packaged_filter_source(
            self.source_read.bytes_v2().ok_or_else(closed)?,
            artifact.payload_filter_digest,
            evidence.claims.payload_filter_digest,
        )?;
        if artifact.nspawn_digest != evidence.binding.executable_sha256
            || artifact.policy_digest != policy.digest()
        {
            return Err(HostError::State(
                "packaged backend policy differs from protected readiness".to_owned(),
            ));
        }

        if matches!(origin, Pid1PackageOriginV1::ExecutedManager) {
            self.pid1_open = Some(open(
                "/proc/1/exe",
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            ));
        }
        let pid1 = match origin {
            Pid1PackageOriginV1::ExecutedManager => native(self.pid1_open.as_ref())?.as_fd(),
            Pid1PackageOriginV1::OriginalHostLaunch(original) => original.pid1_original()?,
            Pid1PackageOriginV1::ComponentPinned(pid1) => pid1,
        };
        self.pid1_stat = Some(fstat(pid1));
        let stat = native(self.pid1_stat.as_ref())?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != 0
            || stat.st_mode & 0o022 != 0
        {
            return Err(HostError::State(
                "live PID 1 executable is not a protected binary".to_owned(),
            ));
        }
        let (pid1_snapshot, pid1_digest) =
            snapshot_and_hash_executable_engine_v2(pid1, |_| {}, Some(&mut self.pid1_measurement))?;
        if pid1_digest != artifact.pid1_digest {
            return Err(HostError::State(
                "live PID 1 differs from the packaged backend policy".to_owned(),
            ));
        }
        observe_binding_v2(evidence, &mut self.binding[1])?;
        Ok(VerifiedPackagedRuntimeV1 {
            binding_identity: evidence.binding.identity,
            pid1_snapshot,
            pid1_digest,
            policy_digest: policy.digest(),
            payload_filter_digest,
        })
    }

    pub(in crate::plan) fn proof_v2(&self) -> Result<&VerifiedPackagedRuntimeV1> {
        if self.refused {
            return Err(closed());
        }
        self.completion
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .ok_or_else(closed)
    }

    pub(in crate::plan) fn take_proof_v2(&mut self) -> Result<VerifiedPackagedRuntimeV1> {
        self.proof_v2()?;
        match self.completion.take() {
            Some(Ok(proof)) => Ok(proof),
            _ => Err(closed()),
        }
    }

    pub(super) fn into_ordinary_result_v2(mut self) -> Result<VerifiedPackagedRuntimeV1> {
        self.completion.take().unwrap_or_else(|| Err(closed()))
    }

    pub(in crate::plan) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.binding[0]
            .failure()
            .or_else(|| self.artifact_open.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.artifact_read.failure())
            .or_else(|| self.artifact.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.source_open.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.source_read.failure())
            .or_else(|| self.pid1_open.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.pid1_stat.as_ref()?.as_ref().err().map(|e| e as _))
            .or_else(|| self.pid1_measurement.failure())
            .or_else(|| self.binding[1].failure())
            .or_else(|| self.completion.as_ref()?.as_ref().err().map(|e| e as _))
    }
}

fn observe_binding_v2(
    evidence: &ProtectedBackendReadinessEvidence,
    original: &mut NspawnRevalidationOriginalV2,
) -> Result<()> {
    let boot = original
        .boot
        .observe_once()
        .map_err(|_| closed())?
        .into_bytes();
    evidence.binding.revalidate_engine_v2(boot, Some(original))
}

fn native<T>(result: Option<&rustix::io::Result<T>>) -> Result<&T> {
    match result {
        Some(Ok(value)) => Ok(value),
        Some(Err(error)) => Err(HostError::State(error.to_string())),
        None => Err(closed()),
    }
}

fn require_executable_metadata_v2(identity: &rustix::fs::Stat) -> Result<()> {
    if FileType::from_raw_mode(identity.st_mode) != FileType::RegularFile
        || identity.st_uid != 0
        || identity.st_mode & 0o111 == 0
        || identity.st_mode & 0o022 != 0
    {
        return Err(HostError::InvalidPlan(
            "nspawn executable pin is not a protected executable".to_owned(),
        ));
    }
    Ok(())
}

fn closed() -> HostError {
    HostError::Fence("retained phase-0 deployment observation is incomplete or closed")
}
