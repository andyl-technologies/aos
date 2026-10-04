//! Same-writer Host canary cells and retained native snapshot readback.
//!
//! Fixed, fully written ext4 cells reserve data extents before a canary
//! effect. They reuse the Host envelope, authentication and transition
//! records. They do not reserve heap, journal credits, I/O latency or Drain.
//!
//! ```text
//! AOSHCC02 | header[176] | AOSHOST envelope | sealed counter[800]
//!          | zero padding | SHA256[32]
//! ```

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::sync::{Arc, Mutex};

use aos_sandbox_linux::inventory::{MountId, MountNamespace, MountObservation};
use aos_sandbox_core::{ResourceAccount, ResourceCeilings, ResourceDimension, ResourceVector};
use aos_sandbox_linux::protected_file::{
    ExactReadFailure, read_exact_positioned_retaining_cause,
};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use sha2::{Digest as _, Sha256};

use super::{FileHostStateStore, HostState, HostStateStore, decode_envelope, encode_envelope};
use crate::authorization::HostAuthorityV1;
use crate::{HostError, Result};

const ROOT: &str = "/var/lib/aos/sandbox-host/canary-capacity-v1";
const NAMES: [&str; 3] = ["baseline", "cell-0", "cell-1"];
const CELL_BYTES: usize = 16_781_312;
const CELL_HEADER_BYTES: usize = 176;
const COUNTER_BYTES: usize = 720;
const SEALED_COUNTER_BYTES: usize = 800;
const CELL_DIGEST_OFFSET: usize = CELL_BYTES - 32;
const MAXIMUM_GENERATION: u64 = 17;
const EXT4_MAGIC: u64 = 0xef53;
const EXTENTS_FLAG: u32 = 0x0008_0000;

/// Keeps the ordinary writer or the selected canary's same-authority cells.
///
/// Construction is owned by the installed canary coordinator. The public
/// store interface remains the existing complete Host snapshot interface;
/// this type exposes no path, capacity or authority constructor.
pub struct HostProductionStateStoreV1 {
    writer: FileHostStateStore,
    selected: Option<SelectedCanaryStoreV1>,
}

struct SelectedCanaryStoreV1 {
    authority: Arc<HostAuthorityV1>,
    candidate: Mutex<CanaryCapacityCandidateV1>,
}

impl HostProductionStateStoreV1 {
    pub(crate) fn ordinary(writer: FileHostStateStore) -> Self {
        Self {
            writer,
            selected: None,
        }
    }

    pub(crate) fn retain_canary_authority(&mut self, authority: Arc<HostAuthorityV1>) -> Result<()> {
        if self.selected.is_some() {
            return Err(storage_refusal());
        }
        self.selected = Some(SelectedCanaryStoreV1 {
            authority,
            candidate: Mutex::new(CanaryCapacityCandidateV1::new()),
        });
        Ok(())
    }

    pub(crate) fn prepare_original(
        &mut self,
        job: &mut crate::broker::canary_job::HostCanaryJobOwnerV1,
        startup: &crate::plan::HostCanaryStartupV1,
    ) -> Result<Option<HostState>> {
        job.recheck()?;
        let selected = self.selected.as_ref().ok_or_else(storage_refusal)?;
        let mut candidate = selected.candidate.lock().map_err(|_| storage_refusal())?;
        candidate.prepare_original(job, startup, &self.writer, &selected.authority)?;
        job.recheck()?;
        if candidate.current.is_some() {
            candidate.load_original(&selected.authority).map(Some)
        } else {
            Ok(None)
        }
    }

    // Only the installed coordinator supplies these actual parked worker
    // observations, after existing native banks have been inspected. They
    // are absence DATA, not a new cleanup or launch authorization.
    pub(crate) fn prepare_fresh_original(
        &mut self,
        job: &mut crate::broker::canary_job::HostCanaryJobOwnerV1,
        payload: &crate::worker::GuardianObservation,
        guardian: &crate::worker::GuardianObservation,
    ) -> Result<HostState> {
        job.recheck()?;
        let selected = self.selected.as_ref().ok_or_else(storage_refusal)?;
        let mut candidate = selected.candidate.lock().map_err(|_| storage_refusal())?;
        candidate.prepare_fresh_original(payload, guardian, &self.writer, &selected.authority)?;
        job.recheck()?;
        candidate.load_original(&selected.authority)
    }

    /// Retains the actual authenticated ordinary baseline before prefix export.
    ///
    /// This performs no initialization or bank write. Missing original bytes
    /// remain UNKNOWN; a synthesized empty state is not baseline provenance.
    pub(crate) fn retain_prefix_baseline_original(
        &self,
        job: &mut crate::broker::canary_job::HostCanaryJobOwnerV1,
    ) -> Result<[u8; 32]> {
        job.recheck()?;
        let selected = self.selected.as_ref().ok_or_else(storage_refusal)?;
        let mut candidate = selected.candidate.lock().map_err(|_| storage_refusal())?;
        if !candidate.attempted || candidate.closed || candidate.current.is_some()
            || candidate.baseline.is_some()
        {
            return Err(storage_refusal());
        }
        candidate.closed = true;
        let result = (|| {
            candidate.baseline = Some(self.writer.load_into(&mut candidate.source)?);
            let baseline = candidate.baseline.as_ref().ok_or(NativeFailure::Original)?;
            baseline.validate_authenticated(&selected.authority)?;
            if candidate.source.file.is_none() || candidate.source.bytes.is_empty()
                || candidate.job_digest != job.originals()?.digest
            {
                return Err(NativeFailure::Original);
            }
            job.recheck()?;
            Ok(Sha256::digest(&candidate.source.bytes).into())
        })();
        match result {
            Ok(digest) => {
                candidate.closed = false;
                Ok(digest)
            }
            Err(cause) => {
                if candidate.first_failure.is_none() {
                    candidate.first_failure = Some(cause);
                }
                Err(storage_refusal())
            }
        }
    }

    /// Refuses fresh generation0 until every remaining component is observed.
    ///
    /// The full tree is a useful measured component, not complete accounting.
    /// Signed maximum charges and authentic bank counters cannot substitute
    /// for missing logging and future writable-byte/entry producers.
    pub(crate) fn require_complete_prefix_components_original(
        &self,
        prefix: &aos_sandbox_protocol::storage_root_export::StorageCanaryExportResponseV1,
    ) -> Result<()> {
        let selected = self.selected.as_ref().ok_or_else(storage_refusal)?;
        let mut candidate = selected.candidate.lock().map_err(|_| storage_refusal())?;
        if candidate.closed || candidate.baseline.is_none() || candidate.source.file.is_none() {
            return Err(storage_refusal());
        }
        candidate.closed = true;
        let cause = match prefix.encode() {
            Ok(_) => NativeFailure::UnobservedComponents,
            Err(_) => NativeFailure::Original,
        };
        if candidate.first_failure.is_none() {
            candidate.first_failure = Some(cause);
        }
        Err(storage_refusal())
    }

    pub(crate) fn export_original_cleanup(&self, state: &HostState) -> Result<()> {
        let selected = self.selected.as_ref().ok_or_else(storage_refusal)?;
        selected.candidate.lock().map_err(|_| storage_refusal())?
            .export_original_cleanup(state, &self.writer, &selected.authority)
    }

    pub(crate) fn require_original_export(&self, state: &HostState) -> Result<()> {
        let selected = self.selected.as_ref().ok_or_else(storage_refusal)?;
        let mut candidate = selected.candidate.lock().map_err(|_| storage_refusal())?;
        candidate.require_completed_export(state, &self.writer, &selected.authority)
    }

    pub(crate) fn retire_original_cells(&self, state: &HostState) -> Result<()> {
        let selected = self.selected.as_ref().ok_or_else(storage_refusal)?;
        let mut candidate = selected.candidate.lock().map_err(|_| storage_refusal())?;
        if candidate.closed || candidate.exported || candidate.current.as_ref() != Some(state)
            || candidate.export_output.file.is_none() || candidate.export_readback.file.is_none()
            || !state.canary_cleanup_is_complete(candidate.request_ids)
        {
            return Err(storage_refusal());
        }

        // The installed coordinator calls this only after complete ordinary
        // readback and its final original-job check. Evidence stays resident;
        // only future store dispatch returns to the same ordinary writer.
        candidate.exported = true;
        Ok(())
    }
}

impl HostStateStore for HostProductionStateStoreV1 {
    fn load(&self) -> Result<HostState> {
        match &self.selected {
            None => self.writer.load(),
            Some(selected) => {
                let mut candidate = selected.candidate.lock().map_err(|_| storage_refusal())?;
                if candidate.exported {
                    self.writer.load()
                } else {
                    candidate.load_original(&selected.authority)
                }
            }
        }
    }

    fn commit(&self, state: &HostState) -> Result<()> {
        match &self.selected {
            None => self.writer.commit(state),
            Some(selected) => {
                let mut candidate = selected.candidate.lock().map_err(|_| storage_refusal())?;
                if candidate.exported {
                    self.writer.commit(state)
                } else {
                    candidate.commit_original(state, &selected.authority)
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum NativeFailure {
    #[error("Host canary native I/O failed")]
    Native(#[from] rustix::io::Errno),
    #[error("Host canary file I/O failed")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Read(#[from] ExactReadFailure),
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    #[error("Host canary original storage or transition changed")]
    Original,
    #[error("Host canary fixed memory reservation failed")]
    Allocation,
    #[error(transparent)]
    State(#[from] HostError),
    #[error(transparent)]
    Accounting(#[from] aos_sandbox_core::AccountingError),
    #[error("Host canary logging and post-launch writable byte/entry components remain unobserved")]
    UnobservedComponents,
}

enum ReadbackDisposition {
    Local,
    Canary,
}

/// Keeps bytes before the File in drop order, matching the ordinary reader.
pub(super) struct NativeStateReadbackV1 {
    bytes: Vec<u8>,
    file: Option<File>,
    disposition: ReadbackDisposition,
    first_failure: Option<NativeFailure>,
}

impl NativeStateReadbackV1 {
    pub(super) fn local() -> Self {
        Self::new(ReadbackDisposition::Local)
    }

    fn retained() -> Self {
        Self::new(ReadbackDisposition::Canary)
    }

    fn new(disposition: ReadbackDisposition) -> Self {
        Self {
            bytes: Vec::new(),
            file: None,
            disposition,
            first_failure: None,
        }
    }

    pub(super) fn park(&mut self, descriptor: OwnedFd) {
        self.file = Some(File::from(descriptor));
    }

    pub(super) fn require_empty_destination(&self) -> Result<()> {
        if self.file.is_some() {
            return Err(storage_refusal());
        }
        Ok(())
    }

    pub(super) fn file(&self) -> Result<&File> {
        self.file.as_ref().ok_or_else(storage_refusal)
    }

    pub(super) fn file_mut(&mut self) -> Result<&mut File> {
        self.file.as_mut().ok_or_else(storage_refusal)
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn allocate(&mut self, length: usize) -> Result<()> {
        match self.disposition {
            ReadbackDisposition::Local => self.bytes = vec![0; length],
            ReadbackDisposition::Canary => {
                if self.bytes.try_reserve_exact(length).is_err() {
                    self.first_failure = Some(NativeFailure::Allocation);
                    return Err(storage_refusal());
                }
                self.bytes.resize(length, 0);
            }
        }
        Ok(())
    }

    pub(super) fn read_body(&mut self) -> Result<()> {
        let input = self.file.as_mut().ok_or_else(storage_refusal)?;
        if let Err(error) = input.read_exact(&mut self.bytes) {
            return Err(self.io(error));
        }
        Ok(())
    }

    pub(super) fn write_original_body(&mut self, bytes: &[u8]) -> Result<()> {
        let output = self.file.as_mut().ok_or_else(storage_refusal)?;
        if let Err(error) = output.write_all(bytes).and_then(|()| output.sync_all()) {
            return Err(self.io(error));
        }
        Ok(())
    }

    pub(super) fn native(&mut self, error: rustix::io::Errno) -> HostError {
        match self.disposition {
            ReadbackDisposition::Local => HostError::State(error.to_string()),
            ReadbackDisposition::Canary => {
                if self.first_failure.is_none() {
                    self.first_failure = Some(NativeFailure::Native(error));
                }
                storage_refusal()
            }
        }
    }

    pub(super) fn io(&mut self, error: std::io::Error) -> HostError {
        match self.disposition {
            ReadbackDisposition::Local => HostError::State(error.to_string()),
            ReadbackDisposition::Canary => {
                if self.first_failure.is_none() {
                    self.first_failure = Some(NativeFailure::Io(error));
                }
                storage_refusal()
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    bytes: u64,
    mount: MountId,
}

pub(crate) struct CanaryCapacityCandidateV1 {
    directory: Option<File>,
    files: [Option<File>; 3],
    identities: [Option<FileIdentity>; 4],
    mount: Option<MountObservation>,
    source: NativeStateReadbackV1,
    export_output: NativeStateReadbackV1,
    export_readback: NativeStateReadbackV1,
    export_bytes: Vec<u8>,
    buffers: [Vec<u8>; 2],
    baseline_bytes: Vec<u8>,
    baseline: Option<HostState>,
    current: Option<HostState>,
    job_digest: [u8; 32],
    request_ids: [[u8; 16]; 2],
    sandbox: [u8; 16],
    incarnation: [u8; 16],
    counter_id: [u8; 16],
    profile_digest: [u8; 32],
    parent: ResourceVector,
    retained: ResourceVector,
    promised: ResourceVector,
    cleanup_release: ResourceVector,
    account: Option<ResourceAccount>,
    generation: u64,
    active: usize,
    attempted: bool,
    closed: bool,
    exported: bool,
    first_failure: Option<NativeFailure>,
}

impl CanaryCapacityCandidateV1 {
    pub(crate) fn new() -> Self {
        Self {
            directory: None,
            files: std::array::from_fn(|_| None),
            identities: [None; 4],
            mount: None,
            source: NativeStateReadbackV1::retained(),
            export_output: NativeStateReadbackV1::retained(),
            export_readback: NativeStateReadbackV1::retained(),
            export_bytes: Vec::new(),
            buffers: std::array::from_fn(|_| Vec::new()),
            baseline_bytes: Vec::new(),
            baseline: None,
            current: None,
            job_digest: [0; 32],
            request_ids: [[0; 16]; 2],
            sandbox: [0; 16],
            incarnation: [0; 16],
            counter_id: [0; 16],
            profile_digest: [0; 32],
            parent: ResourceVector::ZERO,
            retained: ResourceVector::ZERO,
            promised: ResourceVector::ZERO,
            cleanup_release: ResourceVector::ZERO,
            account: None,
            generation: 0,
            active: 0,
            attempted: false,
            closed: false,
            exported: false,
            first_failure: None,
        }
    }

    pub(crate) fn prepare_original(
        &mut self,
        job_owner: &crate::broker::canary_job::HostCanaryJobOwnerV1,
        startup: &crate::plan::HostCanaryStartupV1,
        writer: &FileHostStateStore,
        authority: &HostAuthorityV1,
    ) -> Result<()> {
        if self.attempted {
            return Err(storage_refusal());
        }
        self.attempted = true;
        self.closed = true;
        let result = (|| {
            let job = job_owner.originals()?;
            self.job_digest = job.digest;
            self.request_ids = [job.request_ids[0], job.request_ids[1]];
            self.sandbox = *job.launch.fence().sandbox_id();
            self.incarnation = *job.launch.fence().incarnation_id();
            self.counter_id = job.request_ids[2];
            self.profile_digest = job.pins[6];
            self.parent = startup.parent_resources()?;
            self.retained = startup.original_retained_charge()?
                .checked_add(job_owner.original_retained_charge()?)?;
            self.promised = ResourceVector::new(job.maximum_charges);
            let (_, guardian) = startup.service_limits()?;
            let guardian = ResourceVector::ZERO
                .with(ResourceDimension::CpuMicrosPerPeriod, guardian[0])
                .with(ResourceDimension::MemoryBytes, guardian[1])
                .with(ResourceDimension::Pids, guardian[2])
                .with(ResourceDimension::OpenFiles, guardian[3]);
            let payload = crate::plan::original_canary_payload_envelope(
                job.launch.launch_plan().ok_or(NativeFailure::Original)?,
            )?;
            self.cleanup_release = guardian.checked_add(payload)?;
            // These are actual fixed native extent and envelope bounds, not
            // a multiplier of JSON bytes or an allocator/funding proof.
            let native_bytes = (CELL_BYTES as u64).checked_mul(2)
                .and_then(|bytes| bytes.checked_add((super::HEADER_BYTES + super::MAXIMUM_STATE_BYTES) as u64))
                .ok_or(NativeFailure::Original)?;
            let minimum = self.cleanup_release
                .with(ResourceDimension::StorageBytes, native_bytes)
                .with(ResourceDimension::MetadataEntries, 4)
                .with(ResourceDimension::PublicationStagingBytes,
                    (super::HEADER_BYTES + super::MAXIMUM_STATE_BYTES) as u64)
                .with(ResourceDimension::OutputBytes,
                    u64::from(job.maximum_response_bytes[0]) + u64::from(job.maximum_response_bytes[1]))
                .with(ResourceDimension::ConcurrentOperations, 1);
            if !minimum.is_within(self.promised) {
                return Err(NativeFailure::Original);
            }
            self.prepare_inner(writer, authority)
        })();
        match result {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(error) => {
                self.first_failure = Some(error);
                Err(storage_refusal())
            }
        }
    }

    fn prepare_inner(
        &mut self,
        writer: &FileHostStateStore,
        authority: &HostAuthorityV1,
    ) -> std::result::Result<(), NativeFailure> {
        writer.ensure_named_root()?;
        let directory = rustix::fs::open(
            ROOT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        self.directory = Some(File::from(directory));
        let identity = file_identity(self.directory()?)?;
        if FileType::from_raw_mode(identity.mode) != FileType::Directory
            || identity.uid != 0 || identity.mode & 0o7777 != 0o700
        {
            return Err(NativeFailure::Original);
        }
        self.identities[0] = Some(identity);
        let filesystem = rustix::fs::fstatfs(self.directory()?)?;
        if filesystem.f_type as u64 != EXT4_MAGIC || filesystem.f_bsize != 4096 {
            return Err(NativeFailure::Original);
        }
        self.mount = Some(MountNamespace::current().observe(identity.mount)?);
        self.require_mount()?;

        let baseline_descriptor = match rustix::fs::openat(
            self.directory()?, NAMES[0],
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => Some(descriptor),
            Err(rustix::io::Errno::NOENT) => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(descriptor) = baseline_descriptor {
            self.files[0] = Some(File::from(descriptor));
            return self.recover_inner(authority);
        }

        // No positive-deadline or unit-absence check precedes authentication
        // of existing banks. Missing banks instead leave this same resident
        // candidate ready for the separately checked fresh creation step.
        Ok(())
    }

    fn prepare_fresh_original(
        &mut self,
        payload: &crate::worker::GuardianObservation,
        guardian: &crate::worker::GuardianObservation,
        writer: &FileHostStateStore,
        authority: &HostAuthorityV1,
    ) -> Result<()> {
        if !self.attempted || self.closed || self.current.is_some()
            || self.files.iter().any(Option::is_some)
        {
            return Err(storage_refusal());
        }
        self.closed = true;
        let result = (|| {
            if payload.state != crate::worker::GuardianObservedState::Absent
                || guardian.state != crate::worker::GuardianObservedState::Absent
            {
                return Err(NativeFailure::Original);
            }
            self.require_directory()?;
            self.require_mount()?;
            self.prepare_fresh_inner(writer, authority)
        })();
        match result {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                self.first_failure = Some(cause);
                Err(storage_refusal())
            }
        }
    }

    fn prepare_fresh_inner(
        &mut self,
        writer: &FileHostStateStore,
        authority: &HostAuthorityV1,
    ) -> std::result::Result<(), NativeFailure> {

        // Missing ordinary state is durably materialized before any canary
        // effect. It does not establish absence of resources or old debt.
        let baseline = writer.load_into(&mut self.source)?;
        baseline.validate_authenticated(authority)?;
        self.baseline = Some(baseline.clone());
        self.account = Some(self.account_for_state(&baseline)?);
        if self.source.file.is_none() {
            writer.commit(&baseline)?;
            let loaded = writer.load_into(&mut self.source)?;
            if loaded != baseline {
                return Err(NativeFailure::Original);
            }
        }
        self.baseline_bytes.try_reserve_exact(self.source.bytes.len())
            .map_err(|_| NativeFailure::Allocation)?;
        self.baseline_bytes.extend_from_slice(&self.source.bytes);
        self.current = Some(baseline);
        self.reserve_cell_buffers()?;

        for slot in 0..3 {
            let descriptor = rustix::fs::openat(
                self.directory()?, NAMES[slot],
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?;
            self.files[slot] = Some(File::from(descriptor));
            if slot == 0 {
                self.file(slot)?.write_all_at(&self.baseline_bytes, 0)?;
                self.file(slot)?.sync_all()?;
                rustix::fs::fchmod(self.file(slot)?, Mode::RUSR)?;
            } else {
                rustix::fs::fallocate(self.file(slot)?, rustix::fs::FallocateFlags::empty(), 0, CELL_BYTES as u64)?;
                self.file(slot)?.write_all_at(&self.buffers[1], 0)?;
                self.file(slot)?.sync_all()?;
            }
            self.identities[slot + 1] = Some(file_identity(self.file(slot)?)?);
            self.require_file(slot)?;
        }

        let baseline_digest: [u8; 32] = Sha256::digest(&self.baseline_bytes).into();
        let counter = self.counter_for_state(
            self.current.as_ref().ok_or(NativeFailure::Original)?, 0, &self.baseline_bytes, authority,
        )?;
        encode_cell(&mut self.buffers[0], 0, self.job_digest, [0; 32], baseline_digest, &self.baseline_bytes, &counter)?;
        self.file(1)?.write_all_at(&self.buffers[0], 0)?;
        self.file(1)?.sync_all()?;
        rustix::fs::fsync(self.directory()?)?;
        self.require_named_files()?;

        // Read the actual immutable baseline, not its prepared byte buffer.
        // The original state.bin File remains held through this copy check.
        let baseline_length = self.baseline_bytes.len();
        read_exact_positioned_retaining_cause(
            self.files[0].as_ref().ok_or(NativeFailure::Original)?,
            &mut self.buffers[1][..baseline_length],
        )?;
        if self.buffers[1][..baseline_length] != self.baseline_bytes {
            return Err(NativeFailure::Original);
        }
        self.require_named_files()?;

        read_exact_positioned_retaining_cause(self.files[1].as_ref().ok_or(NativeFailure::Original)?, &mut self.buffers[1])?;
        if self.buffers[0] != self.buffers[1] {
            return Err(NativeFailure::Original);
        }
        read_exact_positioned_retaining_cause(
            self.files[2].as_ref().ok_or(NativeFailure::Original)?,
            &mut self.buffers[1],
        )?;
        if self.buffers[1].iter().any(|byte| *byte != 0) {
            return Err(NativeFailure::Original);
        }
        self.require_named_files()?;
        let original = decode_envelope(&self.baseline_bytes)?;
        original.validate_authenticated(authority)?;
        if self.baseline.as_ref() != Some(&original) {
            return Err(NativeFailure::Original);
        }

        writer.ensure_named_root()?;
        let source = self.source.file.as_ref().ok_or(NativeFailure::Original)?;
        let held = rustix::fs::fstat(source)?;
        let named = rustix::fs::statat(
            writer.directory_fd.as_ref(),
            "state.bin",
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        if held.st_dev != named.st_dev
            || held.st_ino != named.st_ino
            || held.st_uid != 0
            || held.st_mode & 0o7777 != 0o600
            || held.st_nlink != 1
            || usize::try_from(held.st_size).ok() != Some(baseline_length)
        {
            return Err(NativeFailure::Original);
        }
        read_exact_positioned_retaining_cause(
            source,
            &mut self.buffers[1][..baseline_length],
        )?;
        if self.buffers[1][..baseline_length] != self.source.bytes {
            return Err(NativeFailure::Original);
        }
        let after = rustix::fs::fstat(source)?;
        if held.st_dev != after.st_dev
            || held.st_ino != after.st_ino
            || held.st_mode != after.st_mode
            || held.st_uid != after.st_uid
            || held.st_gid != after.st_gid
            || held.st_nlink != after.st_nlink
            || held.st_size != after.st_size
            || held.st_mtime != after.st_mtime
            || held.st_mtime_nsec != after.st_mtime_nsec
            || held.st_ctime != after.st_ctime
            || held.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(NativeFailure::Original);
        }
        writer.ensure_named_root()?;
        self.require_named_files()?;

        // The independent baseline now owns the exact authenticated bytes.
        // Only this successful copy can retire the temporary source File.
        self.source.file = None;
        self.source.bytes.clear();
        Ok(())
    }

    fn directory(&self) -> std::result::Result<&File, NativeFailure> {
        self.directory.as_ref().ok_or(NativeFailure::Original)
    }

    fn file(&self, slot: usize) -> std::result::Result<&File, NativeFailure> {
        self.files[slot].as_ref().ok_or(NativeFailure::Original)
    }

    fn require_mount(&self) -> std::result::Result<(), NativeFailure> {
        let mount = self.mount.as_ref().ok_or(NativeFailure::Original)?;
        if mount.superblock_magic != EXT4_MAGIC || mount.is_read_only()
            || mount.mount_attributes & 0x0010_0000 != 0
            || mount.uid_map.as_ref().is_some_and(|map| !map.is_empty())
            || mount.gid_map.as_ref().is_some_and(|map| !map.is_empty())
        {
            return Err(NativeFailure::Original);
        }
        let fresh = MountNamespace::current().observe(mount.mount_id)?;
        if &fresh != mount {
            return Err(NativeFailure::Original);
        }
        Ok(())
    }

    fn require_file(&self, slot: usize) -> std::result::Result<(), NativeFailure> {
        let identity = file_identity(self.file(slot)?)?;
        let expected = self.identities[slot + 1].ok_or(NativeFailure::Original)?;
        let mode = if slot == 0 { 0o400 } else { 0o600 };
        let size_valid = if slot == 0 {
            (super::HEADER_BYTES as u64..=(super::HEADER_BYTES + super::MAXIMUM_STATE_BYTES) as u64)
                .contains(&identity.bytes)
        } else {
            identity.bytes == CELL_BYTES as u64
        };
        if identity != expected || identity.uid != 0 || identity.links != 1
            || FileType::from_raw_mode(identity.mode) != FileType::RegularFile
            || identity.mode & 0o7777 != mode || !size_valid
            || identity.mount != self.identities[0].ok_or(NativeFailure::Original)?.mount
        {
            return Err(NativeFailure::Original);
        }
        if slot != 0 && rustix::fs::ioctl_getflags(self.file(slot)?)?.bits() != EXTENTS_FLAG {
            return Err(NativeFailure::Original);
        }
        let named = rustix::fs::statat(self.directory()?, NAMES[slot], AtFlags::SYMLINK_NOFOLLOW)?;
        if named.st_dev != identity.device || named.st_ino != identity.inode {
            return Err(NativeFailure::Original);
        }
        Ok(())
    }

    fn require_directory(&self) -> std::result::Result<(), NativeFailure> {
        let directory = file_identity(self.directory()?)?;
        if self.identities[0] != Some(directory) {
            return Err(NativeFailure::Original);
        }
        let named = rustix::fs::statat(rustix::fs::CWD, ROOT, AtFlags::SYMLINK_NOFOLLOW)?;
        if named.st_dev != directory.device || named.st_ino != directory.inode {
            return Err(NativeFailure::Original);
        }
        Ok(())
    }

    fn require_named_files(&self) -> std::result::Result<(), NativeFailure> {
        self.require_directory()?;
        for slot in 0..3 {
            self.require_file(slot)?;
        }
        self.require_mount()
    }

    fn recover_inner(&mut self, authority: &HostAuthorityV1) -> std::result::Result<(), NativeFailure> {
        let baseline_identity = file_identity(self.file(0)?)?;
        self.identities[1] = Some(baseline_identity);
        self.require_file(0)?;
        let length = usize::try_from(baseline_identity.bytes).map_err(|_| NativeFailure::Original)?;
        self.baseline_bytes.try_reserve_exact(length).map_err(|_| NativeFailure::Allocation)?;
        self.baseline_bytes.resize(length, 0);
        read_exact_positioned_retaining_cause(self.files[0].as_ref().ok_or(NativeFailure::Original)?, &mut self.baseline_bytes)?;
        let baseline = decode_envelope(&self.baseline_bytes)?;
        baseline.validate_authenticated(authority)?;
        self.baseline = Some(baseline);
        self.account = Some(self.account_for_state(self.baseline.as_ref().ok_or(NativeFailure::Original)?)?);
        self.reserve_cell_buffers()?;

        for slot in 1..3 {
            let descriptor = rustix::fs::openat(
                self.directory()?, NAMES[slot], OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            self.files[slot] = Some(File::from(descriptor));
            self.identities[slot + 1] = Some(file_identity(self.file(slot)?)?);
            self.require_file(slot)?;
            read_exact_positioned_retaining_cause(self.files[slot].as_ref().ok_or(NativeFailure::Original)?, &mut self.buffers[slot - 1])?;
        }
        self.require_named_files()?;
        // Selection below validates both full envelopes and reducer links.
        // A torn inactive bank remains debt, never an empty-state fallback.
        self.select_cold_current(authority)
    }

    fn select_cold_current(&mut self, authority: &HostAuthorityV1) -> std::result::Result<(), NativeFailure> {
        let baseline_digest: [u8; 32] = Sha256::digest(&self.baseline_bytes).into();
        let first = decode_cell(&self.buffers[0], self.job_digest, baseline_digest);
        let second = decode_cell(&self.buffers[1], self.job_digest, baseline_digest);
        let (active, selected) = match (first, second) {
            (Ok(first), Ok(second)) => {
                let (older, newer, active) = if first.generation < second.generation {
                    (first, second, 1)
                } else {
                    (second, first, 0)
                };
                if newer.generation != older.generation + 1 || newer.previous != older.digest {
                    return Err(NativeFailure::Original);
                }
                older.state.validate_authenticated(authority)?;
                newer.state.validate_authenticated(authority)?;
                self.require_counter(&older, authority)?;
                self.require_counter(&newer, authority)?;
                self.require_transition(&older.state, &newer.state, newer.generation)?;
                (active, newer)
            }
            (Ok(first), Err(_)) if first.generation == 0 && self.buffers[1].iter().all(|byte| *byte == 0) => (0, first),
            (Ok(_), Err(_)) | (Err(_), Ok(_)) | (Err(_), Err(_)) => {
                // A lone valid cell cannot establish the current generation,
                // including for cleanup. Both originals remain cold debt;
                // this owner neither repairs nor synchronizes a torn peer.
                return Err(NativeFailure::Original);
            }
        };
        selected.state.validate_authenticated(authority)?;
        if selected.generation == 0 && self.baseline.as_ref() != Some(&selected.state) {
            return Err(NativeFailure::Original);
        }
        self.require_original_rows(&selected.state)?;
        self.require_counter(&selected, authority)?;
        self.active = active;
        self.generation = selected.generation;
        self.account = Some(self.account_for_state(&selected.state)?);
        self.current = Some(selected.state);
        Ok(())
    }

    fn require_original_rows(&self, state: &HostState) -> std::result::Result<(), NativeFailure> {
        let baseline = self.baseline.as_ref().ok_or(NativeFailure::Original)?;
        if !state.canary_rows_preserve(baseline, self.sandbox, self.incarnation, self.request_ids) {
            return Err(NativeFailure::Original);
        }
        Ok(())
    }

    fn reserve_cell_buffers(&mut self) -> std::result::Result<(), NativeFailure> {
        for buffer in &mut self.buffers {
            buffer.try_reserve_exact(CELL_BYTES).map_err(|_| NativeFailure::Allocation)?;
            buffer.resize(CELL_BYTES, 0);
        }
        Ok(())
    }

    fn require_transition(&self, before: &HostState, after: &HostState, generation: u64) -> std::result::Result<(), NativeFailure> {
        self.require_original_rows(before)?;
        self.require_original_rows(after)?;
        if generation > MAXIMUM_GENERATION
            || !after.canary_follows(before, self.request_ids)
            || generation + after.canary_remaining(self.request_ids)? > MAXIMUM_GENERATION
        {
            return Err(NativeFailure::Original);
        }
        Ok(())
    }

    fn account_for_state(&self, state: &HostState) -> std::result::Result<ResourceAccount, NativeFailure> {
        let baseline = self.baseline.as_ref().ok_or(NativeFailure::Original)?;
        let baseline_bytes = u64::try_from(encode_envelope(baseline)?.len())
            .map_err(|_| NativeFailure::Original)?;
        let native_span = (CELL_BYTES as u64).checked_mul(2)
            .and_then(|bytes| bytes.checked_add(baseline_bytes))
            .ok_or(NativeFailure::Original)?;
        let observed = self.observed_native_blocks()?;
        let native_storage = native_span.max(observed)
            .checked_add((super::HEADER_BYTES + super::MAXIMUM_STATE_BYTES) as u64)
            .ok_or(NativeFailure::Original)?;
        if self.promised.get(ResourceDimension::StorageBytes) < native_storage {
            return Err(NativeFailure::Original);
        }
        let committed = baseline.original_canary_baseline_debt()?.checked_add(self.retained)?;
        let mut account = ResourceAccount::from_usage(
            ResourceCeilings::bounded(self.parent), committed, ResourceVector::ZERO,
        )?.reserve(self.promised)?;
        let issued = state.canary_reservation_is_issued(self.request_ids);
        if issued {
            account = account.commit(self.promised)?;
        }
        if state.canary_cleanup_is_complete(self.request_ids) {
            // Only reducer-proven same-unit cleanup retires these two finite
            // execution envelopes. Native history, pinned originals and all
            // other declared debt remain charged across cold admission.
            account = if issued {
                account.release_committed(self.cleanup_release)?
            } else {
                account.release_reservation(self.cleanup_release)?
            };
        }
        Ok(account)
    }

    fn observed_native_blocks(&self) -> std::result::Result<u64, NativeFailure> {
        let mut bytes = 0_u64;
        for file in self.directory.iter().chain(self.files.iter().filter_map(Option::as_ref)) {
            let blocks = u64::try_from(rustix::fs::fstat(file)?.st_blocks)
                .map_err(|_| NativeFailure::Original)?;
            let allocated = blocks.checked_mul(512).ok_or(NativeFailure::Original)?;
            bytes = bytes.checked_add(allocated).ok_or(NativeFailure::Original)?;
        }

        // The full written extent admission remains separate. st_blocks is
        // an observed accounting contribution, never sparse-file capacity or
        // reserved filesystem journal/metadata space.
        Ok(bytes)
    }

    fn export_original_cleanup(
        &mut self,
        state: &HostState,
        writer: &FileHostStateStore,
        authority: &HostAuthorityV1,
    ) -> Result<()> {
        if self.closed || self.export_output.file.is_some() || self.export_readback.file.is_some() {
            return Err(storage_refusal());
        }
        self.closed = true;
        let result = (|| {
            self.require_named_files()?;
            self.require_current_cell(authority)?;
            if self.current.as_ref() != Some(state) || !state.canary_cleanup_is_complete(self.request_ids) {
                return Err(NativeFailure::Original);
            }
            state.validate_authenticated(authority)?;
            self.export_bytes = encode_envelope(state)?;
            writer.write_atomic_inner(&self.export_bytes, Some(&mut self.export_output))?;
            let actual = writer.load_into(&mut self.export_readback)?;
            if &actual != state || self.export_readback.bytes != self.export_bytes {
                return Err(NativeFailure::Original);
            }
            let written = self.export_output.file.as_ref().ok_or(NativeFailure::Original)?;
            let read = self.export_readback.file.as_ref().ok_or(NativeFailure::Original)?;
            if file_identity(written)? != file_identity(read)? {
                return Err(NativeFailure::Original);
            }
            self.require_named_files()?;
            self.require_current_cell(authority)
        })();
        match result {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                self.first_failure = Some(cause);
                Err(storage_refusal())
            }
        }
    }

    fn require_completed_export(
        &mut self,
        state: &HostState,
        writer: &FileHostStateStore,
        authority: &HostAuthorityV1,
    ) -> Result<()> {
        if self.closed || self.export_output.file.is_none() || self.export_readback.file.is_none() {
            return Err(storage_refusal());
        }
        self.closed = true;
        let result = (|| {
            writer.ensure_named_root()?;
            self.require_named_files()?;
            self.require_current_cell(authority)?;
            if self.current.as_ref() != Some(state) || !state.canary_cleanup_is_complete(self.request_ids) {
                return Err(NativeFailure::Original);
            }
            let read = self.export_readback.file.as_ref().ok_or(NativeFailure::Original)?;
            let held = file_identity(read)?;
            let written = self.export_output.file.as_ref().ok_or(NativeFailure::Original)?;
            let named = rustix::fs::statat(
                writer.directory_fd.as_ref(), "state.bin", AtFlags::SYMLINK_NOFOLLOW,
            )?;
            if held != file_identity(written)? || named.st_dev != held.device
                || named.st_ino != held.inode || held.uid != 0
                || held.mode & 0o7777 != 0o600 || held.links != 1
                || usize::try_from(held.bytes).ok() != Some(self.export_bytes.len())
            {
                return Err(NativeFailure::Original);
            }
            read_exact_positioned_retaining_cause(read, &mut self.export_readback.bytes)?;
            if self.export_readback.bytes != self.export_bytes || file_identity(read)? != held {
                return Err(NativeFailure::Original);
            }
            let actual = decode_envelope(&self.export_readback.bytes)?;
            actual.validate_authenticated(authority)?;
            if &actual != state {
                return Err(NativeFailure::Original);
            }
            writer.ensure_named_root()?;
            self.require_named_files()
        })();
        match result {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(cause) => {
                self.first_failure = Some(cause);
                Err(storage_refusal())
            }
        }
    }

    fn counter_for_state(
        &self,
        state: &HostState,
        generation: u64,
        envelope: &[u8],
        authority: &HostAuthorityV1,
    ) -> std::result::Result<[u8; SEALED_COUNTER_BYTES], NativeFailure> {
        let account = self.account_for_state(state)?;
        let mut payload = [0_u8; COUNTER_BYTES];
        payload[..8].copy_from_slice(b"AOSHCAC1");
        payload[8..10].copy_from_slice(&1_u16.to_be_bytes());
        payload[12..16].copy_from_slice(&(COUNTER_BYTES as u32).to_be_bytes());
        payload[16..48].copy_from_slice(&self.job_digest);
        payload[48..80].copy_from_slice(&self.profile_digest);
        payload[80..112].copy_from_slice(&Sha256::digest(&self.baseline_bytes));
        payload[112..144].copy_from_slice(&Sha256::digest(envelope));
        payload[144..152].copy_from_slice(&generation.to_be_bytes());
        payload[152..160].copy_from_slice(&100_000_u64.to_be_bytes());
        let disposition: u64 = if state.canary_cleanup_is_complete(self.request_ids) {
            2
        } else if state.canary_reservation_is_issued(self.request_ids) {
            1
        } else {
            0
        };
        payload[160..168].copy_from_slice(&disposition.to_be_bytes());
        payload[168..184].copy_from_slice(&self.counter_id);
        for (base, vector) in [(184, self.parent), (360, account.committed()), (536, account.reserved())] {
            for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
                let offset = base + index * 8;
                payload[offset..offset + 8].copy_from_slice(&vector.get(dimension).to_be_bytes());
            }
        }
        let sealed = authority.seal_execution_record(&self.counter_id, &payload)
            .map_err(HostError::from)?;
        sealed.try_into().map_err(|_| NativeFailure::Original)
    }

    fn require_counter(&self, cell: &DecodedCell, authority: &HostAuthorityV1)
        -> std::result::Result<(), NativeFailure>
    {
        // The old Host record engine verifies the exact location and MAC
        // before any counter fields can influence admission or arithmetic.
        let payload = authority.open_execution_record(&self.counter_id, &cell.counter)
            .map_err(HostError::from)?;
        let envelope = encode_envelope(&cell.state)?;
        let expected = self.counter_for_state(&cell.state, cell.generation, &envelope, authority)?;
        let expected_payload = authority.open_execution_record(&self.counter_id, &expected)
            .map_err(HostError::from)?;
        if payload != expected_payload {
            return Err(NativeFailure::Original);
        }
        Ok(())
    }

    fn load_original(&mut self, authority: &HostAuthorityV1) -> Result<HostState> {
        if self.closed {
            return Err(storage_refusal());
        }
        self.closed = true;

        let result = self.load_inner(authority);
        match result {
            Ok(state) => {
                self.closed = false;
                Ok(state)
            }
            Err(error) => {
                self.first_failure = Some(error);
                Err(storage_refusal())
            }
        }
    }

    fn load_inner(&mut self, authority: &HostAuthorityV1) -> std::result::Result<HostState, NativeFailure> {
        self.require_named_files()?;
        self.require_current_cell(authority)?;
        let current = self.current.as_ref().ok_or(NativeFailure::Original)?;
        current.validate_authenticated(authority)?;
        self.require_original_rows(current)?;
        Ok(current.clone())
    }

    pub(crate) fn commit_original(&mut self, state: &HostState, authority: &HostAuthorityV1) -> Result<()> {
        if self.closed { return Err(storage_refusal()); }
        self.closed = true;
        match self.commit_inner(state, authority) {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(error) => {
                self.first_failure = Some(error);
                Err(storage_refusal())
            }
        }
    }

    fn commit_inner(&mut self, state: &HostState, authority: &HostAuthorityV1) -> std::result::Result<(), NativeFailure> {
        let current = self.current.as_ref().ok_or(NativeFailure::Original)?;
        current.validate_authenticated(authority)?;
        state.validate_authenticated(authority)?;
        self.require_named_files()?;
        if state == current {
            return self.require_current_cell(authority);
        }
        let next = self.generation.checked_add(1).ok_or(NativeFailure::Original)?;
        self.require_transition(current, state, next)?;
        let envelope = encode_envelope(state)?;
        let previous: [u8; 32] = self.buffers[self.active][CELL_DIGEST_OFFSET..]
            .try_into().map_err(|_| NativeFailure::Original)?;
        let baseline_digest: [u8; 32] = Sha256::digest(&self.baseline_bytes).into();
        let inactive = 1 - self.active;
        let counter = self.counter_for_state(state, next, &envelope, authority)?;
        encode_cell(&mut self.buffers[inactive], next, self.job_digest, previous, baseline_digest, &envelope, &counter)?;
        self.file(inactive + 1)?.write_all_at(&self.buffers[inactive], 0)?;
        self.file(inactive + 1)?.sync_all()?;
        self.require_named_files()?;
        // The active buffer is no longer needed as scratch only after its
        // complete authenticated current value has been retained above.
        read_exact_positioned_retaining_cause(self.files[inactive + 1].as_ref().ok_or(NativeFailure::Original)?, &mut self.buffers[self.active])?;
        if self.buffers[self.active] != self.buffers[inactive] {
            return Err(NativeFailure::Original);
        }
        let verified = decode_cell(&self.buffers[inactive], self.job_digest, baseline_digest)?;
        verified.state.validate_authenticated(authority)?;
        self.require_counter(&verified, authority)?;
        if verified.state != *state {
            return Err(NativeFailure::Original);
        }
        self.active = inactive;
        self.generation = next;
        self.account = Some(self.account_for_state(&verified.state)?);
        self.current = Some(verified.state);
        Ok(())
    }

    fn require_current_cell(&mut self, authority: &HostAuthorityV1) -> std::result::Result<(), NativeFailure> {
        let scratch = 1 - self.active;
        read_exact_positioned_retaining_cause(self.files[self.active + 1].as_ref().ok_or(NativeFailure::Original)?, &mut self.buffers[scratch])?;
        if self.buffers[scratch] != self.buffers[self.active] {
            return Err(NativeFailure::Original);
        }
        let verified = decode_cell(&self.buffers[scratch], self.job_digest, Sha256::digest(&self.baseline_bytes).into())?;
        verified.state.validate_authenticated(authority)?;
        self.require_counter(&verified, authority)?;
        if self.current.as_ref() != Some(&verified.state) {
            return Err(NativeFailure::Original);
        }
        if self.account != Some(self.account_for_state(&verified.state)?) {
            return Err(NativeFailure::Original);
        }
        Ok(())
    }
}

struct DecodedCell {
    generation: u64,
    previous: [u8; 32],
    digest: [u8; 32],
    state: HostState,
    counter: [u8; SEALED_COUNTER_BYTES],
}

fn encode_cell(output: &mut [u8], generation: u64, job: [u8; 32], previous: [u8; 32], baseline: [u8; 32], envelope: &[u8], counter: &[u8; SEALED_COUNTER_BYTES]) -> std::result::Result<(), NativeFailure> {
    let body_end = CELL_HEADER_BYTES.checked_add(envelope.len())
        .and_then(|end| end.checked_add(SEALED_COUNTER_BYTES))
        .ok_or(NativeFailure::Original)?;
    if output.len() != CELL_BYTES || generation > MAXIMUM_GENERATION
        || (generation == 0 && previous != [0; 32])
        || envelope.len() > super::HEADER_BYTES + super::MAXIMUM_STATE_BYTES
        || body_end > CELL_DIGEST_OFFSET
    {
        return Err(NativeFailure::Original);
    }
    output.fill(0);
    output[..8].copy_from_slice(b"AOSHCC02");
    output[8..10].copy_from_slice(&2_u16.to_le_bytes());
    output[12..16].copy_from_slice(&(CELL_HEADER_BYTES as u32).to_le_bytes());
    output[16..24].copy_from_slice(&generation.to_le_bytes());
    output[24..32].copy_from_slice(&(envelope.len() as u64).to_le_bytes());
    output[32..64].copy_from_slice(&job);
    output[64..96].copy_from_slice(&previous);
    output[96..128].copy_from_slice(&Sha256::digest(envelope));
    output[128..160].copy_from_slice(&baseline);
    output[160..164].copy_from_slice(&(SEALED_COUNTER_BYTES as u32).to_le_bytes());
    output[CELL_HEADER_BYTES..CELL_HEADER_BYTES + envelope.len()].copy_from_slice(envelope);
    let counter_offset = CELL_HEADER_BYTES + envelope.len();
    output[counter_offset..counter_offset + SEALED_COUNTER_BYTES].copy_from_slice(counter);
    let digest = Sha256::digest(&output[..CELL_DIGEST_OFFSET]);
    output[CELL_DIGEST_OFFSET..].copy_from_slice(&digest);
    Ok(())
}

fn decode_cell(bytes: &[u8], job: [u8; 32], baseline: [u8; 32]) -> std::result::Result<DecodedCell, NativeFailure> {
    if bytes.len() != CELL_BYTES || &bytes[..8] != b"AOSHCC02"
        || bytes[8..10] != 2_u16.to_le_bytes() || bytes[10..12] != [0; 2]
        || bytes[12..16] != (CELL_HEADER_BYTES as u32).to_le_bytes()
        || bytes[32..64] != job || bytes[128..160] != baseline
        || bytes[160..164] != (SEALED_COUNTER_BYTES as u32).to_le_bytes()
        || bytes[164..176] != [0; 12]
        || Sha256::digest(&bytes[..CELL_DIGEST_OFFSET]).as_slice() != &bytes[CELL_DIGEST_OFFSET..]
    {
        return Err(NativeFailure::Original);
    }
    let generation = u64::from_le_bytes(bytes[16..24].try_into().map_err(|_| NativeFailure::Original)?);
    let length = usize::try_from(u64::from_le_bytes(bytes[24..32].try_into().map_err(|_| NativeFailure::Original)?))
        .map_err(|_| NativeFailure::Original)?;
    if generation > MAXIMUM_GENERATION
        || (generation == 0 && bytes[64..96] != [0; 32])
        || !(super::HEADER_BYTES..=super::HEADER_BYTES + super::MAXIMUM_STATE_BYTES).contains(&length)
    {
        return Err(NativeFailure::Original);
    }
    let end = CELL_HEADER_BYTES.checked_add(length).ok_or(NativeFailure::Original)?;
    if end.checked_add(SEALED_COUNTER_BYTES).is_none_or(|end| end > CELL_DIGEST_OFFSET) {
        return Err(NativeFailure::Original);
    }
    let envelope = &bytes[CELL_HEADER_BYTES..end];
    if Sha256::digest(envelope).as_slice() != &bytes[96..128]
        || bytes[end + SEALED_COUNTER_BYTES..CELL_DIGEST_OFFSET].iter().any(|byte| *byte != 0)
    {
        return Err(NativeFailure::Original);
    }
    Ok(DecodedCell {
        generation,
        previous: bytes[64..96].try_into().map_err(|_| NativeFailure::Original)?,
        digest: bytes[CELL_DIGEST_OFFSET..].try_into().map_err(|_| NativeFailure::Original)?,
        state: decode_envelope(envelope)?,
        counter: bytes[end..end + SEALED_COUNTER_BYTES].try_into()
            .map_err(|_| NativeFailure::Original)?,
    })
}

fn file_identity(file: &File) -> std::result::Result<FileIdentity, NativeFailure> {
    let stat = rustix::fs::fstat(file)?;
    Ok(FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        uid: stat.st_uid,
        mode: stat.st_mode,
        links: u64::from(stat.st_nlink),
        bytes: u64::try_from(stat.st_size).map_err(|_| NativeFailure::Original)?,
        mount: MountId::from_fd(file.as_fd())?,
    })
}

fn storage_refusal() -> HostError {
    HostError::State("original Host canary capacity requires retained recovery".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These exercise checksum/layout DATA only. The zero counter is never a
    // genuine HostAuthority admission and cannot reach a store/effect caller.
    #[test]
    fn checksum_layout_roundtrip_does_not_authenticate_counter_data() {
        let state = HostState::default();
        let envelope = encode_envelope(&state).expect("pure envelope fixture");
        let baseline = Sha256::digest(&envelope).into();
        let mut bytes = vec![0; CELL_BYTES];

        encode_cell(&mut bytes, 0, [1; 32], [0; 32], baseline, &envelope, &[0; SEALED_COUNTER_BYTES])
            .expect("pure cell encoding");
        let decoded = decode_cell(&bytes, [1; 32], baseline).expect("pure cell decoding");

        assert_eq!(decoded.generation, 0);
        assert_eq!(decoded.previous, [0; 32]);
        assert_eq!(decoded.state, state);
        assert_eq!(decoded.counter, [0; SEALED_COUNTER_BYTES]);
    }

    #[test]
    fn canonical_layout_rejects_cross_job_padding_and_genesis_links() {
        let envelope = encode_envelope(&HostState::default()).expect("pure envelope fixture");
        let baseline = Sha256::digest(&envelope).into();
        let mut bytes = vec![0; CELL_BYTES];
        assert!(encode_cell(
            &mut bytes, 0, [1; 32], [2; 32], baseline, &envelope, &[0; SEALED_COUNTER_BYTES],
        ).is_err());

        encode_cell(&mut bytes, 0, [1; 32], [0; 32], baseline, &envelope, &[0; SEALED_COUNTER_BYTES])
            .expect("pure cell encoding");
        assert!(decode_cell(&bytes, [2; 32], baseline).is_err());

        let padding = CELL_HEADER_BYTES + envelope.len() + SEALED_COUNTER_BYTES;
        bytes[padding] = 1;
        let digest = Sha256::digest(&bytes[..CELL_DIGEST_OFFSET]);
        bytes[CELL_DIGEST_OFFSET..].copy_from_slice(&digest);
        assert!(decode_cell(&bytes, [1; 32], baseline).is_err());
    }
}
