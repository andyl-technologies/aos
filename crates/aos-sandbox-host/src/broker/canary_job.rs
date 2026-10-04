//! Fixed independent Host canary job admission and original credential custody.
//!
//! The undeployed private job format is not a broker request or a runtime
//! execution claim. Its signature permits only the fixed startup canary;
//! every Launch, Guardian and Stop still passes the existing Host authority.
//!
//! ```text
//! AOSHCJ01 | header[968] | ten bounded segments | Ed25519 signature[64]
//! approval pin = stable key ID[16] | Ed25519 public key[32]
//! ```
//!
//! The final header word is the independent issuer's nonzero namespace
//! generation. It is a private canary coordinate, not runtime currentness.

use std::fs::File;
use std::ops::Range;
use std::os::fd::AsFd as _;

use aos_proto::aos::sandbox::local::v1::{ApplyRuntimeRequest, BrokerMethod, RuntimeAction};
use aos_sandbox_core::ProtocolId;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::protected_file::{
    ExactReadFailure, open_nofollow_child, read_exact_positioned_retaining_cause,
};
use aos_sandbox_protocol::session::{
    AuthorizationArtifactBytes, ValidatedUntrustedAuthorizationArtifacts,
    decode_request_envelope, encode_authorized_request_envelope,
};
use aos_sandbox_protocol::{ValidatedRuntimeTemplateV1, decode_runtime_template_v1};
use ed25519_dalek::{Signature, VerifyingKey};
use buffa::Message as _;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use sha2::{Digest as _, Sha256};

use crate::authorization::HostAuthorityV1;
use crate::{HostError, Result};

const DIRECTORY: &str = "/run/credentials/aos-sandbox-hostd.service";
const NAMES: [&str; 2] = ["host-canary-approval-public-key-v1", "host-canary-job-v1"];
const HEADER_BYTES: usize = 968;
const MAXIMUM_JOB_BYTES: usize = 349_192;
const APPROVAL_PIN_BYTES: usize = 48;
const DOMAIN: &[u8] = b"aos.sandbox.host.canary-job.v1\0";
const SEGMENT_LIMITS: [usize; 10] = [
    65_536, 65_536, 65_536, 4_096, 65_536,
    4_096, 65_536, 4_096, 4_096, 4_096,
];

#[derive(Debug, thiserror::Error)]
enum JobCaptureFailure {
    #[error("Host canary credential I/O failed")]
    Native(#[from] rustix::io::Errno),
    #[error(transparent)]
    Read(#[from] ExactReadFailure),
    #[error("Host canary original credential changed or is invalid")]
    Original,
    #[error("Host canary allocation could not be reserved")]
    Allocation,
    #[error("Host canary job signature or closed schema is invalid")]
    Job,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OriginalMetadata {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    bytes: u64,
    modified: (u64, u64),
    changed: (u64, u64),
}

/// Retains the fixed independently approved startup job and all capture prefixes.
///
/// Construction performs no I/O and confers no authority. The caller retains
/// this move-only owner even when capture fails or unwinds. A failed instance
/// never retries or discards its original files, buffers or first native cause.
pub struct HostCanaryJobOwnerV1 {
    files: [Option<File>; 3],
    snapshots: [Option<OriginalMetadata>; 3],
    bytes: [Vec<u8>; 2],
    repeated_bytes: [Vec<u8>; 2],
    originals: Option<OriginalHostCanaryJobV1>,
    attempted: bool,
    closed: bool,
    first_failure: Option<JobCaptureFailure>,
}

pub(crate) struct OriginalHostCanaryJobV1 {
    pub(crate) digest: [u8; 32],
    pub(crate) job_id: [u8; 16],
    pub(crate) node_id: [u8; 16],
    pub(crate) boot_id: [u8; 16],
    pub(crate) payload_boot_id: [u8; 16],
    pub(crate) request_ids: [[u8; 16]; 3],
    pub(crate) maximum_response_bytes: [u32; 2],
    pub(crate) nonce: [u8; 32],
    pub(crate) pins: [[u8; 32]; 12],
    pub(crate) guest_public_key: [u8; 32],
    pub(crate) attach_public_key: [u8; 32],
    pub(crate) maximum_charges: [u64; 22],
    pub(crate) not_before: u64,
    pub(crate) deadline: u64,
    pub(crate) approval_generation: u64,
    pub(crate) namespace_generation: u64,
    pub(crate) launch: ValidatedRuntimeTemplateV1,
    pub(crate) stop: ValidatedRuntimeTemplateV1,
    segments: [Range<usize>; 10],
}

#[derive(Clone, Copy)]
pub(crate) enum CanaryAction {
    Launch,
    Stop,
}

impl Default for HostCanaryJobOwnerV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl HostCanaryJobOwnerV1 {
    /// Creates empty resident slots before any protected file is opened.
    #[must_use]
    pub fn new() -> Self {
        Self {
            files: std::array::from_fn(|_| None),
            snapshots: [None; 3],
            bytes: std::array::from_fn(|_| Vec::new()),
            repeated_bytes: std::array::from_fn(|_| Vec::new()),
            originals: None,
            attempted: false,
            closed: false,
            first_failure: None,
        }
    }

    /// Captures the two fixed independent credentials exactly once.
    ///
    /// Files enter resident slots before metadata, allocation, reads or schema
    /// checks. An unwind leaves the prearmed owner closed. This is job DATA
    /// admission, not Host effect admission or backend readiness.
    ///
    /// # Errors
    ///
    /// Refuses repeated capture, unsafe files, changed names, oversized input,
    /// allocation or native read failure, invalid signatures and mismatched
    /// boot or template identities. The first actual cause remains borrowed
    /// through [`Self::failure_cause`].
    pub fn capture_original(&mut self) -> Result<()> {
        if self.attempted {
            return Err(job_refusal());
        }
        self.attempted = true;
        self.closed = true;

        match self.capture_inner() {
            Ok(()) => {
                self.closed = false;
                Ok(())
            }
            Err(error) => {
                self.first_failure = Some(error);
                Err(job_refusal())
            }
        }
    }

    /// Borrows the original failure without moving or stringifying its cause.
    #[must_use]
    pub fn failure_cause(&self) -> Option<&dyn std::error::Error> {
        self.first_failure.as_ref().map(|error| error as &dyn std::error::Error)
    }

    fn capture_inner(&mut self) -> std::result::Result<(), JobCaptureFailure> {
        let directory = rustix::fs::open(
            DIRECTORY,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        self.files[0] = Some(File::from(directory));
        let original = metadata(self.file(0)?)?;
        if FileType::from_raw_mode(original.mode) != FileType::Directory
            || original.uid != 0 || original.mode & 0o022 != 0
        {
            return Err(JobCaptureFailure::Original);
        }
        self.snapshots[0] = Some(original);

        for (index, name) in NAMES.iter().enumerate() {
            let descriptor = open_nofollow_child(self.file(0)?, name)?;
            self.files[index + 1] = Some(File::from(descriptor));
            let original = metadata(self.file(index + 1)?)?;
            let length = usize::try_from(original.bytes)
                .map_err(|_| JobCaptureFailure::Original)?;
            let valid_length = if index == 0 {
                length == APPROVAL_PIN_BYTES
            } else {
                (HEADER_BYTES + 64..=MAXIMUM_JOB_BYTES).contains(&length)
            };
            if FileType::from_raw_mode(original.mode) != FileType::RegularFile
                || original.uid != 0 || original.links != 1
                || original.mode & 0o7777 != 0o400 || !valid_length
            {
                return Err(JobCaptureFailure::Original);
            }
            self.snapshots[index + 1] = Some(original);
            self.bytes[index].try_reserve_exact(length)
                .map_err(|_| JobCaptureFailure::Allocation)?;
            self.bytes[index].resize(length, 0);
            self.repeated_bytes[index].try_reserve_exact(length)
                .map_err(|_| JobCaptureFailure::Allocation)?;
            self.repeated_bytes[index].resize(length, 0);

            let file = self.files[index + 1].as_ref()
                .ok_or(JobCaptureFailure::Original)?;
            read_exact_positioned_retaining_cause(file, &mut self.bytes[index])?;
            self.require_original_files()?;
        }

        self.originals = Some(decode_job(&self.bytes[1], &self.bytes[0])?);
        let current_boot = KernelBootId::current()
            .map_err(|_| JobCaptureFailure::Original)?;
        if self.originals.as_ref().is_none_or(|job| job.boot_id != current_boot.into_bytes()) {
            return Err(JobCaptureFailure::Original);
        }
        self.require_original_files()
    }

    fn file(&self, slot: usize) -> std::result::Result<&File, JobCaptureFailure> {
        self.files[slot].as_ref().ok_or(JobCaptureFailure::Original)
    }

    fn require_original_files(&self) -> std::result::Result<(), JobCaptureFailure> {
        for slot in 0..3 {
            let Some(expected) = self.snapshots[slot] else { continue };
            if metadata(self.file(slot)?)? != expected {
                return Err(JobCaptureFailure::Original);
            }
            let named = if slot == 0 {
                rustix::fs::statat(rustix::fs::CWD, DIRECTORY, AtFlags::SYMLINK_NOFOLLOW)?
            } else {
                rustix::fs::statat(self.file(0)?, NAMES[slot - 1], AtFlags::SYMLINK_NOFOLLOW)?
            };
            if named.st_dev != expected.device || named.st_ino != expected.inode {
                return Err(JobCaptureFailure::Original);
            }
        }
        Ok(())
    }

    pub(crate) fn recheck(&mut self) -> Result<&OriginalHostCanaryJobV1> {
        if self.closed || self.originals.is_none() {
            return Err(job_refusal());
        }
        self.closed = true;
        let result = self.recheck_inner();
        if let Err(error) = result {
            self.first_failure = Some(error);
            return Err(job_refusal());
        }
        self.closed = false;
        self.originals.as_ref().ok_or_else(job_refusal)
    }

    fn recheck_inner(&mut self) -> std::result::Result<(), JobCaptureFailure> {
        self.require_original_files()?;
        for index in 0..2 {
            let file = self.files[index + 1].as_ref()
                .ok_or(JobCaptureFailure::Original)?;
            read_exact_positioned_retaining_cause(file, &mut self.repeated_bytes[index])?;
            if self.repeated_bytes[index] != self.bytes[index] {
                return Err(JobCaptureFailure::Original);
            }
        }
        self.require_original_files()
    }

    pub(crate) fn originals(&self) -> Result<&OriginalHostCanaryJobV1> {
        if self.closed { return Err(job_refusal()); }
        self.originals.as_ref().ok_or_else(job_refusal)
    }

    pub(crate) fn segment(&self, index: usize) -> Result<&[u8]> {
        let job = self.originals()?;
        self.bytes[1].get(job.segments[index].clone()).ok_or_else(job_refusal)
    }

    pub(crate) fn original_retained_charge(&self) -> Result<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension, ResourceVector};

        self.originals()?;
        self.require_original_files().map_err(|_| job_refusal())?;
        let pinned = self.snapshots.iter().skip(1).flatten().try_fold(0_u64, |total, snapshot| {
            total.checked_add(snapshot.bytes).ok_or(HostError::ResourceExhausted)
        })?;
        Ok(ResourceVector::ZERO
            .with(ResourceDimension::PinnedBytes, pinned)
            .with(ResourceDimension::MetadataEntries, 3))
    }

    pub(crate) fn authorization(&self, stop: bool) -> Result<ValidatedUntrustedAuthorizationArtifacts> {
        let plan_index = if stop { 6 } else { 2 };
        // This is the existing structural artifact codec, not a fabricated
        // authenticated session or peer. The real Host authority verifies it.
        let packet = encode_authorized_request_envelope(
            ProtocolId::HostBroker,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            self.segment(usize::from(stop))?,
            &[],
            AuthorizationArtifactBytes {
                broker_plan: self.segment(plan_index)?,
                broker_plan_signature: self.segment(plan_index + 1)?,
                ownership_lease: self.segment(8)?,
                ownership_lease_signature: self.segment(9)?,
            },
        )?;
        decode_request_envelope(&packet, ProtocolId::HostBroker, 0)?
            .authorization().cloned().ok_or_else(job_refusal)
    }

    pub(crate) fn require_key_separation(&self, authority: &HostAuthorityV1) -> Result<()> {
        let public_digest: [u8; 32] = Sha256::digest(&self.bytes[0][16..]).into();
        let protected = authority.revalidated_guardian_credentials()
            .map_err(|error| HostError::State(error.to_string()))?
            .ok_or_else(job_refusal)?;
        if protected.iter().any(|(_, _, snapshot)| snapshot.sha256() == public_digest) {
            return Err(job_refusal());
        }
        let job = self.originals()?;
        if self.bytes[0][16..] == job.guest_public_key
            || self.bytes[0][16..] == job.attach_public_key
        {
            return Err(job_refusal());
        }
        Ok(())
    }
}

fn metadata(file: &File) -> std::result::Result<OriginalMetadata, JobCaptureFailure> {
    let stat = rustix::fs::fstat(file.as_fd())?;
    Ok(OriginalMetadata {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        uid: stat.st_uid,
        gid: stat.st_gid,
        links: u64::from(stat.st_nlink),
        bytes: u64::try_from(stat.st_size).map_err(|_| JobCaptureFailure::Original)?,
        modified: (stat.st_mtime as u64, stat.st_mtime_nsec as u64),
        changed: (stat.st_ctime as u64, stat.st_ctime_nsec as u64),
    })
}

fn decode_job(bytes: &[u8], approval: &[u8]) -> std::result::Result<OriginalHostCanaryJobV1, JobCaptureFailure> {
    if bytes.len() < HEADER_BYTES + 64 || bytes.len() > MAXIMUM_JOB_BYTES
        || approval.len() != APPROVAL_PIN_BYTES || &bytes[..8] != b"AOSHCJ01"
        || field::<2>(bytes, 8)? != 1_u16.to_be_bytes()
        || field::<2>(bytes, 10)? != [0; 2]
        || u32::from_be_bytes(field(bytes, 12)?) != HEADER_BYTES as u32
        || u32::from_be_bytes(field(bytes, 16)?) as usize != bytes.len()
        || field::<4>(bytes, 956)? != [0; 4]
        || bytes[892..908] != approval[..16] || approval[..16] == [0; 16]
    {
        return Err(JobCaptureFailure::Job);
    }
    let signed_end = bytes.len() - 64;
    let key = VerifyingKey::from_bytes(&field(approval, 16)?)
        .map_err(|_| JobCaptureFailure::Job)?;
    let mut preimage = Vec::new();
    preimage.try_reserve_exact(DOMAIN.len() + signed_end)
        .map_err(|_| JobCaptureFailure::Allocation)?;
    preimage.extend_from_slice(DOMAIN);
    preimage.extend_from_slice(&bytes[..signed_end]);
    key.verify_strict(&preimage, &Signature::from_bytes(&field(bytes, signed_end)?))
        .map_err(|_| JobCaptureFailure::Job)?;

    let mut segments: [Range<usize>; 10] = std::array::from_fn(|_| 0..0);
    let mut position = HEADER_BYTES;
    for index in 0..10 {
        let length = u32::from_be_bytes(field(bytes, 916 + index * 4)?) as usize;
        if length == 0 || length > SEGMENT_LIMITS[index] {
            return Err(JobCaptureFailure::Job);
        }
        let end = position.checked_add(length).ok_or(JobCaptureFailure::Job)?;
        if end > signed_end { return Err(JobCaptureFailure::Job); }
        segments[index] = position..end;
        position = end;
    }
    if position != signed_end { return Err(JobCaptureFailure::Job); }
    let launch = decode_runtime_template_v1(&bytes[segments[0].clone()])
        .map_err(|_| JobCaptureFailure::Job)?;
    let stop = decode_runtime_template_v1(&bytes[segments[1].clone()])
        .map_err(|_| JobCaptureFailure::Job)?;
    let fence = launch.fence();
    if launch.action() != RuntimeAction::RUNTIME_ACTION_LAUNCH
        || stop.action() != RuntimeAction::RUNTIME_ACTION_STOP || stop.fence() != fence
        || *fence.sandbox_id() != field::<16>(bytes, 68)?
        || *fence.incarnation_id() != field::<16>(bytes, 84)?
        || fence.assignment_epoch() != u64::from_be_bytes(field(bytes, 116)?)
        || fence.desired_generation() != u64::from_be_bytes(field(bytes, 124)?)
        || *fence.assignment_digest() != field::<32>(bytes, 132)?
    {
        return Err(JobCaptureFailure::Job);
    }
    let boot_id = field(bytes, 52)?;
    let not_before = u64::from_be_bytes(field(bytes, 164)?);
    let deadline = u64::from_be_bytes(field(bytes, 172)?);
    let approval_generation = u64::from_be_bytes(field(bytes, 180)?);
    let namespace_generation = u64::from_be_bytes(field(bytes, 960)?);
    let request_ids = [field(bytes, 188)?, field(bytes, 204)?, field(bytes, 220)?];
    let mut maximum_response_bytes = [0; 2];
    for index in 0..2 {
        // The sole inert-template validator deliberately does not retain the
        // header. Borrow its already validated exact wire through the same
        // generated protobuf codec; this comparison creates no live request.
        let template = ApplyRuntimeRequest::decode_from_slice(&bytes[segments[index].clone()])
            .map_err(|_| JobCaptureFailure::Job)?;
        let header = template.header.as_option().ok_or(JobCaptureFailure::Job)?;
        if header.request_id.as_slice() != request_ids[index]
            || header.maximum_response_bytes > 4096
        {
            return Err(JobCaptureFailure::Job);
        }
        maximum_response_bytes[index] = header.maximum_response_bytes;
    }
    let pins = std::array::from_fn(|index| {
        let mut pin = [0; 32];
        pin.copy_from_slice(&bytes[268 + index * 32..300 + index * 32]);
        pin
    });
    let maximum_charges = std::array::from_fn(|index| {
        let mut value = [0; 8];
        value.copy_from_slice(&bytes[716 + index * 8..724 + index * 8]);
        u64::from_be_bytes(value)
    });
    if deadline <= not_before
        || approval_generation == 0
        || namespace_generation == 0
        || approval_generation != u64::from_be_bytes(field(bytes, 908)?)
        || request_ids.iter().any(|id| *id == [0; 16])
        || request_ids[0] == request_ids[1] || request_ids[0] == request_ids[2]
        || request_ids[1] == request_ids[2] || pins.iter().any(|pin| *pin == [0; 32])
    {
        return Err(JobCaptureFailure::Job);
    }
    let job_id = field(bytes, 20)?;
    let node_id = field(bytes, 36)?;
    let payload_boot_id = field(bytes, 100)?;
    let nonce = field(bytes, 236)?;
    let guest_public_key = field(bytes, 652)?;
    let attach_public_key = field(bytes, 684)?;
    if job_id == [0; 16] || node_id == [0; 16] || payload_boot_id == [0; 16]
        || nonce == [0; 32] || guest_public_key == [0; 32]
        || attach_public_key == [0; 32] || guest_public_key == attach_public_key
    {
        return Err(JobCaptureFailure::Job);
    }
    Ok(OriginalHostCanaryJobV1 {
        digest: Sha256::digest(bytes).into(),
        job_id, node_id, boot_id, payload_boot_id, request_ids, maximum_response_bytes, nonce, pins,
        guest_public_key, attach_public_key, maximum_charges,
        not_before, deadline, approval_generation, namespace_generation, launch, stop, segments,
    })
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> std::result::Result<[u8; N], JobCaptureFailure> {
    bytes.get(offset..offset + N).and_then(|value| value.try_into().ok())
        .ok_or(JobCaptureFailure::Job)
}

fn job_refusal() -> HostError {
    HostError::State("original independently approved Host canary job is unavailable".to_owned())
}
