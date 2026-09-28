//! Non-detachable Root proofs backed by the same actual authenticated stream.
//!
//! The conditional producer invariant is normal Root's exact immutable code
//! and enforcing policy: no accepted-FD fork/transfer, out-of-role endpoint
//! fd-use/write, task-file theft/ptrace, role escape or SYS_ADMIN nomination.
//! Every received fragment must additionally nominate the exact still-live
//! original daemon TGID. SCM_SECURITY is the socket SID, not the task SID.
//! Endpoint credentials, a Boolean, cached bytes, or a raw floor cannot mint
//! these proofs. The normal Root role and canonical loaded-policy comparison
//! must be genuinely installed; the old init_t endpoint necessarily refuses.

use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::path::Path;
use std::time::{Duration, Instant};

use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};

use crate::hierarchy::genesis_profile::{SourceGenesisErrorV1, take};

use super::super::controller_readback_session::fresh_root_nonce;
use super::super::root_v8_released_proof::POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2;
use super::records::{RootSourceGenesisIntentRecordV1, SourceHierarchyFloorRecordV1};

pub(super) const START_MAGIC: &[u8; 8] = b"AOSSGQ01";
pub(super) const HELLO_MAGIC: &[u8; 8] = b"AOSSGH01";
const ROOT_CONTEXT: &[u8] = b"system_u:system_r:aos_sandbox_policy_authority_t:s0";
const ROOT_CGROUP: &str = "system.slice/aos-sandbox-policy-authorityd.service";
const MAXIMUM_FLIGHT: Duration = Duration::from_secs(60);

/// Borrows one actual Root prepare flight; decoding an intent cannot create it.
pub struct HeldRootSourceGenesisIntentV1<'flight> {
    origin: &'flight OriginalRootGenesisFlightV1,
    record: RootSourceGenesisIntentRecordV1,
    deadline: u64,
    expires: i64,
}

impl HeldRootSourceGenesisIntentV1<'_> {
    /// Borrows the exact Root-owned prepare record from this original flight.
    #[must_use]
    pub const fn record(&self) -> &RootSourceGenesisIntentRecordV1 {
        &self.record
    }

    /// Rechecks the actual Root role, original endpoint, process and held flight.
    ///
    /// # Errors
    /// Rejects lost or changed original peer/cgroup/policy, poisoned transport,
    /// or a different privileged Source UID. This is historical custody only.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.recheck()?;
        if self.record.source_uid() != self.origin.source_uid {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }

    /// Separately checks the unchanged initial paired-clock admission deadline.
    ///
    /// # Errors
    /// Rejects expiry or clock/boot discontinuity before genuinely new Source
    /// mutation. Historical prepared readback/ACK does not grant this condition.
    pub fn recheck_current_admission(&self) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let later = kernel_pair()?;
        self.origin
            .clock
            .validate_later_sample(later)
            .map_err(|_| SourceGenesisErrorV1::AdmissionClosed)?;
        if later.wall_seconds() >= self.expires || later.boottime_nanoseconds() >= self.deadline {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        Ok(())
    }
}

/// Borrows the actual original Root flight through Controller and Source ACK.
pub struct RootSourceGenesisFloorProofV1<'flight> {
    origin: &'flight OriginalRootGenesisFlightV1,
    floor: SourceHierarchyFloorRecordV1,
}

impl RootSourceGenesisFloorProofV1<'_> {
    /// Borrows the exact Root-owned floor, whose raw bytes remain data only.
    #[must_use]
    pub const fn floor(&self) -> &SourceHierarchyFloorRecordV1 {
        &self.floor
    }

    /// Returns the privileged Source UID bound by the actual Root flight hello.
    ///
    /// This comes from normal Root's protected service configuration, never
    /// decoded floor data, Source journal ownership, or a caller assertion.
    #[must_use]
    pub const fn source_uid(&self) -> u32 {
        self.origin.source_uid
    }

    /// Rechecks actual original live Root custody without granting fresh genesis.
    ///
    /// # Errors
    /// Rejects changed endpoint/process/cgroup, unenforcing or changed exact
    /// deployed policy, failed subject receive, or a completed/lost flight.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.origin.recheck()
    }
}

// Private to the same-flight coordinator. There is no adoption constructor
// accepting caller-supplied peers, subjects, floor bytes, or ready flags.
pub(super) struct OriginalRootGenesisFlightV1 {
    stream: RefCell<RetainedUnixStream>,
    cgroup: RetainedCgroupAnchor,
    policy: VerifiedLiveSelinuxPolicy,
    policy_path: String,
    clock: RawPairedClockSample,
    started: Instant,
    poisoned: Cell<bool>,
    nonce: [u8; 16],
    source_uid: u32,
}

impl OriginalRootGenesisFlightV1 {
    pub(super) fn connect_configured(policy_path: &str) -> Result<Self, SourceGenesisErrorV1> {
        let policy = VerifiedLiveSelinuxPolicy::verify(policy_path)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let clock = kernel_pair()?;
        let started = Instant::now();
        let mut stream =
            RetainedUnixStream::connect(Path::new(POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2))?;
        stream.enable_subject_reporting()?;
        let cgroups = CgroupV2Root::from_owned(File::open("/sys/fs/cgroup")?.into())?;
        let cgroup = cgroups.resolve(Path::new(ROOT_CGROUP))?;
        let client_nonce = fresh_root_nonce()?;
        let mut request = [0; 32];
        request[..8].copy_from_slice(START_MAGIC);
        request[8..24].copy_from_slice(&client_nonce);
        let origin = Self {
            stream: RefCell::new(stream),
            cgroup,
            policy,
            policy_path: policy_path.to_owned(),
            clock,
            started,
            poisoned: Cell::new(false),
            nonce: [0; 16],
            source_uid: 0,
        };
        origin.recheck()?;
        origin.write(&request)?;
        let hello = origin.receive_exact(56)?;
        if hello.get(..8) != Some(HELLO_MAGIC.as_slice())
            || hello[8..16] != [0, 1, 0, 0, 0, 0, 0, 0]
            || take::<16>(&hello, 16)? != client_nonce
            || take::<16>(&hello, 32)? == [0; 16]
            || u32::from_be_bytes(take(&hello, 48)?) == 0
            || u32::from_be_bytes(take(&hello, 52)?) != rustix::process::getuid().as_raw()
        {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        Ok(Self {
            nonce: take(&hello, 32)?,
            source_uid: u32::from_be_bytes(take(&hello, 48)?),
            ..origin
        })
    }

    fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        if self.poisoned.get() || self.started.elapsed() >= MAXIMUM_FLIGHT {
            return Err(SourceGenesisErrorV1::Stale);
        }
        self.policy
            .revalidate(&self.policy_path)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let stream = self
            .stream
            .try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        stream.revalidate_original()?;
        let peer = stream.peer();
        let credentials = peer.credentials();
        let info = self.cgroup.verify_exact_membership(peer.pidfd())?;
        if credentials.uid() != 0
            || credentials.gid() != 0
            || info.thread_group_id() != credentials.pid().get()
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }

    pub(super) fn write(&self, bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let stream = self
            .stream
            .try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let duplicate = stream.duplicate()?;
        let descriptor =
            rustix::io::fcntl_dupfd_cloexec(duplicate.as_fd(), 0).map_err(std::io::Error::from)?;
        File::from(descriptor).write_all(bytes)?;
        drop(stream);
        self.recheck()
    }

    pub(super) fn receive_exact(&self, length: usize) -> Result<Vec<u8>, SourceGenesisErrorV1> {
        if length == 0 || length > 4096 {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let result = self.receive_fragments(length);
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    fn receive_fragments(&self, length: usize) -> Result<Vec<u8>, SourceGenesisErrorV1> {
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            self.recheck()?;
            let chunk = self
                .stream
                .try_borrow_mut()
                .map_err(|_| SourceGenesisErrorV1::Stale)?
                .try_receive_subject_chunk(length - bytes.len());
            match chunk {
                Ok(chunk) => {
                    self.require_root_chunk(&chunk)?;
                    bytes.extend_from_slice(chunk.payload());
                }
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    let stream = self
                        .stream
                        .try_borrow()
                        .map_err(|_| SourceGenesisErrorV1::Stale)?;
                    let mut fds = [rustix::event::PollFd::new(
                        stream.as_fd(),
                        rustix::event::PollFlags::IN,
                    )];
                    rustix::event::poll(
                        &mut fds,
                        Some(&rustix::event::Timespec {
                            tv_sec: 0,
                            tv_nsec: 100_000_000,
                        }),
                    )
                    .map_err(std::io::Error::from)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.recheck()?;
        Ok(bytes)
    }

    fn require_root_chunk(
        &self,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let stream = self
            .stream
            .try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let expected = stream.peer().credentials();
        let subject = chunk.subject();
        let actual = subject.credentials();
        let info = self.cgroup.verify_exact_membership(subject.pidfd())?;
        if chunk.socket_context() != ROOT_CONTEXT
            || actual.pid() != expected.pid()
            || actual.uid() != expected.uid()
            || actual.gid() != expected.gid()
            || info.thread_group_id() != expected.pid().get()
            || !subject.is_alive()?
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }
}

fn kernel_pair() -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
    let before = KernelBootId::current()?.into_bytes();
    let boot = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let wall = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    let after = KernelBootId::current()?.into_bytes();
    if before != after {
        return Err(SourceGenesisErrorV1::Stale);
    }
    let boot = u64::try_from(boot.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(boot.tv_nsec)
                .ok()
                .and_then(|fraction| seconds.checked_add(fraction))
        })
        .ok_or(SourceGenesisErrorV1::Stale)?;
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
            .map_err(|_| SourceGenesisErrorV1::Stale)?,
        before,
        wall,
        boot,
    )
    .map_err(|_| SourceGenesisErrorV1::Stale)
}
