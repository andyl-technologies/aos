//! Bounded original worker cutoff DATA and one nonrenewable kernel timer.
//!
//! Decoding grants no authority. Only the containing actual Storage owner can
//! produce a dispatch loan; workers additionally authenticate the original
//! connection, both records, complete selection and a direct kernel pair.
//!
//! ```text
//! AOSWCO03 | v3:u16 | zero[6] | boot[16] | first-wall:i64 |
//! first-BOOTTIME:u64 | cutoff:u64 | signed-N-length:u32 | AOSZNQ02
//! intro[92] = purpose[8] | version:u16 | zero[6] | same clock fields |
//!             body-length:u32 | complete-body-request-digest[32]
//! body = purpose[8] | version:u16 | zero[6] | cutoff-length:u32 |
//!        cutoff | selection-length:u32 | exact legacy selection
//! AOSHSM04/v4 and AOSZHO02/v2 carry the sole existing complete result fields.
//! ACK = AOSWAK03 | v3:u16 | complete-body-request-digest[32]
//! ```

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aos_sandbox_core::{ObjectDigest, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_source_provider_protocol::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V3, SignedStorageNativeAcquireRequestV2,
    StorageNativeAcquireErrorV2, decode_acquire_request,
};
use rustix::time::{
    Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, Timespec,
    timerfd_create, timerfd_settime,
};
use sha2::{Digest as _, Sha256};

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::seqpacket::{ReceivedRecord, SeqpacketSocket};

use crate::runtime::{
    KERNEL_CLOCK_PROVENANCE, StorageRuntimeError, original_fail_stop_deadline,
    trusted_paired_clock_sample, validate_original_clock,
};

pub(crate) const MAXIMUM_ORIGINAL_BODY_BYTES: usize = 128 * 1024;
pub(crate) const INTRODUCTION_BYTES: usize = 92;
const CUTOFF_MAGIC: &[u8; 8] = b"AOSWCO03";
const CUTOFF_PREFIX_BYTES: usize = 60;
const BODY_OVERHEAD_BYTES: usize = 24;
const ACKNOWLEDGEMENT_MAGIC: &[u8; 8] = b"AOSWAK03";

#[derive(Debug, thiserror::Error)]
pub(crate) enum OriginalWorkerCutoffErrorV3 {
    #[error("original worker envelope is noncanonical")]
    Encoding,
    #[error("original worker envelope exceeds its fixed bound")]
    Bound,
    #[error("original worker envelope allocation failed")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error(transparent)]
    Native(#[from] StorageNativeAcquireErrorV2),
    #[error(transparent)]
    Clock(#[from] StorageRuntimeError),
    #[error("original worker kernel timer failed: {0}")]
    Timer(#[from] rustix::io::Errno),
    #[error(transparent)]
    Worker(#[from] Box<super::ZfsWorkerError>),
}

fn worker_error(cause: super::ZfsWorkerError) -> OriginalWorkerCutoffErrorV3 {
    OriginalWorkerCutoffErrorV3::Worker(Box::new(cause))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OriginalWorkerPurposeV3 {
    Reader,
    Observer,
}

impl OriginalWorkerPurposeV3 {
    const fn intro(self) -> (&'static [u8; 8], u16) {
        match self {
            Self::Reader => (b"AOSHSR03", 3),
            Self::Observer => (b"AOSZHS02", 2),
        }
    }

    const fn body(self) -> (&'static [u8; 8], u16) {
        match self {
            Self::Reader => (b"AOSHSB03", 3),
            Self::Observer => (b"AOSZHB02", 2),
        }
    }

    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Reader => b"aos.sandbox.storage.original-held-reader-request.v3\0",
            Self::Observer => b"aos.sandbox.storage.original-held-observer-request.v2\0",
        }
    }

    pub(crate) fn selects_introduction(self, bytes: &[u8]) -> bool {
        bytes.get(..8) == Some(self.intro().0.as_slice())
    }

    pub(crate) fn digest(self, body: &[u8]) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(self.domain())
                .chain_update(body)
                .finalize()
                .into(),
        )
    }
}

/// Owned decoded DATA; neither signatures nor the remote writer are admitted.
pub(crate) struct DecodedOriginalWorkerCutoffV3 {
    pub(crate) request: SignedStorageNativeAcquireRequestV2,
    pub(crate) first: RawPairedClockSample,
    pub(crate) cutoff: u64,
}

impl DecodedOriginalWorkerCutoffV3 {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, OriginalWorkerCutoffErrorV3> {
        if bytes.len() > MAXIMUM_ORIGINAL_BODY_BYTES {
            return Err(OriginalWorkerCutoffErrorV3::Bound);
        }
        require_header(bytes, CUTOFF_MAGIC, 3)?;
        let first = decode_pair(bytes)?;
        let cutoff = u64::from_be_bytes(array(bytes, 48)?);
        let length = usize::try_from(u32::from_be_bytes(array(bytes, 56)?))
            .map_err(|_| OriginalWorkerCutoffErrorV3::Bound)?;
        if CUTOFF_PREFIX_BYTES.checked_add(length) != Some(bytes.len()) {
            return Err(OriginalWorkerCutoffErrorV3::Encoding);
        }
        let request = SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&bytes[60..])?;
        let root = decode_acquire_request(request.request().signed_root_request().subject())
            .map_err(|_| OriginalWorkerCutoffErrorV3::Encoding)?;
        if root.acquisition_version() != ACQUIRE_SOURCE_REQUEST_VERSION_V3
            || root.kernel_coupled()
            || cutoff <= first.boottime_nanoseconds()
            || cutoff > original_fail_stop_deadline(&request, first)?
        {
            return Err(OriginalWorkerCutoffErrorV3::Encoding);
        }
        Ok(Self {
            request,
            first,
            cutoff,
        })
    }

    pub(crate) fn check_kernel_pair(
        &self,
    ) -> Result<RawPairedClockSample, OriginalWorkerCutoffErrorV3> {
        let later = trusted_paired_clock_sample()?;
        validate_original_clock(&self.request, self.first, later, self.cutoff)?;
        Ok(later)
    }
}

pub(crate) fn encode_cutoff(
    signed_bytes: &[u8],
    first: RawPairedClockSample,
    cutoff: u64,
) -> Result<Vec<u8>, OriginalWorkerCutoffErrorV3> {
    let length = CUTOFF_PREFIX_BYTES
        .checked_add(signed_bytes.len())
        .filter(|length| *length <= MAXIMUM_ORIGINAL_BODY_BYTES)
        .ok_or(OriginalWorkerCutoffErrorV3::Bound)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.extend_from_slice(CUTOFF_MAGIC);
    bytes.extend_from_slice(&3_u16.to_be_bytes());
    bytes.extend_from_slice(&[0; 6]);
    encode_pair(&mut bytes, first, cutoff);
    bytes.extend_from_slice(
        &u32::try_from(signed_bytes.len())
            .map_err(|_| OriginalWorkerCutoffErrorV3::Bound)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(signed_bytes);
    Ok(bytes)
}

pub(crate) fn encode_body(
    purpose: OriginalWorkerPurposeV3,
    cutoff: &[u8],
    selected: &[u8],
) -> Result<Vec<u8>, OriginalWorkerCutoffErrorV3> {
    let length = BODY_OVERHEAD_BYTES
        .checked_add(cutoff.len())
        .and_then(|length| length.checked_add(selected.len()))
        .filter(|length| *length <= MAXIMUM_ORIGINAL_BODY_BYTES)
        .ok_or(OriginalWorkerCutoffErrorV3::Bound)?;
    let (magic, version) = purpose.body();
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(
        &u32::try_from(cutoff.len())
            .map_err(|_| OriginalWorkerCutoffErrorV3::Bound)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(cutoff);
    bytes.extend_from_slice(
        &u32::try_from(selected.len())
            .map_err(|_| OriginalWorkerCutoffErrorV3::Bound)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(selected);
    Ok(bytes)
}

pub(crate) fn decode_body(
    purpose: OriginalWorkerPurposeV3,
    bytes: &[u8],
) -> Result<(DecodedOriginalWorkerCutoffV3, &[u8]), OriginalWorkerCutoffErrorV3> {
    if bytes.len() > MAXIMUM_ORIGINAL_BODY_BYTES {
        return Err(OriginalWorkerCutoffErrorV3::Bound);
    }
    let (magic, version) = purpose.body();
    require_header(bytes, magic, version)?;
    let cutoff_length = usize::try_from(u32::from_be_bytes(array(bytes, 16)?))
        .map_err(|_| OriginalWorkerCutoffErrorV3::Bound)?;
    let cutoff_end = 20_usize
        .checked_add(cutoff_length)
        .ok_or(OriginalWorkerCutoffErrorV3::Bound)?;
    let cutoff_bytes = bytes
        .get(20..cutoff_end)
        .ok_or(OriginalWorkerCutoffErrorV3::Encoding)?;
    let selected_length = usize::try_from(u32::from_be_bytes(array(bytes, cutoff_end)?))
        .map_err(|_| OriginalWorkerCutoffErrorV3::Bound)?;
    let selected_start = cutoff_end
        .checked_add(4)
        .ok_or(OriginalWorkerCutoffErrorV3::Bound)?;
    if selected_start.checked_add(selected_length) != Some(bytes.len()) || selected_length == 0 {
        return Err(OriginalWorkerCutoffErrorV3::Encoding);
    }
    Ok((
        DecodedOriginalWorkerCutoffV3::decode(cutoff_bytes)?,
        &bytes[selected_start..],
    ))
}

#[derive(Clone, Copy)]
pub(crate) struct OriginalWorkerIntroductionV3 {
    pub(crate) first: RawPairedClockSample,
    pub(crate) cutoff: u64,
    pub(crate) body_length: usize,
    pub(crate) digest: ObjectDigest,
}

impl OriginalWorkerIntroductionV3 {
    /// Bounds only protocol progress before the complete signed body arrives.
    /// This DATA check cannot authorize a mount or a process launch.
    pub(super) fn remaining_kernel_time(
        &self,
    ) -> Result<std::time::Duration, OriginalWorkerCutoffErrorV3> {
        let later = trusted_paired_clock_sample()?;
        self.first.validate_later_sample(later)
            .map_err(|_| OriginalWorkerCutoffErrorV3::Encoding)?;
        let remaining = self
            .cutoff
            .checked_sub(later.boottime_nanoseconds())
            .filter(|remaining| *remaining != 0)
            .ok_or(OriginalWorkerCutoffErrorV3::Encoding)?;
        Ok(std::time::Duration::from_nanos(remaining))
    }

    pub(crate) fn decode(
        purpose: OriginalWorkerPurposeV3,
        bytes: &[u8],
    ) -> Result<Self, OriginalWorkerCutoffErrorV3> {
        if bytes.len() != INTRODUCTION_BYTES {
            return Err(OriginalWorkerCutoffErrorV3::Encoding);
        }
        let (magic, version) = purpose.intro();
        require_header(bytes, magic, version)?;
        let first = decode_pair(bytes)?;
        let cutoff = u64::from_be_bytes(array(bytes, 48)?);
        let body_length = usize::try_from(u32::from_be_bytes(array(bytes, 56)?))
            .map_err(|_| OriginalWorkerCutoffErrorV3::Bound)?;
        let digest = ObjectDigest::from_bytes(array(bytes, 60)?);
        if !(BODY_OVERHEAD_BYTES + CUTOFF_PREFIX_BYTES..=MAXIMUM_ORIGINAL_BODY_BYTES)
            .contains(&body_length)
            || cutoff <= first.boottime_nanoseconds()
            || digest.as_bytes() == &[0; 32]
        {
            return Err(OriginalWorkerCutoffErrorV3::Encoding);
        }
        Ok(Self {
            first,
            cutoff,
            body_length,
            digest,
        })
    }

    pub(crate) fn encode(
        self,
        purpose: OriginalWorkerPurposeV3,
    ) -> Result<[u8; INTRODUCTION_BYTES], OriginalWorkerCutoffErrorV3> {
        let (magic, version) = purpose.intro();
        let mut bytes = [0; INTRODUCTION_BYTES];
        bytes[..8].copy_from_slice(magic);
        bytes[8..10].copy_from_slice(&version.to_be_bytes());
        bytes[16..32].copy_from_slice(&self.first.host_boot_id());
        bytes[32..40].copy_from_slice(&self.first.wall_seconds().to_be_bytes());
        bytes[40..48].copy_from_slice(&self.first.boottime_nanoseconds().to_be_bytes());
        bytes[48..56].copy_from_slice(&self.cutoff.to_be_bytes());
        bytes[56..60].copy_from_slice(
            &u32::try_from(self.body_length)
                .map_err(|_| OriginalWorkerCutoffErrorV3::Bound)?
                .to_be_bytes(),
        );
        bytes[60..92].copy_from_slice(self.digest.as_bytes());
        Ok(bytes)
    }

    pub(crate) fn require_body(
        self,
        purpose: OriginalWorkerPurposeV3,
        bytes: &[u8],
        decoded: &DecodedOriginalWorkerCutoffV3,
    ) -> Result<(), OriginalWorkerCutoffErrorV3> {
        if bytes.len() != self.body_length
            || purpose.digest(bytes) != self.digest
            || self.first != decoded.first
            || self.cutoff != decoded.cutoff
        {
            return Err(OriginalWorkerCutoffErrorV3::Encoding);
        }
        Ok(())
    }
}

/// Exclusive temporary view of the actual socket and both retained records.
///
/// Only the fixed worker branch can construct it. Canonical bytes alone are
/// insufficient: construction and every check require the original cap-empty
/// Storage peer's live fixed cgroup, both actual record subjects, complete
/// selected request and a fresh direct kernel pair. It attests neither remote
/// executable bytes nor independent Provider/Root signatures; those belong to
/// the genuine parent owner and its exclusive original channel.
pub(crate) struct WorkerOriginalCheckedViewV3<'a> {
    socket: &'a mut SeqpacketSocket,
    introduction_record: &'a ReceivedRecord,
    body_record: &'a ReceivedRecord,
    storaged: &'a RetainedCgroupAnchor,
    decoded: DecodedOriginalWorkerCutoffV3,
    digest: ObjectDigest,
    open: bool,
    first_failure: Option<OriginalWorkerCutoffErrorV3>,
}

/// The sole legacy selector decoder's already checked DATA, not effect authority.
pub(super) enum OriginalWorkerSelectionV3<'a> {
    Reader {
        name: &'a str,
        pool_guid: u64,
        snapshot_guid: u64,
    },
    Observer(super::held_snapshot::HeldSnapshotWorkerRequestV1),
}

impl<'a> WorkerOriginalCheckedViewV3<'a> {
    pub(super) fn admit(
        purpose: OriginalWorkerPurposeV3,
        socket: &'a mut SeqpacketSocket,
        introduction_record: &'a ReceivedRecord,
        body_record: &'a ReceivedRecord,
        storaged: &'a RetainedCgroupAnchor,
    ) -> Result<(Self, OriginalWorkerSelectionV3<'a>), OriginalWorkerCutoffErrorV3> {
        let introduction =
            OriginalWorkerIntroductionV3::decode(purpose, introduction_record.payload())?;
        let (decoded, selected) = decode_body(purpose, body_record.payload())?;
        introduction.require_body(purpose, body_record.payload(), &decoded)?;
        let selection = match purpose {
            OriginalWorkerPurposeV3::Reader => {
                super::held_snapshot_reader::original::validate_selected(&decoded, selected)
                    .map(|(name, pool_guid, snapshot_guid)| OriginalWorkerSelectionV3::Reader {
                        name,
                        pool_guid,
                        snapshot_guid,
                    })
            }
            OriginalWorkerPurposeV3::Observer => {
                super::held_snapshot::validate_original_selected(&decoded, selected)
                    .map(OriginalWorkerSelectionV3::Observer)
            }
        }
        .map_err(worker_error)?;
        let mut view = Self {
            socket,
            introduction_record,
            body_record,
            storaged,
            decoded,
            digest: introduction.digest,
            open: true,
            first_failure: None,
        };
        if let Err(cause) = view.check() {
            return Err(view.take_first_failure().unwrap_or(cause));
        }
        Ok((view, selection))
    }

    pub(crate) fn check(&mut self) -> Result<RawPairedClockSample, OriginalWorkerCutoffErrorV3> {
        if !self.open {
            return Err(OriginalWorkerCutoffErrorV3::Encoding);
        }
        self.open = false;
        let checked_peer = (|| {
            super::verify_storaged_peer(self.socket.peer(), self.storaged)?;
            super::verify_same_subject(self.socket.peer(), self.introduction_record.subject())?;
            super::verify_same_subject(self.socket.peer(), self.body_record.subject())?;
            super::verify_same_live_subject(
                self.introduction_record.subject(),
                self.body_record.subject(),
            )?;
            self.storaged
                .verify_exact_membership(self.introduction_record.subject().pidfd())?;
            self.storaged
                .verify_exact_membership(self.body_record.subject().pidfd())?;
            let info = self.socket.peer().pidfd().info()?;
            let credentials = info.credentials().ok_or(super::ZfsWorkerError::PeerMismatch)?;
            if info.parent_pid() != 1
                || [
                    credentials.real_user_id(),
                    credentials.effective_user_id(),
                    credentials.saved_user_id(),
                    credentials.filesystem_user_id(),
                    credentials.real_group_id(),
                    credentials.effective_group_id(),
                    credentials.saved_group_id(),
                    credentials.filesystem_group_id(),
                ]
                .iter()
                .any(|identity| *identity != 0)
            {
                return Err(super::ZfsWorkerError::PeerMismatch);
            }
            Ok::<_, super::ZfsWorkerError>(())
        })();
        let result = checked_peer
            .map_err(worker_error)
            .and_then(|()| self.decoded.check_kernel_pair());
        match result {
            Ok(later) => {
                self.open = true;
                Ok(later)
            }
            Err(cause) => Err(cause),
        }
    }

    /// Retains a typed refusal across the unchanged public tree error shape.
    pub(crate) fn check_for_tree(&mut self) -> Result<(), OriginalWorkerCutoffErrorV3> {
        match self.check() {
            Ok(_) => Ok(()),
            Err(cause) => {
                if self.first_failure.is_none() {
                    self.first_failure = Some(cause);
                }
                Err(OriginalWorkerCutoffErrorV3::Encoding)
            }
        }
    }

    pub(super) const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub(super) const fn cutoff(&self) -> u64 {
        self.decoded.cutoff
    }

    pub(super) fn decoded(&self) -> &DecodedOriginalWorkerCutoffV3 {
        &self.decoded
    }

    pub(super) fn take_first_failure(&mut self) -> Option<OriginalWorkerCutoffErrorV3> {
        self.first_failure.take()
    }

    /// Ends the exclusive observation without exporting any checked authority.
    pub(super) fn into_data(self) -> DecodedOriginalWorkerCutoffV3 {
        self.decoded
    }

    /// Keeps the exclusive socket loan through transport and both bookends.
    pub(super) fn send_once(
        &mut self,
        bytes: &[u8],
        mount: Option<BorrowedFd<'_>>,
    ) -> Result<(), OriginalWorkerCutoffErrorV3> {
        self.check()?;
        let sent = match mount {
            Some(mount) => self.socket.send_with_descriptors(bytes, &[mount]),
            None => self.socket.send(bytes),
        };
        // A concrete send failure precedes a failed postcheck.
        let checked = self.check();
        sent
            .map_err(super::ZfsWorkerError::from)
            .map_err(worker_error)?;
        checked?;
        Ok(())
    }

    pub(super) fn receive_once(
        &mut self,
        slot: &mut super::RetainedWorkerRecordSlot,
        maximum: usize,
    ) -> Result<(), OriginalWorkerCutoffErrorV3> {
        self.check()?;
        slot.capture_once(self.socket, maximum)
            .map_err(worker_error)?;
        self.check()?;
        Ok(())
    }

    pub(super) fn wait(
        &mut self,
        events: rustix::event::PollFlags,
    ) -> Result<(), OriginalWorkerCutoffErrorV3> {
        let later = self.check()?;
        let remaining = self
            .decoded
            .cutoff
            .checked_sub(later.boottime_nanoseconds())
            .filter(|remaining| *remaining != 0)
            .ok_or(OriginalWorkerCutoffErrorV3::Encoding)?;
        let timeout = rustix::event::Timespec::try_from(std::time::Duration::from_nanos(remaining))
            .map_err(|_| OriginalWorkerCutoffErrorV3::Bound)?;
        let descriptor = self
            .socket
            .as_fd()
            .map_err(super::ZfsWorkerError::from)
            .map_err(worker_error)?;
        let mut descriptors = [rustix::event::PollFd::new(&descriptor, events)];
        let polled = rustix::event::poll(&mut descriptors, Some(&timeout));
        let checked = self.check();
        if polled? == 0 {
            return Err(OriginalWorkerCutoffErrorV3::Encoding);
        }
        checked?;
        Ok(())
    }

    pub(super) fn require_acknowledgement(
        &mut self,
        record: &ReceivedRecord,
    ) -> Result<(), OriginalWorkerCutoffErrorV3> {
        self.check()?;
        super::verify_same_subject(self.socket.peer(), record.subject())
            .and_then(|()| {
                super::verify_same_live_subject(self.body_record.subject(), record.subject())
            })
            .map_err(worker_error)?;
        self.storaged
            .verify_exact_membership(record.subject().pidfd())
            .map_err(super::ZfsWorkerError::from)
            .map_err(worker_error)?;
        decode_acknowledgement(record.payload(), self.digest)?;
        self.check()?;
        Ok(())
    }
}

pub(crate) fn encode_acknowledgement(digest: ObjectDigest) -> [u8; 42] {
    let mut bytes = [0; 42];
    bytes[..8].copy_from_slice(ACKNOWLEDGEMENT_MAGIC);
    bytes[8..10].copy_from_slice(&3_u16.to_be_bytes());
    bytes[10..].copy_from_slice(digest.as_bytes());
    bytes
}

pub(crate) fn decode_acknowledgement(
    bytes: &[u8],
    expected: ObjectDigest,
) -> Result<(), OriginalWorkerCutoffErrorV3> {
    if bytes != encode_acknowledgement(expected) {
        return Err(OriginalWorkerCutoffErrorV3::Encoding);
    }
    Ok(())
}

/// Owns the actual timer before arm failure; no caller descriptor is accepted.
#[derive(Default)]
pub(crate) struct OriginalBoottimeTimerV3 {
    descriptor: Option<OwnedFd>,
}

impl OriginalBoottimeTimerV3 {
    pub(crate) fn arm(&mut self, cutoff: u64) -> Result<(), OriginalWorkerCutoffErrorV3> {
        if self.descriptor.is_some() || cutoff == 0 {
            return Err(OriginalWorkerCutoffErrorV3::Encoding);
        }
        self.descriptor = Some(timerfd_create(
            TimerfdClockId::Boottime,
            TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK,
        )?);
        let descriptor = self
            .descriptor
            .as_ref()
            .ok_or(OriginalWorkerCutoffErrorV3::Encoding)?;
        timerfd_settime(
            descriptor,
            TimerfdTimerFlags::ABSTIME,
            &Itimerspec {
                it_interval: Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: Timespec {
                    tv_sec: i64::try_from(cutoff / 1_000_000_000)
                        .map_err(|_| OriginalWorkerCutoffErrorV3::Bound)?,
                    tv_nsec: i64::try_from(cutoff % 1_000_000_000)
                        .map_err(|_| OriginalWorkerCutoffErrorV3::Bound)?,
                },
            },
        )?;
        Ok(())
    }

    pub(crate) fn descriptor(&self) -> Result<BorrowedFd<'_>, OriginalWorkerCutoffErrorV3> {
        self.descriptor
            .as_ref()
            .map(|descriptor| descriptor.as_fd())
            .ok_or(OriginalWorkerCutoffErrorV3::Encoding)
    }
}

/// Watches only the original absolute BOOTTIME timer through the sole runner.
/// The callback never blocks, reaps or starts a process. It cannot authorize a
/// launch; its caller must already hold the checked fixed-worker view.
pub(super) struct OriginalCutoffExchangeV3<'loan, 'records> {
    view: &'loan mut WorkerOriginalCheckedViewV3<'records>,
}

impl<'loan, 'records> OriginalCutoffExchangeV3<'loan, 'records> {
    pub(super) fn new(view: &'loan mut WorkerOriginalCheckedViewV3<'records>) -> Self {
        Self { view }
    }
}

impl aos_sandbox_linux::process::FixedProcessSessionExchange for OriginalCutoffExchangeV3<'_, '_> {
    type Output = ();
    type Error = OriginalWorkerCutoffErrorV3;

    fn start(
        &mut self,
        _child: &aos_sandbox_linux::process::FixedLiveChild<'_>,
        _control: BorrowedFd<'_>,
    ) -> Result<aos_sandbox_linux::process::ExchangeStep<()>, Self::Error> {
        self.view.check()?;
        Ok(aos_sandbox_linux::process::ExchangeStep::Pending(
            aos_sandbox_linux::process::FixedProcessControlInterest::Readable,
        ))
    }

    fn advance(
        &mut self,
        _child: &aos_sandbox_linux::process::FixedLiveChild<'_>,
        _control: BorrowedFd<'_>,
        _readiness: aos_sandbox_linux::process::FixedProcessControlReadiness,
    ) -> Result<aos_sandbox_linux::process::ExchangeStep<()>, Self::Error> {
        self.view.check()?;
        // Timer readiness is a refusal trigger, never exchange completion.
        Err(OriginalWorkerCutoffErrorV3::Encoding)
    }
}

fn require_header(
    bytes: &[u8],
    magic: &[u8; 8],
    version: u16,
) -> Result<(), OriginalWorkerCutoffErrorV3> {
    if bytes.get(..8) != Some(magic.as_slice())
        || bytes.get(8..10) != Some(version.to_be_bytes().as_slice())
        || bytes.get(10..16) != Some([0; 6].as_slice())
    {
        return Err(OriginalWorkerCutoffErrorV3::Encoding);
    }
    Ok(())
}

fn decode_pair(bytes: &[u8]) -> Result<RawPairedClockSample, OriginalWorkerCutoffErrorV3> {
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(KERNEL_CLOCK_PROVENANCE)
            .map_err(|_| OriginalWorkerCutoffErrorV3::Encoding)?,
        array(bytes, 16)?,
        i64::from_be_bytes(array(bytes, 32)?),
        u64::from_be_bytes(array(bytes, 40)?),
    )
    .map_err(|_| OriginalWorkerCutoffErrorV3::Encoding)
}

fn encode_pair(bytes: &mut Vec<u8>, first: RawPairedClockSample, cutoff: u64) {
    bytes.extend_from_slice(&first.host_boot_id());
    bytes.extend_from_slice(&first.wall_seconds().to_be_bytes());
    bytes.extend_from_slice(&first.boottime_nanoseconds().to_be_bytes());
    bytes.extend_from_slice(&cutoff.to_be_bytes());
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], OriginalWorkerCutoffErrorV3> {
    let end = offset
        .checked_add(N)
        .ok_or(OriginalWorkerCutoffErrorV3::Bound)?;
    bytes
        .get(offset..end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(OriginalWorkerCutoffErrorV3::Encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn introduction() -> OriginalWorkerIntroductionV3 {
        OriginalWorkerIntroductionV3 {
            first: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted(KERNEL_CLOCK_PROVENANCE).unwrap(),
                [7; 16],
                100,
                10,
            )
            .unwrap(),
            cutoff: 1_000_000_010,
            body_length: 1024,
            digest: ObjectDigest::from_bytes([8; 32]),
        }
    }

    #[test]
    fn original_introduction_roundtrips_all_fields_without_accepting_other_versions() {
        let expected = introduction();
        for purpose in [
            OriginalWorkerPurposeV3::Reader,
            OriginalWorkerPurposeV3::Observer,
        ] {
            let encoded = expected.encode(purpose).unwrap();
            let actual = OriginalWorkerIntroductionV3::decode(purpose, &encoded).unwrap();
            assert_eq!(actual.first, expected.first);
            assert_eq!(actual.cutoff, expected.cutoff);
            assert_eq!(actual.body_length, expected.body_length);
            assert_eq!(actual.digest, expected.digest);

            let mut reserved = encoded;
            reserved[10] = 1;
            assert!(OriginalWorkerIntroductionV3::decode(purpose, &reserved).is_err());
            let mut wrong_version = encoded;
            wrong_version[9] ^= 1;
            assert!(OriginalWorkerIntroductionV3::decode(purpose, &wrong_version).is_err());
            let mut expired = encoded;
            expired[48..56].copy_from_slice(&expected.first.boottime_nanoseconds().to_be_bytes());
            assert!(OriginalWorkerIntroductionV3::decode(purpose, &expired).is_err());
        }
    }

    #[test]
    fn original_cutoff_rejects_truncation_reserved_and_wrong_purpose() {
        for length in 0..CUTOFF_PREFIX_BYTES {
            assert!(DecodedOriginalWorkerCutoffV3::decode(&vec![0; length]).is_err());
        }
        let bytes = vec![0; INTRODUCTION_BYTES];
        assert!(
            OriginalWorkerIntroductionV3::decode(OriginalWorkerPurposeV3::Reader, &bytes).is_err(),
        );
        assert!(!OriginalWorkerPurposeV3::Reader.selects_introduction(b"AOSHSR02"));
        assert!(!OriginalWorkerPurposeV3::Observer.selects_introduction(b"AOSZHS01"));
    }

    #[test]
    fn original_body_bound_precedes_header_or_growth() {
        let bytes = vec![0; MAXIMUM_ORIGINAL_BODY_BYTES + 1];
        assert!(matches!(
            decode_body(OriginalWorkerPurposeV3::Reader, &bytes),
            Err(OriginalWorkerCutoffErrorV3::Bound),
        ));
        assert!(matches!(
            encode_body(OriginalWorkerPurposeV3::Observer, &bytes, b"selected"),
            Err(OriginalWorkerCutoffErrorV3::Bound),
        ));
    }

    #[test]
    fn original_ack_and_domains_do_not_retag_legacy_bytes() {
        let digest = ObjectDigest::from_bytes([1; 32]);
        let acknowledgement = encode_acknowledgement(digest);
        assert_eq!(acknowledgement.len(), 42);
        assert!(decode_acknowledgement(&acknowledgement, digest).is_ok());
        assert!(
            decode_acknowledgement(&acknowledgement, ObjectDigest::from_bytes([2; 32])).is_err(),
        );
        assert_ne!(
            OriginalWorkerPurposeV3::Reader.digest(b"same body"),
            OriginalWorkerPurposeV3::Observer.digest(b"same body"),
        );
        assert!(decode_acknowledgement(b"AOSZWAK1\0\x01", digest).is_err());
    }
}
