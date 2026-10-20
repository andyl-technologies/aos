//! Systemd-activated runtime for one authenticated Network preparation.
//!
//! The capability-free broker authenticates PID 1 and a fresh private-network
//! worker before transferring an exact dispatch and its own retained Network
//! namespace. The request is split into bounded sequenced-packet frames; every
//! frame carries a kernel-generated process subject, while only the first frame
//! carries the host namespace descriptor. The worker independently opens all
//! protected authority, replay, and immutable-helper state before authenticating
//! and executing the request.
//!
//! A successful result is correlation evidence only. The broker returns the
//! target namespace descriptor only after the worker leader has exited and the
//! retained unit cgroup reports `populated 0`. A separate observation worker is
//! still required before committing or publishing the namespace.

mod child_intake_v2;
pub(crate) mod child_programme_v2;
mod executor_opening;
mod preparation_input_v2;
mod retaining;
pub use child_programme_v2::run_inherited_network_prepare_worker_entry_v2;

pub(crate) use child_intake_v2::{NetworkPreparationIntakeOriginalV2, PreparationIntakeClosedV2};
pub(crate) use preparation_input_v2::PreparationInputDataV2;

pub(crate) use retaining::{
    NetworkParentMutationInputV2, NetworkParentMutationOriginalV2,
    NetworkParentTransportOriginalV2, WorkerQuiescenceOriginalV4,
};

pub(crate) use executor_opening::CompletedObservationOpeningV4;
pub(crate) use executor_opening::prepare_observation_local;
pub use executor_opening::{
    NetworkObservationExecutorOpeningOriginalV4, NetworkPrepareExecutorOpeningOriginalV4,
    NetworkPrepareExecutorOpeningRefusalV4,
};

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aos_sandbox_model::{ObjectDigest, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::cgroup::{
    CgroupPopulationMonitor, CgroupPopulationState, CgroupV2Root, RetainedCgroupAnchor,
};
use aos_sandbox_linux::pidfd::NamespaceIdentity;
use aos_sandbox_linux::pidfd::{NamespaceFd, SingleThreadedProcess};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use sha2::{Digest as _, Sha256};

use crate::authorization::NetworkAuthorityV1;
use crate::kernel_mutator::{FixedNetworkKernelMutator, NetworkKernelMutationError};
use crate::worker_process::{
    NetworkWorkerProcessError, NetworkWorkerReadyV1, NetworkWorkerResultV1, acknowledgement,
    decode_acknowledgement, validate_broker_peer, validate_broker_request, validate_broker_subject,
    validate_exact_worker_subject, validate_same_worker_execution, validate_systemd_manager_peer,
};
use crate::worker_protocol::{
    MAXIMUM_NETWORK_WORKER_REQUEST_BYTES, NetworkPrepareWorkerDispatchV1,
    NetworkWorkerProtocolError,
};
use crate::{
    NetworkAdmissionError, NetworkLifecycleAdmissionCoordinator, NetworkNamespaceStoreError,
    NetworkNamespaceStoreName, NetworkWorkerReplayLedger, SystemdNetworkNamespaceStore,
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const FRAME_MAGIC: &[u8; 8] = b"AOSNFRM2";
const FRAME_VERSION: u16 = 2;
const FRAME_FIRST: u16 = 1;
const FRAME_FINAL: u16 = 2;
const FRAME_HEADER_BYTES: usize = 56;
const MAXIMUM_FRAME_BYTES: usize = 64 * 1024;
const MAXIMUM_FRAME_PAYLOAD_BYTES: usize = MAXIMUM_FRAME_BYTES - FRAME_HEADER_BYTES;
const MAXIMUM_READY_BYTES: usize = 544;
const RESULT_BYTES: usize = 128;
const ACK_BYTES: usize = 10;
const MAXIMUM_CGROUP_BYTES: usize = 512;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(5);
const NATURAL_EXIT_TIMEOUT: Duration = Duration::from_secs(1);
const QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(5);
const QUIESCENCE_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Reports rejected worker provenance, framing, authority, effects, or quiescence.
#[derive(Debug, thiserror::Error)]
pub enum NetworkWorkerRuntimeError {
    /// A bounded runtime record, path, clock, or state transition was invalid.
    #[error("Network worker runtime protocol is invalid: {0}")]
    Protocol(&'static str),
    /// The protected Network authority could not be opened.
    #[error("Network worker protected authority was rejected")]
    Authority,
    /// A worker that may have mutated could not be proved completely stopped.
    #[error("Network worker whole-unit quiescence failed: {0}")]
    Quiescence(String),
    /// The kernel-authorized process protocol rejected a peer or record.
    #[error(transparent)]
    Process(#[from] NetworkWorkerProcessError),
    /// The authenticated worker protocol rejected the dispatch or replay state.
    #[error(transparent)]
    Worker(#[from] NetworkWorkerProtocolError),
    /// The fixed kernel mutator rejected or failed the requested effect.
    #[error(transparent)]
    Mutation(#[from] NetworkKernelMutationError),
    /// The bounded sequenced-packet transport failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// A Linux descriptor, namespace, cgroup, or process check failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A procfs read failed.
    #[error("Network worker local I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A safe polling operation failed.
    #[error("Network worker polling failed: {0}")]
    Poll(#[from] rustix::io::Errno),
    /// Confirmed systemd namespace custody failed or became ambiguous.
    #[error(transparent)]
    NamespaceStore(#[from] NetworkNamespaceStoreError),
    /// Durable namespace-custody correlation could not be committed.
    #[error(transparent)]
    Broker(#[from] crate::NetworkBrokerError),
}

/// Carries a prepared namespace only after the effect worker is wholly quiescent.
#[derive(Debug)]
pub struct PreparedNetworkWorkerOutput {
    namespace: NamespaceFd,
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    kernel_plan_digest: ObjectDigest,
    kernel_boot_id: [u8; 16],
}

impl PreparedNetworkWorkerOutput {
    /// Returns the retained, independently validated target namespace.
    #[must_use]
    pub const fn namespace(&self) -> &NamespaceFd {
        &self.namespace
    }

    /// Returns the correlated durable request identity.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the correlated durable effect digest.
    #[must_use]
    pub const fn effect_digest(&self) -> ObjectDigest {
        self.effect_digest
    }

    /// Returns the correlated canonical kernel-plan digest.
    #[must_use]
    pub const fn kernel_plan_digest(&self) -> ObjectDigest {
        self.kernel_plan_digest
    }

    /// Returns the worker-observed current kernel boot ID.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> [u8; 16] {
        self.kernel_boot_id
    }

    /// Consumes the result and transfers target namespace custody.
    #[must_use]
    pub fn into_namespace(self) -> NamespaceFd {
        self.namespace
    }
}

/// Borrows the retained namespace and durable tuple of an ambiguous recovery.
///
/// This value carries observation authority only. It contains no worker
/// dispatch, effect permit, helper configuration, or namespace-store mutation
/// capability.
#[derive(Clone, Copy, Debug)]
pub struct RecoveredNetworkPreparationObservation<'a> {
    namespace: &'a NamespaceFd,
    request_id: [u8; 16],
    effect_digest: ObjectDigest,
    kernel_plan_digest: ObjectDigest,
    kernel_boot_id: [u8; 16],
}

impl<'a> RecoveredNetworkPreparationObservation<'a> {
    pub(crate) const fn new(
        namespace: &'a NamespaceFd,
        request_id: [u8; 16],
        effect_digest: ObjectDigest,
        kernel_plan_digest: ObjectDigest,
        kernel_boot_id: [u8; 16],
    ) -> Self {
        Self {
            namespace,
            request_id,
            effect_digest,
            kernel_plan_digest,
            kernel_boot_id,
        }
    }

    /// Returns the exact restart-retained target namespace.
    #[must_use]
    pub const fn namespace(self) -> &'a NamespaceFd {
        self.namespace
    }

    /// Returns the correlated durable request identity.
    #[must_use]
    pub const fn request_id(self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the correlated durable effect digest.
    #[must_use]
    pub const fn effect_digest(self) -> ObjectDigest {
        self.effect_digest
    }

    /// Returns the durable canonical kernel-plan digest.
    #[must_use]
    pub const fn kernel_plan_digest(self) -> ObjectDigest {
        self.kernel_plan_digest
    }

    /// Returns the boot in which systemd retained namespace custody.
    #[must_use]
    pub const fn kernel_boot_id(self) -> [u8; 16] {
        self.kernel_boot_id
    }
}

#[derive(Clone, Copy)]
enum ExecutorOriginV4 {
    Ordinary,
    FixedService,
}

/// Executes authenticated preparation dispatches through systemd one-shot workers.
pub struct SystemdNetworkPrepareExecutor {
    socket_path: PathBuf,
    systemd_manager_cgroup: RetainedCgroupAnchor,
    worker_parent_cgroup: RetainedCgroupAnchor,
    host_namespace: NamespaceFd,
    fail_stopped: bool,
    origin: ExecutorOriginV4,
}

fn release_after_quiescence<T>(
    quiescence: Result<(), NetworkWorkerRuntimeError>,
    release: impl FnOnce() -> T,
) -> Result<T, NetworkWorkerRuntimeError> {
    quiescence?;
    Ok(release())
}

fn exchange_after_confirmed_custody<T>(
    custody: Result<(), NetworkWorkerRuntimeError>,
    exchange: impl FnOnce() -> Result<T, NetworkWorkerRuntimeError>,
) -> Result<T, NetworkWorkerRuntimeError> {
    custody?;
    exchange()
}

fn output_from_result(
    namespace: NamespaceFd,
    result: NetworkWorkerResultV1,
) -> PreparedNetworkWorkerOutput {
    PreparedNetworkWorkerOutput {
        namespace,
        request_id: result.request_id(),
        effect_digest: result.effect_digest(),
        kernel_plan_digest: result.kernel_plan_digest(),
        kernel_boot_id: result.kernel_boot_id(),
    }
}

struct DecodedFrame<'a> {
    flags: u16,
    total: usize,
    offset: usize,
    digest: [u8; 32],
    payload: &'a [u8],
}

fn encode_frame(
    request: &[u8],
    digest: [u8; 32],
    offset: usize,
    end: usize,
) -> Result<Vec<u8>, NetworkWorkerRuntimeError> {
    if request.is_empty()
        || request.len() > MAXIMUM_NETWORK_WORKER_REQUEST_BYTES
        || offset >= end
        || end > request.len()
        || end - offset > MAXIMUM_FRAME_PAYLOAD_BYTES
    {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker frame bounds are invalid",
        ));
    }
    let mut flags = 0;
    if offset == 0 {
        flags |= FRAME_FIRST;
    }
    if end == request.len() {
        flags |= FRAME_FINAL;
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + end - offset);
    frame.extend_from_slice(FRAME_MAGIC);
    frame.extend_from_slice(&FRAME_VERSION.to_be_bytes());
    frame.extend_from_slice(&flags.to_be_bytes());
    frame.extend_from_slice(&u32_length(request.len())?.to_be_bytes());
    frame.extend_from_slice(&u32_length(offset)?.to_be_bytes());
    frame.extend_from_slice(&u32_length(end - offset)?.to_be_bytes());
    frame.extend_from_slice(&digest);
    frame.extend_from_slice(&request[offset..end]);
    Ok(frame)
}

fn decode_frame(bytes: &[u8]) -> Result<DecodedFrame<'_>, NetworkWorkerRuntimeError> {
    if bytes.len() <= FRAME_HEADER_BYTES || bytes.len() > MAXIMUM_FRAME_BYTES {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker frame length is invalid",
        ));
    }
    if &bytes[..8] != FRAME_MAGIC || bytes[8..10] != FRAME_VERSION.to_be_bytes() {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker frame header is invalid",
        ));
    }
    let flags = u16::from_be_bytes(copy_array(&bytes[10..12])?);
    let total = usize::try_from(u32::from_be_bytes(copy_array(&bytes[12..16])?))
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("frame total does not fit usize"))?;
    let offset = usize::try_from(u32::from_be_bytes(copy_array(&bytes[16..20])?))
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("frame offset does not fit usize"))?;
    let length = usize::try_from(u32::from_be_bytes(copy_array(&bytes[20..24])?))
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("frame length does not fit usize"))?;
    let digest = copy_array(&bytes[24..56])?;
    let end = offset
        .checked_add(length)
        .ok_or(NetworkWorkerRuntimeError::Protocol(
            "frame range overflowed",
        ))?;
    let first = flags & FRAME_FIRST != 0;
    let final_frame = flags & FRAME_FINAL != 0;
    if flags & !(FRAME_FIRST | FRAME_FINAL) != 0
        || total == 0
        || total > MAXIMUM_NETWORK_WORKER_REQUEST_BYTES
        || length == 0
        || length > MAXIMUM_FRAME_PAYLOAD_BYTES
        || bytes.len() != FRAME_HEADER_BYTES + length
        || end > total
        || first != (offset == 0)
        || final_frame != (end == total)
    {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker frame fields are invalid",
        ));
    }
    Ok(DecodedFrame {
        flags,
        total,
        offset,
        digest,
        payload: &bytes[FRAME_HEADER_BYTES..],
    })
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NetworkWorkerRuntimeError> {
    bytes
        .try_into()
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("Network worker frame is truncated"))
}

fn u32_length(value: usize) -> Result<u32, NetworkWorkerRuntimeError> {
    u32::try_from(value)
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("Network worker frame field is too large"))
}

pub(crate) fn send_record_before(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    deadline: u64,
) -> Result<(), NetworkWorkerRuntimeError> {
    aos_sandbox_linux::seqpacket::bounded::send_provisioned_worker_record(
        socket,
        payload,
        &[],
        deadline,
    )
    .map_err(map_worker_record_error)
}

pub(crate) fn send_record_with_descriptors_before(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    descriptors: &[BorrowedFd<'_>],
    deadline: u64,
) -> Result<(), NetworkWorkerRuntimeError> {
    aos_sandbox_linux::seqpacket::bounded::send_provisioned_worker_record(
        socket,
        payload,
        descriptors,
        deadline,
    )
    .map_err(map_worker_record_error)
}

pub(crate) fn receive_record_before(
    socket: &mut DescriptorSubjectSocket,
    maximum: usize,
    descriptors: usize,
    deadline: u64,
) -> Result<ReceivedDescriptorRecord, NetworkWorkerRuntimeError> {
    aos_sandbox_linux::seqpacket::bounded::receive_provisioned_worker_record_without_io_uring(
        socket,
        maximum,
        descriptors,
        deadline,
    )
    .map_err(map_worker_record_error)
}

pub(crate) fn quiesce_worker(
    subject: &KernelAuthorizedRecordSubject,
    cgroup: &RetainedCgroupAnchor,
    population: &CgroupPopulationMonitor,
) -> Result<(), NetworkWorkerRuntimeError> {
    retaining::quiesce_engine_v4(
        subject,
        cgroup,
        population,
        &mut retaining::LocalQuiescenceV4,
    )
}

pub(crate) fn wait_for_quiescence(
    subject: &KernelAuthorizedRecordSubject,
    population: &CgroupPopulationMonitor,
    timeout: Duration,
) -> Result<(), NetworkWorkerRuntimeError> {
    retaining::wait_engine_v4(
        subject,
        population,
        timeout,
        &mut retaining::LocalQuiescenceV4,
    )
}

fn cgroup_is_quiescent(
    population: &CgroupPopulationMonitor,
) -> Result<bool, NetworkWorkerRuntimeError> {
    Ok(matches!(
        population.state()?,
        CgroupPopulationState::Empty | CgroupPopulationState::Retired
    ))
}

fn map_worker_record_error(
    error: aos_sandbox_linux::seqpacket::bounded::WorkerRecordError,
) -> NetworkWorkerRuntimeError {
    use aos_sandbox_linux::seqpacket::bounded::{WorkerRecordClockError, WorkerRecordError};

    match error {
        WorkerRecordError::Transport(error) => NetworkWorkerRuntimeError::Transport(error),
        WorkerRecordError::Poll(error) => NetworkWorkerRuntimeError::Poll(error),
        WorkerRecordError::Linux(error) => NetworkWorkerRuntimeError::Linux(error),
        WorkerRecordError::Clock(reason) => NetworkWorkerRuntimeError::Protocol(match reason {
            WorkerRecordClockError::InvalidSeconds => "CLOCK_BOOTTIME seconds are invalid",
            WorkerRecordClockError::InvalidNanoseconds => "CLOCK_BOOTTIME nanoseconds are invalid",
            WorkerRecordClockError::Overflow => "CLOCK_BOOTTIME overflowed",
            WorkerRecordClockError::Expired => "Network worker transfer deadline elapsed",
            WorkerRecordClockError::InvalidTimeout => "invalid transfer deadline",
        }),
    }
}

pub(crate) fn deadline_after(duration: Duration) -> Result<u64, NetworkWorkerRuntimeError> {
    boottime_now_nanoseconds()?
        .checked_add(duration.as_nanos() as u64)
        .ok_or(NetworkWorkerRuntimeError::Protocol(
            "Network worker deadline overflowed",
        ))
}

fn ensure_before_deadline(deadline: u64) -> Result<(), NetworkWorkerRuntimeError> {
    if boottime_now_nanoseconds()? < deadline {
        Ok(())
    } else {
        Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker transfer deadline elapsed",
        ))
    }
}

fn boottime_now_nanoseconds() -> Result<u64, NetworkWorkerRuntimeError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("CLOCK_BOOTTIME seconds are invalid"))?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| {
        NetworkWorkerRuntimeError::Protocol("CLOCK_BOOTTIME nanoseconds are invalid")
    })?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(NetworkWorkerRuntimeError::Protocol(
            "CLOCK_BOOTTIME overflowed",
        ))
}

fn protected_clock() -> Result<RawPairedClockSample, NetworkAdmissionError> {
    let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let provenance = RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
        .map_err(|_| NetworkAdmissionError::FenceRejected)?;
    RawPairedClockSample::new_untrusted(
        provenance,
        KernelBootId::current()
            .map_err(|_| NetworkAdmissionError::FenceRejected)?
            .into_bytes(),
        realtime.tv_sec,
        boottime_now_nanoseconds().map_err(|_| NetworkAdmissionError::FenceRejected)?,
    )
    .map_err(|_| NetworkAdmissionError::FenceRejected)
}

pub(crate) fn current_cgroup() -> Result<String, NetworkWorkerRuntimeError> {
    let mut bytes = Vec::new();
    File::open("/proc/self/cgroup")?
        .take((MAXIMUM_CGROUP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAXIMUM_CGROUP_BYTES {
        return Err(NetworkWorkerRuntimeError::Protocol(
            "Network worker cgroup text is too long",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| NetworkWorkerRuntimeError::Protocol("cgroup text is not UTF-8"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .map(str::to_owned)
        .ok_or(NetworkWorkerRuntimeError::Protocol(
            "unified Network worker cgroup is absent",
        ))
}

pub(crate) fn open_cgroup_root() -> Result<CgroupV2Root, NetworkWorkerRuntimeError> {
    let descriptor = open_cgroup_root_candidate_retaining_v4()?;
    CgroupV2Root::from_owned(descriptor).map_err(Into::into)
}

/// Returns the existing raw root-open result to the genuine startup owner.
/// The caller parks it before the same retained CgroupV2Root admission.
pub(crate) fn open_cgroup_root_candidate_retaining_v4() -> Result<OwnedFd, rustix::io::Errno> {
    rustix::fs::open(
        CGROUP_ROOT,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
}

pub(crate) fn normalized_absolute_path(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = path.as_os_str().as_bytes();
    path.is_absolute()
        && bytes.len() > 1
        && bytes.len() <= 4096
        && !bytes.contains(&0)
        && bytes[1..]
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && !matches!(component, b"." | b".."))
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    #[test]
    fn version_one_network_frame_is_refused() {
        let request = b"canonical request framing data";
        let digest = Sha256::digest(request).into();
        let mut bytes = encode_frame(request, digest, 0, request.len()).unwrap();
        bytes[..8].copy_from_slice(b"AOSNFRM1");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());

        assert!(decode_frame(&bytes).is_err());
    }

    use std::cell::Cell;

    use super::*;

    fn prepared_observation_output(
        plan_digest: ObjectDigest,
        boot_id: [u8; 16],
    ) -> PreparedNetworkWorkerOutput {
        PreparedNetworkWorkerOutput {
            namespace: NamespaceFd::current_network().unwrap(),
            request_id: [1; 16],
            effect_digest: ObjectDigest::from_bytes([2; 32]),
            kernel_plan_digest: plan_digest,
            kernel_boot_id: boot_id,
        }
    }

    #[test]
    fn prepared_observation_rejects_substituted_plan_boot_and_host() {
        let plan_digest = ObjectDigest::from_bytes([3; 32]);
        let boot_id = [4; 16];
        let prepared = prepared_observation_output(plan_digest, boot_id);
        let target = prepared.namespace().identity();
        let distinct_host = NamespaceIdentity {
            device: target.device,
            inode: target.inode.checked_add(1).unwrap(),
        };
        let validate = |digest, boot, host| {
            crate::namespace_observer::validate_prepared_observation_authority(
                digest,
                prepared.kernel_plan_digest(),
                prepared.kernel_boot_id(),
                prepared.namespace().identity(),
                boot,
                host,
            )
        };

        assert!(validate(plan_digest, boot_id, distinct_host).is_ok());
        assert!(validate(ObjectDigest::from_bytes([5; 32]), boot_id, distinct_host).is_err());
        assert!(validate(plan_digest, [6; 16], distinct_host).is_err());
        assert!(validate(plan_digest, boot_id, target).is_err());
    }

    #[test]
    fn request_frames_are_bounded_canonical_and_contiguous() {
        let request = vec![0x5a; MAXIMUM_FRAME_PAYLOAD_BYTES + 17];
        let digest = Sha256::digest(&request).into();
        let first = encode_frame(&request, digest, 0, MAXIMUM_FRAME_PAYLOAD_BYTES).unwrap();
        let second =
            encode_frame(&request, digest, MAXIMUM_FRAME_PAYLOAD_BYTES, request.len()).unwrap();
        let first = decode_frame(&first).unwrap();
        let second = decode_frame(&second).unwrap();

        assert_eq!(first.flags, FRAME_FIRST);
        assert_eq!(first.offset, 0);
        assert_eq!(first.payload.len(), MAXIMUM_FRAME_PAYLOAD_BYTES);
        assert_eq!(second.flags, FRAME_FINAL);
        assert_eq!(second.offset, first.payload.len());
        assert_eq!(second.payload.len(), 17);
        assert_eq!(first.total, request.len());
        assert_eq!(second.total, request.len());
    }

    #[test]
    fn frame_flags_lengths_and_ranges_fail_closed() {
        let request = vec![7; 32];
        let digest = Sha256::digest(&request).into();
        let valid = encode_frame(&request, digest, 0, request.len()).unwrap();
        for offset in [8, 10, 12, 16, 20] {
            let mut changed = valid.clone();
            changed[offset] ^= 0x80;
            assert!(decode_frame(&changed).is_err(), "offset {offset}");
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(decode_frame(&trailing).is_err());
        assert!(decode_frame(&valid[..FRAME_HEADER_BYTES]).is_err());
    }

    #[test]
    fn only_normalized_absolute_socket_paths_are_accepted() {
        assert!(normalized_absolute_path(Path::new(
            "/run/aos/network-worker.sock"
        )));
        for path in [
            "run/aos/network-worker.sock",
            "/run//network-worker.sock",
            "/run/../network-worker.sock",
            "/run/./network-worker.sock",
        ] {
            assert!(!normalized_absolute_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn custody_refusal_prevents_the_shared_effect_exchange() {
        let effects = Cell::new(0);
        let result = exchange_after_confirmed_custody(
            Err(NetworkWorkerRuntimeError::Authority),
            || {
                effects.set(effects.get() + 1);
                Ok(())
            },
        );

        assert!(matches!(result, Err(NetworkWorkerRuntimeError::Authority)));
        assert_eq!(effects.get(), 0);
    }

    #[test]
    fn worker_output_is_released_only_after_whole_unit_quiescence() {
        let released = Cell::new(0);
        let fail = release_after_quiescence::<()>(
            Err(NetworkWorkerRuntimeError::Quiescence(
                "unit remained populated".to_owned(),
            )),
            || released.set(released.get() + 1),
        );

        assert!(fail.is_err());
        assert_eq!(released.get(), 0);

        release_after_quiescence(Ok(()), || released.set(released.get() + 1)).unwrap();
        assert_eq!(released.get(), 1);
    }
}

impl SystemdNetworkPrepareExecutor {
    // Synchronous calls retain all live worker custody until completion. This
    // local check is only a conjunct of the independent whole-native census.
    pub(crate) fn inventory_local_custody_clear_v2(&self) -> bool {
        !self.fail_stopped && matches!(self.origin, ExecutorOriginV4::FixedService)
    }
}
