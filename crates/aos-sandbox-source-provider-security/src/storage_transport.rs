//! Fixed authenticated SourceProvider clients for Storage intake.
//!
//! This client accepts an already signed plan; it cannot mint one. The fixed
//! Storage socket, root account, retained service cgroup, connection peer, and
//! record subject must agree before a reply is retained. LocalLive inspection
//! remains descriptor-free and unavailable-only. Native reply custody still
//! requires independent signature, protected-state, and physical validation.

use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::bounded::{BoundedRecordError, boottime, receive, send};
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, SeqpacketSocket,
};
use aos_sandbox_source_provider_protocol::{
    STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3, SignedStorageLiveExportRequestV1,
    SignedStorageNativeAcquireRequestV2, StorageLiveExportTransportRequestV1,
    StorageLiveExportUnavailableV1, StorageNativeAcquireReplyV3, StorageZfsHoldUnavailableV1,
};
use rustix::fs::{Mode, OFlags, open};
use rustix::rand::{GetRandomFlags, getrandom};

const LIVE_EXPORT_SOCKET: &str = "/run/aos/sandbox-storage/live-export-request.sock";
const NATIVE_HOLD_SOCKET: &str = "/run/aos/sandbox-storage/zfs-hold-request.sock";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const STORAGE_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const EXCHANGE_NANOSECONDS: u64 = 60_000_000_000;
const UNAVAILABLE_RESPONSE_BYTES: usize = 96;

/// Reports transport, descriptor framing, or Storage-peer authentication failure.
#[derive(Debug, thiserror::Error)]
pub enum ProductionSourceProviderStorageErrorV1 {
    /// The fixed Storage endpoint or retained cgroup could not be established.
    #[error("SourceProvider Storage endpoint is unavailable")]
    Endpoint,
    /// The connection peer or record subject is not the live Storage service.
    #[error("SourceProvider Storage peer is unauthenticated")]
    Peer,
    /// Kernel entropy could not produce a fresh challenge.
    #[error("SourceProvider Storage challenge generation failed")]
    Entropy,
    /// The bounded record exchange failed.
    #[error("SourceProvider Storage exchange failed: {0}")]
    Transport(#[from] BoundedRecordError),
    /// Storage's response did not match the exact signed request.
    #[error("SourceProvider Storage response is invalid")]
    Response,
    /// The descriptor-bearing carrier failed.
    #[error("SourceProvider Storage descriptor exchange failed: {0}")]
    DescriptorTransport(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
}

/// Reports the only currently permitted Storage exchange outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionSourceProviderStorageOutcomeV1 {
    /// Storage inspected a request but granted no export or descriptor.
    Unavailable,
}

/// Retains an exact native reply and its live, kernel-authenticated Storage peer.
///
/// Private fields prevent callers from manufacturing live origin with scalar
/// peer claims. This retains peer and FD custody, not perpetual currentness of
/// Storage's global journal or Provider completion authority.
pub struct ReceivedStorageNativeAcquireV3 {
    reply: StorageNativeAcquireReplyV3,
    descriptor: Option<OwnedFd>,
    connection: SeqpacketSocket,
    cgroup: aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
    execution: StorageEndpointExecutionV1,
    subject: KernelAuthorizedRecordSubject,
}

impl ReceivedStorageNativeAcquireV3 {
    /// Borrows the exact canonical acceptance and receipt bundle.
    #[must_use]
    pub const fn reply(&self) -> &StorageNativeAcquireReplyV3 {
        &self.reply
    }

    /// Rechecks the same live Storage process, subject, connection, and cgroup.
    ///
    /// # Errors
    ///
    /// Rejects Storage process death, peer substitution, or cgroup drift.
    pub fn revalidate(&self) -> Result<(), ProductionSourceProviderStorageErrorV1> {
        verify_storage_record(
            &self.cgroup,
            self.execution,
            self.connection.peer(),
            &self.subject,
        )
    }

    /// Takes the originally received FD once after peer revalidation.
    ///
    /// This releases received custody, never durable Provider handoff authority.
    ///
    /// # Errors
    ///
    /// Rejects stale peer custody or a descriptor already taken.
    pub fn take_original_descriptor(
        &mut self,
    ) -> Result<OwnedFd, ProductionSourceProviderStorageErrorV1> {
        self.revalidate()?;
        self.descriptor
            .take()
            .ok_or(ProductionSourceProviderStorageErrorV1::Response)
    }
}

/// Exchanges exact retained native bytes with the fixed authenticated endpoint.
///
/// Retries send identical signed bytes and nonce. A positive result owns one
/// SourceRoot FD plus live peer custody; explicit unavailability owns none.
/// A transport error never proves that Storage did not accept the request.
///
/// # Errors
///
/// Rejects endpoint, peer, deadline, packet, response binding, descriptor-table,
/// or nominated record-subject failures.
pub fn exchange_signed_storage_native_acquire_v2(
    request: &SignedStorageNativeAcquireRequestV2,
) -> Result<Option<ReceivedStorageNativeAcquireV3>, ProductionSourceProviderStorageErrorV1> {
    let cgroup = retained_storage_cgroup()?;
    let mut connection = SeqpacketSocket::connect(Path::new(NATIVE_HOLD_SOCKET))
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Endpoint)?;
    let execution = verify_storage_peer(&cgroup, connection.peer())?;
    let deadline = boottime()?
        .checked_add(EXCHANGE_NANOSECONDS)
        .ok_or(ProductionSourceProviderStorageErrorV1::Response)?;
    send(&mut connection, &request.to_canonical_bytes(), deadline)?;
    let record = receive_native_reply(
        &mut connection,
        STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3,
        deadline,
    )?;
    verify_storage_record(&cgroup, execution, connection.peer(), record.subject())?;
    let bound = connection
        .bind_received_descriptors(record)
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?;
    let (payload, subject, mut descriptors, _) = bound.into_parts();

    if payload.starts_with(b"AOSZHU01") {
        if !descriptors.is_empty() {
            return Err(ProductionSourceProviderStorageErrorV1::Response);
        }
        StorageZfsHoldUnavailableV1::from_canonical_bytes(&payload)
            .and_then(|response| response.verify_for(request.request().claims()))
            .map_err(|_| ProductionSourceProviderStorageErrorV1::Response)?;
        verify_storage_record(&cgroup, execution, connection.peer(), &subject)?;
        return Ok(None);
    }

    let reply = StorageNativeAcquireReplyV3::from_canonical_bytes(&payload)
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Response)?;
    if descriptors.len() != 1
        || reply.acceptance().acceptance().request_digest() != request.digest()
    {
        return Err(ProductionSourceProviderStorageErrorV1::Response);
    }
    let descriptor = descriptors
        .pop()
        .ok_or(ProductionSourceProviderStorageErrorV1::Response)?;
    let received = ReceivedStorageNativeAcquireV3 {
        reply,
        descriptor: Some(descriptor),
        connection,
        cgroup,
        execution,
        subject,
    };
    received.revalidate()?;
    Ok(Some(received))
}

fn receive_native_reply(
    socket: &mut SeqpacketSocket,
    maximum: usize,
    deadline: u64,
) -> Result<
    aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    ProductionSourceProviderStorageErrorV1,
> {
    use aos_sandbox_linux::seqpacket::SeqpacketError;
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    loop {
        let remaining = deadline
            .checked_sub(boottime()?)
            .filter(|remaining| *remaining > 0)
            .ok_or(BoundedRecordError::Clock)?;
        match socket.receive_with_optional_descriptor(maximum) {
            Ok(record) => {
                if boottime()? >= deadline {
                    return Err(BoundedRecordError::Clock.into());
                }
                return Ok(record);
            }
            Err(SeqpacketError::Interrupted) => continue,
            Err(SeqpacketError::WouldBlock) => {}
            Err(error) => return Err(error.into()),
        }
        let timeout = Timespec {
            tv_sec: i64::try_from(remaining / 1_000_000_000)
                .map_err(|_| BoundedRecordError::Clock)?,
            tv_nsec: i64::try_from(remaining % 1_000_000_000)
                .map_err(|_| BoundedRecordError::Clock)?,
        };
        let mut ready = [PollFd::from_borrowed_fd(socket.as_fd()?, PollFlags::IN)];
        match poll(&mut ready, Some(&timeout)) {
            Ok(0) => return Err(BoundedRecordError::Clock.into()),
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(BoundedRecordError::Io(error).into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageEndpointExecutionV1 {
    Storage(PidFdInfo),
    SocketManager(PidFdInfo),
}

/// Submits one already signed plan to the fixed Storage service.
///
/// This is a closed readback seam: it cannot construct a Provider plan, sign
/// one, or convert `Unavailable` into a lease or Mount Acquire success.
///
/// # Errors
///
/// Rejects missing/changed endpoint, cgroup, peer, record subject, challenge,
/// deadline, packet, or exact response binding.
pub fn inspect_signed_storage_export_plan(
    signed_plan: SignedStorageLiveExportRequestV1,
) -> Result<ProductionSourceProviderStorageOutcomeV1, ProductionSourceProviderStorageErrorV1> {
    let storage_cgroup = retained_storage_cgroup()?;
    let mut connection = SeqpacketSocket::connect(Path::new(LIVE_EXPORT_SOCKET))
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Endpoint)?;
    let execution = verify_storage_peer(&storage_cgroup, connection.peer())?;

    let mut nonce = [0; 32];
    let mut filled = 0;
    while filled < nonce.len() {
        let count = getrandom(&mut nonce[filled..], GetRandomFlags::empty())
            .map_err(|_| ProductionSourceProviderStorageErrorV1::Entropy)?;
        if count == 0 {
            return Err(ProductionSourceProviderStorageErrorV1::Entropy);
        }
        filled += count;
    }
    let request = StorageLiveExportTransportRequestV1::new(1, nonce, signed_plan)
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Response)?;
    let deadline = boottime()?
        .checked_add(EXCHANGE_NANOSECONDS)
        .ok_or(ProductionSourceProviderStorageErrorV1::Response)?;
    send(&mut connection, &request.to_canonical_bytes(), deadline)?;
    let record = receive(&mut connection, UNAVAILABLE_RESPONSE_BYTES, deadline)?;
    if verify_storage_record(
        &storage_cgroup,
        execution,
        connection.peer(),
        record.subject(),
    )
    .is_err()
    {
        return Err(ProductionSourceProviderStorageErrorV1::Peer);
    }
    let response = StorageLiveExportUnavailableV1::from_canonical_bytes(record.payload())
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Response)?;
    response
        .matches_request(&request)
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Response)?;
    verify_storage_peer(&storage_cgroup, connection.peer())?;
    Ok(ProductionSourceProviderStorageOutcomeV1::Unavailable)
}

fn retained_storage_cgroup()
-> Result<aos_sandbox_linux::cgroup::RetainedCgroupAnchor, ProductionSourceProviderStorageErrorV1> {
    let descriptor = open(
        CGROUP_ROOT,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProductionSourceProviderStorageErrorV1::Endpoint)?;
    CgroupV2Root::from_owned(descriptor)
        .and_then(|root| root.resolve(Path::new(STORAGE_CGROUP)))
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Endpoint)
}

fn verify_storage_peer(
    cgroup: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
    peer: &ConnectionPeerIdentity,
) -> Result<StorageEndpointExecutionV1, ProductionSourceProviderStorageErrorV1> {
    cgroup
        .validate_current()
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?;
    let credentials = peer.credentials();
    if credentials.uid() != 0 || credentials.gid() != 0 {
        return Err(ProductionSourceProviderStorageErrorV1::Peer);
    }
    // With socket activation the connection establisher may be PID 1, while
    // each response record must independently name the live Storage service.
    let info = peer.initial_info();
    let pid = credentials.pid().get();
    if info.pid() != pid
        || info.thread_group_id() != pid
        || !peer
            .is_alive()
            .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?
    {
        return Err(ProductionSourceProviderStorageErrorV1::Peer);
    }
    if let Ok(storage) = cgroup.verify_exact_membership(peer.pidfd()) {
        if same_process(storage, info) {
            return Ok(StorageEndpointExecutionV1::Storage(storage));
        }
    }
    if pid == 1 {
        return Ok(StorageEndpointExecutionV1::SocketManager(info));
    }
    Err(ProductionSourceProviderStorageErrorV1::Peer)
}

fn verify_storage_record(
    cgroup: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
    expected: StorageEndpointExecutionV1,
    peer: &ConnectionPeerIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<(), ProductionSourceProviderStorageErrorV1> {
    let current = verify_storage_peer(cgroup, peer)?;
    let credentials = subject.credentials();
    if current != expected
        || credentials.uid() != 0
        || credentials.gid() != 0
        || !subject
            .is_alive()
            .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?
    {
        return Err(ProductionSourceProviderStorageErrorV1::Peer);
    }
    let record = cgroup
        .verify_exact_membership(subject.pidfd())
        .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?;
    if credentials.pid().get() != record.pid()
        || record.thread_group_id() != record.pid()
        || (matches!(expected, StorageEndpointExecutionV1::Storage(info) if !same_process(info, record)))
        || verify_storage_peer(cgroup, peer)? != expected
    {
        return Err(ProductionSourceProviderStorageErrorV1::Peer);
    }
    Ok(())
}

fn same_process(left: PidFdInfo, right: PidFdInfo) -> bool {
    left.pid() == right.pid()
        && left.thread_group_id() == right.thread_group_id()
        && left.cgroup_id() == right.cgroup_id()
}

use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RecordBindingError, RetainedSeqpacketAdmissionErrorV1,
    RetainedSeqpacketReceiveErrorV1, descriptor_subject::ReceivedDescriptorRecord,
};

/// Retains a fixed original Storage exchange and every returned failure owner.
///
/// This is carrier custody, not Source completion, remote journal-currentness
/// or an issuer capability. A closed attempt has no descriptor extraction or
/// revival operation. The wire mount FD and the socket's custody-only duplicate
/// are separate owners; the duplicate never performs I/O.
pub struct OriginalStorageOfferTransportV5 {
    stage: OriginalStorageOfferStageV5,
    cgroup: Option<aos_sandbox_linux::cgroup::RetainedCgroupAnchor>,
    connection: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    socket_custody: Option<Result<OwnedFd, std::io::Error>>,
    execution: Option<StorageEndpointExecutionV1>,
    root_packet: Option<Vec<u8>>,
    request_packet: Option<Vec<u8>>,
    sends: [Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>; 2],
    clock: Option<OriginalStorageOfferClockV5>,
    clock_samples: [Option<Result<aos_sandbox_core::RawPairedClockSample, crate::SourceProviderSecurityError>>; 10],
    clock_validations: [Option<Result<(), OriginalStorageOfferErrorV5>>; 10],
    control_receive: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    control_bind_failure: Option<(RecordBindingError, ReceivedRecord)>,
    control: Option<OriginalStorageControlV5>,
    reply_receive: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    reply_bind_failure: Option<(RecordBindingError, ReceivedDescriptorRecord)>,
    reply: Option<OriginalStorageReplyV5>,
    validation_failure: Option<OriginalStorageOfferErrorV5>,
    first_failure: Option<OriginalStorageOfferFailureV5>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OriginalStorageOfferStageV5 {
    Unstaged,
    Connect,
    SendRoot,
    SendRequest,
    ReceiveControl,
    ReceiveReply,
    Offered,
    Closed,
}

struct OriginalStorageControlV5 {
    payload: Vec<u8>,
    subject: KernelAuthorizedRecordSubject,
}

// Comparison DATA copied from the SAME actual upper guard, never a clock
// constructor or authority. Receipt intersection can only narrow these cuts.
struct OriginalStorageOfferClockV5 {
    initial: aos_sandbox_core::RawPairedClockSample,
    deadline: u64,
    issued_seconds: i64,
    expires_seconds: i64,
}

impl OriginalStorageOfferClockV5 {
    fn require_current(
        &self,
        later: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<(), OriginalStorageOfferErrorV5> {
        self.initial.validate_later_sample(later)?;
        if later.wall_seconds() < self.issued_seconds
            || later.wall_seconds() >= self.expires_seconds
            || later.boottime_nanoseconds() >= self.deadline
        {
            return Err(OriginalStorageOfferErrorV5::ClockExpired);
        }
        Ok(())
    }
}

struct OriginalStorageReplyV5 {
    payload: Vec<u8>,
    subject: KernelAuthorizedRecordSubject,
    descriptors: Vec<OwnedFd>,
}

#[derive(Clone, Copy)]
enum OriginalStorageOfferFailureV5 {
    Admission,
    SocketDuplicate,
    Send(usize),
    ControlReceive,
    ControlBind,
    ReplyReceive,
    ReplyBind,
    ClockSample(usize),
    ClockValidation(usize),
    Validation,
}

/// Reports a concrete fixed-offer validation failure without replacing custody.
#[derive(Debug, thiserror::Error)]
pub enum OriginalStorageOfferErrorV5 {
    /// The existing fixed endpoint or subject validator refused the observation.
    #[error("original Storage offer peer failed")]
    Peer(#[from] ProductionSourceProviderStorageErrorV1),
    /// A retained socket's current binding or readiness could not be checked.
    #[error("original Storage offer socket failed")]
    Socket(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
    /// The actual nonblocking readiness observation failed.
    #[error("original Storage offer readiness failed")]
    Poll(#[from] rustix::io::Errno),
    /// The actual later pair did not preserve the original continuity policy.
    #[error("original Storage offer clock continuity failed")]
    ClockContinuity(#[from] aos_sandbox_core::OwnershipLeaseVerificationError),
    /// An original or narrower absolute cutoff was reached without renewal.
    #[error("original Storage offer deadline expired")]
    ClockExpired,
    /// A fixed stage or exact record/table shape was violated.
    #[error("original Storage offer shape failed: {0}")]
    Shape(&'static str),
}

impl core::fmt::Debug for OriginalStorageOfferTransportV5 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("OriginalStorageOfferTransportV5([resident original custody])")
    }
}

// This fence protects returned residents and the subsequent short loans. It
// does not claim to retain a lower producer's deeper pre-return locals.
struct OriginalStorageOfferCrossingV5;

impl Drop for OriginalStorageOfferCrossingV5 {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

impl OriginalStorageOfferTransportV5 {
    /// Creates an empty fixed-purpose reservoir, without opening an endpoint.
    #[must_use]
    pub fn pending_original() -> Self {
        Self {
            stage: OriginalStorageOfferStageV5::Unstaged,
            cgroup: None,
            connection: None,
            socket_custody: None,
            execution: None,
            root_packet: None,
            request_packet: None,
            sends: [None, None],
            clock: None,
            clock_samples: std::array::from_fn(|_| None),
            clock_validations: std::array::from_fn(|_| None),
            control_receive: None,
            control_bind_failure: None,
            control: None,
            reply_receive: None,
            reply_bind_failure: None,
            reply: None,
            validation_failure: None,
            first_failure: None,
        }
    }

    /// Parks the original canonical packets without asserting their authority.
    ///
    /// The owning Source path must independently hold the genuine Root1/pair,
    /// protected Requested/Issued readbacks and its original paired clock.
    ///
    /// # Errors
    ///
    /// Rejects repeated staging, another kind, or a canonical packet ceiling.
    pub fn stage_original_packets(
        &mut self,
        root: &aos_sandbox_source_provider_protocol::native_held_completion::frame::SignedNativeHeldControlV1,
        request: &SignedStorageNativeAcquireRequestV2,
        initial: aos_sandbox_core::RawPairedClockSample,
        original_deadline: u64,
        stage_deadline: u64,
    ) -> Result<(), OriginalStorageOfferErrorV5> {
        use aos_sandbox_source_provider_protocol::{
            MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2,
            native_held_completion::{
                MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1, NativeHeldControlKindV1,
            },
        };

        if self.stage != OriginalStorageOfferStageV5::Unstaged {
            self.stage = OriginalStorageOfferStageV5::Closed;
            return Err(OriginalStorageOfferErrorV5::Shape("original packets already staged"));
        }
        self.stage = OriginalStorageOfferStageV5::Closed;
        let _crossing = OriginalStorageOfferCrossingV5;
        if root.kind() != NativeHeldControlKindV1::RootPrepared {
            return Err(OriginalStorageOfferErrorV5::Shape("original Root1 kind"));
        }
        let (issued_seconds, expires_seconds) = request.request().claims().validity();
        if stage_deadline > original_deadline || stage_deadline <= initial.boottime_nanoseconds()
            || expires_seconds <= issued_seconds
        {
            return Err(OriginalStorageOfferErrorV5::ClockExpired);
        }
        self.clock = Some(OriginalStorageOfferClockV5 {
            initial,
            deadline: stage_deadline,
            issued_seconds,
            expires_seconds,
        });

        // These typed canonical formats have already enforced their finite
        // schema bounds. Park serializer returns before follow-up comparisons.
        self.root_packet = Some(root.to_canonical_bytes());
        self.request_packet = Some(request.to_canonical_bytes());
        if self.root_packet.as_ref()
            .is_none_or(|bytes| bytes.len() > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1)
            || self.request_packet.as_ref()
                .is_none_or(|bytes| bytes.len() > MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2)
        {
            return Err(OriginalStorageOfferErrorV5::Shape("original packet ceiling"));
        }
        self.stage = OriginalStorageOfferStageV5::Connect;
        Ok(())
    }

    /// Advances one fixed nonblocking crossing with its result parked first.
    ///
    /// The caller bookends every call with the same genuine Source clock and
    /// writer cut. The existing kernel adapter also bookends each syscall
    /// against comparison DATA copied from that guard. No deadline is renewed.
    pub fn advance_original(&mut self) {
        if matches!(self.stage, OriginalStorageOfferStageV5::Closed | OriginalStorageOfferStageV5::Offered) {
            return;
        }
        let _crossing = OriginalStorageOfferCrossingV5;
        if let Err(cause) = self.advance_inner() {
            if self.first_failure.is_none() {
                self.validation_failure = Some(cause);
                self.first_failure = Some(OriginalStorageOfferFailureV5::Validation);
            }
            self.stage = OriginalStorageOfferStageV5::Closed;
        }
    }

    /// Irreversibly closes progress without releasing or shutting down custody.
    pub fn close_original(&mut self) {
        self.stage = OriginalStorageOfferStageV5::Closed;
    }

    /// Reports the permanently closed stage, not absence or peer termination.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.stage == OriginalStorageOfferStageV5::Closed
    }

    /// Reports both retained records, without granting Source success.
    #[must_use]
    pub fn is_offered(&self) -> bool {
        self.stage == OriginalStorageOfferStageV5::Offered
    }

    /// Borrows the first actual resident cause instead of cloning or redacting it.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_failure? {
            OriginalStorageOfferFailureV5::Admission => {
                self.connection.as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            OriginalStorageOfferFailureV5::SocketDuplicate => {
                self.socket_custody.as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            OriginalStorageOfferFailureV5::Send(index) => {
                self.sends[index].as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            OriginalStorageOfferFailureV5::ControlReceive => {
                self.control_receive.as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            OriginalStorageOfferFailureV5::ControlBind => {
                self.control_bind_failure.as_ref().map(|(cause, _)| cause as _)
            }
            OriginalStorageOfferFailureV5::ReplyReceive => {
                self.reply_receive.as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            OriginalStorageOfferFailureV5::ReplyBind => {
                self.reply_bind_failure.as_ref().map(|(cause, _)| cause as _)
            }
            OriginalStorageOfferFailureV5::ClockSample(index) => {
                self.clock_samples[index].as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            OriginalStorageOfferFailureV5::ClockValidation(index) => {
                self.clock_validations[index].as_ref()?.as_ref().err().map(|cause| cause as _)
            }
            OriginalStorageOfferFailureV5::Validation => {
                self.validation_failure.as_ref().map(|cause| cause as _)
            }
        }
    }

    /// Borrows the actual control bytes only while the original attempt is open.
    #[must_use]
    pub fn control_packet(&self) -> Option<&[u8]> {
        if self.is_closed() {
            return None;
        }
        self.control.as_ref().map(|record| record.payload.as_slice())
    }

    /// Borrows the actual descriptor-bearing reply bytes without creating authority.
    #[must_use]
    pub fn reply_packet(&self) -> Option<&[u8]> {
        if !self.is_offered() {
            return None;
        }
        self.reply.as_ref().map(|record| record.payload.as_slice())
    }

    /// Intersects a received expiry with the same original guard's derived cut.
    ///
    /// The values are comparison DATA, not receipt verification or permission.
    ///
    /// # Errors
    ///
    /// Rejects a closed attempt, missing original clock or an extended cutoff.
    pub fn narrow_original_receipt(
        &mut self,
        expires_seconds: i64,
        stage_deadline: u64,
    ) -> Result<(), OriginalStorageOfferErrorV5> {
        if self.is_closed() {
            return Err(OriginalStorageOfferErrorV5::Shape("original offer closed"));
        }
        let Some(clock) = self.clock.as_mut() else {
            self.stage = OriginalStorageOfferStageV5::Closed;
            return Err(OriginalStorageOfferErrorV5::Shape("original clock absent"));
        };
        if expires_seconds > clock.expires_seconds || stage_deadline > clock.deadline {
            self.stage = OriginalStorageOfferStageV5::Closed;
            return Err(OriginalStorageOfferErrorV5::ClockExpired);
        }
        clock.expires_seconds = expires_seconds;
        clock.deadline = stage_deadline;
        Ok(())
    }

    /// Borrows the original mount FD after complete retained-carrier revalidation.
    ///
    /// # Errors
    ///
    /// Rejects a stale/closed offer or anything other than its exact one-FD table.
    pub fn original_mount_descriptor(
        &mut self,
    ) -> Result<std::os::fd::BorrowedFd<'_>, OriginalStorageOfferErrorV5> {
        use std::os::fd::AsFd as _;

        self.revalidate_original()?;
        if !self.is_offered() {
            self.stage = OriginalStorageOfferStageV5::Closed;
            return Err(OriginalStorageOfferErrorV5::Shape("native reply not received"));
        }
        if self.reply.as_ref().is_none_or(|reply| reply.descriptors.len() != 1) {
            self.stage = OriginalStorageOfferStageV5::Closed;
            return Err(OriginalStorageOfferErrorV5::Shape("native descriptor table"));
        }
        let reply = self.reply.as_ref().ok_or(OriginalStorageOfferErrorV5::Shape("native reply missing"))?;
        Ok(reply.descriptors[0].as_fd())
    }

    /// Rechecks the same socket, cgroup and every actually retained record subject.
    ///
    /// # Errors
    ///
    /// Rejects closure, cookie/path drift, task death, subject substitution or membership drift.
    pub fn revalidate_original(&mut self) -> Result<(), OriginalStorageOfferErrorV5> {
        let result = self.revalidate_inner();
        if result.is_err() {
            self.stage = OriginalStorageOfferStageV5::Closed;
        }
        result
    }

    /// Borrows the cookie of the SAME original, revalidated Storage transport.
    ///
    /// # Errors
    ///
    /// Rejects a closed or changed original connection. No reconnect is attempted.
    pub fn original_socket_cookie_v5(
        &mut self,
    ) -> Result<std::num::NonZeroU64, OriginalStorageOfferErrorV5> {
        if self.stage != OriginalStorageOfferStageV5::Offered {
            self.stage = OriginalStorageOfferStageV5::Closed;
            return Err(OriginalStorageOfferErrorV5::Shape("original Storage not offered"));
        }
        self.revalidate_original()?;
        let cookie = self.socket()?.peer().socket_cookie();
        self.revalidate_original()?;
        Ok(cookie)
    }

    fn revalidate_inner(&self) -> Result<(), OriginalStorageOfferErrorV5> {
        let socket = self.socket()?;
        socket.peer().require_peer_filesystem_path(socket.as_fd()?, Path::new(NATIVE_HOLD_SOCKET))?;
        let cgroup = self.cgroup.as_ref().ok_or(OriginalStorageOfferErrorV5::Shape("Storage cgroup absent"))?;
        let expected = self.execution.ok_or(OriginalStorageOfferErrorV5::Shape("Storage execution absent"))?;
        if self.is_closed() || verify_storage_peer(cgroup, socket.peer())? != expected {
            return Err(OriginalStorageOfferErrorV5::Shape("original Storage custody changed"));
        }

        if let Some(control) = &self.control {
            verify_storage_record(cgroup, expected, socket.peer(), &control.subject)?;
        }
        if let Some(reply) = &self.reply {
            verify_storage_record(cgroup, expected, socket.peer(), &reply.subject)?;
            let control = self.control.as_ref().ok_or(OriginalStorageOfferErrorV5::Shape("Storage control absent"))?;
            // PID1 activation does not make two service subjects interchangeable.
            let first = cgroup.verify_exact_membership(control.subject.pidfd())
                .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?;
            let second = cgroup.verify_exact_membership(reply.subject.pidfd())
                .map_err(|_| ProductionSourceProviderStorageErrorV1::Peer)?;
            if !same_process(first, second) {
                return Err(OriginalStorageOfferErrorV5::Shape("Storage records name different tasks"));
            }
        }
        socket.peer().require_peer_filesystem_path(socket.as_fd()?, Path::new(NATIVE_HOLD_SOCKET))?;
        Ok(())
    }

    fn socket(&self) -> Result<&SeqpacketSocket, OriginalStorageOfferErrorV5> {
        self.connection.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(OriginalStorageOfferErrorV5::Shape("original Storage socket absent"))
    }

    fn socket_mut(&mut self) -> Result<&mut SeqpacketSocket, OriginalStorageOfferErrorV5> {
        self.connection.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(OriginalStorageOfferErrorV5::Shape("original Storage socket absent"))
    }

    fn fail(&mut self, slot: OriginalStorageOfferFailureV5) {
        if self.first_failure.is_none() {
            self.first_failure = Some(slot);
        }
        self.stage = OriginalStorageOfferStageV5::Closed;
    }

    fn ready(&self, events: rustix::event::PollFlags) -> Result<bool, OriginalStorageOfferErrorV5> {
        use rustix::event::{PollFd, Timespec, poll};

        let mut descriptors = [PollFd::from_borrowed_fd(self.socket()?.as_fd()?, events)];
        let count = poll(&mut descriptors, Some(&Timespec { tv_sec: 0, tv_nsec: 0 }))?;
        Ok(count != 0)
    }

    // Each finite syscall has distinct before/after slots. Park the actual
    // sample and validation Result before closing; a post-effect failure never
    // replaces an earlier send/receive cause or erases its attempted debt.
    fn check_clock(&mut self, index: usize) -> bool {
        self.clock_samples[index] = Some(crate::handshake::original_kernel_clock());
        let Some(Ok(later)) = self.clock_samples[index].as_ref() else {
            self.fail(OriginalStorageOfferFailureV5::ClockSample(index));
            return false;
        };
        self.clock_validations[index] = Some(match self.clock.as_ref() {
            Some(clock) => clock.require_current(*later),
            None => Err(OriginalStorageOfferErrorV5::Shape("original clock absent")),
        });
        if self.clock_validations[index].as_ref().is_some_and(Result::is_err) {
            self.fail(OriginalStorageOfferFailureV5::ClockValidation(index));
            return false;
        }
        true
    }

    fn advance_inner(&mut self) -> Result<(), OriginalStorageOfferErrorV5> {
        use aos_sandbox_source_provider_protocol::native_held_completion::MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1;
        use rustix::event::PollFlags;
        use std::os::fd::AsFd as _;

        if self.stage == OriginalStorageOfferStageV5::Connect {
            self.cgroup = Some(retained_storage_cgroup()?);
            if !self.check_clock(8) { return Ok(()); }
            self.connection = Some(SeqpacketSocket::connect_retaining(Path::new(NATIVE_HOLD_SOCKET)));
            if self.connection.as_ref().is_some_and(Result::is_err) {
                self.fail(OriginalStorageOfferFailureV5::Admission);
                self.check_clock(9);
                return Ok(());
            }
            if !self.check_clock(9) { return Ok(()); }
            self.socket_custody = Some(self.socket()?.as_fd()?.try_clone_to_owned());
            if self.socket_custody.as_ref().is_some_and(Result::is_err) {
                self.fail(OriginalStorageOfferFailureV5::SocketDuplicate);
                return Ok(());
            }
            self.execution = Some(verify_storage_peer(
                self.cgroup.as_ref().ok_or(OriginalStorageOfferErrorV5::Shape("Storage cgroup absent"))?,
                self.socket()?.peer(),
            )?);
            self.revalidate_original()?;
            self.stage = OriginalStorageOfferStageV5::SendRoot;
            return Ok(());
        }

        self.revalidate_original()?;
        match self.stage {
            OriginalStorageOfferStageV5::SendRoot | OriginalStorageOfferStageV5::SendRequest => {
                if !self.ready(PollFlags::OUT)? { return Ok(()); }
                let index = usize::from(self.stage == OriginalStorageOfferStageV5::SendRequest);
                if !self.check_clock(index * 2) { return Ok(()); }
                let packet = if index == 0 { &self.root_packet } else { &self.request_packet };
                let packet = packet.as_deref().ok_or(OriginalStorageOfferErrorV5::Shape("staged packet absent"))?;
                let socket = self.connection.as_mut().and_then(|result| result.as_mut().ok())
                    .ok_or(OriginalStorageOfferErrorV5::Shape("original Storage socket absent"))?;
                self.sends[index] = Some(socket.send(packet));
                if self.sends[index].as_ref().is_some_and(Result::is_err) {
                    self.fail(OriginalStorageOfferFailureV5::Send(index));
                    self.check_clock(index * 2 + 1);
                    return Ok(());
                }
                if !self.check_clock(index * 2 + 1) { return Ok(()); }
                self.stage = if index == 0 {
                    OriginalStorageOfferStageV5::SendRequest
                } else {
                    OriginalStorageOfferStageV5::ReceiveControl
                };
            }
            OriginalStorageOfferStageV5::ReceiveControl => {
                if !self.ready(PollFlags::IN)? { return Ok(()); }
                if !self.check_clock(4) { return Ok(()); }
                self.control_receive = Some(
                    self.socket_mut()?.receive_retaining(MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1),
                );
                if self.control_receive.as_ref().is_some_and(Result::is_err) {
                    // Even nonconsuming races retain their owning lower error.
                    // This bounded lane closes conservatively rather than retrying.
                    self.fail(OriginalStorageOfferFailureV5::ControlReceive);
                    self.check_clock(5);
                    return Ok(());
                }
                if !self.check_clock(5) { return Ok(()); }
                let record = self.control_receive.take().and_then(Result::ok)
                    .ok_or(OriginalStorageOfferErrorV5::Shape("control receive absent"))?;
                match self.socket_mut()?.bind_received_retaining(record) {
                    Ok(bound) => {
                        let (payload, subject, _) = bound.into_parts();
                        self.control = Some(OriginalStorageControlV5 { payload, subject });
                    }
                    Err(failure) => {
                        self.control_bind_failure = Some(failure);
                        self.fail(OriginalStorageOfferFailureV5::ControlBind);
                        return Ok(());
                    }
                }
                self.stage = OriginalStorageOfferStageV5::ReceiveReply;
            }
            OriginalStorageOfferStageV5::ReceiveReply => {
                if !self.ready(PollFlags::IN)? { return Ok(()); }
                if !self.check_clock(6) { return Ok(()); }
                self.reply_receive = Some(self.socket_mut()?.receive_with_descriptors_retaining(
                    STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3, 1,
                ));
                if self.reply_receive.as_ref().is_some_and(Result::is_err) {
                    self.fail(OriginalStorageOfferFailureV5::ReplyReceive);
                    self.check_clock(7);
                    return Ok(());
                }
                if !self.check_clock(7) { return Ok(()); }
                let record = self.reply_receive.take().and_then(Result::ok)
                    .ok_or(OriginalStorageOfferErrorV5::Shape("reply receive absent"))?;
                match self.socket_mut()?.bind_received_descriptors_retaining(record) {
                    Ok(bound) => {
                        let (payload, subject, descriptors, _) = bound.into_parts();
                        self.reply = Some(OriginalStorageReplyV5 { payload, subject, descriptors });
                    }
                    Err(failure) => {
                        self.reply_bind_failure = Some(failure);
                        self.fail(OriginalStorageOfferFailureV5::ReplyBind);
                        return Ok(());
                    }
                }
                self.stage = OriginalStorageOfferStageV5::Offered;
            }
            _ => return Err(OriginalStorageOfferErrorV5::Shape("original exchange stage")),
        }
        self.revalidate_original()
    }
}

#[cfg(test)]
mod original_offer_clock_tests {
    //! UNRUN comparison DATA only; no socket, role, Session or currentness proof.

    use super::*;
    use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};

    fn sample(wall: i64, boot_seconds: u64, boot: u8) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [boot; 16], wall, boot_seconds * 1_000_000_000,
        ).unwrap()
    }

    fn original() -> OriginalStorageOfferClockV5 {
        OriginalStorageOfferClockV5 {
            initial: sample(10, 10, 1),
            deadline: 19_000_000_000,
            issued_seconds: 10,
            expires_seconds: 20,
        }
    }

    #[test]
    fn unchanged_pair_is_only_comparison_data() {
        assert!(original().require_current(sample(11, 11, 1)).is_ok());
    }

    #[test]
    fn exact_original_cutoff_does_not_renew() {
        assert!(matches!(original().require_current(sample(19, 19, 1)),
            Err(OriginalStorageOfferErrorV5::ClockExpired)));
        assert!(matches!(original().require_current(sample(20, 20, 1)),
            Err(OriginalStorageOfferErrorV5::ClockExpired)));
    }

    #[test]
    fn changed_boot_and_rollback_preserve_continuity_errors() {
        assert!(matches!(original().require_current(sample(11, 11, 2)),
            Err(OriginalStorageOfferErrorV5::ClockContinuity(_))));
        assert!(matches!(original().require_current(sample(9, 11, 1)),
            Err(OriginalStorageOfferErrorV5::ClockContinuity(_))));
    }
}
