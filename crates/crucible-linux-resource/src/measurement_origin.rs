//! Authenticates one private measurement invocation issued by the real root PID1.
//!
//! The immutable operator file has this identity prefix and requires every
//! finite resource field in `OperatorPolicy` below:
//!
//! ```text
//! {"schema":"crucible.measurement-operator.v1","initExecutable":"/nix/store/INIT/bin/crucible-measurement-init","actorExecutable":"/nix/store/ACTOR/bin/crucible-measurement-actor"}
//! ```
//!
//! The transferred sealed record is evidence only after the live issuance socket
//! authenticates both PID1 and its exact spawned child. This layer publishes no
//! capacity account, factory root or native birth grant. Complete preloader and
//! Source costs remain obligations of the evaluated disposable-host contract.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, memfd_create};

use serde::Deserialize;

mod actor_partition;
mod issuer_birth;
mod issuer_catalog;
mod issuer_custody;
mod issuer_parent;
mod parent_evidence;

pub use actor_partition::{CertifiedActorPartition, CertifiedNativeStage};
pub use issuer_custody::IssuerCustodyRefusal;
pub use parent_evidence::{
    AuthenticatedParentInvocation, CertifiedMeasurementMode, CertifiedNativeRoleEvidence,
    VerifiedImageInventory,
};

const POLICY_PATH: &str = "/etc/crucible/measurement-operator.json";
const ISSUER_PATH: &str = "/run/crucible-measurement-issuer.sock";
const START_ENV: &str = "CRUCIBLE_PRIVATE_ORIGIN_START_NS";
const END_ENV: &str = "CRUCIBLE_PRIVATE_ORIGIN_END_NS";
const MAX_POLICY_BYTES: usize = 16_384;
const RECORD_BYTES: usize = 128;
const RUNTIME_NS: u64 = 3_900_000_000_000;
const MAGIC: &[u8; 8] = b"CMORIG01";
static ENTRY: AtomicBool = AtomicBool::new(false);

/// First refusal from the immutable producer, kernel or original clock.
#[derive(Debug, thiserror::Error)]
pub enum MeasurementOriginError {
    /// An original issuer refuses while its non-Clone first cause stays retained.
    #[error("retained original issuer refusal: {0}")]
    RetainedIssuer(IssuerCustodyRefusal),
    /// The actual external issuer Source/control purpose has not been supplied.
    #[error("original issuer lacks genuine external Source/preloader/control purpose")]
    MissingIssuerPurpose,
    /// The peer, record, executable or policy does not identify this invocation.
    #[error("original measurement issuance refused at {0}")]
    Authentication(&'static str),
    /// The fixed policy omits or exceeds an original role.
    #[error("original measurement operator contract is invalid")]
    Contract,
    /// An authentication refusal remains primary when its postcheck expires.
    #[error("original issuance refused at {site}; post-original refusal: {after}")]
    AuthenticationBoundary {
        /// Exact first authentication boundary.
        site: &'static str,
        /// Separate same-original clock refusal after the check.
        after: OriginalClockRefusal,
    },
    /// An invalid contract remains primary when its postcheck expires.
    #[error("original operator contract invalid; post-original refusal: {0}")]
    ContractBoundary(OriginalClockRefusal),
    /// The original absolute monotonic interval has ended or is unrepresentable.
    #[error("original measurement invocation clock refused")]
    Clock,
    /// The concrete original kernel operation failed.
    #[error("original measurement kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    /// A failed kernel operation retains the original postcheck separately.
    #[error("original measurement kernel failed: {source}; post-original refusal: {after:?}")]
    KernelBoundary {
        /// First concrete kernel error.
        #[source]
        source: rustix::io::Errno,
        /// Original interval refusal observed after the failed operation.
        after: Option<OriginalClockRefusal>,
    },
    /// The concrete process or file operation failed.
    #[error("original measurement IO failed: {0}")]
    Io(#[from] std::io::Error),
    /// A concrete IO failure retains the original boundary refusal after it.
    #[error("original measurement IO failed: {source}; post-original refusal: {after:?}")]
    IoBoundary {
        /// First actual IO failure, without replacement by its postcheck.
        #[source]
        source: std::io::Error,
        /// Original interval refusal observed after the failed operation.
        after: Option<OriginalClockRefusal>,
    },
}

/// Refusal from the same original kernel interval, never a renewed deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OriginalClockRefusal {
    /// CLOCK_MONOTONIC could not be represented in the fixed local domain.
    #[error("original monotonic clock overflow")]
    Overflow,
    /// The sampled kernel coordinate preceded the retained original start.
    #[error("original monotonic clock moved backwards")]
    Backwards,
    /// The retained absolute original end was reached.
    #[error("original absolute invocation ended")]
    Expired,
}

#[derive(Clone, Copy, Debug)]
struct OriginalInterval {
    start_ns: u64,
    end_ns: u64,
}

impl OriginalInterval {
    fn remaining(self) -> Result<Duration, OriginalClockRefusal> {
        let now = monotonic_ns().map_err(|_| OriginalClockRefusal::Overflow)?;
        if now < self.start_ns {
            return Err(OriginalClockRefusal::Backwards);
        }
        self.end_ns
            .checked_sub(now)
            .filter(|left| *left != 0)
            .map(Duration::from_nanos)
            .ok_or(OriginalClockRefusal::Expired)
    }

    fn before(self) -> Result<Duration, MeasurementOriginError> {
        self.remaining().map_err(|_| MeasurementOriginError::Clock)
    }

    // Called on successes AND failures. A late original refusal never replaces
    // the concrete first kernel/IO error from the completed operation.
    fn after_io<T>(self, result: std::io::Result<T>) -> Result<T, MeasurementOriginError> {
        let after = self.remaining().err();
        match result {
            Err(source) => Err(MeasurementOriginError::IoBoundary { source, after }),
            Ok(value) if after.is_none() => Ok(value),
            Ok(_) => Err(MeasurementOriginError::Clock),
        }
    }
    fn after_result<T>(
        self,
        result: Result<T, MeasurementOriginError>,
    ) -> Result<T, MeasurementOriginError> {
        let after = self.remaining().err();
        match (result, after) {
            (Err(MeasurementOriginError::Io(source)), after) => {
                Err(MeasurementOriginError::IoBoundary { source, after })
            }
            (Err(MeasurementOriginError::Kernel(source)), after) => {
                Err(MeasurementOriginError::KernelBoundary { source, after })
            }
            (Err(MeasurementOriginError::Authentication(site)), Some(after)) => {
                Err(MeasurementOriginError::AuthenticationBoundary { site, after })
            }
            (Err(MeasurementOriginError::Contract), Some(after)) => {
                Err(MeasurementOriginError::ContractBoundary(after))
            }
            (Err(first), _) => Err(first),
            (Ok(value), None) => Ok(value),
            (Ok(_), Some(_)) => Err(MeasurementOriginError::Clock),
        }
    }

    fn after_kernel<T>(self, result: rustix::io::Result<T>) -> Result<T, MeasurementOriginError> {
        let after = self.remaining().err();
        match result {
            Err(source) => Err(MeasurementOriginError::KernelBoundary { source, after }),
            Ok(value) if after.is_none() => Ok(value),
            Ok(_) => Err(MeasurementOriginError::Clock),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackingRoles {
    source_and_tools: u64,
    host_helpers_and_evidence: u64,
    filesystem_overhead: u64,
    catalog: u64,
    registry: u64,
    native_domain: u64,
    swap_device: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResidentRoles {
    source_and_loader: u64,
    host_controls_and_helpers: u64,
    catalog: u64,
    registry: u64,
    native_domain: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum StaticMode {
    NativeOnly,
    KernelMeasurement,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperatorPolicy {
    schema: String,
    init_executable: PathBuf,
    actor_executable: PathBuf,
    native_count: u64,
    actor_cpu_slots: u64,
    actor_resident_bytes: u64,
    host_memory_bytes: u64,
    host_backing_bytes: u64,
    actor_task_limit: u64,
    actor_descriptors: u64,
    mode: StaticMode,
    backing: BackingRoles,
    resident: ResidentRoles,
}

impl OperatorPolicy {
    fn validate(&self) -> Result<(), MeasurementOriginError> {
        if self.schema != "crucible.measurement-operator.v1"
            || !matches!(self.native_count, 1 | 2 | 4)
            || self.actor_cpu_slots != 10
            || self.actor_resident_bytes != 16 << 30
            || self.host_memory_bytes != 20 << 30
            || self.host_backing_bytes != 64 << 30
            || self.actor_task_limit == 0
            || self.actor_descriptors != 1024
            || !self.init_executable.starts_with("/nix/store")
            || !self.actor_executable.starts_with("/nix/store")
            || !self
                .init_executable
                .ends_with("bin/crucible-measurement-init")
            || !self
                .actor_executable
                .ends_with("bin/crucible-measurement-actor")
        {
            return Err(MeasurementOriginError::Contract);
        }
        let b = &self.backing;
        let r = &self.resident;
        let backing = [
            b.source_and_tools,
            b.host_helpers_and_evidence,
            b.filesystem_overhead,
            b.catalog,
            b.registry,
            b.native_domain,
        ];
        let resident = [
            r.source_and_loader,
            r.host_controls_and_helpers,
            r.catalog,
            r.registry,
            r.native_domain,
        ];
        let expected_swap = match self.mode {
            StaticMode::NativeOnly => 0,
            StaticMode::KernelMeasurement => 4 << 30,
        };
        if b.swap_device != expected_swap || b.catalog < 8 << 30 || b.registry < 16 << 20 {
            return Err(MeasurementOriginError::Contract);
        }
        for (roles, ceiling) in [
            (backing.as_slice(), self.host_backing_bytes - expected_swap),
            (resident.as_slice(), self.actor_resident_bytes),
        ] {
            if roles.contains(&0)
                || roles
                    .iter()
                    .try_fold(0u64, |sum, value| sum.checked_add(*value))
                    .is_none_or(|sum| sum > ceiling)
            {
                return Err(MeasurementOriginError::Contract);
            }
        }
        Ok(())
    }
}

/// Fixed private kernel coordinates propagated into the same supervisor owner.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MeasurementClock {
    pub(crate) start_ns: u64,
    pub(crate) end_ns: u64,
}

impl MeasurementClock {
    pub(crate) fn span(self) -> Duration {
        Duration::from_nanos(self.end_ns - self.start_ns)
    }

    pub(crate) fn elapsed(self) -> Duration {
        match monotonic_ns() {
            Ok(now) if now >= self.start_ns && now < self.end_ns => {
                Duration::from_nanos(now - self.start_ns)
            }
            // Even a removed or enlarged class budget cannot turn an invalid
            // original kernel coordinate into live ownership.
            _ => Duration::MAX,
        }
    }
}

/// Retains one authenticated original record, policy and PID1 issuance channel.
///
/// This non-clone token preserves the original absolute kernel deadline and a
/// conservative `Instant` mapping. It cannot itself issue capacity or waive the
/// original Source, loader, role, storage or native-birth proof.
#[derive(Debug)]
#[must_use = "the original invocation must remain retained through its owner"]
pub struct MeasurementInvocationOrigin {
    started: Instant,
    start_ns: u64,
    end_ns: u64,
    _record: File,
    _policy: File,
    _issuer: UnixStream,
    // Authenticated role values move with the descriptor-owning origin. They
    // remain ceilings, not a certificate for Source or constructor costs.
    policy: OperatorPolicy,
    // Retain the digest verified by load_policy and the sealed issuance record;
    // later parent binding must not authenticate a caller-supplied digest.
    policy_digest: [u8; 32],
}

/// Immutable authored ceilings borrowed from the authenticated actor policy.
///
/// These values do not certify complete Source, descriptor, stack or factory
/// purposes and cannot publish an original account without those compiled facts.
/// The fields have no public constructor or setters.
#[derive(Debug)]
pub struct MeasurementActorAccountCeilings {
    tasks: u64,
    descriptors: u64,
    resident_bytes: u64,
    metadata_bytes: u64,
}

impl MeasurementActorAccountCeilings {
    /// Returns the authenticated actor's finite task ceiling.
    pub fn tasks(&self) -> u64 {
        self.tasks
    }

    /// Returns the authenticated actor's descriptor ceiling.
    pub fn descriptors(&self) -> u64 {
        self.descriptors
    }

    /// Returns the authenticated actor's resident ceiling.
    pub fn resident_bytes(&self) -> u64 {
        self.resident_bytes
    }

    /// Returns its authored host-control and helper metadata ceiling.
    pub fn metadata_bytes(&self) -> u64 {
        self.metadata_bytes
    }
}

impl MeasurementInvocationOrigin {
    /// Binds the actor's account ceilings to this retained authenticated origin.
    ///
    /// Authentication already validated the immutable role table. Reading its
    /// inline values does not issue credits or complete missing purpose facts.
    ///
    /// # Errors
    /// Refuses failure or expiry of the same absolute original interval.
    pub fn actor_account_ceilings(
        &self,
    ) -> Result<MeasurementActorAccountCeilings, MeasurementOriginError> {
        self.remaining()?;
        Ok(MeasurementActorAccountCeilings {
            tasks: self.policy.actor_task_limit,
            descriptors: self.policy.actor_descriptors,
            resident_bytes: self.policy.actor_resident_bytes,
            metadata_bytes: self.policy.resident.host_controls_and_helpers,
        })
    }

    /// Authenticates the one used private entry against the actual PID1 issuer.
    ///
    /// Provisional environment coordinates are never authoritative. PID1 confirms its
    /// exact record and the child it actually spawned over its own socket.
    ///
    /// # Errors
    /// Refuses repeated adoption, fabricated/orphan issuance, wrong immutable
    /// producer/policy/executable, missing seals, changed vector or expired clock.
    pub fn receive_original() -> Result<Self, MeasurementOriginError> {
        if ENTRY.swap(true, Ordering::AcqRel) {
            return Err(MeasurementOriginError::Authentication("repeated entry"));
        }
        let (policy, policy_file, digest) = load_policy()?;
        same_executable(Path::new("/proc/1/exe"), &policy.init_executable)?;
        let actor = same_executable(Path::new("/proc/self/exe"), &policy.actor_executable)?;
        let interval = provisional_interval()?;
        let mut issuer = connect_issuer(interval)?;
        interval.before()?;
        interval.after_result(authenticate_pid1_peer(&issuer))?;
        let mut record = receive_record(&issuer, interval)?;
        interval.before()?;
        if interval.after_kernel(fcntl_get_seals(&record))? != required_seals() {
            return Err(MeasurementOriginError::Authentication("record seals"));
        }
        interval.before()?;
        let metadata = interval.after_io(record.metadata())?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.len() != RECORD_BYTES as u64 {
            return Err(MeasurementOriginError::Authentication(
                "record extent/owner",
            ));
        }
        let mut bytes = [0; RECORD_BYTES];
        // SCM_RIGHTS shares the producer's open-file offset; rewind the owned
        // immutable record rather than depending on a /proc duplicate offset.
        interval.before()?;
        interval.after_io(record.rewind())?;
        interval.before()?;
        interval.after_io(record.read_exact(&mut bytes))?;
        let (start_ns, end_ns) = check_record(&bytes, digest, actor, &policy)?;
        let mut request = [0u8; 32];
        request[..16].copy_from_slice(&bytes[8..24]);
        request[16..24].copy_from_slice(&metadata.dev().to_le_bytes());
        request[24..].copy_from_slice(&metadata.ino().to_le_bytes());
        if (start_ns, end_ns) != (interval.start_ns, interval.end_ns) {
            return Err(MeasurementOriginError::Authentication(
                "original coordinates",
            ));
        }
        write_issuance(&mut issuer, &request, interval)?;
        let mut acknowledged = [0; 1];
        read_issuance(&mut issuer, &mut acknowledged, interval)?;
        if acknowledged != [1] {
            return Err(MeasurementOriginError::Authentication("PID1 adoption"));
        }
        // Instant must be sampled first: backdating the earlier sample by the
        // later kernel elapsed interval is conservative and cannot renew the cap.
        let sampled = original_host_now();
        let now = monotonic_ns()?;
        let elapsed = now
            .checked_sub(start_ns)
            .ok_or(MeasurementOriginError::Clock)?;
        if now >= end_ns {
            return Err(MeasurementOriginError::Clock);
        }
        let started = sampled
            .checked_sub(Duration::from_nanos(elapsed))
            .ok_or(MeasurementOriginError::Clock)?;
        Ok(Self {
            started,
            start_ns,
            end_ns,
            _record: record,
            _policy: policy_file,
            _issuer: issuer,
            policy,
            policy_digest: digest,
        })
    }

    pub(crate) fn supervision_coordinates(
        &self,
    ) -> Result<(Instant, MeasurementClock), MeasurementOriginError> {
        self.remaining()?;
        Ok((
            self.started,
            MeasurementClock {
                start_ns: self.start_ns,
                end_ns: self.end_ns,
            },
        ))
    }

    /// Checks the same absolute kernel interval and conservative local mapping.
    ///
    /// # Errors
    /// Refuses clock overflow, a backward kernel sample or original expiration.
    pub fn remaining(&self) -> Result<Duration, MeasurementOriginError> {
        let now = monotonic_ns()?;
        if now < self.start_ns || now >= self.end_ns {
            return Err(MeasurementOriginError::Clock);
        }
        let kernel = Duration::from_nanos(self.end_ns - now);
        let mapped = Duration::from_nanos(self.end_ns - self.start_ns)
            .checked_sub(original_host_now().saturating_duration_since(self.started))
            .ok_or(MeasurementOriginError::Clock)?;
        Ok(kernel.min(mapped))
    }
}

/// Runs the immutable private init issuer as the real root PID1.
///
/// The retained issuer refuses before effects while its genuine external
/// Source/control purpose is absent. Later child and issuance custody stays
/// reachable on refusal; returning an error terminates the disposable kernel. The
/// enclosing original VM owner must still join and physically retire it.
/// This source does not install any cgroup, mount, swap device or native factory.
///
/// # Errors
/// Refuses a non-PID1/non-root process, invalid immutable policy, endpoint reuse,
/// changed executable, wrong child adoption, clock expiration or child failure.
pub fn run_original_pid1() -> Result<(), MeasurementOriginError> {
    if rustix::process::getpid().as_raw_nonzero().get() != 1 || !rustix::process::getuid().is_root()
    {
        return Err(MeasurementOriginError::Authentication("real root PID1"));
    }
    let start_ns = monotonic_ns()?;
    let end_ns = start_ns
        .checked_add(RUNTIME_NS)
        .ok_or(MeasurementOriginError::Clock)?;
    issuer_custody::run_original(OriginalInterval { start_ns, end_ns })?;
    // Successful actor completion is already sent through the retained parent
    // port. Poweroff terminates this disposable domain; the parent still must
    // wait its actual QEMU Child and retire the physical ownership.
    rustix::system::reboot(rustix::system::RebootCommand::PowerOff)?;
    Err(MeasurementOriginError::Authentication(
        "owned kernel poweroff returned",
    ))
}

fn provisional_interval() -> Result<OriginalInterval, MeasurementOriginError> {
    let coordinate = |name| {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(MeasurementOriginError::Authentication(
                "provisional interval",
            ))
    };
    validate_provisional_interval(coordinate(START_ENV)?, coordinate(END_ENV)?)
}

fn validate_provisional_interval(
    start_ns: u64,
    end_ns: u64,
) -> Result<OriginalInterval, MeasurementOriginError> {
    if end_ns.checked_sub(start_ns) != Some(RUNTIME_NS) {
        return Err(MeasurementOriginError::Authentication("provisional span"));
    }
    let interval = OriginalInterval { start_ns, end_ns };
    interval.before()?;
    Ok(interval)
}

fn send_record(
    peer: &UnixStream,
    record: &File,
    interval: OriginalInterval,
) -> Result<(), MeasurementOriginError> {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    let rights = [record.as_fd()];
    loop {
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&rights)) {
            return Err(MeasurementOriginError::Authentication(
                "record control extent",
            ));
        }
        interval.before()?;
        let sent = sendmsg(
            peer,
            &[std::io::IoSlice::new(&[1])],
            &mut control,
            SendFlags::NOSIGNAL,
        );
        match sent {
            Err(rustix::io::Errno::AGAIN) => {
                interval.after_kernel(Ok(()))?;
                wait_ready(peer, rustix::event::PollFlags::OUT, interval)?;
            }
            result => {
                if interval.after_kernel(result)? != 1 {
                    return Err(MeasurementOriginError::Authentication("record send extent"));
                }
                return Ok(());
            }
        }
    }
}

fn receive_record(
    peer: &UnixStream,
    interval: OriginalInterval,
) -> Result<File, MeasurementOriginError> {
    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg};
    loop {
        let mut marker = [0];
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        interval.before()?;
        let received = recvmsg(
            peer,
            &mut [std::io::IoSliceMut::new(&mut marker)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        );
        let received = match received {
            Err(rustix::io::Errno::AGAIN) => {
                interval.after_kernel(Ok(()))?;
                wait_ready(peer, rustix::event::PollFlags::IN, interval)?;
                continue;
            }
            result => interval.after_kernel(result)?,
        };
        // Drain owns every received right, including malformed packets. No
        // numeric descriptor is reconstructed or left inherited on refusal.
        let mut record = None;
        let mut invalid = received.bytes != 1
            || marker != [1]
            || received
                .flags
                .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC);
        for message in control.drain() {
            match message {
                RecvAncillaryMessage::ScmRights(rights) => {
                    for right in rights {
                        if record.is_some() {
                            invalid = true;
                        } else {
                            record = Some(File::from(right));
                        }
                    }
                }
                _ => invalid = true,
            }
        }
        if invalid {
            return Err(MeasurementOriginError::Authentication(
                "record ancillary extent",
            ));
        }
        let record = record.ok_or(MeasurementOriginError::Authentication("missing record"))?;
        interval.before()?;
        if !interval
            .after_kernel(rustix::io::fcntl_getfd(&record))?
            .contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(MeasurementOriginError::Authentication(
                "record exec custody",
            ));
        }
        return Ok(record);
    }
}

fn connect_issuer(interval: OriginalInterval) -> Result<UnixStream, MeasurementOriginError> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    interval.before()?;
    let fd = interval.after_kernel(rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    ))?;
    let address = SocketAddrUnix::new(ISSUER_PATH)?;
    interval.before()?;
    let connected = rustix::net::connect(&fd, &address);
    match connected {
        Err(rustix::io::Errno::INPROGRESS) => {
            interval.before()?;
            wait_ready(&fd, rustix::event::PollFlags::OUT, interval)?;
            let status = interval.after_kernel(rustix::net::sockopt::socket_error(&fd))?;
            interval.after_kernel(status)?;
        }
        result => interval.after_kernel(result)?,
    }
    Ok(UnixStream::from(fd))
}

fn wait_ready<F: AsFd>(
    fd: &F,
    events: rustix::event::PollFlags,
    interval: OriginalInterval,
) -> Result<(), MeasurementOriginError> {
    let timeout = rustix::event::Timespec::try_from(interval.before()?)
        .map_err(|_| MeasurementOriginError::Clock)?;
    let mut descriptors = [rustix::event::PollFd::new(fd, events)];
    let result = rustix::event::poll(&mut descriptors, Some(&timeout));
    interval.after_kernel(result)?;
    Ok(())
}

fn read_issuance(
    peer: &mut UnixStream,
    mut bytes: &mut [u8],
    interval: OriginalInterval,
) -> Result<(), MeasurementOriginError> {
    while !bytes.is_empty() {
        interval.before()?;
        match peer.read(bytes) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                interval.after_io(Ok(()))?;
                wait_ready(peer, rustix::event::PollFlags::IN, interval)?;
            }
            result => {
                let count = interval.after_io(result)?;
                if count == 0 {
                    return Err(MeasurementOriginError::Authentication(
                        "issuance channel closed",
                    ));
                }
                bytes = &mut bytes[count..];
            }
        }
    }
    Ok(())
}

fn write_issuance(
    peer: &mut UnixStream,
    mut bytes: &[u8],
    interval: OriginalInterval,
) -> Result<(), MeasurementOriginError> {
    while !bytes.is_empty() {
        interval.before()?;
        match peer.write(bytes) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                interval.after_io(Ok(()))?;
                wait_ready(peer, rustix::event::PollFlags::OUT, interval)?;
            }
            result => {
                let count = interval.after_io(result)?;
                if count == 0 {
                    return Err(MeasurementOriginError::Authentication(
                        "issuance channel closed",
                    ));
                }
                bytes = &bytes[count..];
            }
        }
    }
    Ok(())
}

fn authenticate_pid1_peer(peer: &UnixStream) -> Result<(), MeasurementOriginError> {
    let credentials = rustix::net::sockopt::socket_peercred(peer)?;
    if credentials.pid.as_raw_nonzero().get() != 1 || !credentials.uid.is_root() {
        return Err(MeasurementOriginError::Authentication(
            "actual root PID1 socket",
        ));
    }
    Ok(())
}

fn load_policy() -> Result<(OperatorPolicy, File, [u8; 32]), MeasurementOriginError> {
    let path = std::fs::canonicalize(POLICY_PATH)?;
    let mut file = immutable_file(&path)?;
    let mut bytes = Vec::with_capacity(MAX_POLICY_BYTES);
    (&mut file)
        .take((MAX_POLICY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(MeasurementOriginError::Contract);
    }
    let policy: OperatorPolicy =
        serde_json::from_slice(&bytes).map_err(|_| MeasurementOriginError::Contract)?;
    policy.validate()?;
    Ok((policy, file, *blake3::hash(&bytes).as_bytes()))
}

fn immutable_file(path: &Path) -> Result<File, MeasurementOriginError> {
    if !path.starts_with("/nix/store") {
        return Err(MeasurementOriginError::Authentication(
            "immutable store identity",
        ));
    }
    let normalized: PathBuf = path.components().collect();
    if normalized.as_os_str() != path.as_os_str()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(MeasurementOriginError::Authentication(
            "immutable path components",
        ));
    }
    let canonical = std::fs::canonicalize(path)?;
    if canonical != path || !canonical.starts_with("/nix/store") {
        return Err(MeasurementOriginError::Authentication(
            "immutable canonical store identity",
        ));
    }
    let store = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits() as i32)
        .open("/nix/store")?;
    let relative = canonical
        .strip_prefix("/nix/store")
        .map_err(|_| MeasurementOriginError::Authentication("immutable store ancestry"))?;
    // Canonicalization names the reviewed path; the kernel also refuses a
    // symlink/magic-link replacement in ANY descendant during the actual open.
    let file = open_store_descendant(&store, relative)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o222 != 0 {
        return Err(MeasurementOriginError::Authentication(
            "immutable file owner/mode",
        ));
    }
    Ok(file)
}

fn open_store_descendant(store: &File, relative: &Path) -> Result<File, MeasurementOriginError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    let descriptor = openat2(
        store,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    Ok(File::from(descriptor))
}

fn same_executable(process: &Path, expected: &Path) -> Result<(u64, u64), MeasurementOriginError> {
    let actual = File::open(process)?.metadata()?;
    let expected = immutable_file(expected)?.metadata()?;
    if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
        return Err(MeasurementOriginError::Authentication(
            "actual executable inode",
        ));
    }
    Ok((actual.dev(), actual.ino()))
}

fn required_seals() -> SealFlags {
    SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE
}

// The private issuer clock bounds host ownership and waiting; its coordinates
// never enter a guest world, semantic digest or execution result.
// crucible-lint: allow clippy-disallowed-method -- this private original host deadline is outside modeled time.
// crucible-lint: allow rust-allow -- one concrete host clock sampler preserves the authenticated original interval.
#[allow(clippy::disallowed_methods)]
fn original_host_now() -> Instant {
    Instant::now()
}

fn monotonic_ns() -> Result<u64, MeasurementOriginError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| seconds.checked_add(u64::try_from(now.tv_nsec).ok()?))
        .ok_or(MeasurementOriginError::Clock)
}

fn check_record(
    bytes: &[u8; RECORD_BYTES],
    digest: [u8; 32],
    actor: (u64, u64),
    policy: &OperatorPolicy,
) -> Result<(u64, u64), MeasurementOriginError> {
    if &bytes[..8] != MAGIC || bytes[8..24] == [0; 16] || bytes[24..56] != digest {
        return Err(MeasurementOriginError::Authentication("record identity"));
    }
    let read = |index: usize| {
        let mut field = [0; 8];
        field.copy_from_slice(&bytes[56 + index * 8..64 + index * 8]);
        u64::from_le_bytes(field)
    };
    let start = read(0);
    let end = read(1);
    if start == 0 || start.checked_add(RUNTIME_NS) != Some(end) {
        return Err(MeasurementOriginError::Clock);
    }
    if [
        read(2),
        read(3),
        read(4),
        read(5),
        read(6),
        read(7),
        read(8),
    ] != [
        actor.0,
        actor.1,
        policy.native_count,
        policy.actor_cpu_slots,
        policy.actor_resident_bytes,
        policy.host_backing_bytes,
        policy.host_memory_bytes,
    ] {
        return Err(MeasurementOriginError::Authentication(
            "record complete vector",
        ));
    }
    Ok((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod capture_controls;

    #[test]
    fn fabricated_socket_and_orphan_style_record_do_not_issue() {
        let (peer, _other) = UnixStream::pair().unwrap();
        assert!(matches!(
            authenticate_pid1_peer(&peer),
            Err(MeasurementOriginError::Authentication(
                "actual root PID1 socket"
            ))
        ));
        // A real sealed memory file changes neither socket credentials nor the
        // issuer's independently retained actual Child identity.
        let record = memfd_create("fabricated-original", MemfdFlags::ALLOW_SEALING).unwrap();
        fcntl_add_seals(&record, required_seals()).unwrap();
        assert_eq!(fcntl_get_seals(&record).unwrap(), required_seals());
        assert!(authenticate_pid1_peer(&peer).is_err());
    }

    #[test]
    fn ordinary_caller_cannot_run_original_pid1_producer() {
        assert!(matches!(
            run_original_pid1(),
            Err(MeasurementOriginError::Authentication("real root PID1"))
        ));
    }

    #[test]
    fn immutable_policy_cannot_adopt_an_arbitrary_caller_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(matches!(
            immutable_file(file.path()),
            Err(MeasurementOriginError::Authentication(
                "immutable store identity"
            ))
        ));
    }
    fn policy() -> OperatorPolicy {
        serde_json::from_value(serde_json::json!({
            "schema":"crucible.measurement-operator.v1",
            "initExecutable":"/nix/store/FIXTURE/bin/crucible-measurement-init",
            "actorExecutable":"/nix/store/FIXTURE/bin/crucible-measurement-actor",
            "nativeCount":4, "actorCpuSlots":10,
            "actorResidentBytes":16u64<<30, "hostMemoryBytes":20u64<<30,
            "hostBackingBytes":64u64<<30, "actorTaskLimit":1024,
            "actorDescriptors":1024, "mode":"nativeOnly",
            "backing":{"sourceAndTools":1,"hostHelpersAndEvidence":1,
                "filesystemOverhead":1,"catalog":8u64<<30,"registry":16u64<<20,
                "nativeDomain":16u64<<30,"swapDevice":0},
            "resident":{"sourceAndLoader":1,"hostControlsAndHelpers":1,
                "catalog":1,"registry":1,"nativeDomain":6u64<<30}
        }))
        .unwrap()
    }

    fn record(policy: &OperatorPolicy) -> [u8; RECORD_BYTES] {
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].fill(1);
        bytes[24..56].fill(2);
        for (index, field) in [
            1,
            1 + RUNTIME_NS,
            3,
            4,
            policy.native_count,
            policy.actor_cpu_slots,
            policy.actor_resident_bytes,
            policy.host_backing_bytes,
            policy.host_memory_bytes,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[56 + index * 8..64 + index * 8].copy_from_slice(&field.to_le_bytes());
        }
        bytes
    }

    fn live_transfer_interval() -> OriginalInterval {
        let start_ns = monotonic_ns().unwrap();
        OriginalInterval {
            start_ns,
            end_ns: start_ns + RUNTIME_NS,
        }
    }

    #[test]
    fn transferred_record_preserves_actual_inode_seals_and_exec_closed_custody() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let fd = memfd_create(
            "closed-record",
            MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
        )
        .unwrap();
        let mut original = File::from(fd);
        original.write_all(&[7; RECORD_BYTES]).unwrap();
        fcntl_add_seals(&original, required_seals()).unwrap();
        let identity = original.metadata().unwrap();
        let interval = live_transfer_interval();

        send_record(&sender, &original, interval).unwrap();
        let mut received = receive_record(&receiver, interval).unwrap();
        assert_eq!(received.metadata().unwrap().ino(), identity.ino());
        assert_eq!(fcntl_get_seals(&received).unwrap(), required_seals());
        assert!(
            rustix::io::fcntl_getfd(&original)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(
            rustix::io::fcntl_getfd(&received)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        received.rewind().unwrap();
        let mut bytes = [0; RECORD_BYTES];
        received.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [7; RECORD_BYTES]);
        assert!(authenticate_pid1_peer(&receiver).is_err());
    }

    #[test]
    fn transfer_refuses_missing_wrong_marker_and_extra_rights_without_retention() {
        use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
        for (marker, count) in [(1, 0), (0, 1), (1, 2), (1, 3)] {
            let (sender, receiver) = UnixStream::pair().unwrap();
            let record = File::from(memfd_create("rejected-record", MemfdFlags::CLOEXEC).unwrap());
            let rights = [record.as_fd(); 3];
            let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(3))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            if count != 0 {
                assert!(control.push(SendAncillaryMessage::ScmRights(&rights[..count])));
            }
            // A retained /proc entry counts actual aliases for this inode,
            // without inferring closure from an arbitrary unrelated IO error.
            let identity = record.metadata().unwrap();
            let aliases = || {
                std::fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .filter(|entry| {
                        entry
                            .as_ref()
                            .ok()
                            .and_then(|entry| std::fs::metadata(entry.path()).ok())
                            .is_some_and(|meta| {
                                meta.dev() == identity.dev() && meta.ino() == identity.ino()
                            })
                    })
                    .count()
            };
            let before = aliases();
            assert_eq!(
                sendmsg(
                    &sender,
                    &[std::io::IoSlice::new(&[marker])],
                    &mut control,
                    SendFlags::NOSIGNAL
                )
                .unwrap(),
                1
            );
            assert!(receive_record(&receiver, live_transfer_interval()).is_err());
            assert_eq!(aliases(), before);
        }
    }

    #[test]
    fn transfer_refuses_eof_expired_interval_and_mismatched_provisional_span() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        drop(sender);
        assert!(receive_record(&receiver, live_transfer_interval()).is_err());
        let (sender, receiver) = UnixStream::pair().unwrap();
        let file = File::from(memfd_create("expired", MemfdFlags::CLOEXEC).unwrap());
        let expired = OriginalInterval {
            start_ns: 0,
            end_ns: 1,
        };
        assert!(send_record(&sender, &file, expired).is_err());
        assert!(receive_record(&receiver, expired).is_err());
        let now = monotonic_ns().unwrap();
        assert!(validate_provisional_interval(now, now + RUNTIME_NS + 1).is_err());
        assert!(validate_provisional_interval(now + 1, now).is_err());
        assert!(validate_provisional_interval(0, RUNTIME_NS).is_err());
        assert!(validate_provisional_interval(now, now + RUNTIME_NS).is_ok());
    }

    #[test]
    fn record_requires_exact_nonce_policy_executable_vector_and_original_span() {
        let policy = policy();
        policy.validate().unwrap();
        let original = record(&policy);
        assert_eq!(
            check_record(&original, [2; 32], (3, 4), &policy).unwrap(),
            (1, 1 + RUNTIME_NS)
        );
        for index in [0, 8, 24, 64, 72, 80, 88, 96, 104, 112, 120] {
            let mut changed = original;
            if index == 8 {
                changed[8..24].fill(0);
            } else {
                changed[index] ^= 1;
            }
            assert!(
                check_record(&changed, [2; 32], (3, 4), &policy).is_err(),
                "field {index}"
            );
        }
        assert!(check_record(&original, [7; 32], (3, 4), &policy).is_err());
        assert!(check_record(&original, [2; 32], (3, 5), &policy).is_err());
    }

    #[test]
    fn named_roles_reject_overflow_missing_resources_and_wrong_static_swap_mode() {
        let mut policy = policy();
        policy.validate().unwrap();
        policy.backing.swap_device = 4 << 30;
        assert!(policy.validate().is_err());
        policy.mode = StaticMode::KernelMeasurement;
        policy.validate().unwrap();
        policy.backing.native_domain = u64::MAX;
        assert!(policy.validate().is_err());
        policy.backing.native_domain = 16 << 30;
        policy.resident.source_and_loader = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn expired_postcheck_keeps_actual_io_failure_and_rejects_success() {
        let now = monotonic_ns().unwrap();
        let interval = OriginalInterval {
            start_ns: 0,
            end_ns: now - 1,
        };
        let directory = tempfile::tempdir().unwrap();
        let result = interval.after_io(File::open(directory.path().join("absent")));
        assert!(matches!(result,Err(MeasurementOriginError::IoBoundary {
            source, after:Some(OriginalClockRefusal::Expired)
        }) if source.kind()==std::io::ErrorKind::NotFound));
        assert!(matches!(
            interval.after_io(Ok(())),
            Err(MeasurementOriginError::Clock)
        ));
        assert!(matches!(
            interval.before(),
            Err(MeasurementOriginError::Clock)
        ));
    }

    #[test]
    fn expired_postcheck_keeps_actual_kernel_failure() {
        let file = tempfile::tempfile().unwrap();
        let now = monotonic_ns().unwrap();
        let interval = OriginalInterval {
            start_ns: 0,
            end_ns: now - 1,
        };
        let original_error = fcntl_get_seals(&file).unwrap_err();
        assert!(matches!(interval.after_kernel(fcntl_get_seals(&file)),
            Err(MeasurementOriginError::KernelBoundary {
                source,after:Some(OriginalClockRefusal::Expired)
            }) if source==original_error));
    }

    #[test]
    fn actual_bounded_socket_transfer_does_not_authenticate_a_caller_peer() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let now = monotonic_ns().unwrap();
        let interval = OriginalInterval {
            start_ns: now,
            end_ns: now + 1_000_000_000,
        };
        write_issuance(&mut sender, &[1, 2, 3], interval).unwrap();
        let mut actual = [0; 3];
        read_issuance(&mut receiver, &mut actual, interval).unwrap();
        assert_eq!(actual, [1, 2, 3]);
        assert!(authenticate_pid1_peer(&receiver).is_err());
        drop(sender);
        let error = read_issuance(&mut receiver, &mut [0], interval).unwrap_err();
        assert!(matches!(
            error,
            MeasurementOriginError::Authentication("issuance channel closed")
        ));
    }

    #[test]
    fn actual_nonblocking_wait_cannot_renew_original_expiration() {
        let (_sender, mut receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let start_ns = monotonic_ns().unwrap();
        let interval = OriginalInterval {
            start_ns,
            end_ns: start_ns + 5_000_000,
        };
        assert!(matches!(
            read_issuance(&mut receiver, &mut [0], interval),
            Err(MeasurementOriginError::Clock)
        ));
        assert!(monotonic_ns().unwrap() >= interval.end_ns);
    }
    // These controlled tokens exercise the consumed supervision mechanism only.
    // They never authenticate PID1, issue a role or certify physical admission.
    pub(super) fn mechanism_origin(age: Duration, span: Duration) -> MeasurementInvocationOrigin {
        let sampled = original_host_now();
        let now = monotonic_ns().unwrap();
        let age_ns = u64::try_from(age.as_nanos()).unwrap();
        let span_ns = u64::try_from(span.as_nanos()).unwrap();
        let (issuer, peer) = UnixStream::pair().unwrap();
        drop(peer);
        MeasurementInvocationOrigin {
            started: sampled.checked_sub(age).unwrap(),
            start_ns: now - age_ns,
            end_ns: now - age_ns + span_ns,
            _record: tempfile::tempfile().unwrap(),
            _policy: tempfile::tempfile().unwrap(),
            _issuer: issuer,
            policy: policy(),
            policy_digest: [0; 32],
        }
    }

    pub(super) fn finite_budgets(
        duration: Duration,
    ) -> crate::host_supervision::HostOperationBudgets {
        use crate::host_supervision::*;
        HostOperationBudgets {
            classes: [HostOperationBudget::finite(duration); HOST_OPERATION_CLASS_COUNT],
        }
    }

    #[test]
    fn consumed_mechanism_counts_real_prior_elapsed_preparation_without_new_start() {
        use crate::host_supervision::*;
        let origin = mechanism_origin(Duration::from_millis(50), Duration::from_secs(60));
        let original_ns = origin.start_ns;
        let mut bootstrap = HostSupervisionBootstrap::from_measurement_origin(
            origin,
            finite_budgets(Duration::from_secs(1)),
        )
        .unwrap();
        assert!(bootstrap.wait_slice().unwrap() <= Duration::from_secs(1));
        // An already spent class budget refuses, despite a still-live outer cap.
        let spent = mechanism_origin(Duration::from_millis(50), Duration::from_secs(60));
        assert!(matches!(
            HostSupervisionBootstrap::from_measurement_origin(
                spent,
                finite_budgets(Duration::from_millis(1))
            ),
            Err(HostSupervisionError::DeadlineExpired {
                class: HostOperationClass::Preparation,
                ..
            })
        ));
        assert_eq!(bootstrap.original_measurement_start_for_test(), original_ns);
    }

    #[test]
    fn published_mechanism_retains_same_kernel_origin_and_rejects_removal_or_extension() {
        use crate::host_services::HostServiceBootstrap;
        use crate::host_supervision::*;
        let origin = mechanism_origin(Duration::from_millis(10), Duration::from_secs(60));
        let original_ns = origin.start_ns;
        let bootstrap = HostSupervisionBootstrap::from_measurement_origin(
            origin,
            finite_budgets(Duration::from_secs(30)),
        )
        .unwrap();
        let accounts = HostServiceBootstrap::new(1, 1, 1 << 20, 1 << 20)
            .unwrap()
            .reserve_structure(
                HostSupervisionBootstrap::structure_bytes().unwrap()
                    + HostServiceBootstrap::control_bytes().unwrap(),
            )
            .unwrap();
        let (root, prep) = bootstrap.publish(&accounts).unwrap();
        let child = root
            .new_budget_owner(finite_budgets(Duration::from_secs(30)))
            .unwrap();
        assert_eq!(
            root.outer_cap_binding().unwrap().original_monotonic_ns,
            original_ns
        );
        assert_eq!(
            child.outer_cap_binding().unwrap().original_monotonic_ns,
            original_ns
        );
        assert!(matches!(
            child.amend_outer_cap(0, None),
            Err(HostSupervisionError::InvalidBudget)
        ));
        assert!(matches!(
            root.amend_outer_cap(0, Some(Duration::from_secs(61))),
            Err(HostSupervisionError::InvalidBudget)
        ));
        root.amend_outer_cap(0, Some(Duration::from_secs(50)))
            .unwrap();
        assert_eq!(
            child.outer_cap_binding().unwrap().allowance,
            Some(Duration::from_secs(50))
        );
        root.cancel().unwrap();
        assert!(prep.wait_slice().is_err());
        assert!(child.verify_original_live().is_err());
    }

    #[test]
    fn real_positive_elapsed_original_end_expires_nested_operation() {
        use crate::host_services::HostServiceBootstrap;
        use crate::host_supervision::*;
        let origin = mechanism_origin(Duration::ZERO, Duration::from_millis(20));
        let bootstrap = HostSupervisionBootstrap::from_measurement_origin(
            origin,
            finite_budgets(Duration::from_secs(1)),
        )
        .unwrap();
        let accounts = HostServiceBootstrap::new(1, 1, 1 << 20, 1 << 20)
            .unwrap()
            .reserve_structure(
                HostSupervisionBootstrap::structure_bytes().unwrap()
                    + HostServiceBootstrap::control_bytes().unwrap(),
            )
            .unwrap();
        let (root, _prep) = bootstrap.publish(&accounts).unwrap();
        let child = root
            .new_budget_owner(finite_budgets(Duration::from_secs(1)))
            .unwrap();
        let work = child.begin(HostOperationClass::Setup).unwrap();
        while work.wait_for_change().is_ok() {}
        assert!(matches!(
            work.wait_slice(),
            Err(HostSupervisionError::Terminal {
                state: HostOperationState::Expired
            })
        ));
        assert!(matches!(
            root.verify_original_live(),
            Err(HostSupervisionError::Terminal {
                state: HostOperationState::Expired
            })
        ));
        assert!(
            root.amend_outer_cap(0, Some(Duration::from_secs(1)))
                .is_err()
        );
    }

    #[test]
    fn private_absolute_end_refuses_new_and_existing_cleanup_without_changing_ordinary_cleanup() {
        use crate::host_services::HostServiceBootstrap;
        use crate::host_supervision::*;
        let origin = mechanism_origin(Duration::ZERO, Duration::from_millis(40));
        let bootstrap = HostSupervisionBootstrap::from_measurement_origin(
            origin,
            finite_budgets(Duration::from_secs(1)),
        )
        .unwrap();
        let accounts = HostServiceBootstrap::new(1, 1, 1 << 20, 1 << 20)
            .unwrap()
            .reserve_structure(
                HostSupervisionBootstrap::structure_bytes().unwrap()
                    + HostServiceBootstrap::control_bytes().unwrap(),
            )
            .unwrap();
        let (root, _prep) = bootstrap.publish(&accounts).unwrap();
        let cleanup = root.begin_control(HostOperationClass::Cleanup).unwrap();
        let ordinary = HostOperationSupervisor::new(
            finite_budgets(Duration::from_secs(1)),
            Some(Duration::from_millis(20)),
        )
        .unwrap();
        let timeout = rustix::event::Timespec::try_from(Duration::from_millis(50)).unwrap();
        rustix::event::poll(&mut [], Some(&timeout)).unwrap();
        // A private authenticated invocation has ended even for Cleanup. This
        // is distinct from an ordinary authored outer cap's existing semantics.
        assert!(cleanup.wait_slice().is_err());
        assert!(root.begin_control(HostOperationClass::Cleanup).is_err());
        assert!(
            ordinary
                .begin_control(HostOperationClass::Cleanup)
                .unwrap()
                .wait_slice()
                .is_ok()
        );
    }
    #[test]
    fn lexical_store_escape_refuses_before_file_owner_or_executable_matching() {
        let path = Path::new("/nix/store/../../tmp/caller/bin/crucible-measurement-actor");
        assert!(matches!(
            immutable_file(path),
            Err(MeasurementOriginError::Authentication(
                "immutable path components"
            ))
        ));
        let dotted = Path::new("/nix/store/./caller/bin/crucible-measurement-init");
        assert!(matches!(
            immutable_file(dotted),
            Err(MeasurementOriginError::Authentication(
                "immutable path components"
            ))
        ));
    }

    #[test]
    fn actual_descendant_open_rejects_intermediate_symlink_and_parent_escape() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("actor"), b"caller").unwrap();
        symlink(outside.path(), root.path().join("substituted")).unwrap();
        let directory = File::open(root.path()).unwrap();
        assert!(matches!(
            open_store_descendant(&directory, Path::new("substituted/actor")),
            Err(MeasurementOriginError::Kernel(rustix::io::Errno::LOOP))
        ));
        assert!(matches!(
            open_store_descendant(&directory, Path::new("../actor")),
            Err(MeasurementOriginError::Kernel(rustix::io::Errno::XDEV))
        ));
        std::fs::write(root.path().join("actual"), b"bounded").unwrap();
        let mut actual = open_store_descendant(&directory, Path::new("actual")).unwrap();
        let mut bytes = [0; 7];
        actual.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"bounded");
        // A successful beneath-open is ancestry mechanism evidence; an arbitrary
        // temporary file still cannot become the immutable operator identity.
        assert!(immutable_file(&root.path().join("actual")).is_err());
    }
    #[test]
    fn private_cleanup_pre_end_slice_is_bounded_by_same_original_remaining() {
        use crate::host_services::HostServiceBootstrap;
        use crate::host_supervision::*;
        let origin = mechanism_origin(Duration::ZERO, Duration::from_secs(1));
        let mut budgets = finite_budgets(Duration::from_secs(60));
        budgets.classes[HostOperationClass::Cleanup as usize].poll_interval =
            Duration::from_secs(5);
        let bootstrap = HostSupervisionBootstrap::from_measurement_origin(origin, budgets).unwrap();
        let accounts = HostServiceBootstrap::new(1, 1, 1 << 20, 1 << 20)
            .unwrap()
            .reserve_structure(
                HostSupervisionBootstrap::structure_bytes().unwrap()
                    + HostServiceBootstrap::control_bytes().unwrap(),
            )
            .unwrap();
        let (root, _prep) = bootstrap.publish(&accounts).unwrap();
        let cleanup = root.begin_control(HostOperationClass::Cleanup).unwrap();
        let before = root.outer_cap_binding().unwrap();
        let current = monotonic_ns().unwrap();
        let original_remaining =
            Duration::from_nanos(before.original_monotonic_ns + 1_000_000_000 - current);
        assert!(cleanup.wait_slice().unwrap() <= original_remaining);
    }
}

#[cfg(test)]
mod actor_role_tests {
    use super::*;

    #[test]
    fn actual_inline_roles_do_not_require_or_issue_an_account() {
        // This retained mechanism token does not claim live PID1 adoption.
        let origin = super::tests::mechanism_origin(Duration::ZERO, Duration::from_secs(60));
        let roles = origin.actor_account_ceilings().unwrap();
        assert_eq!(roles.tasks(), origin.policy.actor_task_limit);
        assert_eq!(roles.descriptors(), 1024);
        assert_eq!(roles.resident_bytes(), 16 << 30);
        assert_eq!(
            roles.metadata_bytes(),
            origin.policy.resident.host_controls_and_helpers
        );
    }

    #[test]
    fn expired_origin_refuses_role_binding_before_account_construction() {
        let origin =
            super::tests::mechanism_origin(Duration::from_millis(50), Duration::from_millis(1));
        assert!(matches!(
            origin.actor_account_ceilings(),
            Err(MeasurementOriginError::Clock)
        ));
    }
}

#[cfg(test)]
mod capture_owner_tests {
    use super::*;
    use crate::host_services::HostServiceBootstrap;
    use crate::host_supervision::*;

    struct OriginalFixture {
        owner: HostOperationSupervisor,
        guard: HostOperationGuard,
        budgets: HostOperationBudgets,
        _accounts: (
            crate::host_services::HostServiceAllocator,
            crate::host_services::HostServiceAllocator,
        ),
    }

    fn original() -> OriginalFixture {
        // This authenticates the retained clock mechanism only, not PID1
        // adoption, a complete original Source purpose or factory eligibility.
        let origin = super::tests::mechanism_origin(Duration::ZERO, Duration::from_secs(60));
        let budgets = super::tests::finite_budgets(Duration::from_secs(60));
        let bootstrap = HostSupervisionBootstrap::from_measurement_origin(origin, budgets).unwrap();
        let accounts = HostServiceBootstrap::new(1, 1, 1 << 20, 1 << 20)
            .unwrap()
            .reserve_structure(
                HostSupervisionBootstrap::structure_bytes().unwrap()
                    + HostServiceBootstrap::control_bytes().unwrap(),
            )
            .unwrap();
        let (owner, guard) = bootstrap.publish(&accounts).unwrap();
        let accounts = accounts.publish();
        OriginalFixture {
            owner,
            guard,
            budgets,
            _accounts: accounts,
        }
    }

    #[test]
    fn service_identity_uses_each_actual_nonreused_child_roster() {
        let fixture = original();
        let (owner, guard, budgets) = (&fixture.owner, &fixture.guard, fixture.budgets);
        let before = guard.status().unwrap();
        let first = guard
            .begin_original_capture_supervisor(owner, budgets)
            .unwrap();
        let second = guard
            .begin_original_capture_supervisor(owner, budgets)
            .unwrap();
        let first_id = first
            .original_capture_service_owner(guard, [7; 32])
            .unwrap();
        let second_id = second
            .original_capture_service_owner(guard, [7; 32])
            .unwrap();

        assert_ne!(first_id, second_id);
        assert_eq!(first.cap_id(), second.cap_id());
        assert_eq!(
            first
                .original_capture_service_owner(guard, [7; 32])
                .unwrap(),
            first_id
        );
        assert_eq!(guard.status().unwrap().operation_id, before.operation_id);
        assert_eq!(guard.status().unwrap().completed_work_units, 0);
        assert!(guard.wait_slice().is_ok());
    }

    #[test]
    fn service_identity_refuses_root_different_original_and_zero_daemon() {
        let fixture = original();
        let (owner, guard, budgets) = (&fixture.owner, &fixture.guard, fixture.budgets);
        let child = guard
            .begin_original_capture_supervisor(owner, budgets)
            .unwrap();
        let other_fixture = original();
        let other = &other_fixture.guard;

        for (supplied, original, daemon) in [
            (owner, guard, [7; 32]),
            (&child, other, [7; 32]),
            (&child, guard, [0; 32]),
        ] {
            assert_eq!(
                supplied.original_capture_service_owner(original, daemon),
                Err(HostSupervisionError::InvalidBudget),
            );
        }
        assert!(guard.wait_slice().is_ok());
    }

    #[test]
    fn service_identity_preserves_the_same_original_terminal_refusal() {
        let fixture = original();
        let (owner, guard, budgets) = (&fixture.owner, &fixture.guard, fixture.budgets);
        let child = guard
            .begin_original_capture_supervisor(owner, budgets)
            .unwrap();
        owner.cancel().unwrap();
        assert_eq!(
            child.original_capture_service_owner(guard, [7; 32]),
            Err(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            }),
        );
    }
}
