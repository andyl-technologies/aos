//! Single-process guardian startup, readiness, and absolute deadline wait.

use std::io::IoSlice;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use aos_sandbox_core::format::{DecodeLimits, decode_trust_policy};
use aos_sandbox_core::model::{KeyReference, KeyUsage, SignaturePurpose};
use aos_sandbox_core::{
    BrokerPlanTrustAnchor, MediaType, NodeId, ObjectDigest, OwnershipLeaseTrustAnchor,
    PortableMediaType, RawClockProvenance, RawPairedClockSample, RevocationScopeId,
    descriptor_for_bytes,
};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::inherited_fd::duplicate_inherited_descriptor;
use aos_sandbox_linux::pidfd::SingleThreadedProcess;
use rustix::fs::{FileType, OFlags, SealFlags, fcntl_get_seals, fcntl_getfl, fstat};
use rustix::net::{
    AddressFamily, SendAncillaryBuffer, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
    sendmsg_addr, socket_with,
};
use rustix::time::{ClockId, Timespec, clock_gettime};
use sha2::{Digest as _, Sha256};

use crate::{
    GuardianArtifacts, GuardianAuthority, GuardianAuthorityError, GuardianStateStore,
    GuardianStateStoreError, ReadinessConfirmedGuardian,
};

const ACTIVATION_FD_BASE: i32 = 3;
const PLAN_POLICY: &str = "broker-plan-policy.cbor";
const PLAN_PUBLIC_KEY: &str = "broker-plan-public-key";
const PLAN_REVOCATION_SCOPE: &str = "broker-revocation-scope";
const LEASE_POLICY: &str = "ownership-lease-policy.cbor";
const LEASE_PUBLIC_KEY: &str = "ownership-lease-public-key";
const NODE_ID: &str = "node-id";
const BROKER_PLAN: &str = "broker-plan.cbor";
const BROKER_PLAN_SIGNATURE: &str = "broker-plan-signature.cbor";
const OWNERSHIP_LEASE: &str = "ownership-lease.cbor";
const OWNERSHIP_LEASE_SIGNATURE: &str = "ownership-lease-signature.cbor";
const ACTIVATION_NAMES: [&str; 10] = [
    PLAN_POLICY,
    PLAN_PUBLIC_KEY,
    PLAN_REVOCATION_SCOPE,
    LEASE_POLICY,
    LEASE_PUBLIC_KEY,
    NODE_ID,
    BROKER_PLAN,
    BROKER_PLAN_SIGNATURE,
    OWNERSHIP_LEASE,
    OWNERSHIP_LEASE_SIGNATURE,
];
const CLOCK_PROVENANCE: [u8; 16] = *b"aos-guardian-v1\0";
const MAXIMUM_POLICY_BYTES: usize = 64 * 1024;
const MAXIMUM_PLAN_BYTES: usize = 256 * 1024;
const MAXIMUM_LEASE_BYTES: usize = 64 * 1024;
const MAXIMUM_SIGNATURE_BYTES: usize = 64 * 1024;
const REQUIRED_DYNAMIC_SEALS: SealFlags = SealFlags::SEAL
    .union(SealFlags::SHRINK)
    .union(SealFlags::GROW)
    .union(SealFlags::WRITE);

/// Sends the sole readiness acknowledgement after durable authority recheck.
pub trait ReadyNotifier {
    /// Sends `READY=1` without granting any other service-manager operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the notification cannot be delivered exactly.
    fn notify_ready(&self) -> Result<(), GuardianRuntimeError>;
}

/// Runs one guardian from exact systemd-provided descriptors and environment.
///
/// Startup verifies both signatures, commits and reads back state, then
/// re-verifies the same artifact bytes against a new paired-clock sample before
/// sending readiness. The process sleeps on an absolute `CLOCK_BOOTTIME`
/// deadline and exits at expiry so the payload's `BindsTo=` edge stops it.
///
/// # Errors
///
/// Returns [`GuardianRuntimeError`] for activation, protected configuration,
/// signed authority, durability, readiness, clock, or deadline-wait failure.
pub fn run_from_environment() -> Result<(), GuardianRuntimeError> {
    let single_threaded =
        SingleThreadedProcess::verify().map_err(|_| GuardianRuntimeError::InvalidActivation)?;
    let activation = ActivatedGuardianInputs::take(&single_threaded)?;
    let expected_incarnation = environment_incarnation("AOS_GUARDIAN_INCARNATION")?;
    let state_directory = single_environment_path("STATE_DIRECTORY")?;
    let mut store = GuardianStateStore::open(&state_directory)?;
    let prior = store.load()?;
    let authority = activation.authority()?;
    let artifacts = activation.artifacts();
    let initial_clock = current_clock()?;
    let pending = authority.admit(
        artifacts,
        expected_incarnation,
        &initial_clock,
        prior.as_ref(),
    )?;
    let durable = store.commit(pending)?;

    let confirmation_clock = current_clock()?;
    let ready = authority.confirm_current(
        artifacts,
        expected_incarnation,
        &confirmation_clock,
        durable,
    )?;
    let notifier = SystemdReadyNotifier::from_environment()?;
    notify_if_current(&ready, &notifier)?;
    wait_until_deadline(ready.deadline_boottime_nanoseconds())
}

fn notify_if_current(
    ready: &ReadinessConfirmedGuardian,
    notifier: &impl ReadyNotifier,
) -> Result<(), GuardianRuntimeError> {
    if boottime_nanoseconds()? >= ready.deadline_boottime_nanoseconds() {
        return Err(GuardianRuntimeError::DeadlineExpired);
    }
    notifier.notify_ready()
}

fn wait_until_deadline(deadline_nanoseconds: u64) -> Result<(), GuardianRuntimeError> {
    let seconds = i64::try_from(deadline_nanoseconds / 1_000_000_000)
        .map_err(|_| GuardianRuntimeError::InvalidClock)?;
    let nanoseconds = i64::try_from(deadline_nanoseconds % 1_000_000_000)
        .map_err(|_| GuardianRuntimeError::InvalidClock)?;
    let deadline = Timespec {
        tv_sec: seconds,
        tv_nsec: nanoseconds,
    };
    loop {
        match rustix::thread::clock_nanosleep_absolute(ClockId::Boottime, &deadline) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(GuardianRuntimeError::Sleep(error)),
        }
    }
}

fn current_clock() -> Result<RawPairedClockSample, GuardianRuntimeError> {
    let boot_id = KernelBootId::current()
        .map_err(|error| GuardianRuntimeError::BootIdentity(error.to_string()))?
        .into_bytes();

    // BOOTTIME precedes REALTIME so adapter delay can only shorten a deadline
    // derived from the later, whole-second wall observation.
    let boottime = clock_gettime(ClockId::Boottime);
    let wall = clock_gettime(ClockId::Realtime);
    let boottime_nanoseconds = timespec_nanoseconds(boottime)?;
    RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(CLOCK_PROVENANCE)
            .map_err(|_| GuardianRuntimeError::InvalidClock)?,
        boot_id,
        wall.tv_sec,
        boottime_nanoseconds,
    )
    .map_err(|_| GuardianRuntimeError::InvalidClock)
}

fn boottime_nanoseconds() -> Result<u64, GuardianRuntimeError> {
    timespec_nanoseconds(clock_gettime(ClockId::Boottime))
}

fn timespec_nanoseconds(value: Timespec) -> Result<u64, GuardianRuntimeError> {
    let seconds = u64::try_from(value.tv_sec).map_err(|_| GuardianRuntimeError::InvalidClock)?;
    let nanoseconds =
        u64::try_from(value.tv_nsec).map_err(|_| GuardianRuntimeError::InvalidClock)?;
    if nanoseconds >= 1_000_000_000 {
        return Err(GuardianRuntimeError::InvalidClock);
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanoseconds))
        .ok_or(GuardianRuntimeError::InvalidClock)
}

struct ActivatedGuardianInputs {
    values: [Vec<u8>; 10],
}

impl ActivatedGuardianInputs {
    fn take(_single_threaded: &SingleThreadedProcess) -> Result<Self, GuardianRuntimeError> {
        let listen_pid = environment_u32("LISTEN_PID")?;
        let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
            .map_err(|_| GuardianRuntimeError::InvalidActivation)?;
        if listen_pid != current_pid
            || environment_u32("LISTEN_FDS")? != ACTIVATION_NAMES.len() as u32
            || std::env::var("LISTEN_FDNAMES").ok().as_deref() != Some(&ACTIVATION_NAMES.join(":"))
        {
            return Err(GuardianRuntimeError::InvalidActivation);
        }
        prove_closed_activation_set()?;

        let mut descriptors = Vec::with_capacity(ACTIVATION_NAMES.len());
        for offset in 0..ACTIVATION_NAMES.len() {
            let raw = ACTIVATION_FD_BASE
                .checked_add(
                    i32::try_from(offset).map_err(|_| GuardianRuntimeError::InvalidActivation)?,
                )
                .ok_or(GuardianRuntimeError::InvalidActivation)?;
            descriptors.push(
                duplicate_inherited_descriptor(raw)
                    .map_err(|_| GuardianRuntimeError::InvalidActivation)?,
            );
        }
        let maxima = [
            MAXIMUM_POLICY_BYTES,
            32,
            16,
            MAXIMUM_POLICY_BYTES,
            32,
            16,
            MAXIMUM_PLAN_BYTES,
            MAXIMUM_SIGNATURE_BYTES,
            MAXIMUM_LEASE_BYTES,
            MAXIMUM_SIGNATURE_BYTES,
        ];
        let mut values = Vec::with_capacity(descriptors.len());
        for (index, (descriptor, maximum)) in descriptors.into_iter().zip(maxima).enumerate() {
            let custody = if index < 6 {
                DescriptorCustody::ProtectedStatic
            } else {
                DescriptorCustody::SealedDynamic
            };
            values.push(read_authority_descriptor(descriptor, maximum, custody)?);
        }
        let values: [Vec<u8>; 10] = values
            .try_into()
            .map_err(|_| GuardianRuntimeError::InvalidActivation)?;
        Ok(Self { values })
    }

    fn artifacts(&self) -> GuardianArtifacts<'_> {
        GuardianArtifacts {
            broker_plan: &self.values[6],
            broker_plan_signature: &self.values[7],
            ownership_lease: &self.values[8],
            ownership_lease_signature: &self.values[9],
        }
    }

    fn authority(&self) -> Result<GuardianAuthority, GuardianRuntimeError> {
        let plan_public_key = exact::<32>(&self.values[1])?;
        let lease_public_key = exact::<32>(&self.values[4])?;
        let plan_policy = decode_trust_policy(&self.values[0], decode_limits(MAXIMUM_POLICY_BYTES))
            .map_err(|_| GuardianRuntimeError::InvalidProtectedConfiguration)?;
        let lease_policy =
            decode_trust_policy(&self.values[3], decode_limits(MAXIMUM_POLICY_BYTES))
                .map_err(|_| GuardianRuntimeError::InvalidProtectedConfiguration)?;
        let plan_signer = select_key(
            plan_policy.allowed_keys(),
            KeyUsage::BrokerAuthorization,
            &plan_public_key,
        )?;
        let lease_signer = select_key(
            lease_policy.allowed_keys(),
            KeyUsage::OwnershipLease,
            &lease_public_key,
        )?;
        if plan_policy.purpose() != SignaturePurpose::BrokerAuthorization
            || lease_policy.purpose() != SignaturePurpose::OwnershipLease
        {
            return Err(GuardianRuntimeError::InvalidProtectedConfiguration);
        }
        let policy_media_type = MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
            .map_err(|_| GuardianRuntimeError::InvalidProtectedConfiguration)?;
        let plan_policy_descriptor =
            descriptor_for_bytes(policy_media_type.clone(), &self.values[0]);
        let lease_policy_descriptor = descriptor_for_bytes(policy_media_type, &self.values[3]);
        let plan_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
            self.values[0].clone(),
            plan_policy_descriptor,
            plan_policy.trust_scope(),
            plan_signer,
            plan_public_key,
            RevocationScopeId::from_bytes(exact::<16>(&self.values[2])?),
            decode_limits(MAXIMUM_POLICY_BYTES),
        )
        .map_err(|_| GuardianRuntimeError::InvalidProtectedConfiguration)?;
        let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            self.values[3].clone(),
            lease_policy_descriptor,
            lease_policy.trust_scope(),
            lease_signer,
            lease_public_key,
            decode_limits(MAXIMUM_POLICY_BYTES),
        )
        .map_err(|_| GuardianRuntimeError::InvalidProtectedConfiguration)?;
        let provenance = RawClockProvenance::new_untrusted(CLOCK_PROVENANCE)
            .map_err(|_| GuardianRuntimeError::InvalidProtectedConfiguration)?;
        GuardianAuthority::new(
            plan_anchor,
            lease_anchor,
            NodeId::from_bytes(exact::<16>(&self.values[5])?),
            provenance,
        )
        .map_err(GuardianRuntimeError::Authority)
    }
}

#[derive(Clone, Copy)]
enum DescriptorCustody {
    ProtectedStatic,
    SealedDynamic,
}

fn prove_closed_activation_set() -> Result<(), GuardianRuntimeError> {
    let pid = rustix::process::getpid().as_raw_nonzero().get();
    let descriptor_directory = format!("/proc/{pid}/fd");
    let entries =
        std::fs::read_dir("/proc/self/fd").map_err(|_| GuardianRuntimeError::InvalidActivation)?;
    let mut activation_seen = [false; ACTIVATION_NAMES.len()];
    let mut scanner_descriptors = 0_usize;
    let mut entry_count = 0_usize;

    for entry in entries {
        let entry = entry.map_err(|_| GuardianRuntimeError::InvalidActivation)?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or(GuardianRuntimeError::InvalidActivation)?;
        if entry_count > ACTIVATION_NAMES.len() + 4 {
            return Err(GuardianRuntimeError::InvalidActivation);
        }
        let raw = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
            .ok_or(GuardianRuntimeError::InvalidActivation)?;
        let target = std::fs::read_link(entry.path())
            .map_err(|_| GuardianRuntimeError::InvalidActivation)?;
        if target == Path::new(&descriptor_directory) {
            scanner_descriptors += 1;
            continue;
        }
        if (0..ACTIVATION_FD_BASE).contains(&raw) {
            continue;
        }
        let offset = raw
            .checked_sub(ACTIVATION_FD_BASE)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|offset| *offset < ACTIVATION_NAMES.len())
            .ok_or(GuardianRuntimeError::InvalidActivation)?;
        if std::mem::replace(&mut activation_seen[offset], true) {
            return Err(GuardianRuntimeError::InvalidActivation);
        }
    }
    if scanner_descriptors != 1 || activation_seen.contains(&false) {
        return Err(GuardianRuntimeError::InvalidActivation);
    }
    Ok(())
}

fn read_authority_descriptor(
    descriptor: OwnedFd,
    maximum: usize,
    custody: DescriptorCustody,
) -> Result<Vec<u8>, GuardianRuntimeError> {
    let metadata = fstat(&descriptor).map_err(GuardianRuntimeError::Descriptor)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != 0
        || fcntl_getfl(&descriptor).map_err(GuardianRuntimeError::Descriptor)? & OFlags::ACCMODE
            != OFlags::RDONLY
    {
        return Err(GuardianRuntimeError::InvalidProtectedDescriptor);
    }
    match custody {
        DescriptorCustody::ProtectedStatic
            if metadata.st_nlink != 1 || !matches!(metadata.st_mode & 0o7777, 0o400 | 0o600) =>
        {
            return Err(GuardianRuntimeError::InvalidProtectedDescriptor);
        }
        DescriptorCustody::SealedDynamic => {
            let seals = fcntl_get_seals(&descriptor)
                .map_err(|_| GuardianRuntimeError::InvalidProtectedDescriptor)?;
            if metadata.st_nlink != 0 || !seals.contains(REQUIRED_DYNAMIC_SEALS) {
                return Err(GuardianRuntimeError::InvalidProtectedDescriptor);
            }
        }
        DescriptorCustody::ProtectedStatic => {}
    }
    let length = usize::try_from(metadata.st_size)
        .ok()
        .filter(|length| *length > 0 && *length <= maximum)
        .ok_or(GuardianRuntimeError::InvalidProtectedDescriptor)?;
    let file = std::fs::File::from(descriptor);
    let bytes = read_exact_descriptor(&file, length)?;
    if matches!(custody, DescriptorCustody::ProtectedStatic)
        && read_exact_descriptor(&file, length)? != bytes
    {
        return Err(GuardianRuntimeError::InvalidProtectedDescriptor);
    }
    let after = fstat(&file).map_err(GuardianRuntimeError::Descriptor)?;
    if after.st_dev != metadata.st_dev
        || after.st_ino != metadata.st_ino
        || after.st_size != metadata.st_size
        || after.st_mtime != metadata.st_mtime
        || after.st_mtime_nsec != metadata.st_mtime_nsec
        || after.st_ctime != metadata.st_ctime
        || after.st_ctime_nsec != metadata.st_ctime_nsec
    {
        return Err(GuardianRuntimeError::InvalidProtectedDescriptor);
    }
    if matches!(custody, DescriptorCustody::SealedDynamic)
        && !fcntl_get_seals(&file)
            .map_err(|_| GuardianRuntimeError::InvalidProtectedDescriptor)?
            .contains(REQUIRED_DYNAMIC_SEALS)
    {
        return Err(GuardianRuntimeError::InvalidProtectedDescriptor);
    }
    Ok(bytes)
}

fn read_exact_descriptor(
    file: &std::fs::File,
    length: usize,
) -> Result<Vec<u8>, GuardianRuntimeError> {
    let mut bytes = vec![0; length];
    let mut offset = 0;
    while offset < bytes.len() {
        let read = file
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(GuardianRuntimeError::StdIo)?;
        if read == 0 {
            return Err(GuardianRuntimeError::InvalidProtectedDescriptor);
        }
        offset += read;
    }
    Ok(bytes)
}

fn select_key(
    candidates: &[KeyReference],
    usage: KeyUsage,
    public_key: &[u8; 32],
) -> Result<KeyReference, GuardianRuntimeError> {
    let fingerprint = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
    let mut matches = candidates
        .iter()
        .filter(|candidate| {
            candidate.usage() == usage && candidate.public_key_sha256() == fingerprint
        })
        .cloned();
    let selected = matches
        .next()
        .ok_or(GuardianRuntimeError::InvalidProtectedConfiguration)?;
    if matches.next().is_some() {
        return Err(GuardianRuntimeError::InvalidProtectedConfiguration);
    }
    Ok(selected)
}

struct SystemdReadyNotifier {
    socket: OwnedFd,
    address: SocketAddrUnix,
}

impl SystemdReadyNotifier {
    fn from_environment() -> Result<Self, GuardianRuntimeError> {
        let value =
            std::env::var_os("NOTIFY_SOCKET").ok_or(GuardianRuntimeError::InvalidNotifySocket)?;
        let value = value
            .to_str()
            .filter(|value| !value.is_empty())
            .ok_or(GuardianRuntimeError::InvalidNotifySocket)?;
        let address = if let Some(name) = value.strip_prefix('@') {
            if name.is_empty() {
                return Err(GuardianRuntimeError::InvalidNotifySocket);
            }
            SocketAddrUnix::new_abstract_name(name.as_bytes())
        } else {
            SocketAddrUnix::new(Path::new(value))
        }
        .map_err(GuardianRuntimeError::Descriptor)?;
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(GuardianRuntimeError::Descriptor)?;
        Ok(Self { socket, address })
    }
}

impl ReadyNotifier for SystemdReadyNotifier {
    fn notify_ready(&self) -> Result<(), GuardianRuntimeError> {
        let payload = b"READY=1";
        let written = sendmsg_addr(
            &self.socket,
            &self.address,
            &[IoSlice::new(payload)],
            &mut SendAncillaryBuffer::default(),
            SendFlags::NOSIGNAL,
        )
        .map_err(GuardianRuntimeError::Descriptor)?;
        if written != payload.len() {
            return Err(GuardianRuntimeError::PartialNotification);
        }
        Ok(())
    }
}

/// Reports guardian startup or fail-stop runtime failure.
#[derive(Debug, thiserror::Error)]
pub enum GuardianRuntimeError {
    /// The systemd activation descriptor tuple is absent or inconsistent.
    #[error("invalid guardian descriptor activation")]
    InvalidActivation,
    /// A protected descriptor has the wrong type, ownership, mode, access, or size.
    #[error("invalid guardian protected descriptor")]
    InvalidProtectedDescriptor,
    /// Protected trust configuration is inconsistent.
    #[error("invalid guardian protected authority configuration")]
    InvalidProtectedConfiguration,
    /// A descriptor or socket operation failed.
    #[error("guardian descriptor operation failed: {0}")]
    Descriptor(rustix::io::Errno),
    /// A positional descriptor read failed.
    #[error("guardian descriptor read failed: {0}")]
    StdIo(std::io::Error),
    /// Signed authority admission failed.
    #[error("guardian authority failed: {0}")]
    Authority(#[from] GuardianAuthorityError),
    /// Durable state handling failed.
    #[error("guardian durable state failed: {0}")]
    State(#[from] GuardianStateStoreError),
    /// Kernel boot identity could not be read.
    #[error("guardian boot identity failed: {0}")]
    BootIdentity(String),
    /// A protected paired-clock observation is invalid.
    #[error("guardian paired clock is invalid")]
    InvalidClock,
    /// Persistence or startup consumed the effective deadline.
    #[error("guardian deadline elapsed before readiness")]
    DeadlineExpired,
    /// `NOTIFY_SOCKET` is missing or malformed.
    #[error("guardian systemd notification socket is invalid")]
    InvalidNotifySocket,
    /// The readiness datagram was only partially written.
    #[error("guardian readiness notification was partially written")]
    PartialNotification,
    /// Absolute `CLOCK_BOOTTIME` sleep failed.
    #[error("guardian absolute deadline wait failed: {0}")]
    Sleep(rustix::io::Errno),
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], GuardianRuntimeError> {
    bytes
        .try_into()
        .map_err(|_| GuardianRuntimeError::InvalidProtectedConfiguration)
}

fn decode_limits(maximum_bytes: usize) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes,
        ..DecodeLimits::default()
    }
}

fn environment_u32(name: &'static str) -> Result<u32, GuardianRuntimeError> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(GuardianRuntimeError::InvalidActivation)
}

fn environment_incarnation(name: &'static str) -> Result<[u8; 16], GuardianRuntimeError> {
    let value = std::env::var(name).map_err(|_| GuardianRuntimeError::InvalidActivation)?;
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GuardianRuntimeError::InvalidActivation);
    }
    let decoded = hex::decode(value).map_err(|_| GuardianRuntimeError::InvalidActivation)?;
    let incarnation: [u8; 16] = decoded
        .try_into()
        .map_err(|_| GuardianRuntimeError::InvalidActivation)?;
    if incarnation == [0; 16] {
        return Err(GuardianRuntimeError::InvalidActivation);
    }
    Ok(incarnation)
}

fn single_environment_path(name: &'static str) -> Result<std::path::PathBuf, GuardianRuntimeError> {
    let value = std::env::var_os(name).ok_or(GuardianRuntimeError::InvalidActivation)?;
    let path = Path::new(&value);
    if !path.is_absolute() || value.as_encoded_bytes().contains(&b':') {
        return Err(GuardianRuntimeError::InvalidActivation);
    }
    Ok(path.to_owned())
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn public_environment_entry_rejects_a_multithreaded_caller() {
        let (started_sender, started_receiver) = mpsc::sync_channel(0);
        let (finish_sender, finish_receiver) = mpsc::sync_channel(0);
        let thread = std::thread::spawn(move || {
            started_sender
                .send(())
                .unwrap_or_else(|error| panic!("cannot signal test thread: {error}"));
            finish_receiver
                .recv()
                .unwrap_or_else(|error| panic!("cannot finish test thread: {error}"));
        });
        started_receiver
            .recv()
            .unwrap_or_else(|error| panic!("cannot await test thread: {error}"));

        let result = run_from_environment();

        finish_sender
            .send(())
            .unwrap_or_else(|error| panic!("cannot release test thread: {error}"));
        thread
            .join()
            .unwrap_or_else(|_| panic!("test thread panicked"));
        assert!(matches!(
            result,
            Err(GuardianRuntimeError::InvalidActivation)
        ));
    }
}
