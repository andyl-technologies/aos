//! Closed transient-unit contract for per-assignment lease guardians.
//!
//! The specification transfers exactly ten named read-only authority
//! descriptors and starts one descriptor-pinned executable. It exposes no
//! general property map or arbitrary service-manager operation.

use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::sync::Arc;
use std::time::Duration;

use zbus::zvariant::Fd;

use super::{
    ExactStartError, ExactUnitRole, SandboxCgroupPath, SandboxDescriptorPath, SandboxUnitName,
    bool_property, complex_property, duration_micros, exec_property, invalid,
    string_array_property, string_property, u32_property, u64_property,
};
use crate::client::{JobOutcome, SystemdClient};
use crate::error::Result;
use crate::manager_proxy::AuxiliaryUnit;

const GUARDIAN_SLICE: &str = "aos-assignment-guardians.slice";
const GUARDIAN_STATE_PREFIX: &str = "aos/lease-guards";
const GUARDIAN_ENVIRONMENT_PREFIX: &str = "AOS_GUARDIAN_INCARNATION=";
const GUARDIAN_BINDING_PREFIX: &str = "AOS_GUARDIAN_LAUNCH_BINDING=";
const GUARDIAN_ALLOWED_ADDRESS_FAMILIES: &[&str] = &["AF_UNIX"];
const GUARDIAN_ALLOWED_SYSCALLS: &[&str] = &["@system-service"];
const GUARDIAN_DENIED_SOCKET_OPERATIONS: &[&str] =
    &["accept", "accept4", "bind", "connect", "listen"];
const MAXIMUM_POLICY_BYTES: u64 = 64 * 1024;
const MAXIMUM_PLAN_BYTES: u64 = 256 * 1024;
const MAXIMUM_LEASE_BYTES: u64 = 64 * 1024;
const MAXIMUM_SIGNATURE_BYTES: u64 = 64 * 1024;
const MAXIMUM_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

/// Copies the complete identity of one descriptor-pinned Guardian executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardianExecutableSnapshot {
    /// Filesystem device containing the executable inode.
    pub device: u64,
    /// Exact executable inode.
    pub inode: u64,
    /// Exact byte length.
    pub bytes: u64,
    /// Owning user ID.
    pub uid: u32,
    /// Complete file type and permission mode.
    pub mode: u32,
    /// Last content-modification seconds.
    pub modified_seconds: i64,
    /// Last content-modification nanoseconds.
    pub modified_nanoseconds: i64,
    /// Last metadata-change seconds.
    pub changed_seconds: i64,
    /// Last metadata-change nanoseconds.
    pub changed_nanoseconds: i64,
    /// SHA-256 over the exact executable contents.
    pub sha256_content: [u8; 32],
}

/// Owns and revalidates one exact read-only Guardian executable descriptor.
#[derive(Clone, Debug)]
pub struct GuardianExecutableDescriptor {
    path: SandboxDescriptorPath,
    snapshot: GuardianExecutableSnapshot,
}

impl GuardianExecutableDescriptor {
    /// Duplicates a protected executable descriptor and records its exact identity.
    ///
    /// # Errors
    ///
    /// Returns an error unless the descriptor is a bounded, creator-owned,
    /// non-group/world-writable executable regular file opened read-only.
    pub fn from_descriptor(descriptor: BorrowedFd<'_>) -> Result<Self> {
        let snapshot = validate_guardian_executable(descriptor)?;
        let path = SandboxDescriptorPath::for_current_process(descriptor)
            .map_err(|error| invalid(format!("cannot pin guardian executable: {error}")))?;
        Ok(Self { path, snapshot })
    }

    /// Returns the exact admitted executable identity.
    #[must_use]
    pub const fn snapshot(&self) -> GuardianExecutableSnapshot {
        self.snapshot
    }

    fn transferred_path(&self) -> Result<SandboxDescriptorPath> {
        if validate_guardian_executable(self.path.descriptor())? != self.snapshot {
            return Err(invalid(
                "guardian executable identity or content changed before start",
            ));
        }
        Ok(self.path.clone())
    }
}

#[cfg(target_os = "linux")]
fn validate_guardian_executable(descriptor: BorrowedFd<'_>) -> Result<GuardianExecutableSnapshot> {
    use std::os::unix::fs::FileExt as _;

    use rustix::fs::{FileType, OFlags, fcntl_getfl, fstat};
    use sha2::{Digest as _, Sha256};

    let before = fstat(descriptor)
        .map_err(|error| invalid(format!("cannot inspect guardian executable: {error}")))?;
    let bytes = u64::try_from(before.st_size)
        .ok()
        .filter(|bytes| (1..=MAXIMUM_EXECUTABLE_BYTES).contains(bytes))
        .ok_or_else(|| invalid("guardian executable size is invalid"))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != rustix::process::geteuid().as_raw()
        || before.st_mode & 0o111 == 0
        || before.st_mode & 0o022 != 0
        || fcntl_getfl(descriptor)
            .map_err(|error| invalid(format!("cannot read guardian executable flags: {error}")))?
            & OFlags::ACCMODE
            != OFlags::RDONLY
    {
        return Err(invalid("guardian executable descriptor is not protected"));
    }

    let length = usize::try_from(bytes)
        .map_err(|_| invalid("guardian executable size does not fit memory"))?;
    let file = File::from(
        descriptor
            .try_clone_to_owned()
            .map_err(|error| invalid(format!("cannot duplicate guardian executable: {error}")))?,
    );
    let mut content = vec![0; length];
    let mut offset = 0;
    while offset < content.len() {
        let read = file
            .read_at(&mut content[offset..], offset as u64)
            .map_err(|error| invalid(format!("cannot read guardian executable: {error}")))?;
        if read == 0 {
            return Err(invalid(
                "guardian executable ended before its declared size",
            ));
        }
        offset += read;
    }
    let after = fstat(descriptor)
        .map_err(|error| invalid(format!("cannot recheck guardian executable: {error}")))?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
        || after.st_mtime != before.st_mtime
        || after.st_mtime_nsec != before.st_mtime_nsec
        || after.st_ctime != before.st_ctime
        || after.st_ctime_nsec != before.st_ctime_nsec
    {
        return Err(invalid("guardian executable changed during exact readback"));
    }
    let modified_nanoseconds = i64::try_from(before.st_mtime_nsec)
        .map_err(|_| invalid("guardian executable modification time is invalid"))?;
    let changed_nanoseconds = i64::try_from(before.st_ctime_nsec)
        .map_err(|_| invalid("guardian executable metadata-change time is invalid"))?;

    Ok(GuardianExecutableSnapshot {
        device: before.st_dev,
        inode: before.st_ino,
        bytes,
        uid: before.st_uid,
        mode: before.st_mode,
        modified_seconds: before.st_mtime,
        modified_nanoseconds,
        changed_seconds: before.st_ctime,
        changed_nanoseconds,
        sha256_content: Sha256::digest(content).into(),
    })
}

#[cfg(not(target_os = "linux"))]
fn validate_guardian_executable(_descriptor: BorrowedFd<'_>) -> Result<GuardianExecutableSnapshot> {
    Err(invalid(
        "guardian executable validation is available only on Linux",
    ))
}

/// Names every exact authority descriptor consumed by a guardian.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GuardianCredentialRole {
    /// Controller-plan trust policy.
    BrokerPlanPolicy,
    /// Controller-plan Ed25519 public key.
    BrokerPlanPublicKey,
    /// Controller-plan revocation scope.
    BrokerPlanRevocationScope,
    /// Ownership-lease trust policy.
    OwnershipLeasePolicy,
    /// Ownership-authority Ed25519 public key.
    OwnershipLeasePublicKey,
    /// Sole node identity accepted by the guardian.
    NodeId,
    /// Canonical signed Guardian plan.
    BrokerPlan,
    /// Detached controller signature over the plan.
    BrokerPlanSignature,
    /// Canonical signed ownership lease.
    OwnershipLease,
    /// Detached authority signature over the lease.
    OwnershipLeaseSignature,
}

impl GuardianCredentialRole {
    const ALL: [Self; 10] = [
        Self::BrokerPlanPolicy,
        Self::BrokerPlanPublicKey,
        Self::BrokerPlanRevocationScope,
        Self::OwnershipLeasePolicy,
        Self::OwnershipLeasePublicKey,
        Self::NodeId,
        Self::BrokerPlan,
        Self::BrokerPlanSignature,
        Self::OwnershipLease,
        Self::OwnershipLeaseSignature,
    ];

    /// Returns the fixed systemd descriptor name consumed by the binary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrokerPlanPolicy => "broker-plan-policy.cbor",
            Self::BrokerPlanPublicKey => "broker-plan-public-key",
            Self::BrokerPlanRevocationScope => "broker-revocation-scope",
            Self::OwnershipLeasePolicy => "ownership-lease-policy.cbor",
            Self::OwnershipLeasePublicKey => "ownership-lease-public-key",
            Self::NodeId => "node-id",
            Self::BrokerPlan => "broker-plan.cbor",
            Self::BrokerPlanSignature => "broker-plan-signature.cbor",
            Self::OwnershipLease => "ownership-lease.cbor",
            Self::OwnershipLeaseSignature => "ownership-lease-signature.cbor",
        }
    }

    const fn maximum_bytes(self) -> u64 {
        match self {
            Self::BrokerPlanPolicy | Self::OwnershipLeasePolicy => MAXIMUM_POLICY_BYTES,
            Self::BrokerPlanPublicKey | Self::OwnershipLeasePublicKey => 32,
            Self::BrokerPlanRevocationScope | Self::NodeId => 16,
            Self::BrokerPlan => MAXIMUM_PLAN_BYTES,
            Self::BrokerPlanSignature | Self::OwnershipLeaseSignature => MAXIMUM_SIGNATURE_BYTES,
            Self::OwnershipLease => MAXIMUM_LEASE_BYTES,
        }
    }

    const fn is_dynamic(self) -> bool {
        matches!(
            self,
            Self::BrokerPlan
                | Self::BrokerPlanSignature
                | Self::OwnershipLease
                | Self::OwnershipLeaseSignature
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuardianDescriptorSnapshot {
    device: u64,
    inode: u64,
    bytes: u64,
    sha256: [u8; 32],
}

#[derive(Clone, Debug)]
struct GuardianCredentialDescriptor {
    descriptor: Arc<std::os::fd::OwnedFd>,
    snapshot: GuardianDescriptorSnapshot,
}

/// Owns one exact complete set of descriptor-pinned guardian authority inputs.
#[derive(Clone, Debug)]
pub struct GuardianCredentialDescriptors {
    descriptors: BTreeMap<GuardianCredentialRole, GuardianCredentialDescriptor>,
}

impl GuardianCredentialDescriptors {
    /// Duplicates and owns one descriptor for every fixed guardian role.
    ///
    /// Static trust inputs must be creator-owned, singly linked, non-executable
    /// protected files opened read-only. Dynamic authority artifacts must be
    /// creator-owned anonymous memfds opened read-only with the complete
    /// write/grow/shrink/seal set. Exact content snapshots are rechecked just
    /// before D-Bus transfer; protected static custody does not claim immutable
    /// content between those checks.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, duplicate, or extra role, invalid type,
    /// ownership, mode, access, size or seals, or a descriptor duplication or
    /// exact-readback failure.
    pub fn from_descriptors(
        entries: Vec<(GuardianCredentialRole, BorrowedFd<'_>)>,
    ) -> Result<Self> {
        if entries.len() != GuardianCredentialRole::ALL.len() {
            return Err(invalid(
                "guardian requires exactly ten authority descriptors",
            ));
        }
        let mut descriptors = BTreeMap::new();
        for (role, descriptor) in entries {
            let snapshot = validate_guardian_descriptor(role, descriptor)?;
            let owned = descriptor.try_clone_to_owned().map_err(|error| {
                invalid(format!("cannot duplicate guardian descriptor: {error}"))
            })?;
            let retained = GuardianCredentialDescriptor {
                descriptor: Arc::new(owned),
                snapshot,
            };
            if descriptors.insert(role, retained).is_some() {
                return Err(invalid("guardian authority descriptor role is duplicated"));
            }
        }
        if !GuardianCredentialRole::ALL
            .iter()
            .all(|role| descriptors.contains_key(role))
        {
            return Err(invalid("guardian authority descriptor role is missing"));
        }
        Ok(Self { descriptors })
    }

    fn transferred(&self) -> Result<Vec<(Fd<'static>, String)>> {
        GuardianCredentialRole::ALL
            .iter()
            .map(|role| {
                let retained = self
                    .descriptors
                    .get(role)
                    .ok_or_else(|| invalid("guardian descriptor set became incomplete"))?;
                if validate_guardian_descriptor(*role, retained.descriptor.as_fd())?
                    != retained.snapshot
                {
                    return Err(invalid(
                        "guardian descriptor identity or content changed before transfer",
                    ));
                }
                let descriptor = retained.descriptor.try_clone().map_err(|error| {
                    invalid(format!("cannot transfer guardian descriptor: {error}"))
                })?;
                Ok((Fd::from(descriptor), role.as_str().to_owned()))
            })
            .collect()
    }
}

#[cfg(target_os = "linux")]
fn validate_guardian_descriptor(
    role: GuardianCredentialRole,
    descriptor: BorrowedFd<'_>,
) -> Result<GuardianDescriptorSnapshot> {
    use rustix::fs::{FileType, OFlags, SealFlags, fcntl_get_seals, fcntl_getfl, fstat};
    use sha2::{Digest as _, Sha256};
    use std::fs::File;

    const REQUIRED_SEALS: SealFlags = SealFlags::SEAL
        .union(SealFlags::SHRINK)
        .union(SealFlags::GROW)
        .union(SealFlags::WRITE);

    let metadata = fstat(descriptor)
        .map_err(|error| invalid(format!("cannot inspect guardian descriptor: {error}")))?;
    let bytes = u64::try_from(metadata.st_size)
        .ok()
        .filter(|bytes| *bytes > 0 && *bytes <= role.maximum_bytes())
        .ok_or_else(|| invalid("guardian descriptor size is invalid"))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || fcntl_getfl(descriptor)
            .map_err(|error| invalid(format!("cannot read guardian descriptor flags: {error}")))?
            & OFlags::ACCMODE
            != OFlags::RDONLY
    {
        return Err(invalid(
            "guardian descriptor type, owner, or access mode is invalid",
        ));
    }
    if role.is_dynamic() {
        let seals = fcntl_get_seals(descriptor)
            .map_err(|_| invalid("guardian dynamic descriptor is not a sealable memfd"))?;
        if metadata.st_nlink != 0 || !seals.contains(REQUIRED_SEALS) {
            return Err(invalid(
                "guardian dynamic descriptor is not anonymous and fully sealed",
            ));
        }
    } else if metadata.st_nlink != 1 || !matches!(metadata.st_mode & 0o7777, 0o400 | 0o600) {
        return Err(invalid(
            "guardian static descriptor is not a protected singly-linked file",
        ));
    }

    let length = usize::try_from(bytes)
        .map_err(|_| invalid("guardian descriptor size does not fit memory"))?;
    let file = File::from(
        descriptor
            .try_clone_to_owned()
            .map_err(|error| invalid(format!("cannot duplicate guardian descriptor: {error}")))?,
    );
    let content = read_guardian_descriptor(&file, length)?;
    if !role.is_dynamic() && read_guardian_descriptor(&file, length)? != content {
        return Err(invalid(
            "guardian static descriptor changed during exact readback",
        ));
    }
    let after = fstat(descriptor)
        .map_err(|error| invalid(format!("cannot recheck guardian descriptor: {error}")))?;
    if after.st_dev != metadata.st_dev
        || after.st_ino != metadata.st_ino
        || after.st_size != metadata.st_size
        || after.st_mtime != metadata.st_mtime
        || after.st_mtime_nsec != metadata.st_mtime_nsec
        || after.st_ctime != metadata.st_ctime
        || after.st_ctime_nsec != metadata.st_ctime_nsec
    {
        return Err(invalid("guardian descriptor changed during exact readback"));
    }

    Ok(GuardianDescriptorSnapshot {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        bytes,
        sha256: Sha256::digest(content).into(),
    })
}

#[cfg(target_os = "linux")]
fn read_guardian_descriptor(file: &std::fs::File, length: usize) -> Result<Vec<u8>> {
    use std::os::unix::fs::FileExt as _;

    let mut content = vec![0; length];
    let mut offset = 0;
    while offset < content.len() {
        let read = file
            .read_at(&mut content[offset..], offset as u64)
            .map_err(|error| invalid(format!("cannot read guardian descriptor: {error}")))?;
        if read == 0 {
            return Err(invalid(
                "guardian descriptor ended before its declared size",
            ));
        }
        offset += read;
    }
    Ok(content)
}

#[cfg(all(not(target_os = "linux"), not(test)))]
fn validate_guardian_descriptor(
    _role: GuardianCredentialRole,
    _descriptor: BorrowedFd<'_>,
) -> Result<GuardianDescriptorSnapshot> {
    Err(invalid(
        "guardian descriptor validation is available only on Linux",
    ))
}

#[cfg(all(not(target_os = "linux"), test))]
fn validate_guardian_descriptor(
    role: GuardianCredentialRole,
    _descriptor: BorrowedFd<'_>,
) -> Result<GuardianDescriptorSnapshot> {
    let role_index = GuardianCredentialRole::ALL
        .iter()
        .position(|candidate| *candidate == role)
        .ok_or_else(|| invalid("guardian test descriptor role is invalid"))?;
    let role_index = u8::try_from(role_index)
        .map_err(|_| invalid("guardian test descriptor role is invalid"))?;
    Ok(GuardianDescriptorSnapshot {
        device: 0,
        inode: u64::from(role_index) + 1,
        bytes: 1,
        sha256: [role_index; 32],
    })
}

/// Defines the sole systemd transient service shape accepted for a guardian.
#[derive(Clone, Debug)]
pub struct GuardianUnitSpec {
    name: SandboxUnitName,
    executable: GuardianExecutableDescriptor,
    credentials: GuardianCredentialDescriptors,
    binding: [u8; 32],
    incarnation_hex: String,
    timeout_start: Duration,
}

impl GuardianUnitSpec {
    /// Constructs one capability-less, network-listener-free guardian unit.
    ///
    /// The executable is descriptor-pinned, automatic restart is disabled, and
    /// each assignment receives a separate dynamic service identity and 0700
    /// durable state directory. The only allowed address family is `AF_UNIX`
    /// for the one readiness datagram; bind/listen/connect/accept are denied.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero incarnation-derived name or invalid start
    /// timeout.
    pub fn new(
        name: SandboxUnitName,
        executable: GuardianExecutableDescriptor,
        credentials: GuardianCredentialDescriptors,
        binding: [u8; 32],
        timeout_start: Duration,
    ) -> Result<Self> {
        let (_, incarnation) = SandboxUnitName::from_service_name(name.as_str())
            .ok_or_else(|| invalid("guardian unit name is not canonical"))?;
        if binding == [0; 32] {
            return Err(invalid("guardian launch binding is zero"));
        }
        duration_micros(timeout_start, "guardian start timeout")?;
        Ok(Self {
            name,
            executable,
            credentials,
            binding,
            incarnation_hex: super::encode_hex(incarnation),
            timeout_start,
        })
    }

    /// Returns the incarnation-derived guardian service name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.guardian()
    }

    /// Returns the authenticated launch binding retained in the unit environment.
    #[must_use]
    pub const fn binding(&self) -> [u8; 32] {
        self.binding
    }

    fn properties(&self) -> Result<Vec<crate::manager_proxy::TransientProperty>> {
        let environment = format!("{GUARDIAN_ENVIRONMENT_PREFIX}{}", self.incarnation_hex);
        let binding = format!(
            "{GUARDIAN_BINDING_PREFIX}{}",
            super::encode_hex32(self.binding)
        );
        let executable = self.executable.transferred_path()?;
        let state_directory = format!("{GUARDIAN_STATE_PREFIX}/{}", self.incarnation_hex);
        Ok(vec![
            string_property("Description", format!("AOS lease guardian {}", self.name)),
            string_property("Type", "notify"),
            string_property("NotifyAccess", "main"),
            string_property("Slice", GUARDIAN_SLICE),
            string_property("Restart", "no"),
            string_property("CollectMode", "inactive-or-failed"),
            bool_property("DynamicUser", true),
            string_array_property("StateDirectory", vec![state_directory])?,
            u32_property("StateDirectoryMode", 0o700),
            u32_property("UMask", 0o077),
            u64_property("CapabilityBoundingSet", 0),
            u64_property("AmbientCapabilities", 0),
            bool_property("NoNewPrivileges", true),
            complex_property(
                "RestrictAddressFamilies",
                (
                    true,
                    GUARDIAN_ALLOWED_ADDRESS_FAMILIES
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                ),
            )?,
            complex_property(
                "SystemCallFilter",
                (
                    true,
                    GUARDIAN_ALLOWED_SYSCALLS
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                ),
            )?,
            complex_property(
                "SystemCallFilter",
                (
                    false,
                    GUARDIAN_DENIED_SOCKET_OPERATIONS
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                ),
            )?,
            string_array_property("SystemCallArchitectures", vec!["native".to_owned()])?,
            string_property("ProtectSystem", "strict"),
            string_property("ProtectHome", "yes"),
            bool_property("PrivateTmp", true),
            bool_property("PrivateDevices", true),
            bool_property("ProtectKernelTunables", true),
            bool_property("ProtectKernelModules", true),
            bool_property("ProtectControlGroups", true),
            bool_property("ProtectClock", true),
            u64_property("RestrictNamespaces", 0),
            bool_property("LockPersonality", true),
            bool_property("MemoryDenyWriteExecute", true),
            bool_property("RestrictRealtime", true),
            bool_property("RestrictSUIDSGID", true),
            string_array_property(
                "InaccessiblePaths",
                vec!["/run/dbus/system_bus_socket".to_owned()],
            )?,
            complex_property("ExtraFileDescriptors", self.credentials.transferred()?)?,
            string_array_property("Environment", vec![environment, binding])?,
            bool_property("SetLoginEnvironment", false),
            u64_property(
                "TimeoutStartUSec",
                duration_micros(self.timeout_start, "guardian start timeout")?,
            ),
            exec_property(&executable.path, vec![executable.path.clone()])?,
        ])
    }
}

/// Reports the manager-retained identity and state of one Guardian unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardianUnitObservation {
    /// Manager-retained launch binding, when exactly one canonical value exists.
    pub binding: Option<[u8; 32]>,
    /// Current systemd invocation identifier.
    pub invocation_id: Option<[u8; 16]>,
    /// High-level activation state.
    pub active_state: String,
    /// Service-specific substate.
    pub sub_state: String,
    /// Exact validated Guardian cgroup path, when realized.
    pub cgroup: Option<SandboxCgroupPath>,
    /// Current Guardian service leader, when systemd reports one.
    pub main_pid: Option<std::num::NonZeroU32>,
}

/// Distinguishes a denied final guard from a systemd start failure.
pub type GuardianStartError<E> = ExactStartError<E>;

impl SystemdClient {
    /// Prepares and starts one Guardian after a final synchronous guard.
    ///
    /// Descriptor validation and property construction complete before
    /// `before_submission` runs. This is the last local authority check before
    /// the asynchronous D-Bus submission; it is not an atomic guarantee about
    /// when PID 1 applies the request. The independently armed Guardian and
    /// subsequent protected observations enforce the remaining lifetime. The
    /// borrowed specification retains executable and authority descriptor pins
    /// through activation; `Restart=no` prevents reuse after their release.
    ///
    /// # Errors
    ///
    /// Returns [`GuardianStartError::Guard`] when the final guard denies the
    /// submission, or [`GuardianStartError::Systemd`] when preparation, D-Bus
    /// submission, or job completion fails.
    pub async fn start_guardian_unit_guarded<E>(
        &self,
        spec: &GuardianUnitSpec,
        before_submission: &mut (dyn FnMut() -> std::result::Result<(), E> + Send),
    ) -> std::result::Result<JobOutcome, GuardianStartError<E>> {
        let properties =
            super::exact_unit::prepare_then_guard(|| spec.properties(), before_submission)?;
        let auxiliary_units: Vec<AuxiliaryUnit> = Vec::new();
        let path = self
            .manager
            .start_transient_unit(spec.name(), "fail", &properties, &auxiliary_units)
            .await
            .map_err(crate::Error::from)
            .map_err(GuardianStartError::Systemd)?;
        self.await_job(path)
            .await
            .map_err(GuardianStartError::Systemd)
    }

    /// Observes one exact incarnation-derived Guardian unit.
    ///
    /// # Errors
    ///
    /// Returns an error for D-Bus failures, malformed invocation identifiers,
    /// or malformed or repeated manager-retained binding entries.
    pub async fn observe_guardian_unit(
        &self,
        name: &SandboxUnitName,
    ) -> Result<Option<GuardianUnitObservation>> {
        let exact = super::ExactUnitClient::connect()
            .await?
            .observe_exact_unit(name, ExactUnitRole::Guardian)
            .await?;
        Ok(exact.map(|observation| GuardianUnitObservation {
            binding: observation.binding,
            invocation_id: observation.invocation_id,
            active_state: observation.active_state,
            sub_state: observation.sub_state,
            cgroup: observation.cgroup,
            main_pid: observation.main_pid,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    #[cfg(target_os = "linux")]
    use std::fs::Permissions;
    use std::os::fd::AsFd as _;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    #[cfg(target_os = "linux")]
    use aos_sandbox_linux::immutable_file::SealedReadOnlyCredential;

    use super::*;

    #[test]
    fn expiry_during_preparation_prevents_submission() {
        let clock = AtomicU64::new(1);
        let starts = AtomicUsize::new(0);
        let mut guard = || {
            (clock.load(Ordering::SeqCst) < 2)
                .then_some(())
                .ok_or("expired")
        };
        let prepared = super::super::exact_unit::prepare_then_guard(
            || -> Result<()> {
                clock.store(2, Ordering::SeqCst);
                Ok(())
            },
            &mut guard,
        );
        if prepared.is_ok() {
            starts.fetch_add(1, Ordering::SeqCst);
        }

        assert!(matches!(
            prepared,
            Err(GuardianStartError::Guard("expired"))
        ));
        assert_eq!(starts.load(Ordering::SeqCst), 0);
    }

    fn spec() -> (tempfile::TempDir, GuardianUnitSpec) {
        let executable = File::open(
            std::env::current_exe()
                .unwrap_or_else(|error| panic!("test executable path failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("test executable failed: {error}"));
        let executable = GuardianExecutableDescriptor::from_descriptor(executable.as_fd())
            .unwrap_or_else(|error| panic!("test executable pin failed: {error}"));
        let directory =
            tempfile::tempdir().unwrap_or_else(|error| panic!("test directory failed: {error}"));
        let descriptors = credential_descriptors(&directory);
        let spec = GuardianUnitSpec::new(
            SandboxUnitName::from_incarnation([0xab; 16]),
            executable,
            descriptors,
            [0xcd; 32],
            Duration::from_secs(10),
        )
        .unwrap_or_else(|error| panic!("test guardian spec failed: {error}"));
        (directory, spec)
    }

    #[cfg(target_os = "linux")]
    fn credential_descriptors(directory: &tempfile::TempDir) -> GuardianCredentialDescriptors {
        let mut static_files = Vec::new();
        let mut dynamic_files = Vec::new();
        for role in GuardianCredentialRole::ALL {
            if role.is_dynamic() {
                dynamic_files.push((
                    role,
                    SealedReadOnlyCredential::create(role.as_str(), b"x", 1)
                        .unwrap_or_else(|error| panic!("sealed credential failed: {error}")),
                ));
            } else {
                let bytes = vec![1; usize::try_from(role.maximum_bytes().min(32)).unwrap()];
                let path = directory.path().join(role.as_str());
                std::fs::write(&path, bytes)
                    .unwrap_or_else(|error| panic!("static credential write failed: {error}"));
                std::fs::set_permissions(&path, Permissions::from_mode(0o400))
                    .unwrap_or_else(|error| panic!("static credential mode failed: {error}"));
                let file = File::open(path)
                    .unwrap_or_else(|error| panic!("static credential open failed: {error}"));
                static_files.push((role, file));
            }
        }
        let mut entries = static_files
            .iter()
            .map(|(role, file)| (*role, file.as_fd()))
            .collect::<Vec<_>>();
        entries.extend(
            dynamic_files
                .iter()
                .map(|(role, file)| (*role, file.as_fd())),
        );
        GuardianCredentialDescriptors::from_descriptors(entries)
            .unwrap_or_else(|error| panic!("test credential set failed: {error}"))
    }

    #[cfg(not(target_os = "linux"))]
    fn credential_descriptors(directory: &tempfile::TempDir) -> GuardianCredentialDescriptors {
        let files = GuardianCredentialRole::ALL
            .iter()
            .map(|role| {
                let path = directory.path().join(role.as_str());
                std::fs::write(&path, b"x")
                    .unwrap_or_else(|error| panic!("test credential write failed: {error}"));
                let file = File::open(path)
                    .unwrap_or_else(|error| panic!("test credential open failed: {error}"));
                (*role, file)
            })
            .collect::<Vec<_>>();
        GuardianCredentialDescriptors::from_descriptors(
            files
                .iter()
                .map(|(role, file)| (*role, file.as_fd()))
                .collect(),
        )
        .unwrap_or_else(|error| panic!("test credential set failed: {error}"))
    }

    #[test]
    fn property_contract_is_capabilityless_and_closed() {
        let (_directory, spec) = spec();
        let properties = spec
            .properties()
            .unwrap_or_else(|error| panic!("property compilation failed: {error}"));
        let names = properties
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "Description",
                "Type",
                "NotifyAccess",
                "Slice",
                "Restart",
                "CollectMode",
                "DynamicUser",
                "StateDirectory",
                "StateDirectoryMode",
                "UMask",
                "CapabilityBoundingSet",
                "AmbientCapabilities",
                "NoNewPrivileges",
                "RestrictAddressFamilies",
                "SystemCallFilter",
                "SystemCallFilter",
                "SystemCallArchitectures",
                "ProtectSystem",
                "ProtectHome",
                "PrivateTmp",
                "PrivateDevices",
                "ProtectKernelTunables",
                "ProtectKernelModules",
                "ProtectControlGroups",
                "ProtectClock",
                "RestrictNamespaces",
                "LockPersonality",
                "MemoryDenyWriteExecute",
                "RestrictRealtime",
                "RestrictSUIDSGID",
                "InaccessiblePaths",
                "ExtraFileDescriptors",
                "Environment",
                "SetLoginEnvironment",
                "TimeoutStartUSec",
                "ExecStart",
            ]
        );

        let signatures = properties
            .iter()
            .map(|(name, value)| (name.as_str(), value.value_signature().to_string()))
            .collect::<Vec<_>>();
        assert_eq!(
            signatures,
            vec![
                ("Description", "s".to_owned()),
                ("Type", "s".to_owned()),
                ("NotifyAccess", "s".to_owned()),
                ("Slice", "s".to_owned()),
                ("Restart", "s".to_owned()),
                ("CollectMode", "s".to_owned()),
                ("DynamicUser", "b".to_owned()),
                ("StateDirectory", "as".to_owned()),
                ("StateDirectoryMode", "u".to_owned()),
                ("UMask", "u".to_owned()),
                ("CapabilityBoundingSet", "t".to_owned()),
                ("AmbientCapabilities", "t".to_owned()),
                ("NoNewPrivileges", "b".to_owned()),
                ("RestrictAddressFamilies", "(bas)".to_owned()),
                ("SystemCallFilter", "(bas)".to_owned()),
                ("SystemCallFilter", "(bas)".to_owned()),
                ("SystemCallArchitectures", "as".to_owned()),
                ("ProtectSystem", "s".to_owned()),
                ("ProtectHome", "s".to_owned()),
                ("PrivateTmp", "b".to_owned()),
                ("PrivateDevices", "b".to_owned()),
                ("ProtectKernelTunables", "b".to_owned()),
                ("ProtectKernelModules", "b".to_owned()),
                ("ProtectControlGroups", "b".to_owned()),
                ("ProtectClock", "b".to_owned()),
                ("RestrictNamespaces", "t".to_owned()),
                ("LockPersonality", "b".to_owned()),
                ("MemoryDenyWriteExecute", "b".to_owned()),
                ("RestrictRealtime", "b".to_owned()),
                ("RestrictSUIDSGID", "b".to_owned()),
                ("InaccessiblePaths", "as".to_owned()),
                ("ExtraFileDescriptors", "a(hs)".to_owned()),
                ("Environment", "as".to_owned()),
                ("SetLoginEnvironment", "b".to_owned()),
                ("TimeoutStartUSec", "t".to_owned()),
                ("ExecStart", "a(sasb)".to_owned()),
            ]
        );

        for name in [
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "RestrictNamespaces",
        ] {
            let (_, value) = properties
                .iter()
                .find(|(property, _)| property == name)
                .unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(u64::try_from(value).unwrap_or(u64::MAX), 0);
        }

        let (_, environment) = properties
            .iter()
            .find(|(name, _)| name == "Environment")
            .unwrap_or_else(|| panic!("guardian environment is absent"));
        let environment = Vec::<String>::try_from(environment.clone())
            .unwrap_or_else(|error| panic!("guardian environment is malformed: {error}"));
        assert_eq!(
            environment,
            vec![
                format!("{GUARDIAN_ENVIRONMENT_PREFIX}{}", "ab".repeat(16)),
                format!("{GUARDIAN_BINDING_PREFIX}{}", "cd".repeat(32)),
            ]
        );
    }

    #[test]
    fn authority_descriptors_have_one_exact_canonical_order() {
        let (_directory, spec) = spec();
        let properties = spec
            .properties()
            .unwrap_or_else(|error| panic!("property compilation failed: {error}"));
        let (_, value) = properties
            .into_iter()
            .find(|(name, _)| name == "ExtraFileDescriptors")
            .unwrap_or_else(|| panic!("guardian descriptor property is absent"));
        let descriptors = Vec::<(Fd<'static>, String)>::try_from(value)
            .unwrap_or_else(|error| panic!("descriptor property decode failed: {error}"));
        assert_eq!(
            descriptors
                .iter()
                .map(|(_, name)| name.as_str())
                .collect::<Vec<_>>(),
            GuardianCredentialRole::ALL
                .iter()
                .map(|role| role.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn descriptor_roles_reject_the_opposite_custody_class() {
        let directory =
            tempfile::tempdir().unwrap_or_else(|error| panic!("test directory failed: {error}"));
        let path = directory.path().join("static");
        std::fs::write(&path, b"x")
            .unwrap_or_else(|error| panic!("static credential write failed: {error}"));
        std::fs::set_permissions(&path, Permissions::from_mode(0o400))
            .unwrap_or_else(|error| panic!("static credential mode failed: {error}"));
        let static_file = File::open(path)
            .unwrap_or_else(|error| panic!("static credential open failed: {error}"));
        assert!(
            validate_guardian_descriptor(GuardianCredentialRole::BrokerPlan, static_file.as_fd())
                .is_err()
        );

        let dynamic = SealedReadOnlyCredential::create("aos-dynamic-role-test", b"x", 1)
            .unwrap_or_else(|error| panic!("sealed credential failed: {error}"));
        assert!(
            validate_guardian_descriptor(
                GuardianCredentialRole::BrokerPlanPolicy,
                dynamic.as_fd(),
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn protected_static_content_drift_is_rejected_before_transfer() {
        let (directory, spec) = spec();
        let path = directory
            .path()
            .join(GuardianCredentialRole::BrokerPlanPolicy.as_str());
        std::fs::set_permissions(&path, Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("static credential mode failed: {error}"));
        std::fs::write(&path, vec![2; 32])
            .unwrap_or_else(|error| panic!("static credential rewrite failed: {error}"));
        std::fs::set_permissions(&path, Permissions::from_mode(0o400))
            .unwrap_or_else(|error| panic!("static credential mode restore failed: {error}"));

        assert!(spec.properties().is_err());
    }
}
