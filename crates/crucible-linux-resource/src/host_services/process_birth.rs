//! Authenticates the campaign manager's actual preexec containment and main birth.
//!
//! This module retains the pinned original cgroup and invocation independently
//! of consumer accounts. Its physical readbacks establish neither resource
//! credit nor permission to publish a different account or workload.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use super::{
    AdmittedHostServiceBootstrap, HostServiceAllocator, HostServiceError, HostServiceLease,
    HostServiceLeasePair,
};

#[cfg(feature = "private-measurement-domain")]
mod backing;
#[cfg(feature = "private-measurement-domain")]
mod cpu;
#[cfg(feature = "private-measurement-domain")]
mod parent_attempt;
#[cfg(feature = "private-measurement-domain")]
pub use cpu::{OriginalCpuCounters, OriginalCpuReadError};
#[cfg(feature = "private-measurement-domain")]
pub use parent_attempt::{OriginalParentAttempt, OriginalParentAttemptRefusal};

/// Expected limits from the caller's immutable operator policy.
///
/// These values are comparison inputs, not a resource grant. Authentication
/// requires the real root PID1 manager, this main process and its actual limits.
pub struct ServiceBirthContract<'policy> {
    /// The original campaign service unit.
    pub unit: &'policy str,
    /// The immutable original main executable.
    pub executable: &'policy str,
    /// The installed aggregate memory ceiling in bytes.
    pub memory_max_bytes: u64,
    /// The installed aggregate task ceiling.
    pub tasks_max: u64,
    /// The installed per-process soft and hard descriptor ceiling.
    pub file_descriptors: u64,
    /// The original main invocation lifetime in seconds.
    pub runtime_seconds: u64,
    /// The finite startup timeout in seconds.
    pub startup_timeout_seconds: u64,
    /// The installed main stack ceiling in bytes.
    pub main_thread_stack_bytes: u64,
    /// The CPU quota as a percentage of one CPU.
    pub cpu_quota_percent: u64,
    /// The original baseline excluded from consumer resident counter capacity.
    pub baseline_resident_bytes: u64,
    /// The independently tracked metadata subset in bytes.
    pub metadata_bytes: u64,
}

/// Retains the authenticated main incarnation and its pinned containment root.
///
/// This owner exposes no raw cgroup path or descriptor and issues no accounts.
pub struct VerifiedServiceBirth {
    deadline: u64,
    invocation: [u8; 16],
    _cgroup: File,
    resident_bytes: u64,
    metadata_bytes: u64,
    tasks: u64,
    descriptors: u64,
    #[cfg(feature = "private-measurement-domain")]
    cpu: std::sync::Mutex<File>,
}

impl VerifiedServiceBirth {
    /// Checks the same incarnation's original operational end.
    pub fn is_live(&self) -> bool {
        self.invocation != [0; 16]
            && monotonic_microseconds().is_some_and(|now| now < self.deadline)
    }

    /// Publishes the matching original counters once beneath this birth owner.
    ///
    /// The complete capacity comparison precedes the existing two shared
    /// account allocations. This consumes the admitted bootstrap and this
    /// incarnation; it does not copy, reset or enlarge either counter.
    ///
    /// # Errors
    /// Refuses expiry or a bootstrap whose exact capacities differ from the
    /// immutable process partitions authenticated with this incarnation.
    pub fn publish_original_process(
        self,
        original: AdmittedHostServiceBootstrap,
    ) -> Result<AuthenticatedProcessResources, ServiceBirthError> {
        if !self.is_live()
            || !original.matches_process_capacity(
                self.tasks,
                self.descriptors,
                self.resident_bytes,
                self.metadata_bytes,
            )
        {
            return Err(ServiceBirthError::policy(
                "campaign original account differs from its authenticated birth",
            ));
        }
        // The immutable operator issues backing once before any account Arc.
        // A partial compiled profile cannot publish a usable replacement owner.
        #[cfg(feature = "private-measurement-domain")]
        let backing = backing::BackingAccount::compiled_original()?;
        let (resident, metadata) = original.publish();
        Ok(AuthenticatedProcessResources {
            resident,
            metadata,
            birth: self,
            #[cfg(feature = "private-measurement-domain")]
            attempt: std::sync::Mutex::new(parent_attempt::AttemptSlot::new(backing)),
        })
    }
}

/// Retains the same published process counters and their authenticated birth.
///
/// Borrowers retain this owner until their allocations and lease controls
/// close. Its reservations lend existing counters and issue no native role.
pub struct AuthenticatedProcessResources {
    resident: HostServiceAllocator,
    metadata: HostServiceAllocator,
    birth: VerifiedServiceBirth,
    #[cfg(feature = "private-measurement-domain")]
    attempt: std::sync::Mutex<parent_attempt::AttemptSlot>,
}

impl AuthenticatedProcessResources {
    /// Checks the unchanged enclosing invocation and operational end.
    pub fn is_live(&self) -> bool {
        self.birth.is_live()
    }

    /// Reserves an existing resident purpose beneath this retained owner.
    ///
    /// # Errors
    /// Refuses enclosing expiry, overflow or exhausted original capacity.
    pub fn reserve_resident(
        &self,
        tasks: u64,
        descriptors: u64,
        bytes: u64,
    ) -> Result<HostServiceLease, HostServiceError> {
        if !self.is_live() {
            return Err(HostServiceError::Unavailable);
        }
        self.resident.reserve_resources(tasks, descriptors, bytes)
    }

    /// Reserves the same metadata amount in both retained original counters.
    ///
    /// # Errors
    /// Refuses enclosing expiry, overflow or either exhausted original counter.
    pub fn reserve_metadata(&self, bytes: u64) -> Result<HostServiceLeasePair, HostServiceError> {
        if !self.is_live() {
            return Err(HostServiceError::Unavailable);
        }
        let (metadata, resident) = self.metadata.reserve_paired_bytes(&self.resident, bytes)?;
        Ok(HostServiceLeasePair::new(resident, metadata))
    }
}

/// Reports an original service-birth authentication diagnostic.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ServiceBirthError(String);

impl ServiceBirthError {
    fn policy(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Authenticates and retains the original service main process and limits.
///
/// # Errors
/// Refuses an unavailable or unauthenticated manager, changed invocation,
/// different main executable or cgroup, mismatched limits or an expired end.
pub async fn authenticate(
    policy: &ServiceBirthContract<'_>,
) -> Result<VerifiedServiceBirth, ServiceBirthError> {
    if policy.unit != "crucible-campaign.service"
        || !policy.executable.starts_with("/nix/store/")
        || !policy.executable.ends_with("/bin/crucible")
        || policy.runtime_seconds.checked_mul(1_000_000).is_none()
        || policy
            .startup_timeout_seconds
            .checked_mul(1_000_000)
            .is_none()
        || policy.cpu_quota_percent.checked_mul(10_000).is_none()
        || policy.metadata_bytes == 0
        || policy.baseline_resident_bytes >= policy.memory_max_bytes
        || policy.metadata_bytes > policy.memory_max_bytes - policy.baseline_resident_bytes
    {
        return Err(ServiceBirthError::policy(
            "campaign process birth contract is invalid",
        ));
    }
    // A fixed endpoint avoids accepting a caller-selected bus through an
    // environment variable. Its manager owner must be the real root PID1.
    let connection = zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
        .map_err(message)?
        .max_queued(8)
        .method_timeout(Duration::from_secs(5))
        .build()
        .await
        .map_err(message)?;
    let bus = zbus::fdo::DBusProxy::new(&connection)
        .await
        .map_err(message)?;
    let manager_name =
        zbus::names::BusName::try_from("org.freedesktop.systemd1").map_err(message)?;
    let owner = bus.get_name_owner(manager_name).await.map_err(message)?;
    let manager_destination = owner.as_str().to_owned();
    let owner_name = zbus::names::BusName::from(owner);
    if bus
        .get_connection_unix_process_id(owner_name.clone())
        .await
        .map_err(message)?
        != 1
        || bus
            .get_connection_unix_user(owner_name)
            .await
            .map_err(message)?
            != 0
    {
        return Err(ServiceBirthError::policy(
            "campaign process manager is not root PID1",
        ));
    }
    let manager = zbus::Proxy::new(
        &connection,
        manager_destination.as_str(),
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await
    .map_err(message)?;
    let path: zbus::zvariant::OwnedObjectPath = manager
        .call("GetUnit", &(policy.unit,))
        .await
        .map_err(message)?;
    let own_path: zbus::zvariant::OwnedObjectPath = manager
        .call("GetUnitByPID", &(std::process::id(),))
        .await
        .map_err(message)?;
    if path != own_path {
        return Err(ServiceBirthError::policy(
            "campaign process is outside its authored service unit",
        ));
    }
    let unit = zbus::Proxy::new(
        &connection,
        manager_destination.as_str(),
        path.as_str(),
        "org.freedesktop.systemd1.Unit",
    )
    .await
    .map_err(message)?;
    let service = zbus::Proxy::new(
        &connection,
        manager_destination.as_str(),
        path.as_str(),
        "org.freedesktop.systemd1.Service",
    )
    .await
    .map_err(message)?;
    let invocation: Vec<u8> = unit.get_property("InvocationID").await.map_err(message)?;
    let invocation: [u8; 16] = invocation.try_into().map_err(|_| {
        ServiceBirthError::policy("campaign invocation identity has the wrong extent")
    })?;
    let main: u32 = service.get_property("MainPID").await.map_err(message)?;
    let start: u64 = service
        .get_property("ExecMainStartTimestampMonotonic")
        .await
        .map_err(message)?;
    let runtime: u64 = service
        .get_property("RuntimeMaxUSec")
        .await
        .map_err(message)?;
    if main != std::process::id()
        || invocation == [0; 16]
        || start == 0
        || runtime != policy.runtime_seconds * 1_000_000
    {
        return Err(ServiceBirthError::policy(
            "campaign process is not the original finite main invocation",
        ));
    }
    for (property, expected) in [
        ("MemoryMax", policy.memory_max_bytes),
        (
            "TimeoutStartUSec",
            policy.startup_timeout_seconds * 1_000_000,
        ),
        ("LimitSTACK", policy.main_thread_stack_bytes),
        ("LimitSTACKSoft", policy.main_thread_stack_bytes),
        ("TasksMax", policy.tasks_max),
        ("LimitNOFILE", policy.file_descriptors),
        ("LimitNOFILESoft", policy.file_descriptors),
        ("CPUQuotaPerSecUSec", policy.cpu_quota_percent * 10_000),
        ("CPUQuotaPeriodUSec", 100_000),
    ] {
        let actual: u64 = service.get_property(property).await.map_err(message)?;
        if actual != expected {
            return Err(ServiceBirthError::policy(format!(
                "campaign preexec {property} differs from its authored policy"
            )));
        }
    }
    if std::fs::read_link("/proc/self/exe").map_err(message)? != Path::new(&policy.executable) {
        return Err(ServiceBirthError::policy(
            "campaign executable differs from its immutable policy",
        ));
    }
    let group: String = service
        .get_property("ControlGroup")
        .await
        .map_err(message)?;
    if group.len() > 4095
        || !group.starts_with('/')
        || group == "/"
        || group
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ServiceBirthError::policy(
            "campaign manager returned an invalid cgroup identity",
        ));
    }
    let own_group = bounded_read(Path::new("/proc/self/cgroup"), 4096)?;
    let same_root = own_group
        .lines()
        .any(|line| line.strip_prefix("0::") == Some(group.as_str()));
    #[cfg(feature = "private-measurement-domain")]
    let same_root = same_root
        || own_group.lines().any(|line| {
            line.strip_prefix("0::")
                .and_then(|value| value.strip_suffix("/guardian"))
                == Some(group.as_str())
        });
    if !same_root {
        return Err(ServiceBirthError::policy(
            "campaign process is not contained in the original unified cgroup",
        ));
    }
    let cgroup_path = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    for (file, expected) in [
        ("memory.max", policy.memory_max_bytes),
        ("pids.max", policy.tasks_max),
    ] {
        let actual = bounded_read(&cgroup_path.join(file), 64)?;
        if actual.trim().parse::<u64>().ok() != Some(expected) {
            return Err(ServiceBirthError::policy(format!(
                "campaign installed {file} differs from its policy"
            )));
        }
    }
    let cpu = bounded_read(&cgroup_path.join("cpu.max"), 128)?;
    let mut cpu = cpu.split_whitespace();
    if cpu.next().and_then(|value| value.parse::<u64>().ok())
        != policy.cpu_quota_percent.checked_mul(1000)
        || cpu.next().and_then(|value| value.parse::<u64>().ok()) != Some(100_000)
        || cpu.next().is_some()
    {
        return Err(ServiceBirthError::policy(
            "campaign installed CPU quota differs from its policy",
        ));
    }
    let now = monotonic_microseconds()
        .ok_or_else(|| ServiceBirthError::policy("campaign monotonic clock is unrepresentable"))?;
    let deadline = start
        .checked_add(runtime)
        .filter(|end| *end > now)
        .ok_or_else(|| {
            ServiceBirthError::policy("campaign original runtime deadline has expired")
        })?;
    let cgroup = File::open(&cgroup_path).map_err(message)?;
    #[cfg(feature = "private-measurement-domain")]
    let cpu = File::from(
        rustix::fs::openat(
            &cgroup,
            "cpu.stat",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(message)?,
    );
    // Recheck the main invocation after reading its complete containment. A
    // helper or a concurrently replaced incarnation cannot publish this proof.
    let final_main: u32 = service.get_property("MainPID").await.map_err(message)?;
    let final_invocation: Vec<u8> = unit.get_property("InvocationID").await.map_err(message)?;
    if final_main != main || final_invocation.as_slice() != invocation {
        return Err(ServiceBirthError::policy(
            "campaign main invocation changed during admission",
        ));
    }
    Ok(VerifiedServiceBirth {
        deadline,
        invocation,
        _cgroup: cgroup,
        resident_bytes: policy.memory_max_bytes - policy.baseline_resident_bytes,
        metadata_bytes: policy.metadata_bytes,
        tasks: policy.tasks_max,
        descriptors: policy.file_descriptors,
        #[cfg(feature = "private-measurement-domain")]
        cpu: std::sync::Mutex::new(cpu),
    })
}

fn bounded_read(path: &Path, maximum: usize) -> Result<String, ServiceBirthError> {
    let file = File::open(path).map_err(message)?;
    let mut bytes = Vec::with_capacity(maximum + 1);
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(message)?;
    if bytes.len() > maximum {
        return Err(ServiceBirthError::policy(
            "campaign containment read exceeds its fixed bound",
        ));
    }
    String::from_utf8(bytes).map_err(message)
}

fn message(error: impl std::fmt::Display) -> ServiceBirthError {
    ServiceBirthError::policy(error.to_string())
}

/// Reads the service manager's host-only monotonic deadline domain.
pub fn monotonic_microseconds() -> Option<u64> {
    // This is the service manager's operational deadline domain. It does not
    // enter a scenario, schedule, replay state or guest-visible clock.
    let clock = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(clock.tv_sec)
        .ok()?
        .checked_mul(1_000_000)?
        .checked_add(u64::try_from(clock.tv_nsec).ok()? / 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn birth() -> VerifiedServiceBirth {
        VerifiedServiceBirth {
            deadline: u64::MAX,
            invocation: [1; 16],
            _cgroup: tempfile::tempfile().unwrap(),
            resident_bytes: 4096,
            metadata_bytes: 1024,
            tasks: 4,
            descriptors: 12,
            #[cfg(feature = "private-measurement-domain")]
            cpu: std::sync::Mutex::new(tempfile::tempfile().unwrap()),
        }
    }

    #[test]
    fn mismatched_original_capacity_refuses_before_shared_controls() {
        let original = super::super::HostServiceBootstrap::new(4, 12, 4097, 1024)
            .unwrap()
            .reserve_structure(super::super::HostServiceBootstrap::control_bytes().unwrap())
            .unwrap();
        let owner = birth();

        let (result, counts) = crate::test_support::TestAllocationObserver::count(|| {
            owner.publish_original_process(original)
        });

        assert!(result.is_err());
        // One diagnostic String is allowed; no two account controls are born.
        assert_eq!(counts.allocations, 1);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
    }

    #[test]
    fn publication_preserves_original_structural_charge_and_counter_identity() {
        let structure = super::super::HostServiceBootstrap::control_bytes().unwrap();
        let original = super::super::HostServiceBootstrap::new(4, 12, 4096, 1024)
            .unwrap()
            .reserve_structure(structure)
            .unwrap();

        let birth = birth();
        let (result, counts) = crate::test_support::TestAllocationObserver::count(|| {
            birth.publish_original_process(original)
        });
        let owner = result.unwrap();

        assert_eq!(counts.allocations, 2);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        let occupied = owner.reserve_resident(4, 12, 4096 - structure).unwrap();
        assert!(owner.reserve_resident(0, 0, 1).is_err());
        assert_eq!(occupied.tasks(), 4);
        assert_eq!(occupied.file_descriptors(), 12);
        drop(occupied);

        let pair = owner.reserve_metadata(1024 - structure).unwrap();
        assert!(owner.reserve_metadata(1).is_err());
        drop(pair);
        assert!(owner.reserve_metadata(1024 - structure).is_ok());
    }

    #[test]
    fn expired_birth_cannot_publish_original_controls() {
        let mut owner = birth();
        owner.deadline = 0;
        let original = super::super::HostServiceBootstrap::new(4, 12, 4096, 1024)
            .unwrap()
            .reserve_structure(super::super::HostServiceBootstrap::control_bytes().unwrap())
            .unwrap();

        assert!(owner.publish_original_process(original).is_err());
    }

    #[test]
    fn bounded_containment_reads_keep_their_typed_refusal_and_extent() -> std::io::Result<()> {
        let file = tempfile::NamedTempFile::new()?;
        std::fs::write(file.path(), b"1234")?;
        let complete = match bounded_read(file.path(), 4) {
            Ok(value) => value,
            Err(error) => panic!("exact bounded containment read: {error}"),
        };
        assert_eq!(complete, "1234");

        let oversized = match bounded_read(file.path(), 3) {
            Ok(_) => panic!("oversized containment must refuse"),
            Err(error) => error,
        };
        assert!(matches!(&oversized, ServiceBirthError(_)));
        assert_eq!(
            oversized.to_string(),
            "campaign containment read exceeds its fixed bound"
        );

        std::fs::write(file.path(), [0xff])?;
        let expected = String::from_utf8(vec![0xff])
            .expect_err("invalid UTF-8")
            .to_string();
        let invalid_text = match bounded_read(file.path(), 1) {
            Ok(_) => panic!("invalid containment text must refuse"),
            Err(error) => error,
        };
        assert!(matches!(&invalid_text, ServiceBirthError(_)));
        assert_eq!(invalid_text.to_string(), expected);
        Ok(())
    }
}
