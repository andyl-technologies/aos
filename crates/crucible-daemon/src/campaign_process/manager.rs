//! Authenticates the service manager's actual main invocation and preexec limits.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use super::CampaignProcessAdmissionError;
use super::policy::ProcessPolicy;

pub(super) struct BirthProof {
    pub deadline: u64,
    pub invocation: [u8; 16],
    pub cgroup: File,
}

pub(super) async fn verify(
    policy: &ProcessPolicy,
) -> Result<BirthProof, CampaignProcessAdmissionError> {
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
        return Err(CampaignProcessAdmissionError::policy(
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
        .call("GetUnit", &(policy.unit.as_str(),))
        .await
        .map_err(message)?;
    let own_path: zbus::zvariant::OwnedObjectPath = manager
        .call("GetUnitByPID", &(std::process::id(),))
        .await
        .map_err(message)?;
    if path != own_path {
        return Err(CampaignProcessAdmissionError::policy(
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
        CampaignProcessAdmissionError::policy("campaign invocation identity has the wrong extent")
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
        return Err(CampaignProcessAdmissionError::policy(
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
            return Err(CampaignProcessAdmissionError::policy(format!(
                "campaign preexec {property} differs from its authored policy"
            )));
        }
    }
    if std::fs::read_link("/proc/self/exe").map_err(message)? != Path::new(&policy.executable) {
        return Err(CampaignProcessAdmissionError::policy(
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
        return Err(CampaignProcessAdmissionError::policy(
            "campaign manager returned an invalid cgroup identity",
        ));
    }
    let own_group = bounded_read(Path::new("/proc/self/cgroup"), 4096)?;
    if !own_group
        .lines()
        .any(|line| line.strip_prefix("0::") == Some(group.as_str()))
    {
        return Err(CampaignProcessAdmissionError::policy(
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
            return Err(CampaignProcessAdmissionError::policy(format!(
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
        return Err(CampaignProcessAdmissionError::policy(
            "campaign installed CPU quota differs from its policy",
        ));
    }
    let now = monotonic_microseconds().ok_or_else(|| {
        CampaignProcessAdmissionError::policy("campaign monotonic clock is unrepresentable")
    })?;
    let deadline = start
        .checked_add(runtime)
        .filter(|end| *end > now)
        .ok_or_else(|| {
            CampaignProcessAdmissionError::policy("campaign original runtime deadline has expired")
        })?;
    let cgroup = File::open(&cgroup_path).map_err(message)?;
    // Recheck the main invocation after reading its complete containment. A
    // helper or a concurrently replaced incarnation cannot publish this proof.
    let final_main: u32 = service.get_property("MainPID").await.map_err(message)?;
    let final_invocation: Vec<u8> = unit.get_property("InvocationID").await.map_err(message)?;
    if final_main != main || final_invocation.as_slice() != invocation {
        return Err(CampaignProcessAdmissionError::policy(
            "campaign main invocation changed during admission",
        ));
    }
    Ok(BirthProof {
        deadline,
        invocation,
        cgroup,
    })
}

fn bounded_read(path: &Path, maximum: usize) -> Result<String, CampaignProcessAdmissionError> {
    let file = File::open(path).map_err(message)?;
    let mut bytes = Vec::with_capacity(maximum + 1);
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(message)?;
    if bytes.len() > maximum {
        return Err(CampaignProcessAdmissionError::policy(
            "campaign containment read exceeds its fixed bound",
        ));
    }
    String::from_utf8(bytes).map_err(message)
}

fn message(error: impl std::fmt::Display) -> CampaignProcessAdmissionError {
    CampaignProcessAdmissionError::policy(error.to_string())
}

pub(super) fn monotonic_microseconds() -> Option<u64> {
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

    #[test]
    fn manager_diagnostics_retain_policy_classification_and_original_text() {
        let original = std::io::Error::other("original manager refusal");
        let expected = original.to_string();
        let classified = message(original);

        assert!(matches!(
            &classified,
            CampaignProcessAdmissionError::Policy(_)
        ));
        assert_eq!(classified.to_string(), expected);
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
        assert!(matches!(
            &oversized,
            CampaignProcessAdmissionError::Policy(_)
        ));
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
        assert!(matches!(
            &invalid_text,
            CampaignProcessAdmissionError::Policy(_)
        ));
        assert_eq!(invalid_text.to_string(), expected);
        Ok(())
    }
}
