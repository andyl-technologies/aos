//! Strict operator-authored partitions for one campaign service process.
//!
//! The same evaluated value installs systemd limits before exec and is read by
//! the admitted main process. Runtime identity includes this complete policy.
//!
//! The identity prefix has this TOML form; every resource field below is also
//! mandatory, and unknown fields are rejected.
//!
//! ```toml
//! schema = "crucible.campaign-process.v1"
//! unit = "crucible-campaign.service"
//! executable = "/nix/store/PACKAGE/bin/crucible"
//! ```

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessPolicy {
    /// Fixed process-contract schema.
    pub schema: String,
    /// Original service unit selected by the evaluated module.
    pub unit: String,
    /// Immutable executable installed by that same service definition.
    pub executable: String,
    /// Complete prebirth service memory ceiling.
    pub memory_max_bytes: u64,
    /// Original task ceiling including main, helpers and runtime workers.
    pub tasks_max: u64,
    /// Original soft and hard descriptor limit.
    pub file_descriptors: u64,
    /// Original main invocation lifetime, without restarting its clock.
    pub runtime_seconds: u64,
    /// Separate finite startup timeout including service preparation.
    pub startup_timeout_seconds: u64,
    /// Installed main-thread soft and hard stack limit.
    pub main_thread_stack_bytes: u64,
    /// Service CPU quota in percent of one CPU at a 100 ms period.
    pub cpu_quota_percent: u64,
    /// Loaded mappings, parsing, runtime, allocator overhead and stacks.
    pub baseline_resident_bytes: u64,
    /// Resident purpose for process and managed SQLite controls.
    pub metadata_bytes: u64,
    /// Independently qualified permanent native storage and initialization peak.
    pub sqlite_bootstrap_bytes: u64,
    /// One exact positive native heap ceiling for this process.
    pub sqlite_heap_bytes: u64,
    /// Fixed connection census capacity from the descriptor contract.
    pub sqlite_connections: usize,
    /// Fixed ordinary Tokio worker count.
    pub worker_threads: usize,
    /// Fixed maximum Tokio blocking worker count.
    pub blocking_threads: usize,
    /// Authored stack extent for each runtime worker.
    pub thread_stack_bytes: usize,
}

impl ProcessPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != "crucible.campaign-process.v1"
            || self.unit != "crucible-campaign.service"
            || !self.executable.starts_with("/nix/store/")
            || !self.executable.ends_with("/bin/crucible")
        {
            return Err("campaign process policy identity is incompatible");
        }
        if [
            self.memory_max_bytes,
            self.tasks_max,
            self.file_descriptors,
            self.runtime_seconds,
            self.startup_timeout_seconds,
            self.main_thread_stack_bytes,
            self.cpu_quota_percent,
            self.baseline_resident_bytes,
            self.metadata_bytes,
            self.sqlite_bootstrap_bytes,
            self.sqlite_heap_bytes,
        ]
        .contains(&0)
            || self.sqlite_connections == 0
            || self.worker_threads == 0
            || self.blocking_threads == 0
            || self.thread_stack_bytes < 16_384
            || self.main_thread_stack_bytes < 16_384
        {
            return Err("campaign process resource partitions must be finite and positive");
        }
        let resident = self
            .baseline_resident_bytes
            .checked_add(self.metadata_bytes)
            .and_then(|n| n.checked_add(self.sqlite_bootstrap_bytes))
            .and_then(|n| n.checked_add(self.sqlite_heap_bytes))
            .ok_or("campaign process resident partitions overflow")?;
        if resident > self.memory_max_bytes {
            return Err("campaign process resident partitions exceed MemoryMax");
        }
        let threads = self
            .worker_threads
            .checked_add(self.blocking_threads)
            .ok_or("campaign runtime thread count overflows")?;
        let tasks = u64::try_from(threads)
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or("campaign runtime task purpose overflows")?;
        let stacks = u64::try_from(self.thread_stack_bytes)
            .ok()
            .and_then(|n| n.checked_mul(tasks - 1))
            .and_then(|n| n.checked_add(self.main_thread_stack_bytes))
            .ok_or("campaign runtime stack purpose overflows")?;
        if tasks > self.tasks_max || stacks > self.baseline_resident_bytes {
            return Err("campaign runtime threads exceed their authored task or baseline purpose");
        }
        if self.sqlite_heap_bytes > i64::MAX as u64
            || u64::try_from(self.sqlite_connections)
                .ok()
                .and_then(|n| n.checked_mul(2))
                .is_none_or(|n| n > self.file_descriptors)
            || self.runtime_seconds.checked_mul(1_000_000).is_none()
            || self
                .startup_timeout_seconds
                .checked_mul(1_000_000)
                .is_none()
            || self.cpu_quota_percent.checked_mul(10_000).is_none()
        {
            return Err("campaign native heap, descriptor, deadline or CPU purpose is invalid");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ProcessPolicy {
        ProcessPolicy {
            schema: "crucible.campaign-process.v1".into(),
            unit: "crucible-campaign.service".into(),
            executable: "/nix/store/example/bin/crucible".into(),
            memory_max_bytes: 64 << 20,
            tasks_max: 8,
            file_descriptors: 64,
            runtime_seconds: 60,
            startup_timeout_seconds: 30,
            main_thread_stack_bytes: 1 << 20,
            cpu_quota_percent: 200,
            baseline_resident_bytes: 16 << 20,
            metadata_bytes: 8 << 20,
            sqlite_bootstrap_bytes: 1 << 20,
            sqlite_heap_bytes: 8 << 20,
            sqlite_connections: 16,
            worker_threads: 2,
            blocking_threads: 2,
            thread_stack_bytes: 1 << 20,
        }
    }

    #[test]
    fn process_schema_requires_all_partitions_and_rejects_unknown_authority() {
        let document = r#"
            schema = "crucible.campaign-process.v1"
            unit = "crucible-campaign.service"
            executable = "/nix/store/example/bin/crucible"
            memory_max_bytes = 67108864
            tasks_max = 8
            file_descriptors = 64
            runtime_seconds = 60
            startup_timeout_seconds = 30
            main_thread_stack_bytes = 1048576
            cpu_quota_percent = 200
            baseline_resident_bytes = 16777216
            metadata_bytes = 8388608
            sqlite_bootstrap_bytes = 1048576
            sqlite_heap_bytes = 8388608
            sqlite_connections = 16
            worker_threads = 2
            blocking_threads = 2
            thread_stack_bytes = 1048576
        "#;
        let parsed: ProcessPolicy = toml::from_str(document).expect("explicit process policy");
        assert!(parsed.validate().is_ok());
        assert!(
            toml::from_str::<ProcessPolicy>(&document.replace("startup_timeout_seconds = 30", ""))
                .is_err()
        );
        assert!(
            toml::from_str::<ProcessPolicy>(&format!(
                "{document}\nexisting_pid_is_authority = true\n"
            ))
            .is_err()
        );

        let mut incompatible = parsed;
        incompatible.unit = "another.service".into();
        assert!(incompatible.validate().is_err());
    }

    #[test]
    fn process_partitions_refuse_overflow_and_unfunded_threads() {
        assert!(policy().validate().is_ok());
        let mut value = policy();
        value.sqlite_heap_bytes = u64::MAX;
        assert!(value.validate().is_err());
        let mut value = policy();
        value.blocking_threads = 8;
        assert!(value.validate().is_err());
        let mut value = policy();
        value.thread_stack_bytes = 16 << 20;
        assert!(value.validate().is_err());
        let mut value = policy();
        value.file_descriptors = 31;
        assert!(value.validate().is_err());
    }
}
