//! Snapshots authorized profiles and actual hierarchical kernel controls.

use std::{
    path::{Component, Path, PathBuf},
    time::Duration,
};

use tokio::time;
use zbus::{Connection, Proxy, zvariant::OwnedObjectPath};

use super::{DESTINATION, SystemdError, SystemdProfile, manager_error, manager_proxy, unit_path};
use crate::{
    WorkerFailureCause, WorkerFailureReport,
    providers::{EnforcedLimits, ResourceBoundary, ResourceLimits},
};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Records local events without including events from descendant boundaries.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct MemoryEvents {
    pub oom: u64,
    pub oom_kill: u64,
}

#[derive(Clone)]
pub(super) struct MemoryObservation {
    leaf: PathBuf,
    leaf_events: MemoryEvents,
    ancestors: Vec<(String, PathBuf, MemoryEvents)>,
}

impl MemoryObservation {
    pub(super) async fn capture(
        leaf: PathBuf,
        limits: &EnforcedLimits,
    ) -> Result<Self, SystemdError> {
        let leaf_events = memory_events(&leaf).await?;
        let mut ancestors = Vec::new();
        for boundary in std::iter::once(&limits.solvers)
            .chain(std::iter::once(&limits.application))
            .chain(limits.outer_ancestors.iter())
        {
            let path = directory(&boundary.cgroup_path)?;
            let events = memory_events(&path).await?;
            ancestors.push((boundary.unit.clone(), path, events));
        }

        Ok(Self {
            leaf,
            leaf_events,
            ancestors,
        })
    }

    pub(super) async fn refresh(&self) -> Result<Self, SystemdError> {
        let leaf_events = memory_events(&self.leaf).await?;
        let mut ancestors = Vec::new();
        for (unit, path, _) in &self.ancestors {
            ancestors.push((unit.clone(), path.clone(), memory_events(path).await?));
        }

        Ok(Self {
            leaf: self.leaf.clone(),
            leaf_events,
            ancestors,
        })
    }

    pub(super) async fn report(&self) -> Result<WorkerFailureReport, SystemdError> {
        let leaf_now = memory_events(&self.leaf).await?;
        let mut ancestors_with_oom = Vec::new();
        for (unit, path, before) in &self.ancestors {
            let now = memory_events(path).await?;
            if now.oom > before.oom {
                ancestors_with_oom.push(unit.as_str());
            }
        }

        Ok(classify_memory_events(
            self.leaf_events,
            leaf_now,
            &ancestors_with_oom,
        ))
    }
}

fn classify_memory_events(
    before: MemoryEvents,
    now: MemoryEvents,
    ancestors_with_oom: &[&str],
) -> WorkerFailureReport {
    // A parent's local OOM event alone says nothing about which worker lost
    // execution. Require a kill in this leaf during the same operation.
    let cause = if now.oom_kill > before.oom_kill {
        if now.oom > before.oom && ancestors_with_oom.is_empty() {
            WorkerFailureCause::WorkerMemoryLimit
        } else if now.oom == before.oom && ancestors_with_oom.len() == 1 {
            WorkerFailureCause::AncestorMemoryLimit {
                unit: ancestors_with_oom[0].to_owned(),
            }
        } else {
            WorkerFailureCause::Unknown
        }
    } else {
        WorkerFailureCause::Unknown
    };

    WorkerFailureReport {
        cause,
        detail: format!(
            "operation-local memory evidence: worker oom {} -> {}, oom_kill {} -> {}; {} enclosing boundaries observed local oom; overlapping or absent evidence remains unknown",
            before.oom,
            now.oom,
            before.oom_kill,
            now.oom_kill,
            ancestors_with_oom.len(),
        ),
    }
}

pub(super) async fn memory_events(directory: &Path) -> Result<MemoryEvents, SystemdError> {
    let text = tokio::fs::read_to_string(directory.join("memory.events.local")).await?;
    parse_memory_events(&text)
}

fn parse_memory_events(text: &str) -> Result<MemoryEvents, SystemdError> {
    let mut oom = None;
    let mut oom_kill = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let name = fields.next();
        if !matches!(name, Some("oom" | "oom_kill")) {
            continue;
        }

        let value = fields
            .next()
            .and_then(|value| value.parse().ok())
            .filter(|_| fields.next().is_none())
            .ok_or(SystemdError::InvalidPolicy("local memory event is invalid"))?;
        let slot = if name == Some("oom") {
            &mut oom
        } else {
            &mut oom_kill
        };
        if slot.replace(value).is_some() {
            return Err(SystemdError::InvalidPolicy(
                "local memory event is duplicated",
            ));
        }
    }

    Ok(MemoryEvents {
        oom: oom.ok_or(SystemdError::InvalidPolicy("local OOM event is missing"))?,
        oom_kill: oom_kill.ok_or(SystemdError::InvalidPolicy(
            "local OOM kill event is missing",
        ))?,
    })
}

pub(super) async fn initialize(
    connection: &Connection,
    profile: &SystemdProfile,
) -> Result<EnforcedLimits, SystemdError> {
    let name = profile.solver_slice();
    let manager = manager_proxy(connection).await?;
    let _: OwnedObjectPath = manager
        .call("StartUnit", &(name.as_str(), "replace"))
        .await
        .map_err(|source| manager_error("start solver slice", source))?;
    time::timeout(
        Duration::from_secs(profile.limits().startup_timeout_seconds),
        async {
            loop {
                let unit = Proxy::new(
                    connection,
                    DESTINATION,
                    unit_path(connection, &name).await?,
                    "org.freedesktop.systemd1.Unit",
                )
                .await
                .map_err(|source| manager_error("solver slice unit proxy", source))?;
                let state: String = unit
                    .get_property("ActiveState")
                    .await
                    .map_err(|source| manager_error("solver slice ActiveState", source))?;
                match state.as_str() {
                    "active" => return Ok(()),
                    "failed" => return Err(SystemdError::AggregatePolicy(name.clone())),
                    _ => time::sleep(Duration::from_millis(20)).await,
                }
            }
        },
    )
    .await
    .map_err(|_| SystemdError::InitializationTimeout)??;

    let application = slice_boundary(connection, &profile.application_slice()).await?;
    let solvers = slice_boundary(connection, &name).await?;
    for boundary in [&application, &solvers] {
        let limits = &boundary.limits;
        if limits.memory_max_bytes.is_none_or(|value| value == 0)
            || limits.task_limit.is_none_or(|value| value == 0)
            || limits
                .cpu_weight
                .is_none_or(|value| !(1..=10_000).contains(&value))
        {
            return Err(SystemdError::AggregatePolicy(boundary.unit.clone()));
        }
    }

    let mut outer_ancestors = Vec::new();
    let application_directory = directory(&application.cgroup_path)?;
    let mut ancestor = application_directory.parent();
    while let Some(path) = ancestor.filter(|path| *path != Path::new(CGROUP_ROOT)) {
        let name =
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or(SystemdError::InvalidPolicy(
                    "ancestor cgroup has no UTF-8 identity",
                ))?;
        let relative = path
            .strip_prefix(CGROUP_ROOT)
            .map_err(|_| SystemdError::InvalidPolicy("ancestor escaped the unified hierarchy"))?;
        let cgroup_path = format!("/{}", relative.display());
        outer_ancestors.push(ResourceBoundary {
            unit: name.to_owned(),
            cgroup_path,
            limits: read_limits(path).await?,
        });
        ancestor = path.parent();
    }

    let limits = profile.limits();
    let worker_policy = ResourceLimits {
        cpu_weight: Some(limits.cpu_weight),
        cpu_quota_micros: Some(u64::from(limits.cpu_quota_percent) * 1_000),
        cpu_period_micros: Some(100_000),
        task_limit: Some(limits.tasks_max),
        memory_high_bytes: Some(limits.memory_high_bytes),
        memory_max_bytes: Some(limits.memory_max_bytes),
    };
    let mut effective_worker_ceiling = worker_policy.clone();
    for boundary in std::iter::once(&solvers)
        .chain(std::iter::once(&application))
        .chain(outer_ancestors.iter())
    {
        restrict(&mut effective_worker_ceiling, &boundary.limits);
    }

    Ok(EnforcedLimits {
        worker_policy,
        effective_worker_ceiling,
        application,
        solvers,
        outer_ancestors,
        owner_unit: profile.owner_unit().to_owned(),
    })
}

async fn slice_boundary(
    connection: &Connection,
    name: &str,
) -> Result<ResourceBoundary, SystemdError> {
    let slice = Proxy::new(
        connection,
        DESTINATION,
        unit_path(connection, name).await?,
        "org.freedesktop.systemd1.Slice",
    )
    .await
    .map_err(|source| manager_error("slice accounting proxy", source))?;
    let cgroup_path: String = slice
        .get_property("ControlGroup")
        .await
        .map_err(|source| manager_error("slice ControlGroup", source))?;
    let limits = read_limits(&directory(&cgroup_path)?).await?;
    Ok(ResourceBoundary {
        unit: name.to_owned(),
        cgroup_path,
        limits,
    })
}

pub(super) fn directory(group: &str) -> Result<PathBuf, SystemdError> {
    let relative = group
        .strip_prefix('/')
        .filter(|relative| !relative.is_empty())
        .ok_or(SystemdError::InvalidPolicy(
            "cgroup path must be absolute and nonempty",
        ))?;
    if Path::new(relative)
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SystemdError::InvalidPolicy(
            "cgroup path contains non-normal components",
        ));
    }

    Ok(Path::new(CGROUP_ROOT).join(relative))
}

async fn number(directory: &Path, resource: &'static str) -> Result<Option<u64>, SystemdError> {
    let text = tokio::fs::read_to_string(directory.join(resource)).await?;
    parse_limit(text.trim())
}

fn parse_limit(text: &str) -> Result<Option<u64>, SystemdError> {
    if text == "max" {
        return Ok(None);
    }

    text.parse().map(Some).map_err(|_| {
        SystemdError::InvalidPolicy("kernel resource limit is neither numeric nor max")
    })
}

async fn read_limits(directory: &Path) -> Result<ResourceLimits, SystemdError> {
    let cpu = tokio::fs::read_to_string(directory.join("cpu.max")).await?;
    let mut fields = cpu.split_whitespace();
    let quota = parse_limit(
        fields
            .next()
            .ok_or(SystemdError::InvalidPolicy("CPU quota is absent"))?,
    )?;
    let period = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(SystemdError::InvalidPolicy("CPU quota period is invalid"))?;
    if fields.next().is_some() {
        return Err(SystemdError::InvalidPolicy("CPU quota has extra fields"));
    }

    Ok(ResourceLimits {
        cpu_weight: number(directory, "cpu.weight").await?,
        cpu_quota_micros: quota,
        cpu_period_micros: Some(period),
        task_limit: number(directory, "pids.max").await?,
        memory_high_bytes: number(directory, "memory.high").await?,
        memory_max_bytes: number(directory, "memory.max").await?,
    })
}

fn minimum(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (None, value) | (value, None) => value,
    }
}

fn restrict(effective: &mut ResourceLimits, ancestor: &ResourceLimits) {
    effective.task_limit = minimum(effective.task_limit, ancestor.task_limit);
    effective.memory_high_bytes = minimum(effective.memory_high_bytes, ancestor.memory_high_bytes);
    effective.memory_max_bytes = minimum(effective.memory_max_bytes, ancestor.memory_max_bytes);

    if let (Some(quota), Some(period)) = (ancestor.cpu_quota_micros, ancestor.cpu_period_micros) {
        let is_stricter = match (effective.cpu_quota_micros, effective.cpu_period_micros) {
            (Some(current_quota), Some(current_period)) => {
                u128::from(quota) * u128::from(current_period)
                    < u128::from(current_quota) * u128::from(period)
            }
            _ => true,
        };
        if is_stricter {
            effective.cpu_quota_micros = Some(quota);
            effective.cpu_period_micros = Some(period);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn memory_evidence_requires_both_unambiguous_local_counters() {
        let events = parse_memory_events("low 0\nmax 42\noom 3\noom_kill 2\n").unwrap();
        assert_eq!(events.oom, 3);
        assert_eq!(events.oom_kill, 2);
        for malformed in ["oom 1", "oom bad\noom_kill 0", "oom 1\noom 2\noom_kill 0"] {
            assert!(parse_memory_events(malformed).is_err());
        }
    }

    #[test]
    fn parent_events_do_not_attribute_an_unrelated_worker_failure() {
        let report = classify_memory_events(
            MemoryEvents::default(),
            MemoryEvents::default(),
            &["solvers.slice"],
        );
        assert!(matches!(report.cause, WorkerFailureCause::Unknown));
        let killed = MemoryEvents {
            oom: 0,
            oom_kill: 1,
        };
        let report = classify_memory_events(MemoryEvents::default(), killed, &["solvers.slice"]);
        assert!(
            matches!(report.cause, WorkerFailureCause::AncestorMemoryLimit { unit } if unit == "solvers.slice")
        );
        let report = classify_memory_events(
            MemoryEvents::default(),
            killed,
            &["solvers.slice", "app.slice"],
        );
        assert!(matches!(report.cause, WorkerFailureCause::Unknown));
        let report = classify_memory_events(
            MemoryEvents::default(),
            MemoryEvents {
                oom: 1,
                oom_kill: 1,
            },
            &[],
        );
        assert!(matches!(
            report.cause,
            WorkerFailureCause::WorkerMemoryLimit
        ));
    }

    #[test]
    fn ancestor_ceilings_restrict_limits_without_flattening_relative_weights() {
        let mut worker = ResourceLimits {
            cpu_weight: Some(250),
            cpu_quota_micros: Some(150_000),
            cpu_period_micros: Some(100_000),
            task_limit: Some(32),
            memory_max_bytes: Some(8192),
            ..ResourceLimits::default()
        };
        let parent = ResourceLimits {
            cpu_weight: Some(400),
            cpu_quota_micros: Some(100_000),
            cpu_period_micros: Some(200_000),
            task_limit: Some(16),
            memory_max_bytes: Some(4096),
            ..ResourceLimits::default()
        };

        restrict(&mut worker, &parent);

        assert_eq!(worker.cpu_weight, Some(250));
        assert_eq!(worker.cpu_quota_micros, Some(100_000));
        assert_eq!(worker.cpu_period_micros, Some(200_000));
        assert_eq!(worker.task_limit, Some(16));
        assert_eq!(worker.memory_max_bytes, Some(4096));
    }

    #[test]
    fn cgroup_paths_and_numeric_limits_reject_ambiguous_values() {
        for path in ["", "/", "relative", "/../outside", "/app/../../outside"] {
            assert!(directory(path).is_err());
        }
        assert_eq!(parse_limit("max").unwrap(), None);
        assert_eq!(parse_limit("1024").unwrap(), Some(1024));
        assert!(parse_limit("unknown").is_err());
    }
}
