//! Native process ceilings for the dedicated provider and inherited companion.
//!
//! Both processes receive half of each admitted address-space, descriptor and
//! CPU ceiling. Linux enforces CPU limits in integral seconds; admission rounds
//! down and refuses allowances too small for two positive native CPU limits.
//! The measured companion has no process-creation path, and the broker owns a
//! single child lifecycle rather than claiming arbitrary executable isolation.

use crucible_node_contract::ResourceLimits;
use rustix::process::{Resource, Rlimit};
use std::collections::BTreeSet;

use crate::ProviderError;

use super::bootstrap::ReferenceServiceBootstrap;

pub(super) fn enforce(bootstrap: &ReferenceServiceBootstrap) -> Result<(), ProviderError> {
    let limits = &bootstrap.resource_limits;
    let memory = limits.memory_bytes.get() / 2;
    let descriptors = limits.descriptors.get() / 2;
    let cpu_seconds = limits.cpu_budget_ns.get() / 2 / 1_000_000_000;
    let reserved = limits
        .content_bytes
        .get()
        .checked_mul(6)
        .and_then(|bytes| bytes.checked_add(bootstrap.limits.frame_bytes.get().checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(32 * 1024 * 1024))
        .ok_or(ProviderError::ResourceExhausted(
            "native memory reservation overflow",
        ))?;
    if limits.processes.get() < 2
        || descriptors < 16
        || cpu_seconds == 0
        || memory < reserved
        || !limits.extensions.is_empty()
    {
        return Err(ProviderError::ResourceExhausted(
            "native process ceilings cannot contain admitted reservations",
        ));
    }
    let current = std::fs::read_to_string("/proc/self/status")?;
    let virtual_memory = current
        .lines()
        .find_map(|line| line.strip_prefix("VmSize:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|value| value.checked_mul(1024))
        .ok_or(ProviderError::Correlation(
            "native virtual memory inventory unavailable",
        ))?;
    let descriptor_count = std::fs::read_dir("/proc/self/fd")?.count() as u64;
    if virtual_memory > memory || descriptor_count > descriptors {
        return Err(ProviderError::ResourceExhausted(
            "native process already exceeds admitted limits",
        ));
    }
    // Hard and soft limits remain equal, and inheritance bounds the actual
    // companion before exec. A failed later limit never relaxes an earlier one.
    set(Resource::As, memory)?;
    set(Resource::Nofile, descriptors)?;
    set(Resource::Cpu, cpu_seconds)?;
    set(Resource::Fsize, limits.writable_bytes.get() / 2)?;
    set(Resource::Core, 0)?;
    verify(limits)
}

pub(super) fn verify(limits: &ResourceLimits) -> Result<(), ProviderError> {
    for (resource, maximum) in [
        (Resource::As, limits.memory_bytes.get() / 2),
        (Resource::Nofile, limits.descriptors.get() / 2),
        (
            Resource::Cpu,
            limits.cpu_budget_ns.get() / 2 / 1_000_000_000,
        ),
        (Resource::Fsize, limits.writable_bytes.get() / 2),
        (Resource::Core, 0),
    ] {
        let actual = rustix::process::getrlimit(resource);
        if actual.current.is_none_or(|value| value > maximum)
            || actual.maximum.is_none_or(|value| value > maximum)
        {
            return Err(ProviderError::Correlation(
                "native limit enforcement differs from admitted ceiling",
            ));
        }
    }
    Ok(())
}

fn set(resource: Resource, maximum: u64) -> Result<(), ProviderError> {
    let existing = rustix::process::getrlimit(resource);
    let maximum = existing
        .maximum
        .map_or(maximum, |previous| maximum.min(previous));
    rustix::process::setrlimit(
        resource,
        Rlimit {
            current: Some(maximum),
            maximum: Some(maximum),
        },
    )
    .map_err(std::io::Error::from)?;
    Ok(())
}

pub(super) fn verify_processes(child: Option<u32>) -> Result<(), ProviderError> {
    let expected: BTreeSet<u32> = child.into_iter().collect();
    if children(std::process::id())? != expected {
        return Err(ProviderError::Correlation(
            "native provider owns an unexpected process",
        ));
    }
    if let Some(child) = child
        && !children(child)?.is_empty()
    {
        return Err(ProviderError::Correlation(
            "measured companion created an unsupported process",
        ));
    }
    Ok(())
}

fn children(pid: u32) -> Result<BTreeSet<u32>, ProviderError> {
    let mut children = BTreeSet::new();
    for thread in std::fs::read_dir(format!("/proc/{pid}/task"))? {
        let bytes = std::fs::read_to_string(thread?.path().join("children"))?;
        for child in bytes.split_whitespace() {
            children.insert(
                child.parse::<u32>().map_err(|_| {
                    ProviderError::Correlation("native process inventory malformed")
                })?,
            );
        }
    }
    Ok(children)
}
