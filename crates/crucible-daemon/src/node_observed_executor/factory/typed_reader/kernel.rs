//! Measures original typed provider/native groups under actual owning custody.
//!
//! This read-only census uses only identities borrowed from the original guard.
//! It authenticates lifetimes, complete maps and enforced limits independently of
//! portable source records; behavioral acceptance remains a separate conjunction.

use std::{collections::BTreeSet, fs::File, io::Read, path::Path};

use crucible_node_contract::{ContentRef, ResourceLimits, U64};
use crucible_node_provider::{
    ProviderError, client::OriginalLineageRealization, conformance::measure_executable,
};

use super::InstalledTypedReaderPackage;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Enrollment {
    provider: Process,
    native: Process,
    pub(super) ready: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Process {
    pid: u32,
    parent: u32,
    start: U64,
    maps: Vec<(String, ContentRef)>,
    limits: Vec<(String, u64, u64)>,
}

/// Pins both actual original process groups to their owning native Ready.
///
/// # Errors
/// Refuses changed package, Ready, PID/start, parent, maps, limits or group
/// facts, and retains the caller's original custody on measurement failures.
pub(super) fn enroll(
    installation: &InstalledTypedReaderPackage,
    provider: u32,
    view: &OriginalLineageRealization<'_>,
    limits: &ResourceLimits,
) -> Result<Enrollment, ProviderError> {
    let native = u32::try_from(view.native_pid().get()).map_err(|_| invalid())?;
    let (_, ready) = view.native_initialization()?;
    let enrollment = current(installation, provider, native, limits, ready)?;
    if enrollment.native.start != view.native_start_ticks()
        || installation
            .artifact_content("device")
            .map_err(|_| invalid())?
            != view.native_executable()
    {
        return Err(invalid());
    }
    Ok(enrollment)
}

/// Measures the exact provider/native tuple and complete private group census.
///
/// # Errors
/// Refuses unexpected ancestry, executable/maps/limits, extra members,
/// changed process lifetimes or inaccessible/exhausted kernel inventories.
pub(super) fn current(
    installation: &InstalledTypedReaderPackage,
    provider: u32,
    native: u32,
    limits: &ResourceLimits,
    ready: &[u8],
) -> Result<Enrollment, ProviderError> {
    let provider_content = installation
        .artifact_content("provider")
        .map_err(|_| invalid())?;
    let device_content = installation
        .artifact_content("device")
        .map_err(|_| invalid())?;
    let measured_provider = measure(provider, provider_content, installation, limits)?;
    let measured_native = measure(native, device_content, installation, limits)?;
    if measured_provider.parent != std::process::id()
        || measured_native.parent != provider
        || provider == native
    {
        return Err(invalid());
    }
    if group_members(provider)? != BTreeSet::from([provider])
        || group_members(native)? != BTreeSet::from([native])
        || children(provider)? != BTreeSet::from([native])
        || !children(native)?.is_empty()
    {
        return Err(invalid());
    }
    if stat(provider)?.2 != measured_provider.start || stat(native)?.2 != measured_native.start {
        return Err(invalid());
    }
    // The view is borrowed inside the owning guard after its actual two-group
    // checks. These measurements do not replace that custody/lifetime anchor.
    if ready.len() > 65536 {
        return Err(invalid());
    }
    let mut retained_ready = Vec::new();
    retained_ready
        .try_reserve_exact(ready.len())
        .map_err(|_| invalid())?;
    retained_ready.extend_from_slice(ready);
    Ok(Enrollment {
        provider: measured_provider,
        native: measured_native,
        ready: retained_ready,
    })
}

fn measure(
    pid: u32,
    executable: &ContentRef,
    installation: &InstalledTypedReaderPackage,
    limits: &ResourceLimits,
) -> Result<Process, ProviderError> {
    let before = stat(pid)?;
    if pid == 0
        || before.1 != pid
        || measure_executable(Path::new(&format!("/proc/{pid}/exe")))? != *executable
    {
        return Err(invalid());
    }
    let status = read(Path::new(&format!("/proc/{pid}/status")), 65536)?;
    let status = std::str::from_utf8(&status).map_err(|_| invalid())?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or_else(invalid)?;
    let mut ids = uid.split_ascii_whitespace();
    if (0..4).any(|_| {
        ids.next().and_then(|id| id.parse::<u32>().ok())
            != Some(rustix::process::geteuid().as_raw())
    }) || ids.next().is_some()
    {
        return Err(invalid());
    }
    let source = read(Path::new(&format!("/proc/{pid}/maps")), 1024 * 1024)?;
    let source = std::str::from_utf8(&source).map_err(|_| invalid())?;
    let mut maps = Vec::new();
    maps.try_reserve_exact(1024).map_err(|_| invalid())?;
    for line in source.lines() {
        let mut fields = line.split_ascii_whitespace();
        for _ in 0..5 {
            fields.next().ok_or_else(invalid)?;
        }
        let Some(path) = fields.next() else { continue };
        if fields.next().is_some() {
            return Err(invalid());
        }
        if path.starts_with('[') {
            continue;
        }
        if maps.len() >= 1024 {
            return Err(invalid());
        }
        if path.len() > 4096 {
            return Err(invalid());
        }
        let (_, reference) = installation
            .runtime_objects()
            .find(|(original, _)| original.as_os_str() == std::ffi::OsStr::new(path))
            .ok_or_else(invalid)?;
        if measure_executable(Path::new(path))? != *reference {
            return Err(invalid());
        }
        if !maps.iter().any(|(old, _)| old == path) {
            maps.push((path.to_owned(), reference.clone()));
        }
    }
    let mut measured_limits = Vec::new();
    measured_limits
        .try_reserve_exact(5)
        .map_err(|_| invalid())?;
    let bytes = read(Path::new(&format!("/proc/{pid}/limits")), 65536)?;
    let source = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    for (name, maximum) in [
        ("Max address space", limits.memory_bytes.get() / 2),
        ("Max open files", limits.descriptors.get() / 2),
        (
            "Max cpu time",
            limits.cpu_budget_ns.get() / 2 / 1_000_000_000,
        ),
        ("Max file size", limits.writable_bytes.get() / 2),
        ("Max core file size", 0),
    ] {
        let line = source
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(invalid)?;
        let mut values = line.split_ascii_whitespace();
        let mut number = || {
            values
                .next()
                .ok_or_else(invalid)?
                .parse::<u64>()
                .map_err(|_| invalid())
        };
        let soft = number()?;
        let hard = number()?;
        if soft != hard || soft > maximum {
            return Err(invalid());
        }
        measured_limits.push((name.to_owned(), soft, hard));
    }
    if stat(pid)? != before {
        return Err(invalid());
    }
    Ok(Process {
        pid,
        parent: before.0,
        start: before.2,
        maps,
        limits: measured_limits,
    })
}

fn stat(pid: u32) -> Result<(u32, u32, U64), ProviderError> {
    let bytes = read(Path::new(&format!("/proc/{pid}/stat")), 65536)?;
    let source = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    let fields = source
        .rsplit_once(") ")
        .ok_or_else(invalid)?
        .1
        .split_ascii_whitespace();
    let number = |index: usize| {
        fields
            .clone()
            .nth(index)
            .ok_or_else(invalid)?
            .parse::<u64>()
            .map_err(|_| invalid())
    };
    Ok((
        u32::try_from(number(1)?).map_err(|_| invalid())?,
        u32::try_from(number(2)?).map_err(|_| invalid())?,
        U64::new(number(19)?),
    ))
}

fn group_members(group: u32) -> Result<BTreeSet<u32>, ProviderError> {
    let mut result = BTreeSet::new();
    for (index, entry) in std::fs::read_dir("/proc")?.enumerate() {
        if index >= 100_000 {
            return Err(invalid());
        }
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let original = match stat(pid) {
            Ok(original) => original,
            Err(ProviderError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(error) => return Err(error),
        };
        if original.1 == group {
            if !result.is_empty() && !result.contains(&pid) {
                return Err(invalid());
            }
            result.insert(pid);
        }
    }
    Ok(result)
}

fn children(pid: u32) -> Result<BTreeSet<u32>, ProviderError> {
    let mut result = BTreeSet::new();
    for (index, entry) in std::fs::read_dir(format!("/proc/{pid}/task"))?.enumerate() {
        if index >= 64 {
            return Err(invalid());
        }
        let source = read(&entry?.path().join("children"), 65536)?;
        let source = std::str::from_utf8(&source).map_err(|_| invalid())?;
        for child in source.split_ascii_whitespace() {
            let child = child.parse::<u32>().map_err(|_| invalid())?;
            if !result.is_empty() && !result.contains(&child) {
                return Err(invalid());
            }
            result.insert(child);
        }
    }
    Ok(result)
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, ProviderError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(maximum.checked_add(1).ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(invalid());
    }
    Ok(bytes)
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("installed typed original kernel enrollment differs")
}
