//! Independently measures the fixed source package beneath two-group custody.
//!
//! This qualification component creates no SourceAuthority or runtime readiness.
//! It binds actual original kernel/ELF/limits facts to the borrowed native Ready.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
};

use crucible_node_contract::{ContentRef, ResourceLimits, U64};
use crucible_node_provider::{
    ProviderError, client::OriginalLineageRealization, conformance::measure_executable,
};

#[path = "installed_binding.rs"]
mod binding;
use binding::Artifact;
pub(super) use binding::PackageSelection;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Enrollment {
    provider: Process,
    native: Process,
    ready: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Process {
    pid: u32,
    parent: u32,
    start: U64,
    maps: Vec<(String, ContentRef)>,
    limits: Vec<(String, u64, u64)>,
}

pub(super) fn enroll(
    installation: &PackageSelection,
    provider: u32,
    view: &OriginalLineageRealization<'_>,
    limits: &ResourceLimits,
) -> Result<Enrollment, ProviderError> {
    let objects = installation.objects();
    let native = u32::try_from(view.native_pid().get()).map_err(|_| invalid())?;
    let measured_provider = measure(provider, installation.provider(), objects, limits)?;
    let measured_native = measure(native, installation.device(), objects, limits)?;
    if measured_provider.parent != std::process::id()
        || measured_native.parent != provider
        || measured_native.start != view.native_start_ticks()
        || installation.device().content != *view.native_executable()
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
    // Recheck both lifetimes after whole-group and child inventories; neither
    // original may be replaced during the independent enrollment observation.
    if stat(provider)?.2 != measured_provider.start || stat(native)?.2 != measured_native.start {
        return Err(invalid());
    }
    // The view is borrowed inside the owning guard after its actual two-group
    // checks. These measurements do not replace that custody/lifetime anchor.
    let (_, ready) = view.native_initialization()?;
    Ok(Enrollment {
        provider: measured_provider,
        native: measured_native,
        ready: ready.to_vec(),
    })
}

fn measure(
    pid: u32,
    artifact: &Artifact,
    objects: &BTreeMap<String, ContentRef>,
    limits: &ResourceLimits,
) -> Result<Process, ProviderError> {
    let before = stat(pid)?;
    if pid == 0
        || before.1 != pid
        || measure_executable(Path::new(&format!("/proc/{pid}/exe")))? != artifact.content
    {
        return Err(invalid());
    }
    let status = read(Path::new(&format!("/proc/{pid}/status")), 65536)?;
    let status = std::str::from_utf8(&status).map_err(|_| invalid())?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or_else(invalid)?;
    let ids = uid.split_ascii_whitespace().collect::<Vec<_>>();
    if ids.len() != 4
        || ids
            .iter()
            .any(|id| id.parse::<u32>().ok() != Some(rustix::process::geteuid().as_raw()))
    {
        return Err(invalid());
    }
    let source = read(Path::new(&format!("/proc/{pid}/maps")), 1024 * 1024)?;
    let source = std::str::from_utf8(&source).map_err(|_| invalid())?;
    let mut maps = BTreeMap::new();
    for line in source.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 || fields.len() > 6 {
            return Err(invalid());
        }
        let Some(path) = fields.get(5) else { continue };
        if path.starts_with('[') {
            continue;
        }
        if maps.len() >= 1024 {
            return Err(invalid());
        }
        let reference = objects.get(*path).ok_or_else(invalid)?;
        if measure_executable(Path::new(path))? != *reference {
            return Err(invalid());
        }
        maps.insert((*path).to_owned(), reference.clone());
    }
    let mut measured_limits = Vec::new();
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
        let values = line
            .split_ascii_whitespace()
            .take(2)
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        if values.len() != 2 || values[0] != values[1] || values[0] > maximum {
            return Err(invalid());
        }
        measured_limits.push((name.to_owned(), values[0], values[1]));
    }
    if stat(pid)? != before {
        return Err(invalid());
    }
    Ok(Process {
        pid,
        parent: before.0,
        start: before.2,
        maps: maps.into_iter().collect(),
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
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let number = |index: usize| {
        fields
            .get(index)
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
            result.insert(pid);
        }
        if result.len() > 1 {
            return Err(invalid());
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
            result.insert(child.parse::<u32>().map_err(|_| invalid())?);
            if result.len() > 1 {
                return Err(invalid());
            }
        }
    }
    Ok(result)
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, ProviderError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(invalid());
    }
    Ok(bytes)
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("fixed installed original lineage measurement differs")
}
