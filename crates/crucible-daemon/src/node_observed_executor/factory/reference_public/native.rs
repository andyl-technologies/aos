//! Independently measures actual public provider and companion process scopes.
//!
//! These host observations bind process lifetime, executable/runtime ELF bytes,
//! private ancestry and enforced limits. They are not native snapshot or timing
//! certificates. The actual stopped gate and original CNP readiness evidence
//! remain mandatory before a common runtime can arm this owner.

use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use crucible_node_contract::{ContentRef, ResourceLimits, U64};
use crucible_node_provider::{ProviderError, conformance::measure_executable};
use serde::Serialize;

use super::package::InstalledPublicReferencePackage;

/// Retains the exact independently observed original process-lifetime tuple.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub(super) struct NativePublicEnrollment {
    provider: NativeProcess,
    companion: NativeProcess,
    supervision: U64,
    package: ContentRef,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
struct NativeProcess {
    pid: U64,
    start_ticks: U64,
    group: U64,
    parent: U64,
    mapped_objects: Vec<(PathBuf, ContentRef)>,
    enforced_limits: Vec<(String, U64, U64)>,
}

impl NativePublicEnrollment {
    pub(super) fn enroll(
        provider: u32,
        companion: u32,
        supervision: U64,
        package: &InstalledPublicReferencePackage,
        limits: &ResourceLimits,
    ) -> Result<Self, ProviderError> {
        if provider == 0 || companion == 0 || provider == companion || supervision.get() == 0 {
            return Err(ProviderError::Correlation(
                "invalid original public process roster",
            ));
        }
        let result = Self {
            provider: NativeProcess::measure(
                provider,
                package
                    .artifact_content("provider")
                    .map_err(package_error)?,
                package,
                limits,
            )?,
            companion: NativeProcess::measure(
                companion,
                package.artifact_content("device").map_err(package_error)?,
                package,
                limits,
            )?,
            supervision,
            package: package.identity().clone(),
        };
        if result.provider.group != U64::new(u64::from(provider))
            || result.provider.parent != U64::new(u64::from(std::process::id()))
            || result.companion.group != result.provider.group
            || result.companion.parent != U64::new(u64::from(provider))
            || children(provider)? != BTreeSet::from([companion])
            || !children(companion)?.is_empty()
            || group_members(provider)? != BTreeSet::from([provider, companion])
        {
            return Err(ProviderError::Correlation(
                "public native process escaped original private custody",
            ));
        }
        Ok(result)
    }

    pub(super) fn authenticate(
        &self,
        package: &InstalledPublicReferencePackage,
        limits: &ResourceLimits,
    ) -> Result<(), ProviderError> {
        let provider = u32::try_from(self.provider.pid.get())
            .map_err(|_| ProviderError::Correlation("original public provider PID overflow"))?;
        let companion = u32::try_from(self.companion.pid.get())
            .map_err(|_| ProviderError::Correlation("original public companion PID overflow"))?;
        let current = Self::enroll(provider, companion, self.supervision, package, limits)?;
        if &current != self {
            return Err(ProviderError::Correlation(
                "original public native scope changed",
            ));
        }
        Ok(())
    }
}

/// Includes reparented members, which a provider-child census cannot detect.
fn group_members(group: u32) -> Result<BTreeSet<u32>, ProviderError> {
    let mut members = BTreeSet::new();
    let mut count = 0usize;
    for entry in std::fs::read_dir("/proc")? {
        count = count
            .checked_add(1)
            .filter(|count| *count <= 100_000)
            .ok_or(ProviderError::ResourceExhausted(
                "public native process-group census",
            ))?;
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = match read_kernel(&entry.path().join("stat"), 65_536) {
            Ok(stat) => stat,
            Err(ProviderError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(error) => return Err(error),
        };
        let actual = stat
            .rsplit_once(") ")
            .and_then(|(_, fields)| fields.split_ascii_whitespace().nth(2))
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(ProviderError::Frame("public native census stat malformed"))?;
        if actual == group {
            if members.len() >= 2 {
                return Err(ProviderError::Correlation(
                    "public native group contains a foreign member",
                ));
            }
            members.insert(pid);
        }
    }
    Ok(members)
}

impl NativeProcess {
    fn measure(
        pid: u32,
        executable: &ContentRef,
        package: &InstalledPublicReferencePackage,
        limits: &ResourceLimits,
    ) -> Result<Self, ProviderError> {
        let stat = read_kernel(&PathBuf::from(format!("/proc/{pid}/stat")), 65_536)?;
        let (_, fields) = stat.rsplit_once(") ").ok_or(ProviderError::Frame(
            "original public process stat malformed",
        ))?;
        let fields = fields.split_ascii_whitespace().collect::<Vec<_>>();
        let number = |index: usize| -> Result<U64, ProviderError> {
            fields
                .get(index)
                .and_then(|field| field.parse::<u64>().ok())
                .map(U64::new)
                .ok_or(ProviderError::Frame(
                    "original public process stat field malformed",
                ))
        };
        let start_ticks = number(19)?;
        let parent = number(1)?;
        let group = number(2)?;
        let actual = measure_executable(&PathBuf::from(format!("/proc/{pid}/exe")))?;
        if &actual != executable {
            return Err(ProviderError::Correlation(
                "actual public executable differs from installed source",
            ));
        }
        let status = read_kernel(&PathBuf::from(format!("/proc/{pid}/status")), 65_536)?;
        let uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .ok_or(ProviderError::Frame("original public process UID absent"))?;
        let credentials = uid.split_ascii_whitespace().collect::<Vec<_>>();
        if credentials.len() != 4
            || credentials
                .iter()
                .any(|uid| uid.parse::<u32>().ok() != Some(rustix::process::geteuid().as_raw()))
        {
            return Err(ProviderError::Correlation(
                "actual public process credentials differ",
            ));
        }
        let mapped_objects = mapped_objects(pid, package)?;
        let enforced_limits = enforced_limits(pid, limits)?;
        // Measurement is bracketed by the original kernel lifetime, preventing
        // observations from distinct processes from sharing one numeric PID.
        let after = read_kernel(&PathBuf::from(format!("/proc/{pid}/stat")), 65_536)?;
        let after_start = after
            .rsplit_once(") ")
            .and_then(|(_, fields)| fields.split_ascii_whitespace().nth(19))
            .and_then(|value| value.parse::<u64>().ok());
        if after_start != Some(start_ticks.get()) {
            return Err(ProviderError::Correlation(
                "actual public process lifetime changed during enrollment",
            ));
        }
        Ok(Self {
            pid: U64::new(u64::from(pid)),
            start_ticks,
            group,
            parent,
            mapped_objects,
            enforced_limits,
        })
    }
}

fn mapped_objects(
    pid: u32,
    package: &InstalledPublicReferencePackage,
) -> Result<Vec<(PathBuf, ContentRef)>, ProviderError> {
    let maps = read_kernel(&PathBuf::from(format!("/proc/{pid}/maps")), 1024 * 1024)?;
    let mut paths = BTreeSet::new();
    for line in maps.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 || fields.len() > 6 {
            return Err(ProviderError::Frame(
                "unsupported original public native memory mapping",
            ));
        }
        let Some(name) = fields.get(5) else {
            continue;
        };
        if name.starts_with('[') {
            continue;
        }
        let path = PathBuf::from(name);
        if !path.is_absolute() || paths.len() >= 1024 {
            return Err(ProviderError::ResourceExhausted(
                "public native mapped object inventory",
            ));
        }
        paths.insert(path);
    }
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(paths.len())
        .map_err(|_| ProviderError::ResourceExhausted("public native map allocation"))?;
    for path in paths {
        let mut magic = [0; 4];
        File::open(&path)?.read_exact(&mut magic)?;
        if &magic != b"\x7fELF" {
            return Err(ProviderError::Correlation(
                "public native maps an unqualified external object",
            ));
        }
        let reference = package
            .authenticate_mapped_elf(&path)
            .map_err(package_error)?;
        objects.push((path, reference));
    }
    Ok(objects)
}

fn enforced_limits(
    pid: u32,
    limits: &ResourceLimits,
) -> Result<Vec<(String, U64, U64)>, ProviderError> {
    let source = read_kernel(&PathBuf::from(format!("/proc/{pid}/limits")), 65_536)?;
    let ceilings = [
        ("Max address space", limits.memory_bytes.get() / 2),
        ("Max open files", limits.descriptors.get() / 2),
        (
            "Max cpu time",
            limits.cpu_budget_ns.get() / 2 / 1_000_000_000,
        ),
        ("Max file size", limits.writable_bytes.get() / 2),
        ("Max core file size", 0),
    ];
    let mut measured = Vec::new();
    for (name, maximum) in ceilings {
        let line = source
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or(ProviderError::Frame("public native enforced limit absent"))?;
        let values = line
            .split_ascii_whitespace()
            .take(2)
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProviderError::Frame("public native limit unbounded or malformed"))?;
        if values.len() != 2 || values[0] > maximum || values[1] > maximum || values[0] != values[1]
        {
            return Err(ProviderError::Correlation(
                "actual public native limit exceeds installed allowance",
            ));
        }
        measured.push((name.into(), U64::new(values[0]), U64::new(values[1])));
    }
    Ok(measured)
}

fn children(pid: u32) -> Result<BTreeSet<u32>, ProviderError> {
    let mut children = BTreeSet::new();
    let mut threads = 0usize;
    for thread in std::fs::read_dir(format!("/proc/{pid}/task"))? {
        threads += 1;
        if threads > 64 {
            return Err(ProviderError::ResourceExhausted(
                "public native thread inventory",
            ));
        }
        let source = read_kernel(&thread?.path().join("children"), 65_536)?;
        for child in source.split_ascii_whitespace() {
            let child = child
                .parse::<u32>()
                .map_err(|_| ProviderError::Frame("public native child inventory malformed"))?;
            if children.len() >= 2 && !children.contains(&child) {
                return Err(ProviderError::Correlation(
                    "public native owns an undeclared process",
                ));
            }
            children.insert(child);
        }
    }
    Ok(children)
}

fn read_kernel(path: &Path, maximum: usize) -> Result<String, ProviderError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(ProviderError::ResourceExhausted(
            "public kernel observation ceiling",
        ));
    }
    String::from_utf8(bytes).map_err(|_| ProviderError::Frame("public kernel observation encoding"))
}

fn package_error(error: super::super::NodeObservedError) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}
