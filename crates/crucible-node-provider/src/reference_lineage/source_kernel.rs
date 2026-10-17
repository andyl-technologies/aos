//! Bounds original two-group kernel observations without portable authority.

use std::fs;
use std::io::Read;

use crucible_node_contract::ContentRef;
use rustix::process::Pid;

use crate::ProviderError;

#[derive(Clone, Copy)]
pub(super) struct Identity {
    pub(super) pid: u32,
    pub(super) parent: u32,
    pub(super) start_ticks: u64,
}

pub(super) fn pid(value: u32) -> Result<Pid, ProviderError> {
    Pid::from_raw(
        i32::try_from(value)
            .map_err(|_| ProviderError::Correlation("lineage source PID extent"))?,
    )
    .ok_or(ProviderError::Correlation("lineage source PID omitted"))
}

pub(super) fn identity(pid: u32) -> Result<Identity, ProviderError> {
    let stat = stat(pid)?.ok_or(ProviderError::Correlation(
        "lineage source original leader absent",
    ))?;
    if stat.group != pid {
        return Err(ProviderError::Correlation(
            "lineage source private group differs",
        ));
    }
    Ok(Identity {
        pid,
        parent: stat.parent,
        start_ticks: stat.start_ticks,
    })
}

pub(super) fn verify_identity(original: Identity) -> Result<(), ProviderError> {
    let actual = identity(original.pid)?;
    if actual.start_ticks != original.start_ticks || actual.parent != original.parent {
        return Err(ProviderError::Correlation(
            "lineage source original kernel identity changed",
        ));
    }
    Ok(())
}

pub(super) fn verify_executable(pid: u32, expected: &ContentRef) -> Result<(), ProviderError> {
    let actual =
        crate::conformance::measure_executable(std::path::Path::new(&format!("/proc/{pid}/exe")))?;
    if &actual != expected {
        return Err(ProviderError::Correlation(
            "lineage source executable differs",
        ));
    }
    Ok(())
}

pub(super) fn group_empty(group: u32) -> Result<bool, ProviderError> {
    for (index, entry) in fs::read_dir("/proc")?.enumerate() {
        if index >= 100_000 {
            return Err(ProviderError::ResourceExhausted(
                "lineage source group census",
            ));
        }
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if stat(pid)?.is_some_and(|stat| stat.group == group) {
            return Ok(false);
        }
    }
    Ok(true)
}

struct Stat {
    parent: u32,
    group: u32,
    start_ticks: u64,
}

fn stat(pid: u32) -> Result<Option<Stat>, ProviderError> {
    let file = match fs::File::open(format!("/proc/{pid}/stat")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(ProviderError::ResourceExhausted(
            "lineage source kernel stat",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ProviderError::Frame("lineage source kernel stat encoding"))?;
    let close = text
        .rfind(')')
        .ok_or(ProviderError::Frame("lineage source kernel stat shape"))?;
    let mut fields = text[close + 1..].split_ascii_whitespace();
    let parent = fields
        .nth(1)
        .ok_or(ProviderError::Frame("lineage source parent omitted"))?
        .parse()
        .map_err(|_| ProviderError::Frame("lineage source parent invalid"))?;
    let group = fields
        .next()
        .ok_or(ProviderError::Frame("lineage source group omitted"))?
        .parse()
        .map_err(|_| ProviderError::Frame("lineage source group invalid"))?;
    let start_ticks = fields
        .nth(16)
        .ok_or(ProviderError::Frame("lineage source start omitted"))?
        .parse()
        .map_err(|_| ProviderError::Frame("lineage source start invalid"))?;
    Ok(Some(Stat {
        parent,
        group,
        start_ticks,
    }))
}
