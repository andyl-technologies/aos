//! Original private group identity and bounded actual kernel reclamation.

use std::{fs, io::Read, process::Child};

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, getpgid, kill_process_group, waitid};

use crate::ProviderError;

pub(super) struct KernelScope {
    pid: u32,
    start_ticks: u64,
    signalled: bool,
    reaped: bool,
}

impl KernelScope {
    pub(super) fn capture(child: &Child) -> Result<Self, ProviderError> {
        let pid = child.id();
        let stat = read_stat(pid)?.ok_or(ProviderError::Correlation(
            "native lineage leader disappeared",
        ))?;
        if stat.group != pid
            || getpgid(Some(native_pid(pid)?)).map_err(std::io::Error::from)? != native_pid(pid)?
        {
            return Err(ProviderError::Correlation(
                "native lineage private group changed",
            ));
        }
        Ok(Self {
            pid,
            start_ticks: stat.start_ticks,
            signalled: false,
            reaped: false,
        })
    }

    pub(super) fn original_start_ticks(&self) -> u64 {
        self.start_ticks
    }

    pub(super) fn poll(&mut self, child: &mut Child) -> Result<bool, ProviderError> {
        if !self.signalled {
            // NOWAIT preserves the leader PID until the original group is signalled.
            // No absence-based signal is allowed after that kernel anchor is lost.
            waitid(
                WaitId::Pid(native_pid(self.pid)?),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
            .map_err(std::io::Error::from)?;
            let stat = read_stat(self.pid)?.ok_or(ProviderError::Correlation(
                "native lineage original leader absent",
            ))?;
            if child.id() != self.pid
                || stat.start_ticks != self.start_ticks
                || stat.group != self.pid
            {
                return Err(ProviderError::Correlation(
                    "native lineage kernel identity changed",
                ));
            }
            kill_process_group(native_pid(self.pid)?, Signal::KILL)
                .map_err(std::io::Error::from)?;
            self.signalled = true;
        }
        if !self.reaped {
            self.reaped = child.try_wait()?.is_some();
        }
        Ok(self.reaped && group_members(self.pid)?.is_empty())
    }
}

pub(super) fn exited_without_reaping(child: &Child) -> Result<bool, ProviderError> {
    Ok(waitid(
        WaitId::Pid(native_pid(child.id())?),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
    .map_err(std::io::Error::from)?
    .is_some())
}

fn native_pid(pid: u32) -> Result<Pid, ProviderError> {
    Pid::from_raw(
        i32::try_from(pid).map_err(|_| ProviderError::Correlation("native lineage PID extent"))?,
    )
    .ok_or(ProviderError::Correlation("native lineage PID omitted"))
}

struct Stat {
    group: u32,
    start_ticks: u64,
}

fn read_stat(pid: u32) -> Result<Option<Stat>, ProviderError> {
    let file = match fs::File::open(format!("/proc/{pid}/stat")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(ProviderError::ResourceExhausted(
            "native lineage kernel stat bytes",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ProviderError::Frame("native lineage kernel stat encoding"))?;
    let close = text
        .rfind(')')
        .ok_or(ProviderError::Frame("native lineage kernel stat shape"))?;
    let mut fields = text[close + 1..].split_ascii_whitespace();
    let group = fields
        .nth(2)
        .ok_or(ProviderError::Frame("native lineage kernel group omitted"))?
        .parse()
        .map_err(|_| ProviderError::Frame("native lineage kernel group invalid"))?;
    let start_ticks = fields
        .nth(16)
        .ok_or(ProviderError::Frame("native lineage kernel start omitted"))?
        .parse()
        .map_err(|_| ProviderError::Frame("native lineage kernel start invalid"))?;
    Ok(Some(Stat { group, start_ticks }))
}

fn group_members(group: u32) -> Result<Vec<u32>, ProviderError> {
    let mut members = Vec::new();
    for (index, entry) in fs::read_dir("/proc")?.enumerate() {
        if index >= 100_000 {
            return Err(ProviderError::ResourceExhausted(
                "native lineage kernel census",
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
        if read_stat(pid)?.is_some_and(|stat| stat.group == group) {
            if members.len() >= 4096 {
                return Err(ProviderError::ResourceExhausted(
                    "native lineage group roster",
                ));
            }
            members.push(pid);
        }
    }
    Ok(members)
}
