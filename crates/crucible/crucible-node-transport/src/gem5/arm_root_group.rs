//! Original waitable kernel-group custody for the ARM native model owner.
//!
//! Exit observations preserve the leader anchor. Once retirement starts, retries
//! may wait or census but cannot signal a retired or replacement process group.

use std::{
    fs,
    os::unix::process::ExitStatusExt,
    process::{Child, ExitStatus},
    time::Duration,
};

use rustix::process::{
    Pid, Signal, WaitId, WaitIdOptions, WaitIdStatus, WaitOptions, getpgid, kill_process_group,
    waitid, waitpid,
};

use super::arm_root_budget::HostBudget;
use crate::ProviderError;

pub(crate) struct ArmRootGroup {
    pub(crate) child: Child,
    pid: Pid,
    start_ticks: String,
    signal_attempted: bool,
    retired: Option<ExitStatus>,
    failed_wait: bool,
    reclaimed: bool,
    deadline: Option<HostBudget>,
}

impl ArmRootGroup {
    // Keep the original Child inside its owning capsule during all fallible
    // measurement; unwinding cannot discard it before enrollment completes.
    pub(crate) fn enroll_retained(child: &mut Option<Child>) -> Result<Self, ProviderError> {
        let measured = Self::measure(
            child
                .as_ref()
                .ok_or(ProviderError::Frame("ARM actual child absent"))?,
        )?;
        let child = child
            .take()
            .ok_or(ProviderError::Frame("ARM enrolled child absent"))?;
        Ok(Self::measured(child, measured))
    }

    pub(crate) fn enroll_helper(children: &mut Vec<Child>) -> Result<Self, ProviderError> {
        let measured = Self::measure(
            children
                .last()
                .ok_or(ProviderError::Frame("ARM actual helper absent"))?,
        )?;
        let child = children
            .pop()
            .ok_or(ProviderError::Frame("ARM enrolled helper absent"))?;
        Ok(Self::measured(child, measured))
    }

    fn measure(child: &Child) -> Result<(Pid, String), ProviderError> {
        let pid = kernel_pid(child.id())?;
        let start_ticks = kernel_start_ticks(child.id())?;
        if getpgid(Some(pid)).map_err(std::io::Error::from)? != pid {
            return Err(ProviderError::Correlation(
                "ARM native child lacks private group",
            ));
        }
        // ECHILD remains unknown custody rather than evidence of safely absent helpers.
        observe(pid)?;
        Ok((pid, start_ticks))
    }

    fn measured(child: Child, (pid, start_ticks): (Pid, String)) -> Self {
        Self {
            child,
            pid,
            start_ticks,
            signal_attempted: false,
            retired: None,
            failed_wait: false,
            reclaimed: false,
            deadline: None,
        }
    }

    pub(crate) fn identity(&self) -> (u32, &str) {
        (self.child.id(), &self.start_ticks)
    }

    pub(crate) fn require_live(&self) -> Result<(), ProviderError> {
        self.require_anchor()?;
        if observe(self.pid)?.is_some() {
            return Err(ProviderError::Correlation("ARM native owner has exited"));
        }
        Ok(())
    }

    pub(crate) fn exit_observation(&self) -> Result<Option<bool>, ProviderError> {
        self.require_anchor()?;
        Ok(observe(self.pid)?.map(|status| status.exited() && status.exit_status() == Some(0)))
    }

    fn require_anchor(&self) -> Result<(), ProviderError> {
        if self.retired.is_some()
            || self.failed_wait
            || kernel_start_ticks(self.child.id())? != self.start_ticks
            || getpgid(Some(self.pid)).map_err(std::io::Error::from)? != self.pid
        {
            return Err(ProviderError::Correlation(
                "ARM original kernel-group anchor lost",
            ));
        }
        Ok(())
    }

    pub(crate) fn begin_retirement(&mut self) -> Result<(), ProviderError> {
        if self.reclaimed || self.signal_attempted {
            return Ok(());
        }
        self.require_anchor()?;
        observe(self.pid)?;
        // Record the attempt before the effect. An uncertain signal cannot be
        // repeated later against an anchor whose retirement status has changed.
        let deadline = HostBudget::after(Duration::from_secs(10))?;
        self.signal_attempted = true;
        self.deadline = Some(deadline);
        kill_process_group(self.pid, Signal::KILL).map_err(std::io::Error::from)?;
        Ok(())
    }

    pub(crate) fn poll_retirement(&mut self) -> Result<bool, ProviderError> {
        if self.reclaimed {
            return Ok(true);
        }
        if self.failed_wait || !self.signal_attempted {
            return Err(ProviderError::Correlation(
                "ARM group retirement custody unresolved",
            ));
        }
        if self.retired.is_none() {
            self.require_anchor()?;
            if observe(self.pid)?.is_none() {
                return self.pending();
            }
            match waitpid(Some(self.pid), WaitOptions::empty()) {
                Ok(Some((pid, status)))
                    if pid == self.pid && (status.exited() || status.signaled()) =>
                {
                    self.retired = Some(ExitStatus::from_raw(status.as_raw()));
                }
                Ok(_) => {
                    self.failed_wait = true;
                    return Err(ProviderError::Correlation(
                        "ARM actual retirement lacks original leader",
                    ));
                }
                Err(error) => {
                    self.failed_wait = true;
                    return Err(std::io::Error::from(error).into());
                }
            }
        }
        let mut count = 0usize;
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !name.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            let body = match fs::read_to_string(entry.path().join("stat")) {
                Ok(body) => body,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let fields = stat_fields(&body)?;
            let group = fields
                .get(2)
                .ok_or(ProviderError::Frame("ARM kernel group field"))?
                .parse::<i32>()
                .map_err(|_| ProviderError::Frame("ARM kernel group scalar"))?;
            if group == self.pid.as_raw_nonzero().get() {
                count += 1;
                if count > 4096 {
                    return Err(ProviderError::ResourceExhausted("ARM helper census"));
                }
            }
        }
        if count != 0 {
            return self.pending();
        }
        self.reclaimed = true;
        Ok(true)
    }

    fn pending(&self) -> Result<bool, ProviderError> {
        if self.deadline.as_ref().is_none_or(HostBudget::is_expired) {
            return Err(ProviderError::Correlation(
                "ARM helper retirement deadline expired",
            ));
        }
        Ok(false)
    }
}

fn kernel_pid(pid: u32) -> Result<Pid, ProviderError> {
    let scalar = i32::try_from(pid).map_err(|_| ProviderError::Frame("ARM kernel PID range"))?;
    Pid::from_raw(scalar).ok_or(ProviderError::Frame("ARM kernel PID absent"))
}

fn observe(pid: Pid) -> Result<Option<WaitIdStatus>, ProviderError> {
    let observed = waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
    .map_err(std::io::Error::from)?;
    if observed
        .as_ref()
        .is_some_and(|status| !(status.exited() || status.killed() || status.dumped()))
    {
        return Err(ProviderError::Correlation(
            "ARM exit observation is not terminal",
        ));
    }
    Ok(observed)
}

fn stat_fields(body: &str) -> Result<Vec<&str>, ProviderError> {
    let end = body
        .rfind(")")
        .ok_or(ProviderError::Frame("ARM kernel stat command"))?;
    Ok(body
        .get(end + 2..)
        .ok_or(ProviderError::Frame("ARM kernel stat suffix"))?
        .split_ascii_whitespace()
        .collect())
}

pub(crate) fn kernel_start_ticks(pid: u32) -> Result<String, ProviderError> {
    let body = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields = stat_fields(&body)?;
    let value = fields
        .get(19)
        .ok_or(ProviderError::Frame("ARM kernel start ticks"))?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProviderError::Frame("ARM kernel start ticks scalar"));
    }
    Ok((*value).to_owned())
}
