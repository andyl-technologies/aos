//! Keeps the closed SSH helper on the existing posix-spawn and exact-child engines.
//!
//! The owning Guest scope supplies its already-created destination. No public
//! PID, program, arbitrary cgroup or process-adoption port exists. Every reached
//! descriptor and actual child is parked before the independently owed clock.

use super::*;

pub(crate) struct GuestSshProcessOriginalV1 {
    null: Option<rustix::io::Result<OwnedFd>>,
    stdin: Option<Result<OwnedFd>>,
    null_high: Option<Result<OwnedFd>>,
    guard: Option<ChildGuard>,
    pidfd: crate::pidfd::PidFdOpenAttemptV1,
    child_pidfd: Option<std::sync::Arc<PidFd>>,
    invocation: Option<(CString, Vec<CString>)>,
    body: Option<Result<()>>,
    wait: Option<rustix::io::Result<Option<rustix::process::WaitStatus>>>,
    status: Option<i32>,
    kill: Option<Result<()>>,
    clock: capture_cut::CaptureProcessCutOriginalV3,
    after_clock: capture_cut::CaptureProcessCutOriginalV3,
    after: Option<Result<Duration>>,
    fork: Option<Box<super::storage_fork::GuestSshForkObservationV1>>,
}

impl GuestSshProcessOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            null: None,
            stdin: None,
            null_high: None,
            guard: None,
            pidfd: crate::pidfd::PidFdOpenAttemptV1::new(),
            child_pidfd: None,
            invocation: None,
            body: None,
            wait: None,
            status: None,
            kill: None,
            clock: Default::default(),
            after_clock: Default::default(),
            after: None,
            fork: None,
        }
    }

    pub(crate) fn spawn_once(
        &mut self,
        cgroup: BorrowedFd<'_>,
        input: BorrowedFd<'_>,
        nofile: u32,
        deadline: u64,
        wall: i64,
        source: crate::guest_cgroup::GuestSshBirthSourceDataV1,
    ) -> Result<()> {
        if self.body.is_some() {
            return Err(closed());
        }
        let cut = FixedProcessCaptureCutV3::new(deadline, wall)?;
        self.body = Some(self.spawn_inner(cgroup, input, nofile, deadline, wall, cut, source));
        // A successful libc return already belongs to this original before
        // the independent post can refuse. The actual pidfd is also retained
        // on its opening owner if adoption or its identity validation fails.
        self.after = Some(self.after_clock.observe(cut));
        if !matches!(self.body, Some(Ok(()))) || !matches!(self.after, Some(Ok(_))) {
            return Err(closed());
        }
        drop(self.stdin.take());
        drop(self.null_high.take());
        drop(self.null.take());
        drop(self.fork.take());
        Ok(())
    }

    fn spawn_inner(
        &mut self,
        cgroup: BorrowedFd<'_>,
        input: BorrowedFd<'_>,
        nofile: u32,
        deadline: u64,
        wall: i64,
        cut: FixedProcessCaptureCutV3,
        source: crate::guest_cgroup::GuestSshBirthSourceDataV1,
    ) -> Result<()> {
        if nofile < 3 {
            return Err(closed());
        }
        uapi::validate_child_reaping_disposition()?;
        let agent = std::env::current_exe().map_err(|source| Error::Syscall {
            operation: "locate actual Guest helper image",
            source,
        })?;
        if agent.file_name() != Some(std::ffi::OsStr::new("aos-sandbox-guest-agent")) {
            return Err(closed());
        }
        let helper = agent.with_file_name("aos-sandbox-guest-exec");
        if agent.as_os_str().as_bytes().len() > 4096 || helper.as_os_str().as_bytes().len() > 4096 {
            return Err(closed());
        }
        let executable = CString::new(helper.as_os_str().as_bytes()).map_err(|_| closed())?;
        let mut arguments = Vec::with_capacity(4);
        for value in [
            "--openssh-bootstrap-v1".to_owned(),
            nofile.to_string(),
            deadline.to_string(),
            wall.to_string(),
        ] {
            arguments.push(CString::new(value).map_err(|_| closed())?);
        }
        self.invocation = Some((executable, arguments));
        self.null = Some(rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ));
        let null = match self.null.as_ref() {
            Some(Ok(null)) => null,
            Some(Err(source)) => return Err(kernel_error("open SSH null output", *source)),
            None => return Err(closed()),
        };
        self.null_high = Some(duplicate_high(null.as_fd()));
        if !matches!(self.null_high, Some(Ok(_))) {
            return Err(closed());
        }
        self.stdin = Some(duplicate_high(input));
        let (Some(Ok(null)), Some(Ok(input)), Some((executable, arguments))) =
            (&self.null_high, &self.stdin, &self.invocation)
        else {
            return Err(closed());
        };
        self.fork = Some(Box::new(super::storage_fork::GuestSshForkObservationV1::new()));
        self.fork.as_mut().ok_or_else(closed)?.capture_once_v1(
            source.copied_files, source.highest_fd, source.future_files)?;
        let mut raw = uapi::posix_spawn_fixed_guest_ssh_v1(
            executable,
            arguments,
            input.as_fd(),
            null.as_fd(),
            uapi::GuestSshBirthV1 { cgroup },
            cut,
            &mut self.clock,
        )?;
        let pid = raw.pid()?;
        self.guard = Some(ChildGuard::new_owned_leader(pid));
        raw.disarm();
        let pid = NonZeroU32::new(u32::try_from(pid.as_raw_nonzero().get()).map_err(|_| closed())?)
            .ok_or_else(closed)?;
        self.pidfd.capture_once(pid).map_err(|_| closed())?;
        let pidfd = self.pidfd.take_validated().ok_or_else(closed)?;
        // The actual native pidfd has one descriptor owner. The monitor may
        // share its Arc after setup, while this unreaped ChildGuard retains
        // the independently owed direct-child kill/wait responsibility.
        self.child_pidfd = Some(std::sync::Arc::new(pidfd));
        Ok(())
    }

    pub(crate) fn id(&self) -> Option<u32> {
        u32::try_from(self.guard.as_ref()?.pid.as_raw_nonzero().get()).ok()
    }

    pub(crate) fn pidfd(&self) -> Result<&PidFd> {
        self.child_pidfd.as_deref().ok_or_else(closed)
    }

    pub(crate) fn shared_pidfd(&self) -> Result<std::sync::Arc<PidFd>> {
        if !matches!(self.body, Some(Ok(()))) || !matches!(self.after, Some(Ok(_))) {
            return Err(closed());
        }
        self.child_pidfd
            .as_ref()
            .map(std::sync::Arc::clone)
            .ok_or_else(closed)
    }

    pub(crate) fn poll_wait(&mut self) -> Result<Option<i32>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        if self.wait.as_ref().is_some_and(|result| result.is_err()) {
            return Err(closed());
        }
        let guard = self.guard.as_mut().ok_or_else(closed)?;
        self.wait = Some(wait_status_once(
            guard.pid,
            rustix::process::WaitOptions::NOHANG,
        ));
        match self.wait.as_ref() {
            Some(Ok(Some(status))) if status.exited() || status.signaled() => {
                self.status = Some(status.as_raw());
                guard.armed = false;
                Ok(self.status)
            }
            Some(Ok(None)) => Ok(None),
            Some(Err(source)) => Err(kernel_error("poll same SSH child", *source)),
            _ => Err(closed()),
        }
    }

    pub(crate) fn kill_once(&mut self) -> Result<()> {
        if self.kill.is_none() {
            self.kill = Some(self.guard.as_ref().ok_or_else(closed)?.cancel());
        }
        if matches!(self.kill, Some(Ok(()))) {
            Ok(())
        } else {
            Err(closed())
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.startup_failure()
            .or_else(|| self.wait_failure())
            .or_else(|| self.kill_failure())
    }

    pub(crate) fn startup_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = self.body.as_ref() {
            // The after sample runs even after an earlier native refusal. It
            // cannot replace that refusal with its own later clock source.
            return self
                .null_high
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| self.stdin.as_ref()?.as_ref().err().map(|cause| cause as _))
                .or_else(|| self.pidfd.failure().map(|cause| cause as _))
                .or_else(|| self.fork.as_ref()?.failure())
                .or_else(|| {
                    capture_cut::is_marker(cause)
                        .then(|| self.clock.failure())
                        .flatten()
                        .map(|cause| cause as _)
                })
                .or(Some(cause));
        }
        self.after_clock.failure().map(|cause| cause as _)
    }

    pub(crate) fn wait_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.wait.as_ref()?.as_ref().err().map(|cause| cause as _)
    }

    pub(crate) fn kill_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.kill.as_ref()?.as_ref().err().map(|cause| cause as _)
    }

    pub(crate) fn receiving_obligations_v1(source_copied_files: u32) -> Option<(usize, usize, usize)> {
        // Actual path plus four fixed CString arguments and the sole libc argv
        // pointer vector. No capture pipe or undrained child stream is created.
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            // current_exe, its replaced helper path, CString conversion and
            // the still-live source/reallocation planes share this checked
            // path ceiling. They coexist before the sole spawn invocation.
            .checked_add(8 * 4096 + 4 * (21 + std::mem::size_of::<CString>()))?
            .checked_add(2 * (std::mem::size_of::<PidFd>() + 2 * std::mem::size_of::<usize>()))?
            .checked_add(6 * std::mem::size_of::<*const libc::c_char>())?
            .checked_add(std::mem::size_of::<libc::posix_spawn_file_actions_t>())?
            .checked_add(std::mem::size_of::<libc::posix_spawnattr_t>())?
            .checked_add(8 * 256)?
            // The configured-kernel helper separately prices the libc stack
            // at that target's actual page size. Never assume a 4KiB page.
            .checked_add(8 * 32)?
            .checked_add(super::storage_fork::GuestSshForkObservationV1::receiving_bytes_v1(source_copied_files)?)?;
        // The full-positive scanner closes before libc and the later pidfd
        // capture. It replaces that fourth transient FD, rather than joining
        // the three null/input aliases plus a still-live pidfd.
        let names = 3_usize.checked_add(
            super::storage_fork::GuestSshForkObservationV1::receiving_metadata_entries_v1(source_copied_files)?,
        )?;
        Some((bytes, 4, names))
    }
}

fn closed() -> Error {
    Error::invalid("Guest SSH child", "original native spawn is incomplete")
}
