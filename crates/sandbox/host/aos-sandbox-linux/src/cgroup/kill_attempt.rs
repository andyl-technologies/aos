//! Shared cgroup cancellation with ordinary and retained native disposition.
//!
//! Both callers run one active/open/filesystem/stat/write recipe. Cancellation
//! never proves process death or subtree emptiness; those owners stay separate.

use super::*;
use std::os::fd::AsFd as _;

trait Opening {
    fn active(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()>;
    fn open(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()>;
    fn file(&self) -> &OwnedFd;
    fn filesystem(&mut self) -> Result<libc::c_long>;
    fn mode(&mut self) -> Result<libc::mode_t>;
}

fn open_native(anchor: &RetainedCgroupAnchor) -> Result<OwnedFd> {
    rustix::fs::openat(
        anchor.root.as_fd(),
        Path::new("cgroup.kill"),
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    ).map_err(|source| Error::Syscall {
        operation: "open cgroup.kill",
        source: source.into(),
    })
}

fn open_control(anchor: &RetainedCgroupAnchor, observation: &mut impl Opening) -> Result<()> {
    observation.active(anchor)?;
    observation.open(anchor)?;
    // Preserve the old short-circuit: stat is not attempted after wrong fs.
    if observation.filesystem()? != CGROUP2_SUPER_MAGIC
        || observation.mode()? & libc::S_IFMT != libc::S_IFREG
    {
        return Err(Error::WrongDescriptorType {
            expected: "cgroup-v2 kill control",
        });
    }
    Ok(())
}

#[derive(Default)]
struct LocalOpening {
    file: Option<OwnedFd>,
}

impl Opening for LocalOpening {
    fn active(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        anchor.validate_active()
    }

    fn open(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        self.file = Some(open_native(anchor)?);
        Ok(())
    }

    fn file(&self) -> &OwnedFd {
        let Some(file) = self.file.as_ref() else { std::process::abort() };
        file
    }

    fn filesystem(&mut self) -> Result<libc::c_long> {
        uapi::filesystem_type(self.file().as_fd())
    }

    fn mode(&mut self) -> Result<libc::mode_t> {
        Ok(uapi::fstat(self.file().as_fd())?.st_mode)
    }
}

pub(super) fn open_local(anchor: &RetainedCgroupAnchor) -> Result<OwnedFd> {
    let mut observation = LocalOpening::default();
    open_control(anchor, &mut observation)?;
    let Some(file) = observation.file.take() else { std::process::abort() };
    Ok(file)
}

pub(super) trait WriteObservation {
    fn write(&mut self, file: &OwnedFd, bytes: &[u8]) -> std::result::Result<usize, rustix::io::Errno>;
}

pub(super) struct LocalWrite;

impl WriteObservation for LocalWrite {
    fn write(&mut self, file: &OwnedFd, bytes: &[u8]) -> std::result::Result<usize, rustix::io::Errno> {
        rustix::io::write(file, bytes)
    }
}

pub(super) fn write_control<E: From<Error>>(
    file: &OwnedFd,
    current: &mut impl FnMut() -> std::result::Result<(), E>,
    observation: &mut impl WriteObservation,
) -> std::result::Result<(), E> {
    let mut remaining: &[u8] = b"1\n";
    while !remaining.is_empty() {
        current()?;
        match observation.write(file, remaining) {
            Ok(0) => {
                return Err(Error::MalformedKernelResponse {
                    object: "cgroup.kill",
                    message: "kernel accepted an incomplete kill record".to_owned(),
                }.into());
            }
            Ok(written) => remaining = &remaining[written..],
            Err(rustix::io::Errno::INTR) => continue,
            Err(source) => {
                return Err(Error::Syscall {
                    operation: "write cgroup.kill",
                    source: source.into(),
                }.into());
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct RetainedWrite {
    last: Option<std::result::Result<usize, rustix::io::Errno>>,
}

impl WriteObservation for RetainedWrite {
    fn write(&mut self, file: &OwnedFd, bytes: &[u8]) -> std::result::Result<usize, rustix::io::Errno> {
        // The shared engine consumes only successful byte counts or native
        // EINTR before another write. The final failing/uncertain result stays.
        self.last = Some(rustix::io::write(file, bytes));
        let Some(result) = self.last else { std::process::abort() };
        result
    }
}

/// Reports refusal while the exact cancellation originals remain retained.
#[derive(Debug, thiserror::Error)]
#[error("retained cgroup cancellation is incomplete or refused")]
pub struct CgroupKillRefusalV1;

/// Owns the entered active probe, kill FD, complete native observations and write.
#[derive(Default)]
pub struct CgroupKillAttemptV1 {
    active_probe: PendingRegularFileV1,
    active: Option<Result<()>>,
    opened: Option<Result<OwnedFd>>,
    filesystem: Option<Result<libc::c_long>>,
    stat: Option<Result<libc::stat>>,
    write: RetainedWrite,
    result: Option<Result<()>>,
    attempted: bool,
    closed: Option<Error>,
}

impl CgroupKillAttemptV1 {
    /// Creates empty cancellation destinations without native work.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs the same fixed cancellation recipe once, retaining every prefix.
    ///
    /// # Errors
    /// Retains the active/open/filesystem/stat/write failure or permanent
    /// reentry refusal. Even success confers no death or disposal proof.
    pub fn capture_once(&mut self, anchor: &RetainedCgroupAnchor) -> std::result::Result<(), CgroupKillRefusalV1> {
        self.capture_with_write_budget(anchor, None)
    }

    /// Enters the same native recipe with at most two actual write attempts.
    ///
    /// This finite scheduler lane refuses interruption/partial-write exhaustion
    /// while retaining the control FD and actual native prefix. It grants no
    /// cancellation authority and ordinary callers retain their prior behavior.
    ///
    /// # Errors
    /// Retains the original refusal or exhausted native retry budget.
    pub fn capture_once_bounded_v2(&mut self, anchor: &RetainedCgroupAnchor)
        -> std::result::Result<(), CgroupKillRefusalV1>
    {
        self.capture_with_write_budget(anchor, Some(Self::maximum_bounded_write_attempts_v4()))
    }

    fn capture_with_write_budget(&mut self, anchor: &RetainedCgroupAnchor, maximum: Option<usize>)
        -> std::result::Result<(), CgroupKillRefusalV1>
    {
        self.capture_with_gate_v4::<std::convert::Infallible>(anchor, maximum, None).0
    }

    /// Enters the same finite cancellation engine with a final native deny gate.
    ///
    /// This method grants no containment permission or target selection. Its
    /// caller must hold the original scoped cleanup authority and retain both
    /// returned results through the independently owed outer observations.
    ///
    /// # Errors
    /// Retains the same active/open/filesystem/stat/write prefix on refusal.
    /// Returns the exact caller-owned gate error alongside the native original.
    pub fn capture_bounded_with_current_cut_v4<E>(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        current: &mut dyn FnMut() -> std::result::Result<(), E>,
    ) -> (std::result::Result<(), CgroupKillRefusalV1>, Option<E>) {
        self.capture_with_gate_v4(anchor, Some(Self::maximum_bounded_write_attempts_v4()), Some(current))
    }

    /// Bounds the actual primitive writes in either retained finite recipe.
    ///
    /// The final-syscall callback runs at most this many times, including
    /// partial writes and EINTR. This is a mechanical bound, not permission.
    #[must_use]
    pub const fn maximum_bounded_write_attempts_v4() -> usize {
        2
    }

    fn capture_with_gate_v4<E>(
        &mut self, anchor: &RetainedCgroupAnchor, maximum: Option<usize>,
        mut current: Option<&mut dyn FnMut() -> std::result::Result<(), E>>,
    ) -> (std::result::Result<(), CgroupKillRefusalV1>, Option<E>) {
        let mut gate_failure = None;
        if self.attempted {
            self.closed.get_or_insert_with(|| Error::invalid("retained cgroup kill", "already attempted"));
            return (Err(CgroupKillRefusalV1), None);
        }
        self.attempted = true;
        self.result = Some((|| {
            open_control(anchor, self)?;
            let Some(Ok(file)) = self.opened.as_ref() else { std::process::abort() };
            let mut entered = 0_usize;
            write_control::<Error>(file, &mut || {
                if let Some(maximum) = maximum {
                    if entered >= maximum {
                        return Err(Error::invalid("retained cgroup kill", "native write attempts exhausted"));
                    }
                    entered += 1;
                }
                if let Some(current) = current.as_deref_mut() {
                    if let Err(error) = current() {
                        gate_failure = Some(error);
                        return Err(Error::invalid("retained cgroup kill", "original native-write gate refused"));
                    }
                }
                Ok(())
            }, &mut self.write)
        })());
        if matches!(self.result, Some(Ok(()))) {
            (Ok(()), gate_failure)
        } else {
            (Err(CgroupKillRefusalV1), gate_failure)
        }
    }

    /// Borrows the earliest actual native or semantic cause without retry.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        fn cause<T>(slot: &Option<Result<T>>) -> Option<&Error> {
            slot.as_ref()?.as_ref().err()
        }
        cause(&self.active).or_else(|| cause(&self.opened))
            .or_else(|| cause(&self.filesystem)).or_else(|| cause(&self.stat))
            .or_else(|| cause(&self.result)).or(self.closed.as_ref())
    }

    /// Borrows the actual native write refusal before its propagated marker.
    #[must_use]
    pub fn native_failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T>(slot: &Option<Result<T>>) -> Option<&(dyn std::error::Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|error| error as _)
        }
        cause(&self.active).or_else(|| cause(&self.opened))
            .or_else(|| cause(&self.filesystem)).or_else(|| cause(&self.stat))
            .or_else(|| self.write.last.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| cause(&self.result)).or_else(|| self.closed.as_ref().map(|error| error as _))
    }

    /// Prices fixed native owner/construction storage, names and exact errors.
    #[must_use]
    pub fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(2 * b"cgroup.procs\0".len())?
            .checked_add(std::mem::size_of::<libc::stat>())?
            .checked_add(8 * 256)
    }

    /// Counts the two relative kernfs names used by the shared native recipe.
    ///
    /// Active validation opens cgroup.procs and cancellation opens cgroup.kill
    /// beneath the same held anchor. Native Results, probes and write retries
    /// add no names; their full representation remains in requested_bytes_v1.
    pub const METADATA_ENTRIES_V1: usize = 2;

    /// Bounds the additional active and kill-control descriptor slots.
    #[must_use]
    pub const fn maximum_retained_files_v1() -> usize {
        2
    }
}

impl Opening for CgroupKillAttemptV1 {
    fn active(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        self.active = Some(anchor.validate_active_retaining(&mut self.active_probe));
        if matches!(self.active, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Error::invalid("retained cgroup kill", "active cause retained"))
        }
    }

    fn open(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        self.opened = Some(open_native(anchor));
        if matches!(self.opened, Some(Ok(_))) {
            Ok(())
        } else {
            Err(Error::invalid("retained cgroup kill", "open cause retained"))
        }
    }

    fn file(&self) -> &OwnedFd {
        let Some(Ok(file)) = self.opened.as_ref() else { std::process::abort() };
        file
    }

    fn filesystem(&mut self) -> Result<libc::c_long> {
        self.filesystem = Some(uapi::filesystem_type(self.file().as_fd()));
        match self.filesystem.as_ref() {
            Some(Ok(value)) => Ok(*value),
            _ => Err(Error::invalid("retained cgroup kill", "filesystem cause retained")),
        }
    }

    fn mode(&mut self) -> Result<libc::mode_t> {
        self.stat = Some(uapi::fstat(self.file().as_fd()));
        match self.stat.as_ref() {
            Some(Ok(stat)) => Ok(stat.st_mode),
            _ => Err(Error::invalid("retained cgroup kill", "stat cause retained")),
        }
    }
}
