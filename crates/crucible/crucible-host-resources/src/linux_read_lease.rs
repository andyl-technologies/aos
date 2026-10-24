//! Holds original read-only descriptors under kernel-enforced Linux read leases.
//!
//! A private notification thread blocks SIGIO only in its own signal mask. Each
//! leased descriptor targets that thread before acquisition. Callers retain
//! original descriptors, measure their complete bytes after acquisition, and
//! verify the actual kernel lease before and after using those measurements.

use std::{
    cell::Cell,
    fs::File,
    io,
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

/// Describes an unavailable or revoked original read-lease capability.
#[derive(Debug, thiserror::Error)]
pub enum LinuxReadLeaseError {
    /// Retains the actual descriptor, signal-mask, thread or kernel error.
    #[error("Linux read lease operation failed: {0}")]
    Io(#[from] io::Error),
    /// Refuses use outside the process that owns the notification thread.
    #[error("Linux read lease belongs to another process")]
    WrongProcess,
    /// Refuses a thread that has not installed its mask or has already exited.
    #[error("Linux read lease notification owner is unavailable")]
    OwnerUnavailable,
    /// Refuses a write-capable descriptor or nonregular file.
    #[error("Linux read lease requires an original read-only regular file")]
    InvalidDescriptor,
    /// Refuses adoption or renewal of an already leased open-file description.
    #[error("Linux read lease requires a previously unleased original descriptor")]
    AlreadyLeased,
    /// Refuses changed notification ownership or any pending/finished break.
    #[error("Linux original read lease was changed or broken")]
    Revoked,
    /// Refuses any loss after successful kernel acquisition; fallback is closed.
    #[error("acquired Linux read lease failed its initial validation: {0}")]
    AcquiredLeaseRevoked(#[source] Box<LinuxReadLeaseError>),
}

struct NotificationState {
    alive: AtomicBool,
    stop: AtomicBool,
}

/// Owns the isolated notification thread used by original read-only files.
///
/// The worker changes only its own SIGIO mask. It installs no signal handler and
/// leaves the calling thread's mask and process-wide dispositions unchanged.
/// Dropping the last owner wakes and joins the worker. Leased descriptors must
/// be closed before their final owner reference is released.
pub struct LinuxReadLeaseOwner {
    process: libc::pid_t,
    thread: libc::pid_t,
    state: Arc<NotificationState>,
    worker: Option<JoinHandle<()>>,
}

impl LinuxReadLeaseOwner {
    /// Starts one bounded notification worker without changing caller signals.
    ///
    /// # Errors
    /// Returns actual thread/mask failures or a failed startup handshake. Only
    /// Linux x86-64 and AArch64 kernel owner layouts are supported.
    pub fn new() -> Result<Self, LinuxReadLeaseError> {
        if !cfg!(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )) {
            return Err(io::Error::from(io::ErrorKind::Unsupported).into());
        }
        let state = Arc::new(NotificationState {
            alive: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        });
        let worker_state = Arc::clone(&state);
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("source-read-lease".into())
            .spawn(move || notification_worker(worker_state, sender))?;
        let startup = receiver.recv_timeout(Duration::from_secs(2));
        let thread = match startup {
            Ok(Ok(thread)) => thread,
            Ok(Err(error)) => {
                state.stop.store(true, Ordering::Release);
                worker.thread().unpark();
                let _ = worker.join();
                return Err(error.into());
            }
            Err(_) => {
                state.stop.store(true, Ordering::Release);
                worker.thread().unpark();
                let _ = worker.join();
                return Err(LinuxReadLeaseError::OwnerUnavailable);
            }
        };
        // SAFETY: getpid takes no pointers and identifies this owning process.
        let process = unsafe { libc::getpid() };
        Ok(Self {
            process,
            thread,
            state,
            worker: Some(worker),
        })
    }

    fn current(&self) -> Result<(), LinuxReadLeaseError> {
        // SAFETY: getpid takes no pointers. An inherited post-fork owner cannot
        // borrow the parent process's worker or join handle.
        if unsafe { libc::getpid() } != self.process {
            return Err(LinuxReadLeaseError::WrongProcess);
        }
        if !self.state.alive.load(Ordering::Acquire) || self.state.stop.load(Ordering::Acquire) {
            return Err(LinuxReadLeaseError::OwnerUnavailable);
        }
        Ok(())
    }
}

impl Drop for LinuxReadLeaseOwner {
    fn drop(&mut self) {
        // The post-fork child has no worker to wake/join. Dropping its local
        // handle cannot close or change the original parent's descriptors.
        // SAFETY: getpid has no arguments and does not mutate signal state.
        if unsafe { libc::getpid() } != self.process {
            return;
        }
        self.state.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

/// Holds one original descriptor and its single acquired kernel read lease.
///
/// Acquisition does not measure file content. The caller must hash complete
/// original bytes after acquisition and verify this lease afterward. Every
/// later use checks the kernel again; a pending break permanently revokes this
/// capability. It never reacquires, renews or downgrades a lease.
/// The caller must keep descriptor ownership private: external `fcntl` calls
/// can change notification or lease state and cause permanent refusal.
pub struct LinuxReadLease {
    // Close the original descriptor reference before releasing the worker.
    file: Arc<File>,
    owner: Arc<LinuxReadLeaseOwner>,
    revoked: Cell<bool>,
}

impl LinuxReadLease {
    /// Acquires one read lease on the caller's original read-only descriptor.
    ///
    /// # Errors
    /// Refuses unsupported filesystems, conflicting writable descriptors or
    /// mappings, wrong-process ownership, changed notification ownership, and
    /// actual kernel failures. Initial acquisition refusal permits complete-byte
    /// validation instead. `AcquiredLeaseRevoked` reports successful SETLEASE
    /// followed by lost validation and MUST refuse the original measurement.
    fn acquire(
        file: Arc<File>,
        owner: Arc<LinuxReadLeaseOwner>,
    ) -> Result<Self, LinuxReadLeaseError> {
        owner.current()?;
        if !file.metadata()?.is_file()
            || descriptor_integer(&file, libc::F_GETFL, 0)? & libc::O_ACCMODE != libc::O_RDONLY
        {
            return Err(LinuxReadLeaseError::InvalidDescriptor);
        }
        // A private fresh original may be acquired once. Never overwrite the
        // notification owner or renew a lease on the same open-file description.
        if descriptor_integer(&file, libc::F_GETLEASE, 0)? != libc::F_UNLCK {
            return Err(LinuxReadLeaseError::AlreadyLeased);
        }
        set_notification_owner(&file, owner.thread)?;
        descriptor_integer(&file, libc::F_SETLEASE, libc::F_RDLCK)?;
        let installed = Self {
            file,
            owner,
            revoked: Cell::new(false),
        };
        Self::validate_acquired(installed)
    }

    fn validate_acquired(installed: Self) -> Result<Self, LinuxReadLeaseError> {
        // SETLEASE already succeeded. A racing pending break or lost worker
        // must refuse the original, never enter the unsupported initial path.
        installed
            .verify_current()
            .map_err(|error| LinuxReadLeaseError::AcquiredLeaseRevoked(Box::new(error)))?;
        Ok(installed)
    }

    /// Verifies the original kernel lease and notification owner directly.
    ///
    /// # Errors
    /// Permanently refuses changed process/thread ownership, a missing worker,
    /// a pending or completed break, altered descriptor flags, and actual
    /// kernel failures. Restoring bytes or lease flags cannot revive it.
    pub fn verify_current(&self) -> Result<(), LinuxReadLeaseError> {
        if self.revoked.get() {
            return Err(LinuxReadLeaseError::Revoked);
        }
        let result = (|| {
            self.owner.current()?;
            let owner = notification_owner(&self.file)?;
            if owner.kind != OWNER_THREAD
                || owner.id != self.owner.thread
                || descriptor_integer(&self.file, libc::F_GETFL, 0)? & libc::O_ACCMODE
                    != libc::O_RDONLY
                || descriptor_integer(&self.file, libc::F_GETLEASE, 0)? != libc::F_RDLCK
            {
                return Err(LinuxReadLeaseError::Revoked);
            }
            Ok(())
        })();
        if result.is_err() {
            self.revoked.set(true);
        }
        result
    }
}

impl Drop for LinuxReadLease {
    fn drop(&mut self) {
        // An inherited descriptor shares the parent's open-file description.
        // A child must only close its reference, never unlock the parent's lease.
        // SAFETY: getpid takes no pointers and does not touch inherited locks.
        if unsafe { libc::getpid() } == self.owner.process {
            let _ = descriptor_integer(&self.file, libc::F_SETLEASE, libc::F_UNLCK);
        }
    }
}

fn notification_worker(
    state: Arc<NotificationState>,
    sender: mpsc::SyncSender<Result<libc::pid_t, io::Error>>,
) {
    struct Lifetime(Arc<NotificationState>);
    impl Drop for Lifetime {
        fn drop(&mut self) {
            self.0.alive.store(false, Ordering::Release);
        }
    }
    let _lifetime = Lifetime(Arc::clone(&state));
    let installed = block_worker_sigio();
    match installed {
        Ok(thread) => {
            state.alive.store(true, Ordering::Release);
            if sender.send(Ok(thread)).is_err() {
                return;
            }
        }
        Err(error) => {
            let _ = sender.send(Err(error));
            return;
        }
    }
    while !state.stop.load(Ordering::Acquire) {
        thread::park();
    }
}

fn block_worker_sigio() -> io::Result<libc::pid_t> {
    let mut set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: sigemptyset initializes this exact sigset_t; sigaddset accesses
    // it only after successful initialization. The mask call runs solely in
    // the fresh owned worker, never in a caller or a process-wide handler.
    unsafe {
        if libc::sigemptyset(set.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut set = set.assume_init();
        if libc::sigaddset(&mut set, libc::SIGIO) != 0 {
            return Err(io::Error::last_os_error());
        }
        let result = libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        let thread = libc::syscall(libc::SYS_gettid);
        if thread <= 0 {
            return Err(io::Error::other("invalid read-lease worker TID"));
        }
        libc::pid_t::try_from(thread).map_err(|_| io::Error::other("invalid read-lease worker TID"))
    }
}

// Linux asm-generic f_owner_ex uses two native C integers on both AOS hosts.
// These values are syscall ABI, not a process protocol or source authority.
const SET_OWNER_EX: libc::c_int = 15;
const GET_OWNER_EX: libc::c_int = 16;
const OWNER_THREAD: libc::c_int = 0;

#[repr(C)]
struct KernelOwner {
    kind: libc::c_int,
    id: libc::pid_t,
}

fn set_notification_owner(file: &File, thread: libc::pid_t) -> io::Result<()> {
    let owner = KernelOwner {
        kind: OWNER_THREAD,
        id: thread,
    };
    // SAFETY: file keeps this descriptor alive; Linux copies exactly the two
    // native integer fields from this initialized stack object before returning.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), SET_OWNER_EX, &owner) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn notification_owner(file: &File) -> io::Result<KernelOwner> {
    let mut owner = KernelOwner { kind: -1, id: 0 };
    // SAFETY: the exact native f_owner_ex layout is writable for this syscall;
    // its initialized object and the borrowed descriptor stay live throughout.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), GET_OWNER_EX, &mut owner) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(owner)
}

fn descriptor_integer(
    file: &File,
    operation: libc::c_int,
    argument: libc::c_int,
) -> io::Result<libc::c_int> {
    // SAFETY: only integer-argument fcntl commands are passed by this module;
    // the borrowed original descriptor cannot be closed during the syscall.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), operation, argument) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

enum OriginalValidation {
    ReadLease(LinuxReadLease),
    CompleteBytesRequired,
}

/// Owns one freshly opened descriptor and its terminal acquisition attempt.
///
/// Construction opens a private read-only descriptor and attempts a kernel lease
/// once. Initial unsupported/conflicting acquisition permanently selects complete
/// byte reads. An acquired lease is retained through every later break; it never
/// transitions to fallback or makes another acquisition attempt.
pub struct LinuxReadLeaseFile {
    file: Arc<File>,
    validation: OriginalValidation,
}

impl LinuxReadLeaseFile {
    /// Opens an original file and completes its single lease attempt.
    ///
    /// The caller must measure all retained descriptor bytes after construction,
    /// check the acquired lease afterward, and retain namespace/process fences.
    /// No arbitrary borrowed descriptor can be adopted by this constructor.
    ///
    /// # Errors
    /// Returns file-open failures and any loss after successful acquisition.
    /// Initial unavailable support selects complete-byte-required validation.
    pub fn open(
        path: &std::path::Path,
        owner: Option<Arc<LinuxReadLeaseOwner>>,
    ) -> Result<Self, LinuxReadLeaseError> {
        let file = Arc::new(File::open(path)?);
        let validation = if let Some(owner) = owner {
            match LinuxReadLease::acquire(Arc::clone(&file), owner) {
                Ok(lease) => OriginalValidation::ReadLease(lease),
                Err(error @ LinuxReadLeaseError::AcquiredLeaseRevoked(_)) => return Err(error),
                Err(_) => OriginalValidation::CompleteBytesRequired,
            }
        } else {
            OriginalValidation::CompleteBytesRequired
        };
        Ok(Self { file, validation })
    }

    /// Borrows the same original descriptor for complete reads and file facts.
    ///
    /// Callers keep descriptor control private. They must not change its lease,
    /// notification owner or flags, or transfer cloned descriptor authority.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Borrows the original acquired token, or requires complete-byte validation.
    ///
    /// Presence alone is not authority. Callers verify the actual token before
    /// and after each use. Absence is terminal initial fallback, not permission
    /// to retry acquisition. A broken token remains present and revoked.
    pub fn lease(&self) -> Option<&LinuxReadLease> {
        match &self.validation {
            OriginalValidation::ReadLease(lease) => Some(lease),
            OriginalValidation::CompleteBytesRequired => None,
        }
    }
}

#[cfg(test)]
#[path = "linux_read_lease/tests.rs"]
mod tests;
