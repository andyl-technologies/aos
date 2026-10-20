//! Owns native kernel confinement of stable host quota charge assignments.
//!
//! The configured allocation roles call [`install`] in their single-threaded
//! bootstrap, before runtimes or mutable cache handles exist. The fixed policy
//! preserves GET and verity operations while refusing project setters, alternate
//! ABIs, rings and operations that could undo non-dumpability. Installation is
//! irreversible; any failure requires process termination, not fallback.
//! [`install_publisher`] additionally fixes Unix-only socket creation and audits
//! inherited descriptors before configured publisher resources are opened.
//!
//! This boundary does not isolate Unix identities. The trusted host must reserve
//! each role identity, exclude unconfined peers and inherited writable cache
//! handles, and authenticate descriptor channels. Received descriptors must be
//! checked as ordinary files by their owning protocol; arbitrary descriptor
//! import is outside this contract. Provisioning helpers and local CLI commands
//! do not call this API. Confined roles do not execute other programs.

mod policy;
mod publisher;

pub use publisher::{PublisherInstalled, install_publisher};

use std::{fs, io, os::fd::AsRawFd};

/// Retains evidence of successful fixed kernel installation in this process.
///
/// Fields are private and no boolean or operator-supplied program can construct
/// this receipt. The irreversible filter covers all synchronized threads and
/// future children. Forked children inherit the policy but cannot use this
/// process-specific factory receipt. External identity isolation remains a
/// separate host obligation.
#[derive(Debug)]
pub struct Installed {
    process: u32,
}

impl Installed {
    /// Checks that this receipt still belongs to the non-dumpable process.
    ///
    /// # Errors
    /// Rejects another process or unavailable/changed kernel confinement state.
    pub fn check_current(&self) -> io::Result<()> {
        if self.process != std::process::id()
            || get_prctl(libc::PR_GET_DUMPABLE)? != 0
            || get_prctl(libc::PR_GET_NO_NEW_PRIVS)? != 1
            || get_prctl(libc::PR_GET_SECCOMP)? != 2
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "quota confinement process changed",
            ));
        }
        Ok(())
    }
}

/// Installs the fixed quota-writer boundary in a fresh native role process.
///
/// Requires exactly one kernel thread, no inherited io_uring descriptors and
/// no effective, permitted or ambient capabilities. The caller must ensure no
/// concurrent thread or descriptor creation during bootstrap. All existing
/// threads are nevertheless synchronized by the actual seccomp TSYNC call.
/// The supported source-audited ABIs are Linux x86-64 and little-endian AArch64;
/// compat/x32 execution is refused by the installed program.
///
/// # Errors
/// Rejects unsupported targets, inaccessible procfs, concurrent bootstrap,
/// inherited rings, capabilities or kernel installation failures. A positive
/// TSYNC failure is an error. Failure may leave irreversible partial hardening;
/// the process must exit without opening mutable cache resources.
pub fn install() -> io::Result<Installed> {
    policy::supported()?;
    audit_startup()?;
    set_prctl(libc::PR_SET_NO_NEW_PRIVS, 1)?;
    set_prctl(libc::PR_SET_DUMPABLE, 0)?;
    policy::install()?;
    let receipt = Installed {
        process: std::process::id(),
    };
    receipt.check_current()?;
    Ok(receipt)
}

fn audit_startup() -> io::Result<()> {
    // The host supplies a stable proc mount. Check its actual filesystem and
    // selected process before using task and descriptor observations; privileged
    // mount replacement remains outside the ordinary-role threat boundary.
    let process = fs::File::open("/proc/self")?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: process is retained and filesystem points to writable ABI storage.
    if unsafe { libc::fstatfs(process.as_raw_fd(), filesystem.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized the structure.
    if unsafe { filesystem.assume_init() }.f_type != 0x9fa0 {
        return Err(io::Error::other("quota bootstrap requires actual procfs"));
    }
    let stat = fs::read_to_string("/proc/self/stat")?;
    if stat
        .split_once(' ')
        .map(|(pid, _)| pid.parse::<u32>())
        .transpose()
        .map_err(io::Error::other)?
        != Some(std::process::id())
    {
        return Err(io::Error::other("procfs does not name the current process"));
    }
    let tasks = fs::read_dir("/proc/self/task")?.collect::<io::Result<Vec<_>>>()?;
    if tasks.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "quota confinement requires single-thread bootstrap",
        ));
    }
    audit_capabilities()?;
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let target = fs::read_link(entry.path())?;
        if target
            .as_os_str()
            .as_encoded_bytes()
            .windows(8)
            .any(|part| part == b"io_uring")
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "inherited io_uring descriptor",
            ));
        }
    }
    Ok(())
}

fn audit_capabilities() -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // Linux capability version 3 carries two 32-bit words per capability set.
    let mut header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    // SAFETY: capget writes the version-3 header and two initialized ABI words
    // for the actual current thread (pid zero), never a procfs assertion.
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if data
        .iter()
        .any(|entry| entry.effective != 0 || entry.permitted != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "quota writer has capabilities",
        ));
    }
    for capability in 0..64 {
        // SAFETY: PR_CAP_AMBIENT_IS_SET (1) takes a scalar capability number;
        // all unused variadic arguments are explicitly initialized.
        let result = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                1 as libc::c_ulong,
                capability as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if result == -1 {
            let error = io::Error::last_os_error();
            if capability != 0 && error.raw_os_error() == Some(libc::EINVAL) {
                return Ok(());
            }
            return Err(error);
        }
        if result != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "quota writer has ambient capabilities",
            ));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "unreviewed capability range",
    ))
}

fn get_prctl(option: libc::c_int) -> io::Result<libc::c_int> {
    // SAFETY: these GET operations have no pointer arguments; trailing arguments
    // are explicitly initialized for the variadic ABI.
    let result = unsafe {
        libc::prctl(
            option,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn set_prctl(option: libc::c_int, value: libc::c_ulong) -> io::Result<()> {
    // SAFETY: these SET operations take one scalar and no pointers.
    let result = unsafe {
        libc::prctl(
            option,
            value,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
