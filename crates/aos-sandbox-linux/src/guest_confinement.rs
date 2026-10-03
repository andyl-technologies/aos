//! Fixed enforcing subjects for Guest ownership and arbitrary execution tenants.
//!
//! UID zero is not a trusted subject. The existing Guest owner enters its fixed
//! domain before its first executable and explicitly selects the Tenant domain
//! only after original credentials and private descriptor closure are complete.
//! These checks observe kernel state; they do not create an admission or grant.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, BorrowedFd};

use rustix::fs::{FileType, Mode, OFlags, XattrFlags, fgetxattr, fsetxattr, fstat, fstatfs, open};

use crate::pidfd::{PidFd, SingleThreadedProcess};
use crate::{Error, Result, uapi};

/// Names the existing trusted Guest owner, independently of its current UID.
pub const GUEST_OWNER_CONTEXT: &str = "system_u:system_r:aos_sandbox_guest_owner_t:s0";
/// Names every original admitted tenant, including UID zero.
pub const GUEST_TENANT_CONTEXT: &str = "system_u:system_r:aos_sandbox_payload_t:s0";

const SELINUXFS_MAGIC: u64 = 0xf97c_ff8c;
const DEVPTS_MAGIC: u64 = 0x1cd1;
const MAXIMUM_CONTEXT_BYTES: usize = 128;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const ANCHOR_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_guest_anchor_t:s0\0";
const PTY_LABEL: &[u8] = b"system_u:object_r:aos_sandbox_guest_pty_t:s0\0";
const CGROUP_LABEL: &[u8] = b"system_u:object_r:cgroup_t:s0\0";

/// Requires the actual protected cgroup object label, including FD aliases.
///
/// The final policy independently forbids Tenant mutation of this object type.
/// This physical check does not turn an arbitrary directory into tree custody.
///
/// # Errors
///
/// Rejects a foreign object label or a failed kernel xattr observation.
pub fn require_guest_cgroup_object(descriptor: BorrowedFd<'_>) -> Result<()> {
    require_object_label(descriptor, CGROUP_LABEL)
}

/// Labels only the fixed fresh runtime mounts before any Guest child starts.
///
/// Copied labels were checked before root publication. Nspawn replaces `/run`
/// and `/dev` with fresh tmpfs mounts, so PID 1 verifies and labels their actual
/// mount-root inodes separately. The Guest bootstrap then protects the entire
/// existing manager subtree before spawning any child; owner-created children
/// inherit private object types from the loaded policy.
///
/// # Errors
///
/// Rejects a non-Owner/nonroot/non-PID-1 caller, a foreign or writable mount
/// anchor, an unexpected manager directory label, or failed physical readback.
pub fn prepare_guest_runtime_anchors() -> Result<()> {
    require_guest_owner()?;
    if std::process::id() != 1 || rustix::process::geteuid().as_raw() != 0 {
        return Err(Error::invalid(
            "Guest runtime anchors",
            "caller is not trusted root PID 1",
        ));
    }
    for path in ["/run", "/dev"] {
        let directory = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(syscall("open fresh Guest runtime anchor"))?;
        let stat = fstat(&directory).map_err(syscall("stat fresh Guest runtime anchor"))?;
        if stat.st_uid != 0
            || stat.st_mode & 0o022 != 0
            || fstatfs(&directory)
                .map_err(syscall("identify fresh Guest runtime anchor"))?
                .f_type as u64
                != TMPFS_MAGIC
        {
            return Err(Error::invalid(
                "Guest runtime anchors",
                "anchor is not protected fresh tmpfs",
            ));
        }
        fsetxattr(
            &directory,
            "security.selinux",
            ANCHOR_LABEL,
            XattrFlags::empty(),
        )
        .map_err(syscall("label fresh Guest runtime anchor"))?;
        require_object_label(directory.as_fd(), ANCHOR_LABEL)?;
    }
    Ok(())
}

fn require_object_label(descriptor: BorrowedFd<'_>, expected: &[u8]) -> Result<()> {
    let mut value = [0_u8; 128];
    let length = fgetxattr(descriptor, "security.selinux", &mut value[..])
        .map_err(syscall("read Guest object label"))?;
    if value[..length] != *expected {
        return Err(Error::invalid(
            "Guest runtime object",
            "physical label differs",
        ));
    }
    Ok(())
}

/// Requires the fixed Owner subject and the enforcing NNP transition profile.
///
/// # Errors
///
/// Rejects a foreign subject, missing inherited NNP, permissive SELinux,
/// non-selinuxfs observation, absent transition policy capability, or I/O error.
pub fn require_guest_owner() -> Result<()> {
    require_subject(GUEST_OWNER_CONTEXT)?;
    if !rustix::thread::no_new_privs().map_err(syscall("read inherited NNP"))? {
        return Err(Error::invalid("Guest owner", "inherited NNP is absent"));
    }
    require_kernel_boolean("/sys/fs/selinux/enforce")?;
    require_kernel_boolean("/sys/fs/selinux/policy_capabilities/nnp_nosuid_transition")
}

/// Verifies the exact current SELinux subject of the calling thread.
///
/// # Errors
///
/// Rejects oversized, empty or foreign contexts and failed procfs observation.
pub fn require_subject(expected: &str) -> Result<()> {
    let actual = read_context("/proc/thread-self/attr/current")?;
    if !context_matches(&actual, expected) {
        return Err(Error::invalid("Guest subject", "current context differs"));
    }
    Ok(())
}

/// Observes a task context between equal live pidfd identity samples.
///
/// This is not holder authentication or a replacement for continuously held
/// process/cgroup custody. Callers retain that custody and their owner barrier.
///
/// # Errors
///
/// Rejects process exit, changed identity, oversized context, or procfs error.
pub fn task_has_subject(process: &PidFd, expected: &str) -> Result<bool> {
    let before = process.process_identity()?;
    let context = read_context(&format!("/proc/{}/attr/current", before.pid()))?;
    if process.process_identity()? != before || !process.is_alive()? {
        return Err(Error::invalid(
            "Guest task subject",
            "retained task changed",
        ));
    }
    Ok(context_matches(&context, expected))
}

/// Selects the explicit Tenant exec SID under the inherited NNP profile.
///
/// The caller first installs the original credentials, then closes every
/// nonstdio descriptor after this check and before exec. Linux 7.2.3 rejects a
/// disallowed explicit exec SID; unlike a
/// default transition it cannot silently execute with the old Owner SID.
/// Actual exec success and the resulting task SID remain a parent observation.
///
/// # Errors
///
/// Rejects a foreign Owner, absent enforcement/NNP capability, a denied or
/// substituted pending exec context, or a kernel/procfs failure.
pub fn select_guest_tenant_exec(_worker: &SingleThreadedProcess) -> Result<()> {
    require_guest_owner()?;
    let descriptor = open(
        "/proc/thread-self/attr/exec",
        OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(syscall("open Tenant exec context"))?;
    File::from(descriptor)
        .write_all(GUEST_TENANT_CONTEXT.as_bytes())
        .map_err(|source| Error::Syscall {
            operation: "select Tenant exec context",
            source,
        })?;
    let selected = read_context("/proc/thread-self/attr/exec")?;
    if !context_matches(&selected, GUEST_TENANT_CONTEXT) {
        return Err(Error::invalid(
            "Guest exec subject",
            "pending context differs",
        ));
    }
    Ok(())
}

/// Checks that all original standard descriptors have only admitted I/O types.
///
/// Pipes are regular execution streams; a PTY requires all three descriptors
/// to name the same exact devpts character inode. Neither regular files nor
/// sockets are permitted to masquerade as inherited standard I/O.
///
/// # Errors
///
/// Rejects closed descriptors, foreign object types, mixed PTYs, or kernel errors.
pub fn require_guest_stdio(pty: bool) -> Result<()> {
    let descriptors = [
        rustix::stdio::stdin(),
        rustix::stdio::stdout(),
        rustix::stdio::stderr(),
    ];
    let mut terminal = None;
    for descriptor in descriptors {
        let stat = fstat(descriptor).map_err(syscall("stat admitted stdio"))?;
        let kind = FileType::from_raw_mode(stat.st_mode);
        if !pty {
            if kind != FileType::Fifo {
                return Err(Error::invalid("Guest stdio", "stream is not a pipe"));
            }
            continue;
        }
        if kind != FileType::CharacterDevice
            || fstatfs(descriptor)
                .map_err(syscall("identify admitted PTY"))?
                .f_type as u64
                != DEVPTS_MAGIC
        {
            return Err(Error::invalid("Guest stdio", "terminal is not devpts"));
        }
        require_object_label(descriptor, PTY_LABEL)?;
        let identity = (stat.st_dev, stat.st_ino);
        if terminal
            .replace(identity)
            .is_some_and(|previous| previous != identity)
        {
            return Err(Error::invalid("Guest stdio", "terminal inodes differ"));
        }
    }
    Ok(())
}

/// Closes every descriptor above stderr in a single-threaded exec helper.
///
/// The helper must have dropped every Rust descriptor owner before this call;
/// it cannot use this primitive as a general process-table mutation API. This
/// closes owner-private anonymous handles too, whose inode hooks can differ
/// from regular-file checks. SELinux `fd:use` is not scoped to FD numbers.
///
/// # Safety
///
/// The caller exclusively owns the single-threaded descriptor table and has
/// dropped every Rust owner of FD >=3. No signal handler may alter that table.
/// The next operation is exec or fail-stop exit, never general caller code.
///
/// # Errors
///
/// Returns an error when the kernel cannot close the complete descriptor tail.
pub unsafe fn close_guest_private_descriptors(_worker: &SingleThreadedProcess) -> Result<()> {
    uapi::close_guest_descriptor_tail()
}

fn require_kernel_boolean(path: &str) -> Result<()> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(syscall("open Guest confinement state"))?;
    require_selinuxfs(descriptor.as_fd())?;
    let mut value = Vec::new();
    File::from(descriptor)
        .take(3)
        .read_to_end(&mut value)
        .map_err(|source| Error::Syscall {
            operation: "read Guest confinement state",
            source,
        })?;
    if value != b"1" && value != b"1\n" {
        return Err(Error::invalid(
            "Guest confinement",
            "required kernel boolean is false",
        ));
    }
    Ok(())
}

fn require_selinuxfs(descriptor: BorrowedFd<'_>) -> Result<()> {
    if fstatfs(descriptor)
        .map_err(syscall("identify Guest confinement state"))?
        .f_type as u64
        != SELINUXFS_MAGIC
    {
        return Err(Error::WrongDescriptorType {
            expected: "selinuxfs confinement state",
        });
    }
    Ok(())
}

fn read_context(path: &str) -> Result<Vec<u8>> {
    let mut context = Vec::new();
    File::open(path)
        .and_then(|file| {
            file.take((MAXIMUM_CONTEXT_BYTES + 1) as u64)
                .read_to_end(&mut context)
        })
        .map_err(|source| Error::Syscall {
            operation: "read Guest context",
            source,
        })?;
    if context.len() > MAXIMUM_CONTEXT_BYTES {
        return Err(Error::invalid(
            "Guest context",
            "context exceeds fixed bound",
        ));
    }
    Ok(context)
}

fn context_matches(actual: &[u8], expected: &str) -> bool {
    actual == expected.as_bytes()
        || actual.strip_suffix(&[0]) == Some(expected.as_bytes())
        || actual.strip_suffix(b"\n") == Some(expected.as_bytes())
}

fn syscall(operation: &'static str) -> impl FnOnce(rustix::io::Errno) -> Error {
    move |source| Error::Syscall {
        operation,
        source: source.into(),
    }
}

#[cfg(test)]
mod tests {
    //! Exact context shape checks; kernel/UID-zero adversarial tests live in the VM.
    use super::*;

    #[test]
    fn subjects_are_exact_and_never_uid_aliases() {
        assert_ne!(GUEST_OWNER_CONTEXT, GUEST_TENANT_CONTEXT);
        assert!(context_matches(
            GUEST_OWNER_CONTEXT.as_bytes(),
            GUEST_OWNER_CONTEXT
        ));
        assert!(!context_matches(
            GUEST_TENANT_CONTEXT.as_bytes(),
            GUEST_OWNER_CONTEXT
        ));
        assert!(!context_matches(b"", GUEST_OWNER_CONTEXT));
        assert!(!context_matches(
            format!("{GUEST_OWNER_CONTEXT}\n\n").as_bytes(),
            GUEST_OWNER_CONTEXT
        ));
    }
}
