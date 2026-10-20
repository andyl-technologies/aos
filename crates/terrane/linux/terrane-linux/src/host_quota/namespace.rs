//! Establishes the native host namespace boundary before minting quota evidence.

use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

/// Establishes the authenticated initial host-root namespace boundary.
///
/// UID zero is relative to a user namespace: an unprivileged user can appear to
/// be root inside a private namespace and run a fabricated helper there. Native
/// evidence therefore also requires the Linux nsfs initial-user-namespace inode,
/// namespace type and initial-root ownership mapping. An initial-namespace
/// descriptor exposed through an untrusted mount tree is insufficient by itself:
/// `NS_GET_OWNER_UID` maps its authenticated owner through the caller's actual
/// current user namespace. Rootless mappings cannot represent initial host UID 0.
/// Initial host root remains a trusted administrator, including namespaces it
/// explicitly delegates with a mapping of host root.
///
/// The inode identifier is Linux 7.2.3 UAPI `USER_NS_INIT_INO`; `fs/nsfs.c`
/// implements the owner mapping and `kernel/user.c` binds the initial owner to
/// `GLOBAL_ROOT_UID`. None of these facts comes from an operator assertion.
///
/// # Errors
/// Returns an error when namespace inspection is unavailable, unsupported or
/// does not establish the native host's initial user namespace boundary.
pub fn require_host_root_namespace_boundary() -> io::Result<()> {
    let namespace = File::open("/proc/self/ns/user")?;
    let mut filesystem = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: namespace remains live and statfs points to writable ABI storage.
    if unsafe { libc::fstatfs(namespace.as_raw_fd(), filesystem.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initializes every field read below.
    let filesystem = unsafe { filesystem.assume_init() };
    if filesystem.f_type != 0x6e736673 || namespace.metadata()?.ino() != 0xeffffffd {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "native quota evidence requires the initial user namespace",
        ));
    }
    // SAFETY: NS_GET_NSTYPE has no output pointer and namespace is a live nsfs FD.
    let namespace_type = unsafe { libc::ioctl(namespace.as_raw_fd(), 0xb703 as libc::c_ulong) };
    if namespace_type == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut owner_uid = u32::MAX;
    // SAFETY: NS_GET_OWNER_UID writes one initialized uid_t-sized integer.
    if unsafe {
        libc::ioctl(
            namespace.as_raw_fd(),
            0xb704 as libc::c_ulong,
            &mut owner_uid,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    // Checking the ownership mapping also rejects a rootless namespace that
    // exposes an ancestor's initial-ns descriptor through a private mount tree.
    if namespace_type != libc::CLONE_NEWUSER || owner_uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "namespace does not establish initial host root ownership",
        ));
    }
    Ok(())
}
