//! Removes usable capabilities after the genuine child credential transition.
//!
//! This pre-exec cut uses allocation-free syscall wrappers and fixed stack
//! storage. Main's containment privileges never enter QEMU or an image helper.
//! Bounding-set bits do not supply usable privilege: all three capability sets
//! and every supported ambient bit must read back empty before exec.

use std::io;

use rustix::thread::{CapabilitySet, CapabilitySets};

use super::QemuChildCredentials;

/// Clears usable privilege and verifies the exact already-installed child IDs.
///
/// # Errors
/// Refuses failed capability or NNP syscalls, nonempty usable readback, different
/// real/effective/saved IDs, or surviving supplementary groups.
pub(super) fn clear_and_verify(credentials: QemuChildCredentials) -> io::Result<()> {
    clear_usable_capabilities()?;
    verify_credentials(credentials)
}

fn clear_usable_capabilities() -> io::Result<()> {
    let empty = CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: CapabilitySet::empty(),
        inheritable: CapabilitySet::empty(),
    };
    rustix::thread::clear_ambient_capability_set()?;
    rustix::thread::set_capabilities(None, empty)?;
    rustix::thread::set_no_new_privs(true)?;
    verify_usable_capabilities()
}

fn verify_usable_capabilities() -> io::Result<()> {
    let actual = rustix::thread::capabilities(None)?;
    if !actual.effective.is_empty()
        || !actual.permitted.is_empty()
        || !actual.inheritable.is_empty()
        || !rustix::thread::no_new_privs()?
    {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }

    // Linux capability numbers are contiguous. EINVAL at the first unsupported
    // number terminates the actual kernel range; other query failures refuse.
    // The capability ABI represents at most 64 bits, including future additions.
    for number in 0..64 {
        let capability = CapabilitySet::from_bits_retain(1_u64 << number);
        match rustix::thread::capability_is_in_ambient_set(capability) {
            Ok(false) => {}
            Ok(true) => return Err(io::Error::from_raw_os_error(libc::EPERM)),
            Err(rustix::io::Errno::INVAL) if number != 0 => return Ok(()),
            Err(source) => return Err(source.into()),
        }
    }
    Ok(())
}

fn verify_credentials(credentials: QemuChildCredentials) -> io::Result<()> {
    let mut users = [0 as libc::uid_t; 3];
    let users_read = unsafe {
        // SAFETY: the three distinct initialized uid_t slots remain writable
        // for this allocation-free, async-signal-safe credential syscall.
        libc::syscall(
            libc::SYS_getresuid,
            &mut users[0] as *mut libc::uid_t,
            &mut users[1] as *mut libc::uid_t,
            &mut users[2] as *mut libc::uid_t,
        )
    };
    if users_read != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut groups = [0 as libc::gid_t; 3];
    let groups_read = unsafe {
        // SAFETY: the three distinct initialized gid_t slots remain writable
        // for this allocation-free, async-signal-safe credential syscall.
        libc::syscall(
            libc::SYS_getresgid,
            &mut groups[0] as *mut libc::gid_t,
            &mut groups[1] as *mut libc::gid_t,
            &mut groups[2] as *mut libc::gid_t,
        )
    };
    if groups_read != 0 {
        return Err(io::Error::last_os_error());
    }
    let supplementary = unsafe {
        // SAFETY: a zero count queries group cardinality without dereferencing
        // the null pointer or allocating a post-fork group buffer.
        libc::syscall(
            libc::SYS_getgroups,
            0_usize,
            std::ptr::null_mut::<libc::gid_t>(),
        )
    };
    if supplementary < 0 {
        return Err(io::Error::last_os_error());
    }
    if users != [credentials.user_id; 3]
        || groups != [credentials.group_id; 3]
        || supplementary != 0
    {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELPER: &str = "spawn::child_privilege::tests::child_privilege_kernel_helper";
    const MODE: &str = "CRUCIBLE_CHILD_PRIVILEGE_KERNEL_HELPER";

    #[test]
    fn child_privilege_kernel_helper() {
        let Ok(mode) = std::env::var(MODE) else {
            return;
        };
        match mode.as_str() {
            "clear" => {
                clear_usable_capabilities().unwrap();
                let status = std::fs::read_to_string("/proc/self/status").unwrap();
                for field in ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"] {
                    let value = status
                        .lines()
                        .find_map(|line| line.strip_prefix(field))
                        .unwrap();
                    assert_eq!(u64::from_str_radix(value.trim(), 16).unwrap(), 0, "{field}");
                }
                assert!(rustix::thread::no_new_privs().unwrap());
                verify_usable_capabilities().unwrap();
            }
            "wrong-credentials" => {
                let wrong = QemuChildCredentials {
                    user_id: rustix::process::geteuid().as_raw().checked_add(1).unwrap(),
                    group_id: rustix::process::getegid().as_raw(),
                };
                assert_eq!(
                    verify_credentials(wrong).unwrap_err().raw_os_error(),
                    Some(libc::EPERM)
                );
            }
            _ => panic!("unknown child privilege helper mode"),
        }
    }

    fn run_helper(mode: &str) {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", HELPER, "--nocapture"])
            .env(MODE, mode)
            .status()
            .unwrap();
        assert!(status.success(), "child privilege helper {mode} failed");
    }

    #[test]
    fn real_child_capability_clear_reads_back_all_usable_sets_empty() {
        run_helper("clear");
    }

    #[test]
    fn real_credential_readback_rejects_another_uid() {
        run_helper("wrong-credentials");
    }
}
