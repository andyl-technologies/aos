//! Canonical systemd socket-activation instance fields.
//!
//! Network worker unit instances encode systemd's accepted-connection ordinal,
//! the accepted socket's `SO_COOKIE`, and the connecting subject's PID, pidfd
//! inode, and UID. Those embedded subject fields describe the process that
//! connected to the accepting socket, not the spawned worker. This module
//! validates only canonical syntax and numeric bounds; no field is process
//! identity evidence.
//!
//! ```text
//! accept-ordinal-socket-cookie-connecting-pid_pidfd-inode-connecting-uid
//! ```

/// Reports a malformed systemd socket-activation instance identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidSystemdSocketInstance;

/// Validates all five canonical decimal fields in a socket unit instance.
///
/// # Errors
///
/// Returns [`InvalidSystemdSocketInstance`] for missing or extra fields,
/// nondecimal or noncanonical numbers, a zero connecting PID or pidfd inode,
/// or a connecting PID or UID outside the `u32` range.
pub(crate) fn validate_systemd_socket_instance_fields(
    instance: &str,
) -> Result<(), InvalidSystemdSocketInstance> {
    let mut fields = instance.split('-');
    parse_canonical_decimal(fields.next())?;
    parse_canonical_decimal(fields.next())?;
    let subject = fields.next().ok_or(InvalidSystemdSocketInstance)?;
    let uid = parse_canonical_decimal(fields.next())?;
    if fields.next().is_some() {
        return Err(InvalidSystemdSocketInstance);
    }

    let (pid, pidfd_inode) = subject
        .split_once('_')
        .ok_or(InvalidSystemdSocketInstance)?;
    let pid = u32::try_from(parse_canonical_decimal(Some(pid))?)
        .map_err(|_| InvalidSystemdSocketInstance)?;
    u32::try_from(uid).map_err(|_| InvalidSystemdSocketInstance)?;
    if pid == 0 || parse_canonical_decimal(Some(pidfd_inode))? == 0 {
        return Err(InvalidSystemdSocketInstance);
    }

    Ok(())
}

fn parse_canonical_decimal(value: Option<&str>) -> Result<u64, InvalidSystemdSocketInstance> {
    let value = value.ok_or(InvalidSystemdSocketInstance)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(InvalidSystemdSocketInstance);
    }
    value.parse().map_err(|_| InvalidSystemdSocketInstance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_instance_is_accepted() {
        assert!(validate_systemd_socket_instance_fields("0-984321-543_876-0").is_ok());
    }

    #[test]
    fn malformed_or_noncanonical_instance_is_rejected() {
        for instance in [
            "",
            "0-1-2_3",
            "0-1-2_3-4-extra",
            "00-1-2_3-4",
            "0-01-2_3-4",
            "0-1-0_3-4",
            "0-1-2_0-4",
            "0-1-2_3-4294967296",
            "0-1-4294967296_3-4",
            "0-1-2_3-+4",
        ] {
            assert!(validate_systemd_socket_instance_fields(instance).is_err());
        }
    }
}
