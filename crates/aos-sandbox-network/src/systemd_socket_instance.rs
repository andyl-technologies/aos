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

/// Holds the five canonical fields of one systemd socket instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SystemdSocketInstanceV1 {
    accept_ordinal: u64,
    socket_cookie: u64,
    connecting_pid: u32,
    connecting_pidfd_inode: u64,
    connecting_uid: u32,
}

impl SystemdSocketInstanceV1 {
    /// Constructs one instance from independently retained activation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSystemdSocketInstance`] when the cookie, connecting
    /// process ID, or connecting pidfd inode is zero.
    pub(crate) fn new(
        accept_ordinal: u64,
        socket_cookie: u64,
        connecting_pid: u32,
        connecting_pidfd_inode: u64,
        connecting_uid: u32,
    ) -> Result<Self, InvalidSystemdSocketInstance> {
        if socket_cookie == 0 || connecting_pid == 0 || connecting_pidfd_inode == 0 {
            return Err(InvalidSystemdSocketInstance);
        }

        Ok(Self {
            accept_ordinal,
            socket_cookie,
            connecting_pid,
            connecting_pidfd_inode,
            connecting_uid,
        })
    }

    /// Parses all five canonical decimal fields.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSystemdSocketInstance`] for malformed, noncanonical,
    /// out-of-range, or zero identity fields.
    pub(crate) fn parse(instance: &str) -> Result<Self, InvalidSystemdSocketInstance> {
        let mut fields = instance.split('-');
        let accept_ordinal = parse_canonical_decimal(fields.next())?;
        let socket_cookie = parse_canonical_decimal(fields.next())?;
        let subject = fields.next().ok_or(InvalidSystemdSocketInstance)?;
        let connecting_uid = u32::try_from(parse_canonical_decimal(fields.next())?)
            .map_err(|_| InvalidSystemdSocketInstance)?;
        if fields.next().is_some() {
            return Err(InvalidSystemdSocketInstance);
        }

        let (connecting_pid, connecting_pidfd_inode) = subject
            .split_once('_')
            .ok_or(InvalidSystemdSocketInstance)?;
        let connecting_pid = u32::try_from(parse_canonical_decimal(Some(connecting_pid))?)
            .map_err(|_| InvalidSystemdSocketInstance)?;
        let connecting_pidfd_inode = parse_canonical_decimal(Some(connecting_pidfd_inode))?;

        Self::new(
            accept_ordinal,
            socket_cookie,
            connecting_pid,
            connecting_pidfd_inode,
            connecting_uid,
        )
    }

    /// Returns the canonical systemd instance text.
    #[must_use]
    pub(crate) fn canonical_text(self) -> String {
        format!(
            "{}-{}-{}_{}-{}",
            self.accept_ordinal,
            self.socket_cookie,
            self.connecting_pid,
            self.connecting_pidfd_inode,
            self.connecting_uid
        )
    }

    pub(crate) const fn accept_ordinal(self) -> u64 {
        self.accept_ordinal
    }

    pub(crate) const fn socket_cookie(self) -> u64 {
        self.socket_cookie
    }

    pub(crate) const fn connecting_pid(self) -> u32 {
        self.connecting_pid
    }

    pub(crate) const fn connecting_pidfd_inode(self) -> u64 {
        self.connecting_pidfd_inode
    }

    pub(crate) const fn connecting_uid(self) -> u32 {
        self.connecting_uid
    }
}

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
    SystemdSocketInstanceV1::parse(instance).map(|_| ())
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
        let parsed = SystemdSocketInstanceV1::parse("0-984321-543_876-0").unwrap();

        assert_eq!(parsed.accept_ordinal(), 0);
        assert_eq!(parsed.socket_cookie(), 984321);
        assert_eq!(parsed.connecting_pid(), 543);
        assert_eq!(parsed.connecting_pidfd_inode(), 876);
        assert_eq!(parsed.connecting_uid(), 0);
        assert_eq!(parsed.canonical_text(), "0-984321-543_876-0");
        assert!(validate_systemd_socket_instance_fields("0-984321-543_876-0").is_ok());
    }

    #[test]
    fn constructed_instance_has_one_canonical_representation() {
        let instance = SystemdSocketInstanceV1::new(7, 9, 11, 13, 17).unwrap();

        assert_eq!(instance.canonical_text(), "7-9-11_13-17");
        assert_eq!(
            SystemdSocketInstanceV1::parse(&instance.canonical_text()),
            Ok(instance)
        );
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
