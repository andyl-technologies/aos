//! Reports completed native role startup to the service manager.
//!
//! The configured role callbacks call this after actual native startup: serving
//! waits for cache owners, snapshots and maintenance listeners; publication
//! waits for recovery, seal probes and its listener. An absent manager endpoint
//! preserves standalone operation; a configured endpoint must accept the whole
//! notification before startup succeeds.

use std::{
    ffi::OsStr,
    io,
    os::{
        linux::net::SocketAddrExt,
        unix::{ffi::OsStrExt, net::SocketAddr, net::UnixDatagram},
    },
    path::Path,
};

const READY: &[u8] = b"READY=1\nSTATUS=Serving configured Terrane snapshots and host cache";

/// Reports readiness without allowing a full manager queue to block startup.
///
/// # Errors
/// Rejects an invalid configured endpoint, socket creation or send failures,
/// including a full manager queue and an incomplete notification datagram.
pub(crate) fn notify() -> io::Result<()> {
    notify_message(READY)
}

/// Reports the recovered, seal-probed and bound native publisher to its manager.
///
/// # Errors
/// Returns invalid endpoints and native notification creation or send failures.
pub(crate) fn notify_publisher() -> io::Result<()> {
    notify_message(b"READY=1\nSTATUS=Serving configured Terrane native publisher")
}

fn notify_message(message: &[u8]) -> io::Result<()> {
    let Some(endpoint) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let address = address(&endpoint)?;
    let socket = UnixDatagram::unbound()?;
    socket.set_nonblocking(true)?;
    let written = socket.send_to_addr(message, &address)?;
    if written != message.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete service readiness notification",
        ));
    }
    Ok(())
}

/// Parses either a filesystem endpoint or Linux's manager-selected abstract name.
fn address(endpoint: &OsStr) -> io::Result<SocketAddr> {
    let bytes = endpoint.as_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        if !name.is_empty() {
            return SocketAddr::from_abstract_name(name);
        }
    } else if Path::new(endpoint).is_absolute() {
        return SocketAddr::from_pathname(endpoint);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "service notification endpoint must be absolute or a nonempty abstract name",
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn preserves_filesystem_and_abstract_manager_addresses() {
        let filesystem = address(OsStr::new("/run/systemd/notify")).unwrap();
        assert_eq!(
            filesystem.as_pathname(),
            Some(Path::new("/run/systemd/notify"))
        );

        let abstract_name = address(OsStr::from_bytes(b"@terrane-\xff")).unwrap();
        assert_eq!(
            abstract_name.as_abstract_name(),
            Some(b"terrane-\xff".as_slice())
        );
    }

    #[test]
    fn refuses_empty_relative_and_unrepresentable_manager_addresses() {
        for endpoint in [
            b"".as_slice(),
            b"@",
            b"notify",
            b"run/systemd/notify",
            b"/run/\0notify",
        ] {
            assert_eq!(
                address(OsStr::from_bytes(endpoint)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(address(OsStr::new(&format!("/{}", "n".repeat(108)))).is_err());
        assert!(address(OsStr::new(&format!("@{}", "n".repeat(108)))).is_err());
    }
}
