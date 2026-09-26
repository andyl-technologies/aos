//! Exact systemd socket-activation descriptor adoption.

use aos_sandbox_linux::inherited_fd::claim_systemd_activation_descriptor_range;

use crate::transport::ActivatedSeqpacketListener;
use crate::{HostError, Result};

const CONTROLLER_FD_NAME: &str = "aos-sandbox-host";
const ROOT_MOUNT_FD_NAME: &str = "aos-sandbox-host-root-mount";

/// Adopts the two role-separated listeners described by systemd activation.
///
/// `LISTEN_PID` must name this exact process, `LISTEN_FDS` must be two, and
/// `LISTEN_FDNAMES` must name each fixed role exactly once. Both descriptors
/// are validated as listening `SOCK_SEQPACKET` sockets by
/// [`ActivatedSeqpacketListener`].
///
/// This function must run before the process creates any threads or closes
/// FDs 3 and 4. It does not mutate the environment, so later child construction
/// must use an explicit sanitized environment.
///
/// # Safety
///
/// The caller must be the single-threaded startup owner of descriptors 3 and
/// 4. No Rust I/O owner may already represent either entry, and no thread,
/// signal handler, or concurrent code may replace them until this returns.
/// Activation environment validation cannot establish these ownership facts.
///
/// # Errors
///
/// Returns an error for a missing/malformed/mismatched activation environment
/// or an invalid inherited descriptor.
pub unsafe fn take_systemd_listeners()
-> Result<(ActivatedSeqpacketListener, ActivatedSeqpacketListener)> {
    let listen_pid = environment_u32("LISTEN_PID")?;
    let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
        .map_err(|_| HostError::State("current PID does not fit u32".to_owned()))?;
    if listen_pid != current_pid {
        return Err(HostError::State(
            "LISTEN_PID does not name this host broker".to_owned(),
        ));
    }
    if environment_u32("LISTEN_FDS")? != 2 {
        return Err(HostError::State(
            "host broker requires exactly two activated descriptors".to_owned(),
        ));
    }
    let names = std::env::var("LISTEN_FDNAMES")
        .map_err(|_| HostError::State("activated descriptor names are absent".to_owned()))?;
    let controller_first = controller_listener_first(&names)?;

    // SAFETY: the validated systemd contract transfers exactly two activation
    // entries to this single-threaded startup path before any Rust FD owner is
    // constructed and before any code can mutate the descriptor table.
    let mut descriptors = unsafe { claim_systemd_activation_descriptor_range(0, 2) }
        .map_err(|error| HostError::State(error.to_string()))?
        .into_descriptors()
        .into_iter();
    let first = descriptors
        .next()
        .ok_or_else(|| HostError::State("first activated listener is absent".to_owned()))?;
    let second = descriptors
        .next()
        .ok_or_else(|| HostError::State("second activated listener is absent".to_owned()))?;
    let first = ActivatedSeqpacketListener::from_owned(first)?;
    let second = ActivatedSeqpacketListener::from_owned(second)?;

    if controller_first {
        Ok((first, second))
    } else {
        Ok((second, first))
    }
}

fn controller_listener_first(names: &str) -> Result<bool> {
    let mut roles = names.split(':');
    match (roles.next(), roles.next(), roles.next()) {
        (Some(CONTROLLER_FD_NAME), Some(ROOT_MOUNT_FD_NAME), None) => Ok(true),
        (Some(ROOT_MOUNT_FD_NAME), Some(CONTROLLER_FD_NAME), None) => Ok(false),
        _ => Err(HostError::State(
            "activated descriptor names do not match the two Host roles".to_owned(),
        )),
    }
}

fn environment_u32(name: &'static str) -> Result<u32> {
    std::env::var(name)
        .map_err(|_| HostError::State(format!("{name} is absent")))?
        .parse()
        .map_err(|_| HostError::State(format!("{name} is not a decimal u32")))
}

#[cfg(test)]
mod tests {
    use super::controller_listener_first;

    #[test]
    fn activation_names_bind_both_listener_roles_in_either_order() {
        assert!(controller_listener_first("aos-sandbox-host:aos-sandbox-host-root-mount").unwrap());
        assert!(
            !controller_listener_first("aos-sandbox-host-root-mount:aos-sandbox-host").unwrap()
        );
        for names in [
            "aos-sandbox-host",
            "aos-sandbox-host:aos-sandbox-host",
            "aos-sandbox-host-root-mount:aos-sandbox-host-root-mount",
            "aos-sandbox-host:aos-sandbox-host-root-mount:extra",
        ] {
            assert!(controller_listener_first(names).is_err(), "{names}");
        }
    }
}
