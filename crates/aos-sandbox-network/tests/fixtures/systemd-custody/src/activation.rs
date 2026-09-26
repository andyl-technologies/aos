//! Exact raw systemd activation ownership for the fixture process.

use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};

use anyhow::{Context as _, Result, bail};
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_network::MAXIMUM_RETAINED_NETWORK_NAMESPACES;

const FIRST_ACTIVATION_FD: RawFd = 3;

/// Owns the listener and retained tail before any unrelated descriptor opens.
pub(crate) struct RawActivation {
    pub(crate) listener: RecordSubjectListener,
    pub(crate) names: String,
    pub(crate) retained: Vec<OwnedFd>,
}

/// Takes the complete systemd activation table for the fixture.
pub(crate) fn take_systemd_activation() -> Result<RawActivation> {
    let listen_pid = environment_u32("LISTEN_PID")?;
    let current_pid = u32::try_from(rustix::process::getpid().as_raw_nonzero().get())
        .context("fixture PID does not fit u32")?;
    if listen_pid != current_pid {
        bail!("LISTEN_PID does not name the fixture process");
    }

    let listen_fds = environment_usize("LISTEN_FDS")?;
    if listen_fds == 0 || listen_fds > MAXIMUM_RETAINED_NETWORK_NAMESPACES + 1 {
        bail!("LISTEN_FDS is outside the fixture's hard bound");
    }
    let names =
        std::env::var("LISTEN_FDNAMES").context("LISTEN_FDNAMES is absent or non-Unicode")?;

    let mut descriptors = Vec::with_capacity(listen_fds);
    for offset in 0..listen_fds {
        let offset = RawFd::try_from(offset).context("activation FD offset does not fit i32")?;
        let raw = FIRST_ACTIVATION_FD
            .checked_add(offset)
            .context("activation FD number overflow")?;

        // SAFETY: systemd's validated LISTEN_PID/LISTEN_FDS contract transfers
        // unique ownership of every contiguous descriptor starting at fd 3.
        descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
    }

    let listener_fd = descriptors.remove(0);
    let listener = RecordSubjectListener::from_owned(listener_fd)
        .context("activation fd 3 is not the record-subject listener")?;
    Ok(RawActivation {
        listener,
        names,
        retained: descriptors,
    })
}

fn environment_u32(name: &'static str) -> Result<u32> {
    std::env::var(name)
        .with_context(|| format!("{name} is absent or non-Unicode"))?
        .parse()
        .with_context(|| format!("{name} is not a decimal u32"))
}

fn environment_usize(name: &'static str) -> Result<usize> {
    std::env::var(name)
        .with_context(|| format!("{name} is absent or non-Unicode"))?
        .parse()
        .with_context(|| format!("{name} is not a decimal usize"))
}
