//! Test-only raw notifications for forcing the real manager capacity edge.

use std::ffi::OsStr;
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use aos_sandbox_network::NetworkNamespaceStoreName;
use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{
    AddressFamily, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix,
    SocketFlags, SocketType, recv, sendmsg_addr, socket_with, socketpair,
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Sends two stores before one barrier so a one-entry manager must reject one.
pub(crate) fn force_capacity_rejection(
    first_name: &NetworkNamespaceStoreName,
    first: BorrowedFd<'_>,
    second_name: &NetworkNamespaceStoreName,
    second: BorrowedFd<'_>,
) -> Result<()> {
    let notifier = ProbeNotifier::from_environment()?;
    notifier.store(first_name, first)?;
    notifier.store(second_name, second)?;
    notifier.barrier()
}

struct ProbeNotifier {
    socket: OwnedFd,
    address: SocketAddrUnix,
}

impl ProbeNotifier {
    fn from_environment() -> Result<Self> {
        let value = std::env::var_os("NOTIFY_SOCKET").context("NOTIFY_SOCKET is absent")?;
        Self::new(&value)
    }

    fn new(value: &OsStr) -> Result<Self> {
        let value = value.to_str().context("NOTIFY_SOCKET is not Unicode")?;
        if value.is_empty() {
            bail!("NOTIFY_SOCKET is empty");
        }
        let address = if let Some(name) = value.strip_prefix('@') {
            if name.is_empty() {
                bail!("NOTIFY_SOCKET abstract name is empty");
            }
            SocketAddrUnix::new_abstract_name(name.as_bytes())
        } else {
            SocketAddrUnix::new(Path::new(value))
        }
        .context("encode NOTIFY_SOCKET")?;
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .context("create capacity-probe notification socket")?;
        set_socket_timeout(&socket, Timeout::Send, Some(PROBE_TIMEOUT))
            .context("bound capacity-probe notification send")?;
        Ok(Self { socket, address })
    }

    fn store(&self, name: &NetworkNamespaceStoreName, descriptor: BorrowedFd<'_>) -> Result<()> {
        let payload = format!("FDSTORE=1\nFDPOLL=0\nFDNAME={}", name.as_str());
        self.notify(payload.as_bytes(), descriptor)
    }

    fn barrier(&self) -> Result<()> {
        let (waiter, manager_end) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .context("create capacity-probe barrier socketpair")?;
        set_socket_timeout(&waiter, Timeout::Recv, Some(PROBE_TIMEOUT))
            .context("bound capacity-probe barrier wait")?;
        self.notify(b"BARRIER=1", manager_end.as_fd())?;
        drop(manager_end);

        let mut byte = [0_u8; 1];
        let (received, _) = recv(&waiter, &mut byte, RecvFlags::empty())
            .context("wait for capacity-probe barrier")?;
        if received != 0 {
            bail!("capacity-probe barrier descriptor carried data");
        }
        Ok(())
    }

    fn notify(&self, payload: &[u8], descriptor: BorrowedFd<'_>) -> Result<()> {
        let iov = [IoSlice::new(payload)];
        let borrowed = [descriptor];
        let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        if !control.push(SendAncillaryMessage::ScmRights(&borrowed)) {
            bail!("capacity-probe ancillary buffer is exhausted");
        }
        let written = sendmsg_addr(
            &self.socket,
            &self.address,
            &iov,
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .context("send capacity-probe notification")?;
        if written != payload.len() {
            bail!("capacity-probe notification was partially written");
        }
        Ok(())
    }
}
