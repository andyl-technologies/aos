//! Owns the shared notify constructor and one actual notify/barrier prefix.
//!
//! These private native destinations do not authorize a Network operation. The
//! enclosing selected Store supplies only the genuine paid F gate immediately
//! before each actual mutation syscall. Ordinary adapters use the same native
//! recipe and retain their existing consuming return boundary.

use super::*;
use aos_sandbox_broker::receiving::FixedServiceOperationClosedV4 as Closed;

#[derive(Default)]
pub(in crate::namespace_store) struct NotifierOpeningV4 {
    value: Option<std::ffi::OsString>,
    native: OpeningNativeV4,
    returned: Option<Result<(), NetworkNamespaceStoreError>>,
    taken: bool,
}

#[derive(Default)]
struct OpeningNativeV4 {
    address: Option<Result<SocketAddrUnix, rustix::io::Errno>>,
    socket: Option<OwnedFd>,
    created: Option<Result<(), rustix::io::Errno>>,
    timeout: Option<Result<(), rustix::io::Errno>>,
}

impl NotifierOpeningV4 {
    pub(in crate::namespace_store) fn prepare_once_v4(
        &mut self,
    ) -> Result<SystemdNotifier, NetworkNamespaceStoreError> {
        if self.returned.is_some() || self.taken {
            return Err(NetworkNamespaceStoreError::Poisoned);
        }
        self.value = std::env::var_os("NOTIFY_SOCKET");
        let result = match self.value.as_deref() {
            Some(value) => open_notifier_engine(value, &mut self.native),
            None => Err(NetworkNamespaceStoreError::Systemd(
                "NOTIFY_SOCKET is absent".to_owned(),
            )),
        };
        match result {
            Ok(notifier) => {
                self.returned = Some(Ok(()));
                self.taken = true;
                Ok(notifier)
            }
            Err(cause) => {
                self.returned = Some(Err(cause));
                Err(NetworkNamespaceStoreError::Poisoned)
            }
        }
    }

    pub(in crate::namespace_store) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native
            .address
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.native
                    .created
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.native
                    .timeout
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }

    pub(in crate::namespace_store) fn receiving_bytes_v4() -> Option<usize> {
        // Linux MAX_ARG_STRLEN bounds this unchanged initial systemd value.
        // The selected single-main source performs no environment mutation.
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(128 * 1024)?
            .checked_add(4 * std::mem::size_of::<SocketAddrUnix>())
    }
}

pub(in crate::namespace_store) fn open_notifier_local(
    value: &OsStr,
) -> Result<SystemdNotifier, NetworkNamespaceStoreError> {
    open_notifier_engine(value, &mut OpeningNativeV4::default())
}

fn open_notifier_engine(
    value: &OsStr,
    native: &mut OpeningNativeV4,
) -> Result<SystemdNotifier, NetworkNamespaceStoreError> {
    let value = value.to_str().ok_or_else(|| {
        NetworkNamespaceStoreError::Systemd("NOTIFY_SOCKET is not Unicode".to_owned())
    })?;
    if value.is_empty() {
        return Err(NetworkNamespaceStoreError::Systemd(
            "NOTIFY_SOCKET is empty".to_owned(),
        ));
    }
    native.address = Some(if let Some(name) = value.strip_prefix('@') {
        if name.is_empty() {
            return Err(NetworkNamespaceStoreError::Systemd(
                "NOTIFY_SOCKET abstract name is empty".to_owned(),
            ));
        }
        SocketAddrUnix::new_abstract_name(name.as_bytes())
    } else {
        SocketAddrUnix::new(Path::new(value))
    });
    let address = native
        .address
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or_else(|| {
            systemd_io_error(
                *native
                    .address
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .unwrap_or(&rustix::io::Errno::INVAL),
            )
        })?;
    // The destination is retained before the first fallible socket setup.
    native.created = Some(
        match socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        ) {
            Ok(socket) => {
                native.socket = Some(socket);
                Ok(())
            }
            Err(cause) => Err(cause),
        },
    );
    if let Some(Err(cause)) = native.created.as_ref() {
        return Err(systemd_io_error(*cause));
    }
    let Some(socket) = native.socket.as_ref() else {
        std::process::abort()
    };
    native.timeout = Some(set_socket_timeout(
        socket,
        Timeout::Send,
        Some(BARRIER_TIMEOUT),
    ));
    if let Some(Err(cause)) = native.timeout.as_ref() {
        return Err(systemd_io_error(*cause));
    }
    let _ = address;
    let Some(Ok(address)) = native.address.take() else {
        std::process::abort()
    };
    let Some(socket) = native.socket.take() else {
        std::process::abort()
    };
    Ok(SystemdNotifier { socket, address })
}

/// Prices the two actual one-FD native send frames and bounded payload text.
pub(in crate::namespace_store) fn mutation_receiving_bytes_v4(name_bytes: usize) -> Option<usize> {
    let payload = b"FDSTORE=1\nFDPOLL=0\nFDNAME="
        .len()
        .checked_add(name_bytes)?;
    let native_frame = std::mem::size_of::<IoSlice<'static>>()
        .checked_add(std::mem::size_of::<BorrowedFd<'static>>())?
        .checked_add(std::mem::size_of::<SendAncillaryBuffer<'static, 'static, 'static>>())?
        .checked_add(rustix::cmsg_space!(ScmRights(1)))?;
    // The barrier's fixed payload is the second send. Prefix/backing and
    // constructor overlap remain distinct from each stored native Result.
    native_frame
        .checked_mul(4)?
        .checked_add(payload.checked_mul(3)?)?
        .checked_add(3 * b"BARRIER=1".len())
}

#[derive(Default)]
pub(in crate::namespace_store) struct NotifyAttemptV4 {
    pub(in crate::namespace_store) gate: Option<Result<(), Closed>>,
    pub(in crate::namespace_store) written: Option<Result<usize, rustix::io::Errno>>,
    pub(in crate::namespace_store) protocol: Option<&'static str>,
}

impl NotifyAttemptV4 {
    pub(in crate::namespace_store) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.gate
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.written
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}

/// Executes exactly the old single native send, with optional paid disposition.
pub(in crate::namespace_store) fn notify_engine(
    notifier: &SystemdNotifier,
    payload: &[u8],
    descriptor: Option<BorrowedFd<'_>>,
    native: &mut NotifyAttemptV4,
    mut before: Option<&mut dyn FnMut() -> Result<(), Closed>>,
) -> Result<(), String> {
    let iov = [IoSlice::new(payload)];
    let borrowed = descriptor.into_iter().collect::<Vec<_>>();
    let mut control_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut control_space);
    if !borrowed.is_empty() && !control.push(SendAncillaryMessage::ScmRights(&borrowed)) {
        native.protocol = Some("systemd notification ancillary buffer is exhausted");
        return Err("systemd notification ancillary buffer is exhausted".to_owned());
    }
    let selected = before.is_some();
    if let Some(before) = before.as_mut() {
        native.gate = Some(before());
        if !matches!(native.gate, Some(Ok(()))) {
            return Err("actual Network notify effect clock refused".to_owned());
        }
    }
    // Selected sends cannot block behind readiness after the paired effect
    // gate. A short send/EINTR/EAGAIN is one retained negative, with no retry.
    let flags = if selected {
        SendFlags::NOSIGNAL | SendFlags::DONTWAIT
    } else {
        SendFlags::NOSIGNAL
    };
    native.written = Some(sendmsg_addr(
        &notifier.socket,
        &notifier.address,
        &iov,
        &mut control,
        flags,
    ));
    let written = match native.written.as_ref() {
        Some(Ok(written)) => *written,
        Some(Err(cause)) => return Err(format!("systemd notification send failed: {cause}")),
        None => std::process::abort(),
    };
    if written != payload.len() {
        native.protocol = Some("systemd notification was partially written");
        return Err("systemd notification was partially written".to_owned());
    }
    Ok(())
}

#[derive(Default)]
pub(in crate::namespace_store) struct BarrierAttemptV4 {
    // Match the ordinary tuple locals' reverse native destruction order.
    pub(in crate::namespace_store) manager_end: Option<OwnedFd>,
    pub(in crate::namespace_store) waiter: Option<OwnedFd>,
    pub(in crate::namespace_store) pair: Option<Result<(), rustix::io::Errno>>,
    pub(in crate::namespace_store) timeout: Option<Result<(), rustix::io::Errno>>,
    pub(in crate::namespace_store) sent: NotifyAttemptV4,
    pub(in crate::namespace_store) send_returned: Option<Result<(), String>>,
    pub(in crate::namespace_store) received: Option<Result<usize, rustix::io::Errno>>,
    pub(in crate::namespace_store) byte: [u8; 1],
    pub(in crate::namespace_store) protocol: Option<&'static str>,
}

impl BarrierAttemptV4 {
    pub(in crate::namespace_store) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.pair
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.timeout
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.sent.failure())
            .or_else(|| {
                self.received
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}

/// Shares socketpair/timeout/send/owning endpoint close/receive order.
pub(in crate::namespace_store) fn barrier_engine(
    notifier: &SystemdNotifier,
    native: &mut BarrierAttemptV4,
    mut before: Option<&mut dyn FnMut() -> Result<(), Closed>>,
    selected_wait: Option<
        &mut dyn FnMut(&OwnedFd, &mut [u8; 1]) -> Result<usize, rustix::io::Errno>,
    >,
) -> Result<(), String> {
    native.pair = Some(
        match socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        ) {
            Ok((waiter, manager_end)) => {
                native.waiter = Some(waiter);
                native.manager_end = Some(manager_end);
                Ok(())
            }
            Err(cause) => Err(cause),
        },
    );
    if let Some(Err(cause)) = native.pair.as_ref() {
        return Err(format!("systemd barrier socketpair failed: {cause}"));
    }
    let Some(waiter) = native.waiter.as_ref() else {
        std::process::abort()
    };
    native.timeout = Some(set_socket_timeout(
        waiter,
        Timeout::Recv,
        Some(BARRIER_TIMEOUT),
    ));
    if let Some(Err(cause)) = native.timeout.as_ref() {
        return Err(format!("systemd barrier timeout setup failed: {cause}"));
    }
    let Some(manager_end) = native.manager_end.as_ref() else {
        std::process::abort()
    };
    native.send_returned = Some(notify_engine(
        notifier,
        b"BARRIER=1",
        Some(manager_end.as_fd()),
        &mut native.sent,
        before.take(),
    ));
    if let Some(Err(cause)) = native.send_returned.as_ref() {
        return Err(cause.clone());
    }
    // This actual alias must close after successful transfer or EOF can never
    // arrive. A failed/ambiguous send keeps it in this original instead.
    drop(native.manager_end.take());
    native.received = Some(match selected_wait {
        Some(wait) => wait(waiter, &mut native.byte),
        None => recv(waiter, &mut native.byte, RecvFlags::empty()).map(|(bytes, _)| bytes),
    });
    let received = match native.received.as_ref() {
        Some(Ok(received)) => *received,
        Some(Err(cause)) => return Err(format!("systemd barrier wait failed: {cause}")),
        None => std::process::abort(),
    };
    if received != 0 {
        native.protocol = Some("systemd barrier descriptor carried data");
        return Err("systemd barrier descriptor carried data".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn refused_effect_gate_sends_no_native_bytes_or_rights() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let notifier = open_notifier_local(path.as_os_str()).unwrap();
        let descriptor = std::fs::File::open("/dev/null").unwrap();
        let mut original = NotifyAttemptV4::default();
        let mut calls = 0;
        let mut gate = || {
            calls += 1;
            Err(Closed)
        };

        assert!(
            notify_engine(
                &notifier,
                b"FDSTORE=1",
                Some(descriptor.as_fd()),
                &mut original,
                Some(&mut gate)
            )
            .is_err()
        );
        assert_eq!(calls, 1);
        assert!(matches!(original.gate, Some(Err(_))));
        assert!(original.written.is_none());
        assert!(rustix::fs::fstat(notifier.socket.as_fd()).is_ok());
        assert_eq!(
            receiver.recv(&mut [0_u8; 64]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn failed_native_send_keeps_the_actual_errno_and_original_socket() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent.sock");
        let notifier = open_notifier_local(absent.as_os_str()).unwrap();
        let inode = rustix::fs::fstat(notifier.socket.as_fd()).unwrap().st_ino;
        let mut original = NotifyAttemptV4::default();
        let mut gate = || Ok(());

        assert!(
            notify_engine(
                &notifier,
                b"FDSTORE=1",
                None,
                &mut original,
                Some(&mut gate)
            )
            .is_err()
        );
        assert!(matches!(
            original.written,
            Some(Err(rustix::io::Errno::NOENT))
        ));
        assert_eq!(
            original
                .failure()
                .unwrap()
                .downcast_ref::<rustix::io::Errno>(),
            Some(&rustix::io::Errno::NOENT)
        );
        assert_eq!(
            rustix::fs::fstat(notifier.socket.as_fd()).unwrap().st_ino,
            inode
        );
    }

    #[test]
    fn failed_barrier_gate_keeps_both_actual_socketpair_owners() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent.sock");
        let notifier = open_notifier_local(absent.as_os_str()).unwrap();
        let mut original = BarrierAttemptV4::default();
        let mut gate = || Err(Closed);

        assert!(barrier_engine(&notifier, &mut original, Some(&mut gate), None).is_err());
        assert!(matches!(original.pair, Some(Ok(()))));
        assert!(matches!(original.sent.gate, Some(Err(_))));
        assert!(original.sent.written.is_none());
        let waiter = original.waiter.as_ref().unwrap();
        let manager = original.manager_end.as_ref().unwrap();
        assert_ne!(
            rustix::fs::fstat(waiter.as_fd()).unwrap().st_ino,
            rustix::fs::fstat(manager.as_fd()).unwrap().st_ino
        );
        assert!(original.received.is_none());
    }
}
