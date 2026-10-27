//! Validates bounded backing replies on a launcher's private worker endpoint.
//!
//! The launcher supplies the connected descriptor, exposure context and serve
//! UID. Kernel credentials identify the sending role; this side does not mint
//! repository authorization or attest a server process incarnation. Each reply
//! must echo the exact outstanding request and carry one sealed read-only file.

mod runtime;

use super::{
    BackingRequest, ExposureContext, RequestedBacking,
    wire::{MAX_PACKET, invalid},
};
use rustix::net::{self, RecvAncillaryBuffer, RecvAncillaryMessage};
use std::{
    fs::File,
    io::{self, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

/// Owns the worker side of one launcher's private backing channel.
///
/// The trusted launcher supplies the descriptor and expected serve UID. A UID
/// or exposure context alone cannot establish the private channel. Operations
/// are nonblocking; the supervisor supplies finite deadlines. Dropping either
/// the client or an incomplete request disconnects the channel without claiming
/// closure of any previously received backing or kernel reference.
pub struct WorkerClient {
    socket: OwnedFd,
    context: ExposureContext,
    serve_uid: u32,
    next_sequence: u64,
    active: bool,
}

impl WorkerClient {
    /// Binds a private connected endpoint before sending its first request.
    ///
    /// Reply credentials are enabled before serve can respond. The expected
    /// serve UID must differ from this worker's effective UID.
    ///
    /// # Errors
    /// Rejects disconnected sockets, another family or type, identical role
    /// UIDs and native socket-option failures.
    pub fn bind(socket: OwnedFd, context: ExposureContext, serve_uid: u32) -> io::Result<Self> {
        if net::sockopt::socket_domain(&socket)? != net::AddressFamily::UNIX
            || net::sockopt::socket_type(&socket)? != net::SocketType::SEQPACKET
            || serve_uid == rustix::process::geteuid().as_raw()
        {
            return Err(invalid(
                "worker client requires distinct Unix process roles",
            ));
        }
        net::getpeername(&socket)?;
        net::sockopt::set_socket_passcred(&socket, true)?;
        net::sockopt::set_socket_recv_buffer_size(&socket, MAX_PACKET * 2)?;
        net::sockopt::set_socket_send_buffer_size(&socket, MAX_PACKET * 2)?;
        Ok(Self {
            socket,
            context,
            serve_uid,
            next_sequence: 1,
            active: true,
        })
    }

    /// Sends one canonical selection and retains exclusive response custody.
    ///
    /// # Errors
    /// Rejects invalid paths, sequence exhaustion, a faulted channel and native
    /// send failures. `WouldBlock` leaves the unsent sequence available for
    /// retry; other transport failures disconnect this channel.
    pub fn request(&mut self, backing: RequestedBacking) -> io::Result<PendingBacking<'_>> {
        let (next, expected) = self.prepare(backing)?;
        self.send(&expected)?;
        self.next_sequence = next;
        Ok(PendingBacking {
            client: self,
            expected,
            completed: false,
        })
    }

    fn prepare(&self, backing: RequestedBacking) -> io::Result<(u64, Vec<u8>)> {
        if !self.active {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "worker client faulted",
            ));
        }
        let next = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("worker sequence exhausted"))?;
        let request = BackingRequest::new(self.context.clone(), self.next_sequence, backing)?;
        Ok((next, request.encode()))
    }

    fn send(&mut self, expected: &[u8]) -> io::Result<()> {
        let sent = net::send(
            &self.socket,
            expected,
            net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
        );
        match sent {
            Ok(count) if count == expected.len() => Ok(()),
            Err(error) if error == rustix::io::Errno::WOULDBLOCK => Err(error.into()),
            result => {
                self.abort();
                Err(match result {
                    Err(error) => error.into(),
                    Ok(_) => invalid("incomplete worker request"),
                })
            }
        }
    }

    fn abort(&mut self) {
        self.active = false;
        let _ = net::shutdown(&self.socket, net::Shutdown::Both);
    }
}

impl AsFd for WorkerClient {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl Drop for WorkerClient {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Retains one outstanding request through complete ancillary validation.
pub struct PendingBacking<'a> {
    client: &'a mut WorkerClient,
    expected: Vec<u8>,
    completed: bool,
}

impl PendingBacking<'_> {
    /// Receives and validates the exact reply without blocking.
    ///
    /// `WouldBlock` permits retry on this same request. Every other refusal
    /// disconnects the channel and closes all received descriptors. A reply is
    /// transport custody, not an independent verification of its content hash.
    ///
    /// # Errors
    /// Rejects repeated completion, EOF, foreign credentials, truncation,
    /// mismatched request bytes, missing or extra descriptors, writable or
    /// nonregular files and failed kernel fs-verity measurement.
    pub fn receive(&mut self) -> io::Result<BackingReply> {
        if self.completed || !self.client.active {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "backing request completed or faulted",
            ));
        }
        let result = self.receive_inner();
        match result {
            Ok(reply) => {
                self.completed = true;
                Ok(reply)
            }
            Err(error) => {
                if error.kind() != io::ErrorKind::WouldBlock {
                    self.client.abort();
                }
                Err(error)
            }
        }
    }

    fn receive_inner(&self) -> io::Result<BackingReply> {
        let mut bytes = [0; MAX_PACKET];
        // Consume the full Linux rights limit even when the peer violates the
        // one-file contract, so every refused descriptor closes through RAII.
        let mut space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253), ScmCredentials(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let received = net::recvmsg(
            &self.client.socket,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            net::RecvFlags::DONTWAIT | net::RecvFlags::CMSG_CLOEXEC,
        )?;
        let mut descriptor = None;
        let mut credentials = None;
        let mut rejected = received.bytes == 0
            || received
                .flags
                .intersects(net::ReturnFlags::TRUNC | net::ReturnFlags::CTRUNC)
            || bytes.get(..received.bytes) != Some(self.expected.as_slice());
        for field in ancillary.drain() {
            match field {
                RecvAncillaryMessage::ScmCredentials(value) if credentials.is_none() => {
                    credentials = Some(value)
                }
                RecvAncillaryMessage::ScmRights(rights) => {
                    for right in rights {
                        if descriptor.is_some() {
                            rejected = true;
                        } else {
                            descriptor = Some(right);
                        }
                    }
                }
                _ => rejected = true,
            }
        }
        if rejected || credentials.is_none_or(|value| value.uid.as_raw() != self.client.serve_uid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid backing reply or serve credentials",
            ));
        }
        let descriptor = descriptor.ok_or_else(|| invalid("missing backing descriptor"))?;
        let flags = rustix::fs::fcntl_getfl(&descriptor)?;
        if flags.intersects(
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::PATH,
        ) {
            return Err(invalid("backing descriptor is not read-only"));
        }
        let file = File::from(descriptor);
        if !file.metadata()?.is_file() {
            return Err(invalid("backing descriptor is not a regular file"));
        }
        let seal = crate::verity::measure(&file)?;
        Ok(BackingReply { file, seal })
    }
}

impl AsFd for PendingBacking<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.client.as_fd()
    }
}

impl Drop for PendingBacking<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.client.abort();
        }
    }
}

/// Owns one original read-only, regular, kernel-sealed reply descriptor.
///
/// This value confirms transport checks and a measured fs-verity seal. Content
/// identity still comes from the authenticated scoped serve grant and signed
/// index; the fs-verity digest is not the Terrane object digest.
pub struct BackingReply {
    file: File,
    seal: terrane_sdk::host::publication::VerityBinding,
}

impl BackingReply {
    /// Transfers the received descriptor to the worker's backing or map owner.
    pub fn into_file(self) -> File {
        self.file
    }
}

impl AsFd for BackingReply {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}
