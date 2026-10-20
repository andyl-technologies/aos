//! Retains the sole fixed Controller-to-Root native connection recipe.
//!
//! This mechanical owner admits no role or work. Its actual J and D callers
//! fund their own complete receiving shape before construction and retain the
//! same native descriptor/adoption errors through independent outer posts.

use std::error::Error;
use std::os::fd::OwnedFd;

use crate::policy_compiler::POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, RetainedUnixStreamAdmissionErrorV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;
use rustix::fs::OFlags;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

#[derive(Default)]
pub(crate) struct ControllerRootConnectionOriginalV1 {
    address: Option<Result<SocketAddrUnix, rustix::io::Errno>>,
    socket: Option<Result<OwnedFd, rustix::io::Errno>>,
    connect: Option<Result<(), rustix::io::Errno>>,
    stream: Option<Result<RetainedUnixStream, RetainedUnixStreamAdmissionErrorV1>>,
    flags: Option<Result<OFlags, rustix::io::Errno>>,
    blocking: Option<Result<(), rustix::io::Errno>>,
}

impl ControllerRootConnectionOriginalV1 {
    /// Supplies the actual retained descriptor/adoption carrier before IO.
    pub(crate) fn receiving_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let (adoption_bytes, adoption_files) = RetainedUnixStream::retained_admission_obligations_v1();
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(std::mem::size_of::<Self>()
                .checked_mul(2)?.checked_add(adoption_bytes)?).ok()?)
            .with(D::OpenFiles, u64::try_from(adoption_files).ok()?))
    }

    pub(crate) fn connect_once(&mut self) -> Result<(), HistoryErrorV1> {
        if self.address.is_some() {
            return Err(HistoryErrorV1::Correlation);
        }
        self.address = Some(SocketAddrUnix::new(POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2));
        self.socket = Some(rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        ));
        // The raw descriptor is parked before connect. No fresh connection,
        // blocking connect, renewed timeout or generic reconnect is possible.
        self.connect = Some(rustix::net::connect(
            positive(&self.socket)?,
            positive(&self.address)?,
        ));
        positive(&self.connect)?;
        let Some(Ok(socket)) = self.socket.take() else {
            return Err(HistoryErrorV1::Correlation);
        };
        self.stream = Some(RetainedUnixStream::from_owned_retaining_v1(socket));
        let stream = positive(&self.stream)?;
        self.flags = Some(rustix::fs::fcntl_getfl(stream.as_fd()));
        self.blocking = Some(rustix::fs::fcntl_setfl(
            stream.as_fd(),
            *positive(&self.flags)? & !OFlags::NONBLOCK,
        ));
        positive(&self.blocking).map(|_| ())
    }

    pub(crate) fn stream(&self) -> Result<&RetainedUnixStream, HistoryErrorV1> {
        positive(&self.stream)
    }

    pub(crate) fn stream_mut(&mut self) -> Result<&mut RetainedUnixStream, HistoryErrorV1> {
        self.stream
            .as_mut()
            .and_then(|result| result.as_mut().ok())
            .ok_or(HistoryErrorV1::Correlation)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.address)
            .or_else(|| cause(&self.socket))
            .or_else(|| cause(&self.connect))
            .or_else(|| cause(&self.stream))
            .or_else(|| cause(&self.flags))
            .or_else(|| cause(&self.blocking))
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, HistoryErrorV1> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(HistoryErrorV1::Correlation)
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
