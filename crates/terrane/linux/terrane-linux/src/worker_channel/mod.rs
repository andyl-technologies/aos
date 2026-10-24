//! Authenticates one bounded worker channel before original backing disclosure.
//!
//! Requests bind a supervised child incarnation, kernel message credentials,
//! exposure generation and strictly increasing sequence. Each successful reply
//! follows a fresh scoped repository Read and a final live-exposure check and
//! descriptor send serialized with draining by the physical owner. Cancellation
//! faults this channel while durable physical obligations remain retained.
//!
//! This component does not launch a worker, mount FUSE, confer privileges or
//! install a worker sandbox. Its owner separately supervises the original child.

mod client;
#[cfg(feature = "native-test-fixtures")]
pub mod native_fixture;
mod runtime;
mod socket;
mod wire;

pub use client::{BackingReply, PendingBacking, WorkerClient};
pub use socket::WorkerIdentity;
pub use wire::{BackingRequest, ExposureContext, RequestedBacking};

use crate::host_cache::{
    NativeExposureLease, NativeExposureRootBacking, NativeFileBacking, NativeMetadataOwner,
    NativeRootIndex,
};
use socket::Endpoint;
use std::{
    fs::File,
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    sync::Arc,
};
use terrane_format::identity::Digest;
use terrane_sdk::{
    host::cache::ExposureBackingKind,
    repository::{Error, PreparedFileRead, PreparedRootRead},
    store::{Clock, Store},
};
use wire::invalid;

/// Creates bounded connected endpoints before a launcher starts its worker.
///
/// The first descriptor belongs to serve and the second is passed to the child.
/// Both are close-on-exec until the launcher explicitly arranges inheritance.
/// Kernel request credentials are enabled before the child can queue a packet.
///
/// # Errors
/// Returns native Unix socket creation or option failures.
pub fn channel_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    use rustix::net::{self, sockopt};

    let pair = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )?;
    sockopt::set_socket_passcred(&pair.0, true)?;
    for socket in [&pair.0, &pair.1] {
        sockopt::set_socket_recv_buffer_size(socket, wire::MAX_PACKET * 2)?;
        sockopt::set_socket_send_buffer_size(socket, wire::MAX_PACKET * 2)?;
    }
    Ok(pair)
}

/// Owns one authenticated worker channel with at most one in-flight request.
///
/// Socket operations are nonblocking; the caller supplies its event loop and
/// finite request deadline. Dropping the channel disconnects it and does not
/// discharge any exposure pins or claim kernel reference closure.
pub struct WorkerChannel {
    endpoint: Arc<Endpoint>,
    exposure: NativeExposureLease,
    context: ExposureContext,
    next_sequence: u64,
}

impl WorkerChannel {
    /// Binds a connected Unix seqpacket socket to an original worker and lease.
    ///
    /// [`channel_pair`] enables `SO_PASSCRED` before launch. With other sockets,
    /// the launcher must enable it on the receiving socket before
    /// allowing the child to send. This constructor also enables it, but a
    /// packet queued earlier without original credentials is always refused.
    /// Creating a channel grants no descriptor or enduring Read authorization.
    ///
    /// # Errors
    /// Rejects another socket family or type, identical worker/serve UIDs,
    /// malformed exposure context, exited workers and native socket failures.
    pub fn bind(
        socket: OwnedFd,
        worker: WorkerIdentity,
        exposure: NativeExposureLease,
    ) -> io::Result<Self> {
        let context =
            ExposureContext::new(exposure.id(), exposure.generation(), exposure.key().root())?;
        Ok(Self {
            endpoint: Arc::new(Endpoint::new(socket, worker)?),
            exposure,
            context,
            next_sequence: 1,
        })
    }

    /// Authenticates and consumes the next exact request without blocking.
    ///
    /// A pending request exclusively borrows this connection. Dropping it before
    /// successful acknowledgment faults the connection, including cancellation
    /// while the physical owner may already have accepted the disclosure job.
    ///
    /// # Errors
    /// Returns `WouldBlock` when no packet is queued. Other errors fault the
    /// channel: malformed or foreign context, replay, sequence exhaustion,
    /// unexpected descriptors, truncation and wrong or exited process peers.
    pub fn receive(&mut self) -> io::Result<PendingRequest<'_>> {
        let result = self.receive_inner();
        match result {
            Ok(request) => Ok(PendingRequest {
                channel: self,
                request,
                completed: false,
            }),
            Err(error) => {
                if error.kind() != io::ErrorKind::WouldBlock {
                    self.endpoint.abort();
                }
                Err(error)
            }
        }
    }

    fn receive_inner(&mut self) -> io::Result<BackingRequest> {
        let bytes = self.endpoint.receive()?;
        let request = BackingRequest::decode(&bytes, &self.context)?;
        if request.sequence != self.next_sequence {
            return Err(invalid("replayed or reordered worker request"));
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("worker sequence exhausted"))?;
        Ok(request)
    }
}

impl AsFd for WorkerChannel {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.endpoint.as_fd()
    }
}

impl Drop for WorkerChannel {
    fn drop(&mut self) {
        self.endpoint.abort();
    }
}

/// Retains exclusive connection custody through preparation and acknowledgment.
pub struct PendingRequest<'a> {
    channel: &'a mut WorkerChannel,
    request: BackingRequest,
    completed: bool,
}

impl PendingRequest<'_> {
    /// Borrows the exact authenticated request for scoped repository selection.
    pub const fn request(&self) -> &BackingRequest {
        &self.request
    }

    /// Prepares and sends the original index after fresh complete-root Read.
    ///
    /// # Errors
    /// Refuses a file request, mismatched selection, failed closing Read,
    /// changed native custody, expired or draining generation, queue exhaustion,
    /// peer exit and nonblocking descriptor-send failures. Failure faults this
    /// connection and never acknowledges release of retained exposure custody.
    pub async fn grant_index<S: Store, C: Clock>(
        mut self,
        owner: &NativeMetadataOwner,
        served: &NativeRootIndex,
        selection: PreparedRootRead<'_, S, C>,
    ) -> Result<(), Error> {
        if self.request.backing != RequestedBacking::Index {
            return Err(Error::Denied);
        }
        let grant = owner
            .prepare_exposure_root_backing(&self.channel.exposure, served, selection)
            .await?;
        self.disclose(owner, Grant::Index(grant)).await?;
        self.completed = true;
        Ok(())
    }

    /// Prepares and sends the exact requested file after fresh scoped Read.
    ///
    /// Request path and typed hash must equal the original SDK selection before
    /// physical pin effects. The existing native bridge independently checks
    /// the served root, domain, path, content, durable exposure and closing Read.
    ///
    /// # Errors
    /// Refuses index requests, foreign paths or content, failed native backing
    /// preparation or closing Read, draining generations and transport failures.
    /// Failure faults the connection without discharging physical obligations.
    pub async fn grant_file<S: Store, C: Clock>(
        mut self,
        owner: &NativeMetadataOwner,
        served: &NativeRootIndex,
        selection: PreparedFileRead<'_, S, C>,
        expires: u64,
    ) -> Result<(), Error> {
        let RequestedBacking::File { path, content } = &self.request.backing else {
            return Err(Error::Denied);
        };
        if selection.path().strip_prefix(b"/") != Some(path.as_slice())
            || selection.content() != *content
        {
            return Err(Error::Denied);
        }
        let grant = owner
            .prepare_exposure_file_backing(&self.channel.exposure, served, selection, expires)
            .await?;
        self.disclose(owner, Grant::File(grant)).await?;
        self.completed = true;
        Ok(())
    }

    async fn disclose(&self, owner: &NativeMetadataOwner, grant: Grant) -> Result<(), Error> {
        owner
            .send_worker_backing(
                &self.channel.exposure,
                Disclosure {
                    endpoint: Arc::clone(&self.channel.endpoint),
                    request: self.request.clone(),
                    grant,
                },
            )
            .await
            .map_err(Error::Io)
    }
}

impl Drop for PendingRequest<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.channel.endpoint.abort();
        }
    }
}

enum Grant {
    Index(NativeExposureRootBacking),
    File(NativeFileBacking),
}

/// Carries only a freshly prepared genuine grant into the serialized owner.
pub(crate) struct Disclosure {
    endpoint: Arc<Endpoint>,
    request: BackingRequest,
    grant: Grant,
}

impl Disclosure {
    pub(crate) fn binding(&self) -> (ExposureBackingKind, Digest) {
        match &self.request.backing {
            RequestedBacking::Index => (ExposureBackingKind::Index, self.request.context.root),
            RequestedBacking::File { content, .. } => match content {
                terrane_format::tree_format::ContentRef::Inline(hash) => {
                    (ExposureBackingKind::Inline, *hash)
                }
                terrane_format::tree_format::ContentRef::Manifest(hash) => {
                    (ExposureBackingKind::Manifest, *hash)
                }
            },
        }
    }

    pub(crate) fn file(&self) -> io::Result<File> {
        Ok(File::from(self.descriptor().try_clone_to_owned()?))
    }

    fn descriptor(&self) -> BorrowedFd<'_> {
        match &self.grant {
            Grant::Index(grant) => grant.as_fd(),
            Grant::File(grant) => grant.as_fd(),
        }
    }

    pub(crate) fn send(&self) -> io::Result<()> {
        self.endpoint
            .send(&self.request.encode(), self.descriptor())
    }
}
