//! Serves a bounded read-only FUSE connection over authenticated sealed backings.
//!
//! [`serve`] obtains the structural mapping on the launcher's original private
//! channel, then runs metadata, independent open deadlines, coalesced backing
//! fetches and kernel handle accounting on one task. The launcher supplies the
//! mounted, confined connection, exposure policies and a stop future tied to
//! its lease/drain controller. This module never mounts, opens a store pathname
//! or acknowledges physical release. Passthrough registration and writable
//! overlays remain separate integrations; this worker implements fallback reads.

mod error;
mod runtime;

pub use error::Error;

use crate::{
    fuse_backing,
    fuse_connection::Connection,
    fuse_dispatch::{Limits as MetadataLimits, Metadata},
    fuse_lifetime,
    fuse_metadata::{CachePolicy, Presentation},
    fuse_open, fuse_protocol,
    fuse_xattr::Policy as XattrPolicy,
    structural_index::{Entry, Index},
    worker_channel::WorkerClient,
};
use std::{future::Future, io, num::NonZeroU64, time::Duration};

/// Bounds startup storage, protocol admission and each outstanding exchange.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Maximum permanently sealed index size mapped at startup.
    pub index_bytes: usize,
    /// Protocol and reusable record-buffer bounds.
    pub protocol: fuse_protocol::init::Limits,
    /// Maximum bytes served by one fallback read, excluding its reply header.
    pub read_bytes: u32,
    /// Touched namespace and permanently assigned inode storage.
    pub metadata: MetadataLimits,
    /// Kernel lookup, handle and pending-work storage.
    pub lifetime: fuse_lifetime::Limits,
    /// Pending original backing tickets and independent open responses.
    pub opens: fuse_open::Limits,
    /// Pending and installed original backing storage.
    pub backings: fuse_backing::Limits,
    /// Maximum entries accepted in one BATCH_FORGET record.
    pub forget_entries: u32,
    /// Cache timeouts selected from the prepared exposure's view mode.
    pub cache: CachePolicy,
    /// Extended-attribute disclosure selected by the prepared exposure.
    pub xattrs: XattrPolicy,
    /// Passthrough policy; `Require` refuses this fallback implementation.
    pub passthrough: fuse_protocol::init::Passthrough,
    /// Maximum wait for each kernel open, independent of backing completion.
    pub open_deadline: Duration,
    /// Whole-exchange bound for original private-channel backing requests.
    pub fetch_deadline: Duration,
    /// Whole-exchange bound for INIT receipt and ordinary device replies.
    pub exchange_deadline: Duration,
}

impl Options {
    fn validate(self) -> Result<(), Error> {
        if self.index_bytes == 0
            || self.index_bytes > isize::MAX as usize
            || self.protocol.request_bytes < 8192
            || u32::try_from(self.protocol.request_bytes).is_err()
            || self.read_bytes == 0
            || self.read_bytes as usize > self.protocol.request_bytes - 16
            || self.protocol.background_requests == 0
            || self.forget_entries == 0
            || self.open_deadline.is_zero()
            || tokio::time::Instant::now()
                .checked_add(self.open_deadline)
                .is_none()
            || [self.fetch_deadline, self.exchange_deadline]
                .iter()
                .any(|timeout| timeout.is_zero() || *timeout > Duration::from_secs(300))
        {
            return Err(Error::State("invalid bounded FUSE worker options"));
        }
        if self.passthrough == fuse_protocol::init::Passthrough::Require {
            return Err(Error::State("fallback worker cannot require passthrough"));
        }
        Ok(())
    }
}

/// Reports connection-local transitions to the exposure's bounded supervisor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// The kernel has received INIT and the fallback worker can serve requests.
    Ready {
        /// Negotiated FUSE minor version.
        minor: u32,
        /// Reports fallback operation for the exposure's feature status.
        degraded: bool,
    },
    /// An original open response has entered the bounded queue.
    OpenQueued {
        /// Original canonical node from the retained structural namespace.
        node: NonZeroU64,
        /// Indicates that this waiter shares an already pending fetch.
        shared: bool,
        /// Indicates that a distinct fetch is waiting for the private channel.
        waiting_for_channel: bool,
    },
    /// An open has received EIO; its accepted physical work may remain retained.
    OpenFailed {
        /// Original canonical node of the failed response.
        node: NonZeroU64,
        /// Reports that this waiter's deadline selected EIO, independently of the fetch.
        expired: bool,
    },
}

/// Describes why the worker stopped without proving physical custody closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exit {
    /// The exposure controller completed its explicit stop future.
    Stopped,
    /// The original backing owner disconnected while no request was outstanding.
    ///
    /// The worker closes its device; retained backing custody remains charged.
    OwnerDisconnected,
    /// The original kernel connection reported that it was unmounted.
    Unmounted,
}

/// Serves an original mounted connection using its channel-bound index root.
///
/// Presentation comes from the prepared schema, and observation publishes
/// readiness/degradation and queue transitions without granting authority.
/// Observers must return promptly without blocking IO. On failure the caller
/// must apply its durable exposure fault/drain policy before declaring closure.
/// The stop future must follow the launcher's lease and durable drain policy.
/// Stop, error and cancellation drop this connection and its local resources;
/// retained kernel references and host-tier obligations remain separately owned.
/// An idle connection waits on readiness without an arbitrary idle timeout.
/// Run this future on the worker's original confined thread.
///
/// # Errors
/// Refuses invalid bounds, allocation failure, authenticated mapping failure,
/// protocol or accounting faults, native exchanges and observer/stop failures.
/// `Require` passthrough fails before requesting any backing. Every failure
/// consumes the original connection; it cannot resume with recycled identities.
///
/// # Panics
/// Panics without a Tokio I/O and time driver after startup validation.
pub async fn serve(
    connection: Connection,
    mut client: WorkerClient,
    options: Options,
    presentation: impl FnMut(Entry<'_>) -> Presentation,
    observe: impl FnMut(Event) -> io::Result<()>,
    stop: impl Future<Output = io::Result<()>>,
) -> Result<Exit, Error> {
    options.validate()?;
    tokio::pin!(stop);
    let mapping = tokio::select! {
        biased;
        result = &mut stop => {
            result?;
            return Ok(Exit::Stopped);
        },
        result = client.request_index_bounded(options.index_bytes, options.fetch_deadline) => result?,
    };
    runtime::run(
        connection,
        client,
        mapping.index(),
        options,
        presentation,
        observe,
        stop,
    )
    .await
}

/// Provides a synthetic-index entry point only for disposable native fixtures.
#[cfg(feature = "native-test-fixtures")]
pub mod native_fixture {
    use super::*;

    /// Exercises the production loop without claiming authenticated root startup.
    ///
    /// # Errors
    /// Preserves the same bounded loop failures as [`serve`]. The supplied
    /// synthetic index grants no repository, exposure or broker authority.
    ///
    /// # Panics
    /// Panics without a Tokio I/O and time driver after validation.
    pub async fn serve_index(
        connection: Connection,
        client: WorkerClient,
        index: Index<'_>,
        options: Options,
        presentation: impl FnMut(Entry<'_>) -> Presentation,
        observe: impl FnMut(Event) -> io::Result<()>,
        stop: impl Future<Output = io::Result<()>>,
    ) -> Result<Exit, Error> {
        runtime::run(
            connection,
            client,
            index,
            options,
            presentation,
            observe,
            stop,
        )
        .await
    }
}
