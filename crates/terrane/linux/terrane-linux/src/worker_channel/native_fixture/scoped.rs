//! Exercises final Send ordering after genuine scoped preparation completes.
//!
//! This native-only control holds the original physical worker, queues actual
//! Drain before actual Send, then releases that same worker. It supplies no
//! fabricated identity, grant, policy snapshot or successful refusal substitute.

use crate::{
    host_cache::{NativeMetadataOwner, NativeRootIndex},
    worker_channel::{Grant, PendingRequest, RequestedBacking},
};
use std::{
    future::Future,
    io,
    task::{Context, Poll, Waker},
};
use terrane_sdk::{
    repository::{Error, PreparedRootRead},
    store::{Clock, Store},
};

/// Requires final native Send to refuse a grant prepared before queued draining.
///
/// Genuine root preparation, descriptor binding and closing Read finish before
/// the worker is stalled. Both real queue submissions must remain pending behind
/// that stall. Only a successful durable drain followed by a permission-denied
/// Send satisfies this control; timeout, backpressure and other errors fail it.
///
/// # Errors
/// Preserves preparation and queue failures. Refuses a non-index request, a
/// submission that completes before the stall is released, a failed drain or
/// any Send result except the final current-generation refusal.
pub async fn require_queued_drain_refusal<S: Store, C: Clock>(
    pending: PendingRequest<'_>,
    owner: &NativeMetadataOwner,
    served: &NativeRootIndex,
    selection: PreparedRootRead<'_, S, C>,
) -> Result<(), Error> {
    if pending.request.backing != RequestedBacking::Index {
        return Err(Error::Denied);
    }
    let exposure = pending.channel.exposure.clone();
    let grant = owner
        .prepare_exposure_root_backing(&exposure, served, selection)
        .await?;
    let stall = owner.stall_policy_for_fixture().await.map_err(Error::Io)?;
    let mut draining = Box::pin(owner.drain_surface_exposure(&exposure));
    let mut sending = Box::pin(pending.disclose(owner, Grant::Index(grant)));
    let mut context = Context::from_waker(Waker::noop());
    if !matches!(draining.as_mut().poll(&mut context), Poll::Pending)
        || !matches!(sending.as_mut().poll(&mut context), Poll::Pending)
    {
        return Err(Error::Denied);
    }

    drop(stall);
    draining.await.map_err(Error::Io)?;
    match sending.await {
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(error),
        Ok(()) => Err(Error::Denied),
    }
}
