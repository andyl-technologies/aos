//! Prepares inline publication from the physical owner's original verified backing.
//!
//! Source selection and publication occupy one executor turn. Original producer
//! custody protects the internal read; no independent consumer grant is created
//! merely to copy the owner's own input. Existing consumer protection remains
//! enforced by the ordinary publication and source-retirement checks.

use super::{NativeInlinePublication, invalid};
use crate::host_cache::owner::{
    consumer::source::ConsumerSource,
    retention::{Command, NativeMetadataOwner, NativeOwnerExecutor},
};
use std::{io, sync::mpsc};
use terrane_format::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};
use tokio::sync::oneshot;

impl NativeMetadataOwner {
    /// Publishes an existing inline chunk using its original native cache custody.
    ///
    /// The physical worker independently selects and verifies actual backing.
    /// It creates no consumer lease for this internal read. Existing independent
    /// consumers retain their ordinary pins and release grace. The canonical
    /// empty chunk needs no stored source; every other chunk must be resident.
    /// Accepted work and funding remain owned after waiter cancellation.
    ///
    /// # Errors
    /// Refuses unsupported or non-inline identities, absent or changed backing,
    /// failed verification, unavailable queues, capacity, publication or quota
    /// errors. No failure acknowledges rollback of accepted physical effects.
    pub async fn publish_resident_inline(
        &self,
        identity: Identity,
    ) -> io::Result<NativeInlinePublication> {
        let (response, receive) = oneshot::channel();
        let commands = self
            .commands
            .as_ref()
            .ok_or_else(|| invalid("native publication owner stopped"))?;
        commands
            .try_send(Command::PublishResidentInline { identity, response })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "publication queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "publication owner stopped")
                }
            })?;
        receive
            .await
            .map_err(|_| invalid("publication owner terminated before completion"))?
    }
}

/// Keeps internal source reading and funded publication on the physical worker.
pub(in crate::host_cache::owner) async fn run(
    executor: &mut NativeOwnerExecutor,
    identity: Identity,
) -> io::Result<NativeInlinePublication> {
    executor.check_physical_worker()?;
    if identity.kind() != IdentityKind::Chunk || identity.profile() != TERRANE_V1.name() {
        return Err(invalid(
            "inline publication requires a registered chunk identity",
        ));
    }

    let empty = TERRANE_V1
        .calculate(IdentityKind::Chunk, &[])
        .map_err(io::Error::other)?;
    if identity == empty {
        let descriptor =
            Descriptor::from_identity(&TERRANE_V1, &identity, &[]).map_err(io::Error::other)?;
        return super::run(executor, descriptor, vec![0]).await;
    }

    super::eviction::restore_for(executor, &identity).await?;
    let source = ConsumerSource::prepare(executor, identity.clone()).await?;
    let plaintext = source.read_verified()?;
    let descriptor =
        Descriptor::from_identity(&TERRANE_V1, &identity, &plaintext).map_err(io::Error::other)?;
    drop(plaintext);
    let encoded = source.read_encoded()?;

    // The original source remains retained across actual publication. This
    // internal scope creates no grant that could block its own source transfer.
    let result = super::run(executor, descriptor, encoded).await;
    drop(source);
    result
}
