//! Repairs verified shared packs before private publisher inventory needs them.
//!
//! Missing metadata indexes can prevent inventory from describing a sealed
//! manifest. This bounded readonly pass supplies repair data only. The owner
//! checks genuine pending absence and its original Drain context before writes;
//! a later complete inventory remains mandatory before adoption or Resume.

use super::retention::{NativeOwnerExecutor, index_repair};
use crate::{
    host_cache::NativeRecoveryInspector,
    publisher_local::{
        Error as PublisherError,
        client::PublisherRecoveryContext,
        wire::{BodyKey, BodyKind, ResultCode},
    },
};
use std::io;
use terrane_sdk::host::cache::HostDomainLocation;

/// Reconciles eligible indexes without treating a partial scan as inventory.
///
/// The returned generation follows actual completed repair snapshots. No receipt
/// is issued here, and the owner remains faulted in its original Drain context.
///
/// # Errors
/// Refuses invalid or unfunded plans, actual pending custody, uncertain publisher
/// outcomes, changed source/context and failed native effects or accounting.
pub(super) async fn run(
    executor: &NativeOwnerExecutor,
    inspector: &NativeRecoveryInspector,
    bootstrap_id: &[u8; 16],
    context: &PublisherRecoveryContext<HostDomainLocation>,
) -> io::Result<Option<u64>> {
    let repairs = inspector.inspect_index_repairs()?;
    let session = executor
        .custody()
        .lock()
        .map_err(|_| io::Error::other("recovery custody poisoned"))?
        .preparation
        .publisher_session();
    let mut generation = None;
    for source in repairs {
        session
            .check_recovery_context(context)
            .map_err(io::Error::other)?;
        let key = BodyKey {
            kind: BodyKind::Pack as i32,
            descriptor: Vec::new(),
            codec: 0,
            pack_id: source.pack_id().as_bytes().to_vec(),
        };
        // Independent pack bytes cannot establish pending absence. Require the
        // actual publisher's completed fixed operation under the original epoch.
        match session.inspect_pending(key) {
            Err(PublisherError::Remote(ResultCode::NotFound)) => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "pending pack custody prevents startup index repair",
                ));
            }
            Err(error) => return Err(io::Error::other(error)),
        }
        session
            .check_recovery_context(context)
            .map_err(io::Error::other)?;
        generation = Some(index_repair::recover(executor, source, bootstrap_id, context).await?);
    }
    Ok(generation)
}
