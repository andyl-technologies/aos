//! Rebuilds missing indexes under the original synchronized startup custody.
//!
//! Every bounded pack is independently verified before its derived index reaches
//! the existing no-replace writer. A fresh exhaustive inventory, rather than the
//! old repair plan, supplies subsequent adoption evidence. Mismatching indexes,
//! pending bodies and unsupported candidates remain unresolved.

use super::{
    recovery_candidates::{self, RecoveryCase},
    retention::{NativeOwnerExecutor, index_repair},
};
use crate::{
    host_cache::{NativeRecoveryInspection, NativeRecoveryInspector},
    publisher_local::client::PublisherRecoveryContext,
};
use std::io;
use terrane_sdk::host::cache::HostDomainLocation;

/// Reconciles eligible missing indexes before any sealed candidate adoption.
///
/// The returned generation follows actual completed repair snapshots. No receipt
/// is issued here, and the owner remains faulted in its original Drain context.
///
/// # Errors
/// Refuses unresolved inventories, invalid or unfunded repair plans, changed
/// original source/publisher custody and failed native effects or accounting.
pub(super) async fn run(
    executor: &NativeOwnerExecutor,
    inventory: NativeRecoveryInspection,
    inspector: &NativeRecoveryInspector,
    bootstrap_id: &[u8; 16],
    context: &PublisherRecoveryContext<HostDomainLocation>,
) -> io::Result<(NativeRecoveryInspection, Option<u64>)> {
    recovery_candidates::preflight_repairable(&inventory)?;
    let mut missing = false;
    for candidate in inventory.candidates() {
        missing |= matches!(
            recovery_candidates::classify(candidate)?,
            RecoveryCase::RepairIndex
        );
    }
    if !missing {
        return Ok((inventory, None));
    }
    // Extraction precedes all repair effects and preserves strict global-failure
    // refusal. Its provisional observations never become adoption evidence.
    let candidates = inventory
        .try_into_candidates()
        .map_err(|_| unresolved("unresolved inventory cannot transfer index repair plans"))?;
    let mut generation = None;
    for mut candidate in candidates {
        if !matches!(
            recovery_candidates::classify(&candidate)?,
            RecoveryCase::RepairIndex
        ) {
            continue;
        }
        let source = candidate
            .take_index_repair()
            .ok_or_else(|| unresolved("verified missing index lost its original source"))?;
        generation = Some(index_repair::recover(executor, source, bootstrap_id, context).await?);
    }
    let fresh = inspector.inspect()?;
    recovery_candidates::preflight(&fresh)?;
    Ok((fresh, generation))
}

fn unresolved(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}
