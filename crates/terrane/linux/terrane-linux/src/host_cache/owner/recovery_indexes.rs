//! Repairs verified shared packs before private publisher inventory needs them.
//!
//! Missing metadata indexes can prevent inventory from describing a sealed
//! manifest. Bounded shared verification supplies repair data only. The owner
//! first funds actual pending inspections, which can reconcile a split pair,
//! and excludes those units from repair. It checks genuine pending absence and
//! its original Drain context before writes;
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
use std::{collections::BTreeSet, io};
use terrane_sdk::host::cache::HostDomainLocation;

/// Describes actual startup work, without completed-recovery authority.
pub(super) struct StartupIndexWork {
    /// Contains the latest generation after an actual synchronized index repair.
    pub(super) generation: Option<u64>,
    /// Records successful pending inspection, which can reconcile split members.
    pub(super) pending_reconciled: bool,
}

/// Reconciles eligible indexes without treating a partial scan as inventory.
///
/// The returned generation follows actual completed repair snapshots. No receipt
/// is issued here, and the owner remains faulted in its original Drain context.
///
/// # Errors
/// Refuses invalid or unfunded plans, uncertain publisher
/// outcomes, changed source/context and failed native effects or accounting.
pub(super) async fn run(
    executor: &NativeOwnerExecutor,
    inspector: &NativeRecoveryInspector,
    bootstrap_id: &[u8; 16],
    context: &PublisherRecoveryContext<HostDomainLocation>,
) -> io::Result<StartupIndexWork> {
    executor.check_physical_worker()?;
    let session = executor
        .custody()
        .lock()
        .map_err(|_| io::Error::other("recovery custody poisoned"))?
        .preparation
        .publisher_session();
    let mut pending = BTreeSet::new();
    for id in inspector.shared_pack_ids()? {
        {
            let owner = executor
                .custody()
                .lock()
                .map_err(|_| io::Error::other("recovery custody poisoned"))?;
            owner.check_synchronized_bootstrap(bootstrap_id)?;
            if !owner.faulted || !owner.recovery_required {
                return Err(io::Error::other(
                    "pending inspection lost original recovery custody",
                ));
            }
            super::recovery::check_charge(&owner, 0)?;
        }
        session
            .check_recovery_context(context)
            .map_err(io::Error::other)?;
        let key = BodyKey {
            kind: BodyKind::Pack as i32,
            descriptor: Vec::new(),
            codec: 0,
            pack_id: id.as_bytes().to_vec(),
        };
        // InspectPending can complete the second rename of a split pair. The
        // synchronized bootstrap precedes that effect; no index may be created
        // over a member which actually belongs to this pending retirement unit.
        match session.inspect_pending(key) {
            Ok(_) => {
                pending.insert(*id.as_bytes());
            }
            Err(PublisherError::Remote(ResultCode::NotFound)) => {}
            Err(error) => return Err(io::Error::other(error)),
        }
        session
            .check_recovery_context(context)
            .map_err(io::Error::other)?;
    }
    let repairs = inspector.inspect_index_repairs(&pending)?;
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
    Ok(StartupIndexWork {
        generation,
        pending_reconciled: !pending.is_empty(),
    })
}
