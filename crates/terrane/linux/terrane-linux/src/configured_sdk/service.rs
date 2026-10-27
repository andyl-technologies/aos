//! Retains genuinely recovered cache workers until an actual process shutdown signal.
//!
//! Snapshot handles remain completed and stopped. The ongoing work belongs to
//! the original native cache owners: periodic consumer expiry and retirement.

use super::{CompletedSnapshot, Error, FailureKind};
use crate::{host_cache::NativeMetadataOwner, quota_confinement::Installed};
use std::{collections::BTreeMap, io, time::Duration};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::{MissedTickBehavior, interval, timeout},
};

/// Receives completed snapshots after the original owners pass a Running check.
pub(super) type Ready = Box<dyn FnOnce(&[CompletedSnapshot]) -> io::Result<()>>;

/// Retains the original cache owners until a native process shutdown signal.
///
/// # Errors
/// Returns signal, notification, confinement, owner-health and deadline failures.
pub(super) async fn maintain(
    notification: Option<Ready>,
    installed: &Installed,
    snapshots: &[CompletedSnapshot],
    owners: &BTreeMap<&str, &NativeMetadataOwner>,
    #[cfg(feature = "surface-fuse")] maintenance: Option<crate::configured_maintenance::Plan>,
) -> Result<(), Error> {
    let Some(notification) = notification else {
        return Ok(());
    };
    let mut terminate = signal(SignalKind::terminate()).map_err(failed)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(failed)?;
    check_owners(installed, owners).await?;
    #[cfg(feature = "surface-fuse")]
    let bindings = maintenance
        .as_ref()
        .map(|plan| plan.bind(owners))
        .transpose()
        .map_err(failed)?;
    let result = {
        let maintenance = async {
            #[cfg(feature = "surface-fuse")]
            if let Some(bindings) = &bindings {
                return bindings.serve(owners).await;
            }
            std::future::pending::<io::Result<()>>().await
        };
        tokio::pin!(maintenance);
        notification(snapshots).map_err(failed)?;

        let mut health = interval(Duration::from_secs(1));
        health.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                received = terminate.recv() => break received.ok_or_else(disconnected),
                received = interrupt.recv() => break received.ok_or_else(disconnected),
                result = &mut maintenance => break result.map_err(failed),
                _ = health.tick() => check_owners(installed, owners).await?,
            }
        }
    };

    // Leaving the scope drops the complete borrowed accept/request future.
    // Retire only on acknowledged shutdown while original owner locks remain
    // held. Errors preserve socket names and never turn into a clean stop.
    #[cfg(feature = "surface-fuse")]
    if result.is_ok()
        && let Some(bindings) = bindings
    {
        bindings.retire().map_err(failed)?;
    }
    result
}

async fn check_owners(
    installed: &Installed,
    owners: &BTreeMap<&str, &NativeMetadataOwner>,
) -> Result<(), Error> {
    installed.check_current().map_err(failed)?;
    timeout(Duration::from_secs(5), async {
        for owner in owners.values() {
            owner.check_running().await?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| failed(io::ErrorKind::TimedOut.into()))?
    .map_err(failed)
}

fn failed(error: io::Error) -> Error {
    Error::io(FailureKind::NativeCacheService, error)
}

fn disconnected() -> Error {
    failed(io::Error::other(
        "native cache shutdown signal disconnected",
    ))
}
