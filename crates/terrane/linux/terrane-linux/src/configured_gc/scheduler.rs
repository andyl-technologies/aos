//! Retains one original collector session through recurring bounded scheduling.

use std::{io, time::Duration};

use terrane_format::gc::{DeletePhase, Phase};
use terrane_sdk::{
    gc::runner::maintenance::{
        MaintenanceCursor, MaintenanceHint, local_deletion::LocalDeletionCursor,
        restoration::RestorationCursor,
    },
    pack::PackId,
    repository::{LocalCollection, LocalRestoration},
    role::Role,
    store::{TokioClock, TokioLocalFs},
};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::{Instant, sleep},
};

use super::{Error, ValidatedCollector};
use crate::quota_confinement::Installed;

type Collector<'repository> = LocalCollection<'repository, TokioLocalFs, TokioClock>;

/// Distinguishes reaching Sweep from actually performing its bounded work.
#[derive(Eq, PartialEq)]
enum Progress {
    Marking,
    Swept,
}

#[derive(Default)]
struct Cursors {
    maintenance: MaintenanceCursor,
    deletion: LocalDeletionCursor,
}

pub(super) async fn run(
    plan: &ValidatedCollector<'_>,
    installed: &Installed,
    ready: Box<dyn FnOnce() -> io::Result<()>>,
) -> Result<(), Error> {
    let mut terminate = signal(SignalKind::terminate()).map_err(Error::Io)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(Error::Io)?;
    tokio::select! {
        biased;
        received = terminate.recv() => received.ok_or_else(disconnected),
        received = interrupt.recv() => received.ok_or_else(disconnected),
        result = collect(plan, installed, ready) => result,
    }
}

async fn collect(
    plan: &ValidatedCollector<'_>,
    installed: &Installed,
    ready: Box<dyn FnOnce() -> io::Result<()>>,
) -> Result<(), Error> {
    let repository = plan
        .config
        .open_local_maintenance(Role::Gc, TokioLocalFs, TokioClock)
        .await
        .map_err(Error::Repository)?;
    let holder = PackId::generate(&TokioLocalFs)
        .await
        .map_err(Error::Io)?
        .to_string();
    let mut restoration = repository
        .start_next_local_restoration(holder, plan.settings.lease_seconds, plan.windows)
        .await?;
    restore_startup_candidates(&mut restoration, plan).await?;
    let mut collector = restoration.begin_next_collection().await?;
    let mut cursors = Cursors::default();
    let mut next_cycle = deadline(plan)?;
    let mut ready = Some(ready);

    loop {
        installed.check_current().map_err(Error::Io)?;
        let progress = step(&mut collector, &mut cursors, plan).await?;
        if collector.state().phase == Phase::Sweep {
            if let Some(notification) = ready.take() {
                notification().map_err(Error::Io)?;
            }
            // Slow marking must still reach sweep work before an expired
            // interval can start another cycle. Otherwise every cycle can mark
            // successfully while retirement and recovery starve indefinitely.
            if progress == Progress::Swept && Instant::now() >= next_cycle {
                collector.begin_next_cycle().await?;
                next_cycle = deadline(plan)?;
            }
        }
        sleep(Duration::from_millis(plan.settings.poll_ms)).await;
    }
}

async fn restore_startup_candidates(
    restoration: &mut LocalRestoration<'_, TokioLocalFs, TokioClock>,
    plan: &ValidatedCollector<'_>,
) -> Result<(), Error> {
    let mut cursor = RestorationCursor::default();
    loop {
        let candidates = restoration
            .restoration_hints(&mut cursor, plan.settings.maintenance_batch)
            .await?;
        if candidates.is_empty() {
            return Ok(());
        }
        for exclusion in candidates {
            let status = restoration.local_deletion_hint(&exclusion).await?;
            if status.as_ref().is_some_and(|hint| {
                !matches!(hint.phase, DeletePhase::Authorized | DeletePhase::Cancelled)
            }) {
                // Irreversible and Done local ownership must keep its original
                // recovery protocol. Status never authorizes restoring a pair.
                continue;
            }
            restoration.restore_pack(exclusion).await?;
        }
        sleep(Duration::from_millis(plan.settings.poll_ms)).await;
    }
}

fn deadline(plan: &ValidatedCollector<'_>) -> Result<Instant, Error> {
    Instant::now()
        .checked_add(Duration::from_millis(plan.settings.cycle_interval_ms))
        .ok_or(Error::Refused("collector cycle deadline overflows"))
}

async fn step(
    collector: &mut Collector<'_>,
    cursors: &mut Cursors,
    plan: &ValidatedCollector<'_>,
) -> Result<Progress, Error> {
    if collector.state().phase == Phase::Mark {
        collector.mark_batch(plan.settings.mark_batch).await?;
        if collector.state().pending.is_empty() {
            collector.finish_mark().await?;
        }
        return Ok(Progress::Marking);
    }

    let intents = collector
        .local_deletion_hints(&mut cursors.deletion, plan.settings.maintenance_batch)
        .await?;
    for intent in intents {
        match intent.phase {
            DeletePhase::Authorized => {
                // A crash before irreversible journal retirement may leave a
                // cancellable intent. Restore through the closed producer, then
                // mark a fresh cycle before considering that pack again.
                if collector.restore_pack(intent.exclusion).await? {
                    collector.begin_next_cycle().await?;
                    return Ok(Progress::Marking);
                }
            }
            DeletePhase::Done | DeletePhase::Cancelled => {}
            _ => {
                collector.resume_local_delete(&intent.operation_key).await?;
            }
        }
    }
    let hints = collector
        .maintenance_hints(&mut cursors.maintenance, plan.settings.maintenance_batch)
        .await?;
    for hint in hints {
        match hint {
            MaintenanceHint::PermanentOwner { operation_key, .. } => {
                collector
                    .reconcile_permanent(&operation_key, plan.settings.maintenance_batch)
                    .await?;
            }
            MaintenanceHint::CopiedRetirement { pack } => {
                collector.own_copied_pack(*pack.as_bytes()).await?;
            }
            MaintenanceHint::ExcludedPack(exclusion) => {
                if let Some(intent) = collector.local_deletion_hint(&exclusion).await? {
                    if intent.phase == DeletePhase::Cancelled
                        && collector.restore_pack(exclusion).await?
                    {
                        collector.begin_next_cycle().await?;
                        return Ok(Progress::Marking);
                    }
                    // Existing intent, including Done, stays in its original
                    // recovery protocol; a paged inventory cannot establish this.
                    continue;
                }
                if exclusion.cycle < collector.state().cycle {
                    if let Some(trash) = collector.refresh_exclusion(exclusion).await? {
                        collector
                            .delete_local_pack(terrane_format::bucket::PackExclusion {
                                pack_id: trash.pack,
                                cycle: trash.cycle,
                                epoch: trash.epoch,
                            })
                            .await?;
                    }
                } else {
                    collector.delete_local_pack(exclusion).await?;
                }
            }
        }
    }
    if let Some(trash) = collector.retire_one().await? {
        collector
            .delete_local_pack(terrane_format::bucket::PackExclusion {
                pack_id: trash.pack,
                cycle: trash.cycle,
                epoch: trash.epoch,
            })
            .await?;
    }
    Ok(Progress::Swept)
}

fn disconnected() -> Error {
    Error::Io(io::Error::other("collector shutdown signal disconnected"))
}
