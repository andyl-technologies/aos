//! Scheduled full-Mirror selection shared by Native serving and confined fixtures.
//!
//! Each pass reloads current mirror sources and runs the existing local or
//! Hybrid sync executor. Pull-through mirrors stay on their request path.
//! Per-registry errors are logged without ending the scheduling loop; callers
//! own the interval and cancellation lifetime of a pass.

use std::sync::Arc;

use crate::db::{Database, MirrorSource};

/// Syncs every full mirror whose schedule is due.
///
/// A full mirror is *due* when it has never synced or `schedule_secs` have
/// elapsed since its last attempt. Each sync verifies the upstream surface and
/// copies it into the local binding; a verification failure is recorded and
/// logged, never fatal to the loop.
pub async fn sync_due_mirrors(
    db: &Arc<Database>,
    work: Option<&Arc<crate::storage_work::RemoteStorageWorkClient>>,
    now: i64,
) {
    let sources = match db.list_mirror_sources().await {
        Ok(sources) => sources,
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), "listing mirror sources");
            return;
        }
    };
    for (registry_id, source) in sources {
        if !is_due(&source, now) {
            continue;
        }
        let registry = match db.registry_by_id(registry_id).await {
            Ok(Some(registry)) => registry,
            Ok(None) => continue,
            Err(err) => {
                tracing::warn!(error = %format!("{err:#}"), "loading mirror registry");
                continue;
            }
        };
        let result = match work {
            Some(work) => crate::mirror::hybrid::sync_full_mirror(db, work, &registry).await,
            None => crate::mirror::sync_full_mirror(db, &registry).await,
        };
        match result {
            Ok(result) => tracing::info!(
                slug = %registry.slug,
                commit = %result.commit,
                files = result.files_copied,
                "full mirror synced"
            ),
            Err(err) => tracing::warn!(
                slug = %registry.slug,
                error = %format!("{err:#}"),
                "full mirror sync failed"
            ),
        }
    }
}

// Pull-through sources are served on demand. A failed full-sync attempt still
// supplies the last-attempt timestamp used by the existing schedule.
fn is_due(source: &MirrorSource, now: i64) -> bool {
    source.mode == "full"
        && match source.last_sync_at {
            None => true,
            Some(last) => now - last >= source.schedule_secs,
        }
}

#[cfg(test)]
mod tests;
