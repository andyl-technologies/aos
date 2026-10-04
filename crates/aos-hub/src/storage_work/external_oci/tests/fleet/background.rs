//! Owned production controllers within the confined helper's original window.
//!
//! These tasks use the same database and accepted work client as the router.
//! Joining cancelled Rust tasks says nothing about remote effect settlement.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::db::Database;
use aos_hub_core::fetch::SurfaceProvider;
use aos_hub_core::surface_write::SurfaceWriteProvider;
use serde::Serialize;
use tokio::task::JoinSet;

use super::RemoteStorageWorkClient;

/// Describes registered controllers without asserting completed provider work.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Selection {
    placement_scan: PlacementScanSelection,
    oci_inventory: InventorySelection,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlacementScanSelection {
    interval_seconds: u64,
    maximum_placements: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InventorySelection {
    collector_id: String,
    idempotency_prefix: String,
    maximum_placements: usize,
    dispatch_budget: &'static str,
}

/// Owns the helper's two controller tasks through cancellation and joining.
pub(super) struct Controllers {
    tasks: JoinSet<Result<()>>,
    selection: Selection,
}

impl Controllers {
    /// Starts the production controllers over the router's current work client.
    ///
    /// # Errors
    /// Refuses malformed run identity, invalid uncertainty or an expired window.
    pub(super) fn start(
        db: Arc<Database>,
        work: Arc<RemoteStorageWorkClient>,
        run_id: &str,
        deadline: Instant,
        expires_at: i64,
        uncertainty: i64,
    ) -> Result<Self> {
        ensure!(
            super::hex_digest(run_id, 32)
                && (1..30).contains(&uncertainty)
                && window_open(deadline, expires_at, uncertainty)?,
            "External OCI controller original is invalid or expired"
        );
        let surfaces: Arc<dyn SurfaceProvider> = Arc::new(
            crate::storage_work::HybridSurfaceProvider::new(Arc::clone(&db), Arc::clone(&work)),
        );
        let writers: Arc<dyn SurfaceWriteProvider> = Arc::new(
            crate::storage_work::HybridSurfaceWrites::new(Arc::clone(&db), work),
        );
        let scans = aos_hub_core::placement_scan::PlacementScanController::new(
            Arc::clone(&db),
            Arc::clone(&surfaces),
        )
        .with_writes(writers);
        let inventory = aos_hub_core::oci_inventory_controller::OciProviderInventoryController::new(
            db, surfaces,
        );
        // The same owned run reuses these identities after a real Native restart;
        // the production controller reloads the durable SQL generation/progress.
        let collector_id = format!("external-oci-inventory-{run_id}");
        let idempotency_prefix = collector_id.clone();
        let selection = Selection {
            placement_scan: PlacementScanSelection {
                interval_seconds: 2,
                maximum_placements: 5,
            },
            oci_inventory: InventorySelection {
                collector_id: collector_id.clone(),
                idempotency_prefix: idempotency_prefix.clone(),
                maximum_placements: 100,
                dispatch_budget: "native",
            },
        };
        let mut tasks = JoinSet::new();
        tasks.spawn(run_owned(deadline, expires_at, uncertainty, async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            loop {
                tick.tick().await;
                if !window_open(deadline, expires_at, uncertainty)? {
                    return Ok(());
                }
                if let Err(error) = scans.run_due(5).await {
                    tracing::warn!(error = %format!("{error:#}"), "External helper placement scan pass failed");
                }
            }
        }));
        tasks.spawn(run_owned(deadline, expires_at, uncertainty, async move {
            let mut continuation: Option<String> = None;
            loop {
                if !window_open(deadline, expires_at, uncertainty)? {
                    return Ok(());
                }
                let now = aos_hub_core::clock::now_unix_secs();
                let delay = match inventory
                    .run_due_bounded(
                        &collector_id,
                        &format!("{idempotency_prefix}-{}", now / 60),
                        now,
                        100,
                        continuation.as_deref(),
                        aos_hub_core::oci_inventory_controller::NATIVE_OCI_INVENTORY_DISPATCH_BUDGET,
                    )
                    .await
                {
                    Ok(stats) => {
                        continuation = stats.continuation;
                        if continuation.is_some() { 1 } else { 60 }
                    }
                    Err(error) => {
                        tracing::warn!(error = %format!("{error:#}"), "External helper OCI inventory pass failed");
                        5
                    }
                };
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        }));
        Ok(Self { tasks, selection })
    }

    /// Returns the registered task choices, independently of provider progress.
    pub(super) fn selection(&self) -> &Selection {
        &self.selection
    }

    /// Observes a controller's cutoff or unexpected failure while serving.
    ///
    /// # Errors
    /// Reports task failure, a panic or an absent controller task.
    pub(super) async fn next_exit(&mut self) -> Result<()> {
        self.tasks
            .join_next()
            .await
            .context("External helper controllers disappeared")??
    }

    /// Aborts and joins every Rust task without claiming remote settlement.
    ///
    /// # Errors
    /// Reports a controller error or panic after every remaining task is joined.
    pub(super) async fn stop(&mut self) -> Result<()> {
        self.tasks.abort_all();
        let mut failure = None;
        while let Some(result) = self.tasks.join_next().await {
            let error = match result {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error),
                Err(error) if error.is_cancelled() => None,
                Err(error) => Some(error.into()),
            };
            if failure.is_none() {
                failure = error;
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }
}

fn window_open(deadline: Instant, expires_at: i64, uncertainty: i64) -> Result<bool> {
    let latest = aos_hub_core::clock::now_unix_secs()
        .checked_add(uncertainty)
        .context("External helper controller clock overflow")?;
    Ok(Instant::now() < deadline && latest < expires_at)
}

async fn run_owned(
    deadline: Instant,
    expires_at: i64,
    uncertainty: i64,
    operation: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    let cutoff = async {
        loop {
            if !window_open(deadline, expires_at, uncertainty)? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::select! {
        biased;
        result = cutoff => result,
        result = operation => result,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[tokio::test]
    async fn original_cutoff_cancels_a_pending_rust_controller_without_settlement_claim() {
        struct Pending(Arc<AtomicBool>);

        impl std::future::Future for Pending {
            type Output = Result<()>;

            fn poll(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<()>> {
                std::task::Poll::Pending
            }
        }

        impl Drop for Pending {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        run_owned(
            Instant::now() + Duration::from_millis(20),
            aos_hub_core::clock::now_unix_secs() + 600,
            2,
            Pending(Arc::clone(&dropped)),
        )
        .await
        .unwrap();

        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn expired_original_cannot_register_controllers() {
        let db = Arc::new(Database::open_in_memory().await.unwrap());
        let work = Arc::new(
            RemoteStorageWorkClient::new(
                "https://localhost:4673",
                "deployment-1".into(),
                &[11; 32],
            )
            .unwrap(),
        );
        let now = aos_hub_core::clock::now_unix_secs();

        assert!(Controllers::start(
            Arc::clone(&db),
            Arc::clone(&work),
            &"1".repeat(32),
            Instant::now(),
            now + 600,
            2,
        )
        .is_err());
        assert!(Controllers::start(
            db,
            work,
            &"1".repeat(32),
            Instant::now() + Duration::from_secs(30),
            now + 2,
            2,
        )
        .is_err());
    }

    #[tokio::test]
    async fn stop_joins_every_registered_controller_and_restart_keeps_collector_identity() {
        let db = Arc::new(Database::open_in_memory().await.unwrap());
        let work = Arc::new(
            RemoteStorageWorkClient::new(
                "https://localhost:4673",
                "deployment-1".into(),
                &[11; 32],
            )
            .unwrap(),
        );
        let start = || {
            Controllers::start(
                Arc::clone(&db),
                Arc::clone(&work),
                &"1".repeat(32),
                Instant::now() + Duration::from_secs(30),
                aos_hub_core::clock::now_unix_secs() + 600,
                2,
            )
            .unwrap()
        };
        let mut first = start();
        assert_eq!(first.tasks.len(), 2);
        let selection = serde_json::to_value(first.selection()).unwrap();
        tokio::task::yield_now().await;
        first.stop().await.unwrap();
        assert!(first.tasks.is_empty());

        let mut restarted = start();
        assert_eq!(
            serde_json::to_value(restarted.selection()).unwrap(),
            selection
        );
        restarted.stop().await.unwrap();
        assert!(restarted.tasks.is_empty());
    }
}
