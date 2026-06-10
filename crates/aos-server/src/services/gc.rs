//! ConnectRPC implementation of `GcService`.

use std::process::Stdio;
use std::sync::Arc;

use connectrpc::{ConnectError, Context, ErrorCode};
use tokio::process::Command;

use aos_proto::aos::gc::v1::*;

use crate::evict;
use crate::routes::AppState;
use crate::services;

/// ConnectRPC GC service backed by the shared `AppState`.
pub struct GcServiceImpl {
    pub state: Arc<AppState>,
}

impl GcService for GcServiceImpl {
    async fn collect(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<GcRequestView<'static>>,
    ) -> Result<(GcResponse, Context), ConnectError> {
        let view: &str = req.view;
        let dry_run: bool = req.dry_run;
        let collect_store: bool = req.collect_store;
        let max_size: Option<u64> = req.max_size;

        if self.state.views.get_view(view).is_none() {
            return Err(ConnectError::new(ErrorCode::NotFound, "unknown view"));
        }
        services::require_rpc_permission(&ctx, &self.state, view, "build")?;

        // Step 1: Expire TTL roots.
        let expired = evict::expire_ttl_roots(&self.state.views, view)
            .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("TTL expiry: {e}")))?;

        // Step 2: Budget-based eviction if max_size is specified.
        let mut evicted_candidates = Vec::new();
        if let Some(budget) = max_size {
            let candidates = evict::evict_until_budget(
                &self.state.store,
                &self.state.views,
                view,
                budget,
                dry_run,
            )
            .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("eviction: {e}")))?;

            evicted_candidates = candidates
                .iter()
                .map(|c| EvictionCandidate {
                    hash: c.hash.clone(),
                    store_path: c.store_path.clone(),
                    unique_size: c.unique_size,
                    age_days: c.age_days,
                    score: c.score,
                    ..Default::default()
                })
                .collect();
        }

        // Step 3: Run `nix-store --gc` if collect_store is true and not dry run.
        let collected_bytes = if collect_store && !dry_run {
            let child = Command::new("nix-store")
                .arg("--gc")
                .arg("--print-freed")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| {
                    ConnectError::new(ErrorCode::Internal, format!("spawning nix-store --gc: {e}"))
                })?;

            let output = child.wait_with_output().await.map_err(|e| {
                ConnectError::new(
                    ErrorCode::Internal,
                    format!("waiting for nix-store --gc: {e}"),
                )
            })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ConnectError::new(
                    ErrorCode::Internal,
                    format!("nix-store --gc failed: {stderr}"),
                ));
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            let freed: u64 = stdout
                .lines()
                .last()
                .and_then(|line| line.trim().parse().ok())
                .unwrap_or(0);

            Some(freed)
        } else {
            None
        };

        let evicted_count = evicted_candidates.len() as u64;

        Ok((
            GcResponse {
                expired: expired.len() as u64,
                evicted: evicted_count,
                eviction_candidates: evicted_candidates,
                dry_run,
                collected_bytes,
                ..Default::default()
            },
            ctx,
        ))
    }
}
