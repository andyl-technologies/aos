//! Jobs mutations in the administration capability.

use super::*;

impl RpcService {
    /// Returns the latest snapshot of an operation for unary polling.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, validation, not-found, or database error.
    pub async fn watch_operation(
        &self,
        auth: Option<&str>,
        req: pb::WatchOperationRequest,
    ) -> Result<pb::WatchOperationResponse, RpcError> {
        if req.timeout_seconds < 0 || req.timeout_seconds > 3600 {
            return Err(RpcError::invalid(
                "timeout_seconds must be between zero and 3600",
            ));
        }
        let after_version = if req.after_resource_version.is_empty() {
            None
        } else {
            Some(
                req.after_resource_version
                    .parse::<i64>()
                    .ok()
                    .filter(|version| *version > 0)
                    .ok_or_else(|| {
                        RpcError::invalid("afterResourceVersion must be a positive integer")
                    })?,
            )
        };
        let started = clock::Instant::now();
        let timeout = std::time::Duration::from_secs(req.timeout_seconds as u64);
        loop {
            let operation = self.authorized_operation(auth, &req.operation_id).await?;
            let terminal = matches!(
                operation.state.as_str(),
                "succeeded" | "failed" | "cancelled"
            );
            let changed =
                after_version.map_or(true, |version| operation.resource_version > version);
            if changed || terminal || started.elapsed() >= timeout {
                return Ok(pb::WatchOperationResponse {
                    operation: Some(self.operation_detail(&operation).await?),
                    terminal,
                });
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            clock::sleep(remaining.min(std::time::Duration::from_millis(200))).await;
        }
    }

    /// Cancels pending or running work with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, stale-version, state, or database error.
    pub async fn cancel_operation(
        &self,
        auth: Option<&str>,
        req: pb::MutateOperationRequest,
    ) -> Result<pb::OperationDetailResponse, RpcError> {
        let operation = self
            .authorized_operation_admin(auth, &req.operation_id)
            .await?;
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let expected = req
            .expected_resource_version
            .parse::<i64>()
            .ok()
            .filter(|version| *version > 0)
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion must be positive"))?;
        let updated = self
            .db
            .mutate_topology_operation(
                &operation.operation_id,
                expected,
                "cancel",
                &req.idempotency_key,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok(pb::OperationDetailResponse {
            operation: Some(self.operation_detail(&updated).await?),
        })
    }

    /// Starts a new attempt for failed or cancelled work.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, stale-version, state, or database error.
    pub async fn retry_operation(
        &self,
        auth: Option<&str>,
        req: pb::MutateOperationRequest,
    ) -> Result<pb::OperationDetailResponse, RpcError> {
        let operation = self
            .authorized_operation_admin(auth, &req.operation_id)
            .await?;
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let expected = req
            .expected_resource_version
            .parse::<i64>()
            .ok()
            .filter(|version| *version > 0)
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion must be positive"))?;
        let updated = self
            .db
            .mutate_topology_operation(
                &operation.operation_id,
                expected,
                "retry",
                &req.idempotency_key,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        if matches!(
            updated.operation_kind.as_str(),
            "scan_placement" | "replicate_placement" | "repair_placement" | "delete_registry"
        ) {
            self.topology_probes
                .wake_controller()
                .await
                .map_err(RpcError::internal)?;
        }
        Ok(pb::OperationDetailResponse {
            operation: Some(self.operation_detail(&updated).await?),
        })
    }
}
