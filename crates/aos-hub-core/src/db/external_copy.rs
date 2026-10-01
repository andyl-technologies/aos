//! Read-only projection of an actual retained placement-copy controller claim.
//!
//! Claim tokens are not retry identities or physical effect evidence. Every
//! fresh copy permission reloads this projection and the sealed stable targets;
//! provider dispatch remains subject to its independent permanent guard floor.

use anyhow::{ensure, Context, Result};

use crate::storage_authority::{external_object::copy::control::CopyClaim, lease::LeaseInteger};

use super::{Database, TopologyOperationRecord};

impl Database {
    /// Loads only the live claim owned by an exact running copy operation.
    ///
    /// This method changes no SQL state and creates no replacement claim. A
    /// metadata caller must still resolve both sealed stable targets to their
    /// actual rows before constructing placement pins and a signed work plan.
    ///
    /// # Errors
    /// Refuses malformed tokens, another operation family, stale/replaced claims,
    /// clock rollback behind the last heartbeat or a database read failure.
    pub async fn placement_copy_claim(
        &self,
        operation: &TopologyOperationRecord,
        claim_token: &str,
        now: i64,
    ) -> Result<CopyClaim> {
        ensure!(
            matches!(
                operation.operation_kind.as_str(),
                "replicate_placement" | "repair_placement"
            ) && operation.state == "running"
                && operation.resource_version > 0
                && now >= 0
                && claim_token.len() == 32
                && claim_token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid retained placement-copy claim selector"
        );
        let row = self
            .backend
            .query_opt(
                "SELECT claim.lease_expires_at
                 FROM placement_scan_claims claim
                 JOIN topology_operations operation
                   ON operation.operation_id = claim.operation_id
                 WHERE claim.operation_id = ?1 AND claim.claim_token = ?2
                   AND claim.operation_resource_version = ?3
                   AND operation.resource_version = ?3
                   AND operation.state = 'running' AND operation.operation_kind = ?4
                   AND claim.heartbeat_at <= ?5 AND claim.lease_expires_at > ?5",
                &vals![
                    operation.operation_id,
                    claim_token,
                    operation.resource_version,
                    operation.operation_kind,
                    now
                ],
            )
            .await?
            .context("placement-copy controller claim is absent or stale")?;
        Ok(CopyClaim {
            operation_resource_version: LeaseInteger::new(operation.resource_version)?,
            claim_token: claim_token.into(),
            expires_at: LeaseInteger::new(row.get(0)?)?,
        })
    }
}
