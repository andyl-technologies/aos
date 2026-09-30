//! Permanent binding identities and bounded validation of deletion history.
//!
//! A reservation survives deletion of its binding. Numeric row identifiers,
//! resource versions, and timestamps cannot establish a new binding lifetime.

use anyhow::{ensure, Context as _, Result};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::{validate_key_bytes, Database};

const HISTORY_PAGE_ROWS: usize = 128;
const HISTORY_DOCUMENT_BYTES: usize = 4096;

/// The permanent reservation of one storage binding's stable identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingIdentityReservation {
    /// Stable binding identity, retained even after the binding is deleted.
    pub stable_id: String,
    /// Canonical random UUID of the reservation's single lifetime.
    pub reservation_id: String,
    /// Informational creation time, never used as an identity or replay fence.
    pub reserved_at: i64,
}

impl BindingIdentityReservation {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_key_bytes(&self.stable_id, "reserved binding stable identity", 64)?;
        validate_reservation_id(&self.reservation_id)?;
        ensure!(
            self.reserved_at >= 0,
            "binding reservation time is negative"
        );
        Ok(())
    }
}

fn validate_reservation_id(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value).context("binding reservation UUID is malformed")?;
    ensure!(
        parsed.to_string() == value && parsed.get_version() == Some(uuid::Version::Random),
        "binding reservation must have a canonical random UUID"
    );
    Ok(())
}

/// Immutable private preconditions for deleting one binding lifetime.
#[derive(Debug, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingDeletePlanInput {
    pub(crate) stable_id: String,
    pub(crate) owner_scope_key: String,
    pub(crate) org_id: Option<i64>,
    pub(crate) binding_db_id: i64,
    pub(crate) baseline_resource_version: i64,
    /// Missing only in plans predating permanent binding reservations.
    #[serde(default)]
    pub(crate) reservation_id: Option<String>,
}

/// Decoded deletion provenance; original canonical plan bytes are never rewritten.
pub(crate) struct BindingDeleteHistory {
    pub(crate) stable_id: String,
    reservation_id: Option<String>,
    was_claimed: bool,
    positively_deleted: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteResult {
    #[serde(default)]
    deleted: bool,
}

pub(crate) fn decode_binding_delete_history(
    input_json: &str,
    applied_at: Option<i64>,
    apply_idempotency_key: Option<&str>,
    apply_result_json: Option<&str>,
) -> Result<BindingDeleteHistory> {
    ensure!(
        input_json.len() <= HISTORY_DOCUMENT_BYTES,
        "binding deletion history exceeds its document bound"
    );
    let input: BindingDeletePlanInput =
        serde_json::from_str(input_json).context("binding deletion original is malformed")?;
    validate_key_bytes(&input.stable_id, "deleted binding stable identity", 64)?;
    validate_key_bytes(&input.owner_scope_key, "deleted binding owner", 64)?;
    ensure!(
        input.binding_db_id > 0
            && input.baseline_resource_version > 0
            && input.org_id.is_none_or(|id| id > 0),
        "binding deletion original has invalid relational pins"
    );
    if let Some(reservation_id) = &input.reservation_id {
        validate_reservation_id(reservation_id)?;
    }
    if let Some(key) = apply_idempotency_key {
        validate_key_bytes(key, "binding deletion apply key", 128)?;
    }
    ensure!(
        applied_at.is_none_or(|time| time >= 0),
        "binding deletion completion time is negative"
    );
    let positively_deleted = if let Some(result_json) = apply_result_json {
        ensure!(
            result_json.len() <= HISTORY_DOCUMENT_BYTES && applied_at.is_some(),
            "binding deletion result is unbounded or lacks completion"
        );
        let result: DeleteResult =
            serde_json::from_str(result_json).context("binding deletion result is malformed")?;
        result.deleted
    } else {
        false
    };
    Ok(BindingDeleteHistory {
        stable_id: input.stable_id,
        reservation_id: input.reservation_id,
        was_claimed: apply_idempotency_key.is_some() || applied_at.is_some(),
        positively_deleted,
    })
}

pub(crate) fn validate_binding_delete_history(
    history: &BindingDeleteHistory,
    live_reservation: Option<&BindingIdentityReservation>,
) -> Result<()> {
    let Some(reservation) = live_reservation else {
        return Ok(());
    };
    reservation.validate()?;
    ensure!(
        history.stable_id == reservation.stable_id,
        "binding deletion history selects another identity"
    );
    ensure!(
        !history.positively_deleted,
        "live binding reuses a positively deleted identity; explicit reconciliation is required"
    );
    if history.was_claimed {
        ensure!(
            history.reservation_id.as_deref() == Some(reservation.reservation_id.as_str()),
            "live binding has ambiguous claimed deletion history; explicit reconciliation is required"
        );
    }
    Ok(())
}

/// Verifies the confirmation hash of an unchanged private binding delete plan.
///
/// # Errors
/// Rejects oversized originals or an absent or changed canonical confirmation.
pub fn validate_binding_identity_plan_confirmation(
    input_json: &str,
    confirmation_hash: Option<&str>,
) -> Result<()> {
    ensure!(
        input_json.len() <= HISTORY_DOCUMENT_BYTES,
        "binding deletion history exceeds its document bound"
    );
    let expected = hex::encode(Sha256::digest(input_json.as_bytes()));
    ensure!(
        confirmation_hash == Some(expected.as_str()),
        "binding deletion original confirmation differs"
    );
    Ok(())
}

/// Checks retained deletion provenance against an optional live binding identity.
///
/// Archive replay uses this bounded, pure check without initializing a database,
/// rewriting an original plan, or authorizing restored provider work. A positive
/// deletion cannot share a live identity; unresolved claims require their exact
/// original permanent reservation UUID.
///
/// # Errors
/// Rejects oversized or malformed closed documents, invalid reservation data,
/// or an unsafe or ambiguous live binding lifetime.
pub fn validate_binding_identity_snapshot_history(
    input_json: &str,
    applied_at: Option<i64>,
    apply_idempotency_key: Option<&str>,
    apply_result_json: Option<&str>,
    live_reservation: Option<&BindingIdentityReservation>,
) -> Result<()> {
    let history = decode_binding_delete_history(
        input_json,
        applied_at,
        apply_idempotency_key,
        apply_result_json,
    )?;
    validate_binding_delete_history(&history, live_reservation)
}

impl Database {
    /// Deletes a binding under its original permanent identity and version.
    ///
    /// # Errors
    /// Rejects changed identity/version, live blockers, or database failure.
    pub async fn delete_topology_binding_checked(
        &self,
        binding: &super::BindingRecord,
        reservation_id: &str,
        expected_resource_version: i64,
    ) -> Result<bool> {
        validate_reservation_id(reservation_id)?;
        self.delete_topology_binding_inner(binding, reservation_id, expected_resource_version)
            .await
    }

    /// Loads a permanent binding identity without resolving provider material.
    ///
    /// # Errors
    /// Rejects malformed stored identity data or a database failure.
    pub async fn binding_identity_reservation(
        &self,
        stable_id: &str,
    ) -> Result<Option<BindingIdentityReservation>> {
        let row = self
            .backend
            .query_opt(
                "SELECT stable_id, reservation_id, reserved_at
             FROM binding_identity_reservations WHERE stable_id = ?1",
                &vals![stable_id],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let reservation = BindingIdentityReservation {
            stable_id: row.get(0)?,
            reservation_id: row.get(1)?,
            reserved_at: row.get(2)?,
        };
        reservation.validate()?;
        ensure!(
            reservation.stable_id == stable_id,
            "binding reservation selects another identity"
        );
        Ok(Some(reservation))
    }

    async fn retain_binding_identity(
        &self,
        stable_id: &str,
        reserved_at: i64,
    ) -> Result<BindingIdentityReservation> {
        validate_key_bytes(stable_id, "reserved binding stable identity", 64)?;
        ensure!(reserved_at >= 0, "binding reservation time is negative");
        let reservation_id = uuid::Uuid::new_v4().to_string();
        self.backend
            .execute(
                "INSERT INTO binding_identity_reservations(stable_id, reservation_id, reserved_at)
             SELECT ?1, ?2, ?3 WHERE NOT EXISTS (
               SELECT 1 FROM binding_identity_reservations WHERE stable_id = ?1)",
                &vals![stable_id, reservation_id, reserved_at],
            )
            .await?;
        self.binding_identity_reservation(stable_id)
            .await?
            .context("retained binding reservation disappeared")
    }

    /// Retains known binding lifetimes and rejects ambiguous legacy deletions.
    ///
    /// Startup and archive activation run this initializer before exposing work.
    /// It uses bounded keyset pages and closed documents, preserves original
    /// plan bytes, and never infers identity from equal times or row numbers.
    /// Offline archive verification does not call this mutating initializer.
    ///
    /// # Errors
    /// Rejects malformed originals, positively deleted or ambiguous claimed
    /// identities that remain live, inconsistent reservations, or database failure.
    pub async fn backfill_binding_identity_reservations(&self) -> Result<()> {
        ensure!(
            self.backend
                .query_opt(
                    "SELECT 1 FROM topology_plans WHERE plan_kind = 'delete_binding'
               AND (length(input_versions_json) > 4096 OR length(apply_result_json) > 4096)
             LIMIT 1",
                    &[],
                )
                .await?
                .is_none(),
            "binding deletion history exceeds its document bound"
        );

        let mut cursor = String::new();
        loop {
            let rows = self
                .backend
                .query(
                    "SELECT stable_id, created_at FROM bindings WHERE stable_id > ?1
                 ORDER BY stable_id LIMIT 128",
                    &vals![&cursor],
                )
                .await?;
            for row in &rows {
                let stable_id: String = row.get(0)?;
                self.retain_binding_identity(&stable_id, row.get(1)?)
                    .await?;
                cursor = stable_id;
            }
            if rows.len() < HISTORY_PAGE_ROWS {
                break;
            }
        }

        self.check_binding_identity_history(true).await
    }

    /// Checks permanent identities and deletion history without mutating SQL.
    ///
    /// Operator activation uses this check even when the schema marker is
    /// current: a failed initializer must not grant authority from table presence.
    ///
    /// # Errors
    /// Rejects missing or malformed reservations, unsafe deletion provenance,
    /// oversized originals, or database failure.
    pub async fn validate_binding_identity_reservations(&self) -> Result<()> {
        let mut cursor = String::new();
        loop {
            let rows = self
                .backend
                .query(
                    "SELECT b.stable_id, r.reservation_id, r.reserved_at
                 FROM bindings b LEFT JOIN binding_identity_reservations r
                   ON r.stable_id = b.stable_id
                 WHERE b.stable_id > ?1 ORDER BY b.stable_id LIMIT 128",
                    &vals![&cursor],
                )
                .await?;
            for row in &rows {
                let stable_id: String = row.get(0)?;
                let reservation_id: Option<String> = row.get(1)?;
                let reserved_at: Option<i64> = row.get(2)?;
                BindingIdentityReservation {
                    stable_id: stable_id.clone(),
                    reservation_id: reservation_id
                        .context("live binding lacks permanent identity")?,
                    reserved_at: reserved_at.context("live binding lacks reservation metadata")?,
                }
                .validate()?;
                cursor = stable_id;
            }
            if rows.len() < HISTORY_PAGE_ROWS {
                break;
            }
        }
        self.check_binding_identity_history(false).await
    }

    async fn check_binding_identity_history(&self, retain_missing: bool) -> Result<()> {
        ensure!(
            self.backend
                .query_opt(
                    "SELECT 1 FROM topology_plans WHERE plan_kind = 'delete_binding'
               AND (length(input_versions_json) > 4096 OR length(apply_result_json) > 4096)
             LIMIT 1",
                    &[],
                )
                .await?
                .is_none(),
            "binding deletion history exceeds its document bound"
        );
        let mut cursor = String::new();
        loop {
            let rows = self
                .backend
                .query(
                    "SELECT plan_id, input_versions_json, created_at, applied_at,
                        apply_idempotency_key, apply_result_json, confirmation_hash
                 FROM topology_plans WHERE plan_kind = 'delete_binding' AND plan_id > ?1
                 ORDER BY plan_id LIMIT 128",
                    &vals![&cursor],
                )
                .await?;
            for row in &rows {
                let plan_id: String = row.get(0)?;
                validate_key_bytes(&plan_id, "binding deletion plan identity", 64)?;
                let original: String = row.get(1)?;
                let confirmation: Option<String> = row.get(6)?;
                validate_binding_identity_plan_confirmation(&original, confirmation.as_deref())?;
                let apply_key: Option<String> = row.get(4)?;
                let result: Option<String> = row.get(5)?;
                let history = decode_binding_delete_history(
                    &original,
                    row.get(3)?,
                    apply_key.as_deref(),
                    result.as_deref(),
                )
                .with_context(|| format!("checking binding deletion plan {plan_id}"))?;
                let reservation = if retain_missing {
                    self.retain_binding_identity(&history.stable_id, row.get(2)?)
                        .await?
                } else {
                    self.binding_identity_reservation(&history.stable_id)
                        .await?
                        .context("deletion history lacks permanent binding reservation")?
                };
                if self
                    .binding_by_stable_id(&history.stable_id)
                    .await?
                    .is_some()
                {
                    validate_binding_delete_history(&history, Some(&reservation))?;
                }
                cursor = plan_id;
            }
            if rows.len() < HISTORY_PAGE_ROWS {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
