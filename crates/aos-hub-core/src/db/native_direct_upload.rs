//! Durable Native-only signed multipart progress in the main Hub database.
//!
//! A journal update and its logical target writes share one checked transaction.
//! The caller owns provider execution and typed state validation. The journal
//! contains public identifiers and progress, never credentials or signed URLs.

use anyhow::{ensure, Context, Result};

use super::Database;
use crate::backend::{CheckedStatement, Statement};
use crate::value::Row;

const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const COLUMNS: &str = "session_id, deployment_id, principal_id, client_operation_id, \
    oci_upload_id, state, source_sha256, declared_size, verified_sha256, verified_size, \
    materialization_placement_id, materialization_binding_id, state_json, resource_version";

/// Stores one Native-owned direct-upload original and its durable progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDirectUploadRecord {
    /// Globally unique server-assigned session identity.
    pub session_id: String,
    /// Deployment that owns this session.
    pub deployment_id: String,
    /// Immutable authenticated account identity.
    pub principal_id: String,
    /// Caller-selected idempotency identity scoped to deployment and account.
    pub client_operation_id: String,
    /// Original OCI allocation, when this upload supplies an OCI blob.
    pub oci_upload_id: Option<String>,
    /// Durable provider and publication phase.
    pub state: String,
    /// Original declared SHA-256, as lowercase hexadecimal.
    pub source_sha256: String,
    /// Original declared object length.
    pub declared_size: i64,
    /// Full object SHA-256 computed by the configured verifier.
    pub verified_sha256: Option<String>,
    /// Full object length counted by the configured verifier.
    pub verified_size: Option<i64>,
    /// Placement positively materialized for OCI completion.
    pub materialization_placement_id: Option<i64>,
    /// Binding positively materialized for OCI completion.
    pub materialization_binding_id: Option<i64>,
    /// Typed owner, provider and part progress without secret material or URLs.
    pub state_json: String,
    /// Journal CAS revision, distinct from public logical request versions.
    pub resource_version: i64,
}

impl NativeDirectUploadRecord {
    fn validate(&self) -> Result<()> {
        for (identity, maximum) in [
            (&self.session_id, 64),
            (&self.deployment_id, 255),
            (&self.principal_id, 255),
            (&self.client_operation_id, 64),
        ] {
            ensure!(
                !identity.is_empty()
                    && identity.len() <= maximum
                    && !identity.chars().any(char::is_control),
                "Native direct upload identity is invalid"
            );
        }
        if let Some(id) = &self.oci_upload_id {
            ensure!(
                !id.is_empty() && id.len() <= 64,
                "Native OCI upload identity is invalid"
            );
        }
        ensure!(
            matches!(
                self.state.as_str(),
                "creating"
                    | "uploading"
                    | "completing"
                    | "verified"
                    | "committed"
                    | "aborting"
                    | "aborted"
                    | "blocked_unknown"
            ) && crate::direct_upload::valid_direct_digest(&self.source_sha256)
                && (0..=i64::try_from(crate::direct_upload::MAX_DIRECT_OBJECT_BYTES)?)
                    .contains(&self.declared_size)
                && self.resource_version > 0,
            "Native direct upload state is invalid"
        );
        ensure!(
            match (&self.verified_sha256, self.verified_size) {
                (None, None) => self.state != "committed",
                (Some(hash), Some(size)) =>
                    hash == &self.source_sha256 && size == self.declared_size,
                _ => false,
            },
            "Native direct upload verification differs from its original"
        );
        ensure!(
            match (
                self.materialization_placement_id,
                self.materialization_binding_id
            ) {
                (None, None) => self.state != "committed" || self.oci_upload_id.is_none(),
                (Some(placement), Some(binding)) => placement > 0 && binding > 0,
                _ => false,
            },
            "Native direct upload materialization is incomplete"
        );
        ensure!(
            !self.state_json.is_empty() && self.state_json.len() <= MAX_STATE_BYTES,
            "Native direct upload progress exceeds its bound"
        );
        let state: serde_json::Value = serde_json::from_str(&self.state_json)
            .map_err(|_| anyhow::anyhow!("Native direct upload progress is malformed"))?;
        ensure!(
            state.is_object(),
            "Native direct upload progress is not an object"
        );
        Ok(())
    }
}

fn decode(row: &Row) -> Result<NativeDirectUploadRecord> {
    let record = NativeDirectUploadRecord {
        session_id: row.get(0)?,
        deployment_id: row.get(1)?,
        principal_id: row.get(2)?,
        client_operation_id: row.get(3)?,
        oci_upload_id: row.get(4)?,
        state: row.get(5)?,
        source_sha256: row.get(6)?,
        declared_size: row.get(7)?,
        verified_sha256: row.get(8)?,
        verified_size: row.get(9)?,
        materialization_placement_id: row.get(10)?,
        materialization_binding_id: row.get(11)?,
        state_json: row.get(12)?,
        resource_version: row.get(13)?,
    };
    record.validate()?;
    Ok(record)
}

impl Database {
    /// Reads a session only within its owning deployment.
    ///
    /// # Errors
    /// Returns an error for database failure or malformed retained progress.
    pub async fn native_direct_upload(
        &self,
        deployment: &str,
        session: &str,
    ) -> Result<Option<NativeDirectUploadRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM native_direct_uploads \
            WHERE deployment_id = ?1 AND session_id = ?2"
                ),
                &vals![deployment, session],
            )
            .await?
            .as_ref()
            .map(decode)
            .transpose()
    }

    /// Finds a retained caller operation within the original account and deployment.
    ///
    /// # Errors
    /// Returns an error for database failure or malformed retained progress.
    pub async fn native_direct_upload_by_operation(
        &self,
        deployment: &str,
        principal: &str,
        operation: &str,
    ) -> Result<Option<NativeDirectUploadRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM native_direct_uploads \
            WHERE deployment_id = ?1 AND principal_id = ?2 AND client_operation_id = ?3"
                ),
                &vals![deployment, principal, operation],
            )
            .await?
            .as_ref()
            .map(decode)
            .transpose()
    }

    /// Reserves a new original, replaying only an exact unchanged initial row.
    ///
    /// # Errors
    /// Rejects invalid progress, conflicting session or operation identities,
    /// changed replays, a noninitial revision, or database failure.
    pub async fn create_native_direct_upload(
        &self,
        record: &NativeDirectUploadRecord,
    ) -> Result<NativeDirectUploadRecord> {
        record.validate()?;
        ensure!(
            record.resource_version == 1,
            "Native direct upload must start at revision one"
        );
        let mut statements = Vec::new();
        if let Some(upload) = &record.oci_upload_id {
            // Both runtime journals lock this allocation before their separate
            // ownership check. The later statement gets a fresh SQL snapshot
            // after a concurrent owner's transaction releases the row lock.
            statements.push(Statement::new(
                "UPDATE oci_upload_sessions SET resource_version = resource_version WHERE id = ?1",
                vals![upload],
            ).expecting(1));
        }
        // This nullable identity also appears against a legacy text column.
        // Type it explicitly before PostgreSQL infers the two SQL contexts.
        statements.push(
            Statement::new(
                format!(
                    "INSERT INTO native_direct_uploads ({COLUMNS}) \
                SELECT ?1, ?2, ?3, ?4, CAST(?5 AS TEXT), ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14 \
                WHERE NOT EXISTS (SELECT 1 FROM direct_upload_sessions legacy \
                    WHERE legacy.state <> 'aborted' \
                      AND (legacy.session_id = ?1 OR legacy.oci_upload_id = CAST(?5 AS TEXT))) \
                ON CONFLICT(deployment_id, principal_id, client_operation_id) DO NOTHING"
                ),
                vals![
                    &record.session_id,
                    &record.deployment_id,
                    &record.principal_id,
                    &record.client_operation_id,
                    record.oci_upload_id.as_deref(),
                    &record.state,
                    &record.source_sha256,
                    record.declared_size,
                    record.verified_sha256.as_deref(),
                    record.verified_size,
                    record.materialization_placement_id,
                    record.materialization_binding_id,
                    &record.state_json,
                    record.resource_version
                ],
            )
            .unchecked(),
        );
        self.backend.checked_batch(&statements).await?;
        let retained = self
            .native_direct_upload_by_operation(
                &record.deployment_id,
                &record.principal_id,
                &record.client_operation_id,
            )
            .await?
            .context("Native direct upload original is unavailable")?;
        ensure!(
            &retained == record,
            "Native direct upload original conflicts with replay"
        );
        Ok(retained)
    }

    /// Replaces progress and commits target writes under one journal CAS.
    ///
    /// The journal CAS precedes target statements so OCI completion can check
    /// the verified scalar fields inside the same transaction. A failed target
    /// or stale CAS rolls back every statement, including the journal update.
    ///
    /// # Errors
    /// Rejects invalid progress, changed originals, stale or overflowing revisions,
    /// target row-count failures, or database failure.
    pub async fn replace_native_direct_upload(
        &self,
        record: &NativeDirectUploadRecord,
        expected_version: i64,
        targets: Vec<CheckedStatement>,
    ) -> Result<NativeDirectUploadRecord> {
        record.validate()?;
        ensure!(
            expected_version > 0
                && expected_version.checked_add(1) == Some(record.resource_version),
            "Native direct upload revision is invalid"
        );
        let update = Statement::new(
            "UPDATE native_direct_uploads SET state = ?1, verified_sha256 = ?2, verified_size = ?3,
                materialization_placement_id = ?4, materialization_binding_id = ?5,
                state_json = ?6, resource_version = ?7
             WHERE deployment_id = ?8 AND session_id = ?9 AND resource_version = ?10
                AND principal_id = ?11 AND client_operation_id = ?12
                AND source_sha256 = ?13 AND declared_size = ?14
                AND (oci_upload_id = ?15 OR (oci_upload_id IS NULL AND ?15 IS NULL))",
            vals![
                &record.state,
                record.verified_sha256.as_deref(),
                record.verified_size,
                record.materialization_placement_id,
                record.materialization_binding_id,
                &record.state_json,
                record.resource_version,
                &record.deployment_id,
                &record.session_id,
                expected_version,
                &record.principal_id,
                &record.client_operation_id,
                &record.source_sha256,
                record.declared_size,
                record.oci_upload_id.as_deref()
            ],
        )
        .expecting(1);

        let mut statements = vec![update];
        statements.extend(targets);
        self.backend.checked_batch(&statements).await?;
        Ok(record.clone())
    }
}

#[cfg(test)]
mod tests;
