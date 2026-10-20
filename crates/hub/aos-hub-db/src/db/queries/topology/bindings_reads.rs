//! Bindings reads in the topology capability.

use super::*;

impl Database {
    /// Lists immutable write revisions for one binding in ascending generation order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_binding_write_revisions(
        &self,
        binding_id: i64,
    ) -> Result<Vec<BindingWriteRevisionRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {BINDING_WRITE_REVISION_COLUMNS}
                     FROM binding_write_revisions
                     WHERE binding_id = ?1 ORDER BY revision"
                ),
                &vals![binding_id],
            )
            .await?;
        rows.iter().map(row_to_binding_write_revision).collect()
    }

    /// Looks up a binding by stable API identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binding_by_stable_id(&self, stable_id: &str) -> Result<Option<BindingRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, name, kind, is_instance_default, stable_id, owner_scope_key,
                 local_root_path, object_bucket, object_prefix, endpoint_scheme,
                 endpoint_host_kind, endpoint_host_bytes, endpoint_port,
                 signing_region, access_mode, resource_version, created_at, updated_at
                 FROM bindings WHERE stable_id = ?1",
                &vals![stable_id],
            )
            .await?
            .map(|row| row_to_binding(&row))
            .transpose()
    }

    /// Looks up the non-sensitive read projection of a binding.
    ///
    /// The SQL projection excludes every provider coordinate and credential
    /// field, so callers with only `binding.read` never materialize
    /// those values in memory.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binding_read_detail_by_stable_id(
        &self,
        stable_id: &str,
    ) -> Result<Option<BindingReadDetail>> {
        self.backend
            .query_opt(BINDING_READ_DETAIL_SQL, &vals![stable_id])
            .await?
            .map(|row| row_to_binding_read_detail(&row))
            .transpose()
    }

    /// Lists the current immutable credential generation for every configured purpose.
    ///
    /// Secret material is never returned; each row carries only its sealed
    /// secret-version reference, fingerprint, and validation observation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_current_binding_credentials(
        &self,
        binding_id: i64,
    ) -> Result<Vec<BindingCredentialRevisionRecord>> {
        self.backend
            .query(
                "SELECT r.binding_id, r.purpose, r.generation,
                   r.secret_version_ref, r.validation_state, r.validated_at,
                   r.validation_error, r.credential_fingerprint, r.created_by,
                   r.created_at, h.resource_version
                 FROM binding_credential_heads h
                 JOIN binding_credential_revisions r
                   ON r.binding_id = h.binding_id
                  AND r.purpose = h.purpose AND r.generation = h.current_generation
                 WHERE h.binding_id = ?1 ORDER BY r.purpose",
                &vals![binding_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(BindingCredentialRevisionRecord {
                    binding_id: row.get(0)?,
                    purpose: row.get(1)?,
                    generation: row.get(2)?,
                    secret_version_ref: row.get(3)?,
                    validation_state: row.get(4)?,
                    validated_at: row.get(5)?,
                    validation_error: row.get(6)?,
                    credential_fingerprint: row.get(7)?,
                    created_by: row.get(8)?,
                    created_at: row.get(9)?,
                    head_resource_version: row.get(10)?,
                })
            })
            .collect()
    }

    /// Lists an organization's non-sensitive storage-binding summaries.
    ///
    /// The SQL projection excludes provider coordinates and all credential
    /// material, making this the only inventory query suitable for principals
    /// with `binding.read` but not `binding.manage`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_binding_read_summaries(
        &self,
        org_id: i64,
    ) -> Result<Vec<BindingReadSummary>> {
        let rows = self
            .backend
            .query(BINDING_READ_SUMMARY_SQL, &vals![org_id])
            .await?;
        rows.iter().map(row_to_binding_read_summary).collect()
    }
}
