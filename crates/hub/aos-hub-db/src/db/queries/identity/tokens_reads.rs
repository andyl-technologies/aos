//! Tokens reads in the identity capability.

use super::*;

impl Database {
    /// List a principal's non-revoked tokens as `(id, scope, permissions)`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_tokens_for(
        &self,
        owner: aos_hub_model::domain::Principal,
    ) -> Result<Vec<(String, String, Vec<aos_hub_model::domain::Permission>)>> {
        if !self
            .principal_is_live(owner.kind.as_str(), owner.id)
            .await?
        {
            return Ok(Vec::new());
        }
        let rows = self
            .backend
            .query(
                "SELECT id, scope_key, permissions FROM tokens
             WHERE owner_kind = ?1 AND owner_id = ?2 AND revoked_at IS NULL
             ORDER BY created_at",
                &vals![owner.kind.as_str(), owner.id],
            )
            .await?;
        let mut out = Vec::new();
        for row in &rows {
            let id: String = row.get(0)?;
            let scope: String = row.get(1)?;
            let perms_json: String = row.get(2)?;
            out.push((id, scope, parse_permission_names(&perms_json)));
        }
        Ok(out)
    }

    /// Lists secret-free token metadata at one exact authorization scope.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed stored permissions.
    pub async fn list_access_token_metadata(
        &self,
        scope: &str,
    ) -> Result<Vec<AccessTokenMetadata>> {
        let rows = self
            .backend
            .query(
                "SELECT id, owner_kind, owner_id, scope_key, permissions, comment,
                        created_at, expires_at, last_used_at, rotated_at, revoked_at
                   FROM tokens
                  WHERE scope_key = ?1
                  ORDER BY created_at, id",
                &vals![scope],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let rotated_at: Option<i64> = row.get(9)?;
                let revoked_at: Option<i64> = row.get(10)?;
                let resource_version = if revoked_at.is_some() {
                    "retired"
                } else if rotated_at.is_some() {
                    "rotated"
                } else {
                    "active"
                };
                let permissions_json: String = row.get(4)?;
                Ok(AccessTokenMetadata {
                    token_id: row.get(0)?,
                    owner_kind: row.get(1)?,
                    owner_id: row.get(2)?,
                    scope: row.get(3)?,
                    permissions: parse_permission_names(&permissions_json),
                    comment: row.get(5)?,
                    created_at: row.get(6)?,
                    expires_at: row.get(7)?,
                    last_used_at: row.get(8)?,
                    rotated_at,
                    retired_at: revoked_at,
                    resource_version: resource_version.to_string(),
                })
            })
            .collect()
    }

    /// The requested scope and permissions of a live, unresolved device
    /// grant, looked up by its `user_code`.
    ///
    /// Returns `Ok(None)` when the code is unknown, already approved or
    /// denied, or expired — the same fail-closed shape as approval. Used by
    /// the `/activate` page to show what the CLI is asking for before the
    /// human approves. Permissions come back as their wire-name strings.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn pending_device_request(
        &self,
        user_code: &str,
    ) -> Result<Option<(String, Vec<String>)>> {
        let now = unix_now();
        let row = self
            .backend
            .query_opt(
                "SELECT scope_key, permissions FROM device_codes
                 WHERE user_code = ?1 AND approved_by_user IS NULL AND denied = 0
                   AND expires_at > ?2",
                &vals![user_code, now],
            )
            .await
            .context("loading pending device request")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let scope: String = row.get(0)?;
        let perms_json: String = row.get(1)?;
        let perms: Vec<String> = serde_json::from_str(&perms_json).unwrap_or_default();
        Ok(Some((scope, perms)))
    }
}
