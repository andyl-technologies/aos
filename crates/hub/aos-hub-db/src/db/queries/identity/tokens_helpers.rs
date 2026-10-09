//! Tokens helpers in the identity capability.

use super::*;

impl Database {
    pub(in crate::db) async fn live_token_auth_by_id(
        &self,
        id: &str,
        touch: bool,
    ) -> Result<Option<TokenAuth>> {
        let now = unix_now();
        let row = self
            .backend
            .query_opt(
                "SELECT t.owner_kind, t.owner_id, t.scope_key, t.permissions,
                        t.expires_at, t.revoked_at, t.rotated_at
                 FROM tokens t
                 JOIN authorization_scopes a ON a.scope_key = t.scope_key
                 LEFT JOIN orgs o ON o.id = a.org_id
                 WHERE t.id = ?1 AND (a.org_id IS NULL OR o.deleted_at IS NULL)
                   AND ((t.owner_kind = 'user' AND EXISTS (
                          SELECT 1 FROM users u
                           WHERE u.id = t.owner_id AND u.deleted_at IS NULL))
                     OR (t.owner_kind = 'service_account' AND EXISTS (
                          SELECT 1 FROM service_accounts s
                          JOIN orgs owner_org ON owner_org.id = s.org_id
                           WHERE s.id = t.owner_id AND owner_org.deleted_at IS NULL)))",
                &vals![id],
            )
            .await
            .context("loading live token by id")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let owner_kind: String = row.get(0)?;
        let owner_id: i64 = row.get(1)?;
        let scope: String = row.get(2)?;
        let perms_json: String = row.get(3)?;
        let expires_at: Option<i64> = row.get(4)?;
        let revoked_at: Option<i64> = row.get(5)?;
        let rotated_at: Option<i64> = row.get(6)?;
        if let Some(exp) = expires_at {
            if now >= exp {
                return Ok(None);
            }
        }
        // A hard revocation cuts off immediately; a rotation grants the
        // grace window so in-flight clients can finish.
        if revoked_at.is_some() {
            return Ok(None);
        }
        if let Some(rotated) = rotated_at {
            if now >= rotated + ROTATION_GRACE_SECS {
                return Ok(None);
            }
        }
        let Some(kind) = aos_hub_model::domain::PrincipalKind::parse(&owner_kind) else {
            return Ok(None);
        };
        let principal = aos_hub_model::domain::Principal { kind, id: owner_id };
        if !self
            .principal_is_live(principal.kind.as_str(), principal.id)
            .await?
        {
            return Ok(None);
        }
        let Some(context) = self.authorization_context(&scope).await? else {
            return Ok(None);
        };
        let grants = self.effective_scopes(principal).await?;
        let permissions: Vec<_> = parse_permission_names(&perms_json)
            .into_iter()
            .filter(|permission| aos_hub_model::domain::iam::allow(&grants, *permission, &context))
            .collect();
        if permissions.is_empty() {
            return Ok(None);
        }
        // Stamping `last_used_at` is bookkeeping, not part of the validation
        // decision: a failure here (e.g. a schema drift on the touch column)
        // must never turn a valid token into an authentication error. Log and
        // continue so the caller still receives the resolved `TokenAuth`.
        if touch {
            if let Err(e) = self
                .backend
                .execute(
                    "UPDATE tokens SET last_used_at = ?2 WHERE id = ?1",
                    &vals![id, now],
                )
                .await
            {
                tracing::warn!(error = %e, token_id = %id, "failed to stamp token last_used_at");
            }
        }
        Ok(Some(TokenAuth {
            token_id: id.to_string(),
            owner: principal,
            scope: aos_hub_model::domain::Scope::parse(&scope),
            permissions,
        }))
    }
}
