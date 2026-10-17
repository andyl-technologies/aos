//! Current IAM locks and database-clock credential eligibility for scan effects.

use anyhow::{ensure, Context as _, Result};

use crate::auth::jwt::{Claims, AUTHORIZATION_CLAIMS_VERSION};
use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;
use crate::domain::Permission;

impl Database {
    /// Prepares current authority locks and live expiry checks for one scan effect.
    ///
    /// Callers must independently authenticate the supplied claims and bind
    /// their actor and registry scope to the operation. These statements run
    /// in the same checked transaction as admission, cancellation or commit;
    /// an earlier asynchronous permission check cannot replace them.
    ///
    /// # Errors
    /// Returns an error for an obsolete authorization epoch, missing current
    /// credential or granting membership, invalid scope, or persistence failure.
    pub async fn assessment_iam_statements(
        &self,
        claims: &Claims,
        scope: &str,
        permission: Permission,
    ) -> Result<Vec<CheckedStatement>> {
        ensure!(
            claims.authz_version == AUTHORIZATION_CLAIMS_VERSION,
            "assessment delegation has an obsolete authorization epoch"
        );
        let now = i64::try_from(self.assessment_database_time().await?.unix_seconds())?;
        let mut statements = self
            .direct_iam_statements(claims, scope, permission, now)
            .await?;
        let clock = self.backend.dialect().unix_time_expression();
        let incarnation = claims
            .owner_incarnation
            .as_ref()
            .context("assessment principal incarnation is absent")?;

        // IAM row locks prevent concurrent revocation, while these live SQL
        // clocks refuse expiry crossed during any prior asynchronous work.
        let credential = if let Some(session) = &claims.browser_session_id_hash {
            Statement::new(
                format!(
                    "UPDATE sessions SET last_seen_at = last_seen_at
                 WHERE id_hash = ?1 AND user_id = ?2 AND owner_incarnation = ?3
                   AND ?4 > {clock} AND expires_at > {clock}
                   AND last_seen_at >= {clock} - ?5 AND created_at >= {clock} - ?6"
                ),
                vals![
                    session,
                    claims.owner_id,
                    incarnation,
                    claims.exp,
                    crate::auth::session::IDLE_TIMEOUT_SECS,
                    crate::auth::session::ABSOLUTE_LIFETIME_SECS
                ],
            )
        } else {
            Statement::new(
                format!(
                    "UPDATE tokens SET last_used_at = last_used_at
                 WHERE id = ?1 AND owner_kind = ?2 AND owner_id = ?3 AND owner_incarnation = ?4
                   AND revoked_at IS NULL AND ?5 > {clock}
                   AND (expires_at IS NULL OR expires_at > {clock})
                   AND (rotated_at IS NULL OR rotated_at > {clock} - ?6)"
                ),
                vals![
                    claims.sub,
                    claims.owner_kind,
                    claims.owner_id,
                    incarnation,
                    claims.exp,
                    crate::db::ROTATION_GRACE_SECS
                ],
            )
        };
        statements.push(credential.expecting(1));
        ensure!(
            statements.len() <= 32,
            "assessment IAM lock scope exceeds its admission ceiling"
        );
        Ok(statements)
    }
}
