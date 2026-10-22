//! Principals helpers in the identity capability.

use super::*;

impl Database {
    /// Creates a user address reserved for one provider identity.
    pub(in crate::db) async fn create_provisional_oidc_user(
        &self,
        verifier_id: &str,
        subject: &str,
    ) -> Result<i64> {
        let digest = aos_hub_model::auth::token::sha256_hex(&format!("{verifier_id}\n{subject}"));
        let email = format!("oidc-{digest}@identity.invalid");

        self.backend
            .execute_insert(
                "INSERT INTO users (email, display_name, created_at) VALUES (?1, NULL, ?2)",
                &vals![email, unix_now()],
            )
            .await
    }

    /// Returns a live user row whose profile address matches `email`.
    pub(in crate::db) async fn user_by_profile_email(&self, email: &str) -> Result<Option<i64>> {
        self.backend
            .query_opt(
                "SELECT id FROM users WHERE email = ?1 AND deleted_at IS NULL",
                &vals![email],
            )
            .await
            .context("loading user by profile email")?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Inserts a verifier-bound OIDC identity for a user.
    pub(in crate::db) async fn insert_oidc_identity(
        &self,
        verifier_id: &str,
        issuer: &str,
        subject: &str,
        user_id: i64,
        email: Option<&str>,
        now: i64,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO oidc_identities
                 (user_id, verifier_id, issuer, subject, email, last_login)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &vals![user_id, verifier_id, issuer, subject, email, now],
            )
            .await?;
        Ok(())
    }

    /// Seeds one issuer-keyed identity from an earlier schema for migration tests.
    ///
    /// # Errors
    ///
    /// Returns an error when persistence fails.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub async fn seed_legacy_oidc_identity(
        &self,
        user_id: i64,
        issuer: &str,
        subject: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO user_identities (user_id, issuer, subject, last_login)
                 VALUES (?1, ?2, ?3, ?4)",
                &vals![user_id, issuer, subject, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// Reports whether every configured use of an issuer has one verifier.
    pub(in crate::db) async fn issuer_has_single_verifier(
        &self,
        issuer: &str,
        verifier_id: &str,
    ) -> Result<bool> {
        let rows = self
            .backend
            .query(
                "SELECT org_id, issuer, authorization_endpoint, token_endpoint, jwks_uri,
                        client_id, client_secret_enc, scopes, groups_claim, role_map_json,
                        allow_jit, enforce_sso, default_role,
                        resource_version, incarnation_id, mutation_plan_id
                 FROM org_idp_configs WHERE issuer = ?1",
                &vals![issuer],
            )
            .await?;

        if rows.is_empty() {
            return Ok(false);
        }

        for row in &rows {
            let config = row_to_idp_config(row)?;
            if aos_hub_model::identity::oidc_verifier_id(&config) != verifier_id {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
