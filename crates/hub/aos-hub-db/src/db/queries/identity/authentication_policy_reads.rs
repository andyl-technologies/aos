//! Current organization authentication-policy reads.

use super::*;

impl Database {
    /// Lists every enforced identity provider that currently applies to a user.
    ///
    /// A provider applies through either the user's verified email domain or a
    /// membership at any live scope beneath the organization. Results are
    /// ordered by organization id and contain no duplicates.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn enforced_sso_providers(
        &self,
        email: &str,
        user_id: Option<i64>,
    ) -> Result<Vec<EnforcedSsoProvider>> {
        let domain = email
            .rsplit_once('@')
            .map_or("", |(_, domain)| domain)
            .trim()
            .to_lowercase();
        let user_id = user_id.unwrap_or(-1);
        let rows = self
            .backend
            .query(
                "SELECT DISTINCT o.id, o.slug, config.issuer
                   FROM orgs o
                   JOIN org_idp_configs config ON config.org_id = o.id
                  WHERE o.deleted_at IS NULL AND config.enforce_sso = 1
                    AND (
                      EXISTS (
                        SELECT 1 FROM org_domains domain
                         WHERE domain.org_id = o.id AND domain.domain = ?1
                           AND domain.verified_at IS NOT NULL
                      )
                      OR EXISTS (
                        SELECT 1 FROM memberships membership
                        JOIN authorization_scopes membership_scope
                          ON membership_scope.scope_key = membership.scope_key
                         AND membership_scope.retired_at IS NULL
                        JOIN authorization_scope_ancestors ancestry
                          ON ancestry.descendant_scope_key = membership.scope_key
                        JOIN authorization_scopes organization_scope
                          ON organization_scope.scope_key = ancestry.ancestor_scope_key
                         AND organization_scope.kind = 'organization'
                         AND organization_scope.org_id = o.id
                        WHERE membership.principal_kind = 'user'
                          AND membership.principal_id = ?2
                          AND organization_scope.retired_at IS NULL
                      )
                    )
                  ORDER BY o.id",
                &vals![domain, user_id],
            )
            .await
            .context("loading current enforced identity providers")?;

        rows.iter()
            .map(|row| {
                Ok(EnforcedSsoProvider {
                    org_id: row.get(0)?,
                    org_slug: row.get(1)?,
                    issuer: row.get(2)?,
                })
            })
            .collect()
    }

    /// Reports whether a user holds the exact instance-root owner grant.
    ///
    /// This deliberately does not infer recovery authority from organization
    /// ownership or inherited permissions.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn user_is_instance_owner(&self, user_id: i64) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM memberships membership
                   JOIN users user_record ON user_record.id = membership.principal_id
                  WHERE membership.principal_kind = 'user'
                    AND membership.principal_id = ?1
                    AND membership.scope_key = 'instance'
                    AND membership.role = 'owner'
                    AND user_record.deleted_at IS NULL",
                &vals![user_id],
            )
            .await
            .context("checking instance owner recovery authority")?
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::Database;

    async fn assert_instance_owner_recovery_authority(db: &Database) {
        let user_id = db
            .find_or_create_user("recovery-owner@example.test")
            .await
            .unwrap();
        let org_id = db
            .create_org("recovery-owner", "Recovery Owner")
            .await
            .unwrap();
        let org = db.org_by_id(org_id).await.unwrap().unwrap();

        assert!(!db.user_is_instance_owner(user_id).await.unwrap());

        db.grant_membership("user", user_id, &org.stable_id, "owner")
            .await
            .unwrap();
        assert!(!db.user_is_instance_owner(user_id).await.unwrap());

        db.grant_membership("user", user_id, "instance", "admin")
            .await
            .unwrap();
        assert!(!db.user_is_instance_owner(user_id).await.unwrap());

        db.grant_membership("user", user_id, "instance", "owner")
            .await
            .unwrap();
        assert!(db.user_is_instance_owner(user_id).await.unwrap());
    }

    #[tokio::test]
    async fn sqlite_instance_owner_recovery_authority() {
        let db = Database::open_in_memory().await.unwrap();
        assert_instance_owner_recovery_authority(&db).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_instance_owner_recovery_authority() {
        let Ok(url) = std::env::var("AOS_HUB_AUTHENTICATION_POLICY_TEST_PG_URL") else {
            eprintln!("live PostgreSQL instance owner recovery authority was not run");
            return;
        };
        let db = Database::connect(&url).await.unwrap();
        assert_instance_owner_recovery_authority(&db).await;
    }
}
