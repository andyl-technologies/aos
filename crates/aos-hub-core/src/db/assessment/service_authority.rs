//! Finite schedule delegation to an existing, currently authorized service account.
//!
//! These private records are reviewed configuration, not signed bearer tokens.
//! The schedule revision is the grant's revocation handle. Every effect still
//! locks the existing credential, principal, organization and granting membership.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::service_authority::{
    service_credential_ref, validate_service_credential_id, ServiceAuthorityV1,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::assessment_actor_ref;
use crate::auth::jwt::{Claims, AUTHORIZATION_CLAIMS_VERSION};
use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;
use crate::domain::{Permission, PrincipalKind};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ReviewedServiceAuthority {
    pub receipt: ServiceAuthorityV1,
    pub principal: Claims,
}

impl ReviewedServiceAuthority {
    pub(super) fn validate(&self, reviewer: &Claims) -> Result<()> {
        validate_service_credential_id(&self.principal.sub)?;
        self.receipt.to_bytes()?;
        ensure!(
            self.principal.owner_kind == "service_account"
                && self.principal.browser_session_id_hash.is_none()
                && self.principal.authz_version == AUTHORIZATION_CLAIMS_VERSION
                && self.receipt.actor_ref.to_string() == assessment_actor_ref(&self.principal)?
                && self.receipt.credential_ref == service_credential_ref(&self.principal.sub)?
                && self.receipt.reviewer_ref.to_string() == assessment_actor_ref(reviewer)?
                && self.receipt.expires_at.unix_seconds() == u64::try_from(self.principal.exp)?
                && self.principal.iat > 0
                && self.principal.exp > self.principal.iat
                && self.principal.exp - self.principal.iat <= 2_592_000,
            "service authority differs from its reviewed principal"
        );
        Ok(())
    }
}

impl Database {
    pub(super) async fn prepare_assessment_service_authority(
        &self,
        registry_id: i64,
        credential_id: &str,
        expires_at: &Timestamp,
        reviewer: &Claims,
        permissions: &[Permission],
    ) -> Result<(ReviewedServiceAuthority, Vec<CheckedStatement>)> {
        validate_service_credential_id(credential_id)?;
        ensure!(
            !permissions.is_empty() && permissions.len() <= 2,
            "service review requires bounded execution permissions"
        );
        let now = self.assessment_database_time().await?;
        ensure!(
            expires_at > &now && expires_at.elapsed_since(&now)? <= 2_592_000,
            "service review must expire within thirty days"
        );
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("service review registry is absent")?;
        let org = registry
            .org_id
            .context("service review requires an organization-owned registry")?;
        let token = self
            .current_token_authority(credential_id)
            .await?
            .context("service review credential is absent or expired")?;
        ensure!(
            token.owner.kind == PrincipalKind::ServiceAccount
                && token.browser_session_id_hash.is_none(),
            "service review requires an existing service-account credential"
        );
        let row = self.backend.query_opt(
            "SELECT token.expires_at FROM tokens token JOIN service_accounts account ON account.id = token.owner_id
             WHERE token.id = ?1 AND token.owner_kind = 'service_account' AND account.org_id = ?2",
            &vals![@slice credential_id, org],
        ).await?.context("service review credential belongs to another organization")?;
        let deadline = if let Some(token_expiry) = row.get::<Option<u64>>(0)? {
            expires_at
                .clone()
                .min(Timestamp::from_unix_seconds(token_expiry)?)
        } else {
            expires_at.clone()
        };

        // This fresh internal principal is constructed from live credential
        // facts and the explicitly reviewed deadline. No JWT is minted and the
        // reviewer's authenticated claims remain unchanged.
        let principal = Claims {
            sub: token.token_id,
            owner_kind: "service_account".into(),
            owner_id: token.owner.id,
            owner_incarnation: token.owner_incarnation,
            browser_session_id_hash: None,
            scope: token.scope.as_str().into(),
            perms: token
                .permissions
                .iter()
                .map(|permission| permission.as_str().into())
                .collect(),
            authz_version: AUTHORIZATION_CLAIMS_VERSION.into(),
            iat: i64::try_from(now.unix_seconds())?,
            exp: i64::try_from(deadline.unix_seconds())?,
        };
        let authority = ReviewedServiceAuthority {
            receipt: ServiceAuthorityV1 {
                schema: "aos.assessment-service-authority/v1".into(),
                actor_ref: Sha256Digest::parse(&assessment_actor_ref(&principal)?)?,
                credential_ref: service_credential_ref(credential_id)?,
                reviewer_ref: Sha256Digest::parse(&assessment_actor_ref(reviewer)?)?,
                expires_at: deadline,
            },
            principal,
        };
        authority.validate(reviewer)?;
        let mut fences = Vec::new();
        for permission in permissions {
            fences.extend(
                self.assessment_iam_statements(
                    &authority.principal,
                    &registry.scope_key,
                    *permission,
                )
                .await?,
            );
        }
        fences.push(self.assessment_service_owner_guard(registry_id, &authority));
        Ok((authority, distinct_authority_fences(fences)?))
    }

    pub(super) fn assessment_service_owner_guard(
        &self,
        registry_id: i64,
        authority: &ReviewedServiceAuthority,
    ) -> CheckedStatement {
        Statement::new(
            "UPDATE service_accounts SET name = name WHERE id = ?1 AND principal_incarnation = ?2
             AND EXISTS(SELECT 1 FROM registries registry JOIN orgs org ON org.id = registry.org_id
                        WHERE registry.id = ?3 AND registry.org_id = service_accounts.org_id AND org.deleted_at IS NULL)",
            vals![authority.principal.owner_id, authority.principal.owner_incarnation, registry_id],
        ).expecting(1)
    }
}

pub(super) fn distinct_authority_fences(
    fences: Vec<CheckedStatement>,
) -> Result<Vec<CheckedStatement>> {
    let mut distinct: Vec<CheckedStatement> = Vec::new();
    for fence in fences {
        if !distinct.iter().any(|held| {
            held.statement.sql == fence.statement.sql
                && held.statement.params == fence.statement.params
                && held.expected_rows == fence.expected_rows
        }) {
            distinct.push(fence);
        }
    }
    ensure!(
        distinct.len() <= 32,
        "service authority exceeds its lock ceiling"
    );
    Ok(distinct)
}
