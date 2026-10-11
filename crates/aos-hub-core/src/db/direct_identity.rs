//! Live authenticated principal incarnations for RPC and direct storage admission.
//!
//! The account UUID determines a public principal commitment. Its recyclable
//! numeric slot is independently reserved by the byte executor before work.
//! A retained JWT is accepted only while its exact token or browser session and
//! the original account incarnation still exist; SQL restore cannot infer a
//! missing token pin from a different owner with the same numeric ID.

use anyhow::{Context as _, Result};

use super::{unix_now, Database};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
use crate::auth::jwt::Claims;
use crate::direct_upload::{DirectActorKind, DirectActorSlot, WireInteger};
use crate::domain::{Principal, PrincipalKind};

fn actor_slot(principal: Principal, incarnation: String) -> Result<DirectActorSlot> {
    let actor = DirectActorSlot {
        kind: match principal.kind {
            PrincipalKind::User => DirectActorKind::User,
            PrincipalKind::ServiceAccount => DirectActorKind::ServiceAccount,
        },
        numeric_id: WireInteger::new(u64::try_from(principal.id)?),
        incarnation,
    };
    actor.validate()?;
    Ok(actor)
}

// Shared by token and cookie loaders; SQL length checks do not establish the
// canonical UUID version or a positive, correctly typed actor slot.
pub(super) fn validate_actor_incarnation(principal: Principal, incarnation: &str) -> Result<()> {
    actor_slot(principal, incarnation.to_owned()).map(|_| ())
}

// Token IDs identify actual minted credentials, never arbitrary restored text.
// The shared live loader applies this before SQL in every credential path.
pub(super) fn canonical_token_id(token_id: &str) -> bool {
    uuid::Uuid::parse_str(token_id).is_ok_and(|id| {
        id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122
            && id.to_string() == token_id
    })
}

impl Database {
    /// Loads the immutable UUID of a live account without creating one.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed retained UUID data.
    pub async fn principal_incarnation(&self, principal: Principal) -> Result<Option<String>> {
        let query = match principal.kind {
            PrincipalKind::User => {
                "SELECT principal_incarnation FROM users WHERE id = ?1 AND deleted_at IS NULL"
            }
            PrincipalKind::ServiceAccount => {
                "SELECT s.principal_incarnation FROM service_accounts s
                 JOIN orgs o ON o.id = s.org_id WHERE s.id = ?1 AND o.deleted_at IS NULL"
            }
        };
        let Some(row) = self.backend.query_opt(query, &vals![principal.id]).await? else {
            return Ok(None);
        };
        let incarnation: Option<String> = row.get(0)?;
        if let Some(value) = &incarnation {
            actor_slot(principal, value.clone())?;
        }
        Ok(incarnation)
    }

    // This port is called while minting a freshly authenticated session or a
    // newly authorized token. It never repairs an old cookie or token pin.
    pub(super) async fn ensure_principal_incarnation(
        &self,
        principal: Principal,
    ) -> Result<String> {
        if let Some(value) = self.principal_incarnation(principal).await? {
            return Ok(value);
        }
        let candidate = uuid::Uuid::new_v4().to_string();
        let query = match principal.kind {
            PrincipalKind::User => {
                "UPDATE users SET principal_incarnation = ?2
                 WHERE id = ?1 AND deleted_at IS NULL AND principal_incarnation IS NULL"
            }
            PrincipalKind::ServiceAccount => {
                "UPDATE service_accounts SET principal_incarnation = ?2
                 WHERE id = ?1 AND principal_incarnation IS NULL
                   AND EXISTS (SELECT 1 FROM orgs o
                               WHERE o.id = service_accounts.org_id AND o.deleted_at IS NULL)"
            }
        };
        self.backend
            .execute(query, &vals![principal.id, candidate])
            .await?;

        // A concurrent first validation may win. Reload its committed UUID;
        // returning our uncommitted candidate would split the public identity.
        self.principal_incarnation(principal)
            .await?
            .context("authenticated principal incarnation is unavailable")
    }

    /// Revalidates a signed access claim against its exact current authority.
    ///
    /// The caller verifies the JWT signature before invoking this method. API
    /// claims resolve a real live token UUID and its immutable owner pin.
    /// Browser claims explicitly carry a cookie-session hash; its current
    /// owner, expiry and UUID are checked instead of guessing from `sub`.
    /// Legacy claims without an incarnation cannot authorize current RPC or direct effects.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed retained account data.
    pub async fn current_authenticated_actor(
        &self,
        claims: &Claims,
    ) -> Result<Option<DirectActorSlot>> {
        let Some(kind) = PrincipalKind::parse(&claims.owner_kind) else {
            return Ok(None);
        };
        let principal = Principal {
            kind,
            id: claims.owner_id,
        };
        let Some(incarnation) = &claims.owner_incarnation else {
            return Ok(None);
        };
        let actor = match actor_slot(principal, incarnation.clone()) {
            Ok(actor) => actor,
            Err(_) => return Ok(None),
        };
        if claims.exp <= unix_now()
            || self.principal_incarnation(principal).await?.as_ref() != Some(incarnation)
        {
            return Ok(None);
        }

        if let Some(hash) = &claims.browser_session_id_hash {
            if kind != PrincipalKind::User
                || hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || claims.sub != format!("browser-session-{}", principal.id)
                || claims.scope != "instance"
            {
                return Ok(None);
            }
            let Some(row) = self
                .backend
                .query_opt(
                    "SELECT s.user_id, s.created_at, s.last_seen_at, s.expires_at
                 FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.id_hash = ?1 AND u.deleted_at IS NULL
                   AND s.owner_incarnation = ?2 AND u.principal_incarnation = ?2",
                    &vals![hash, incarnation],
                )
                .await?
            else {
                return Ok(None);
            };
            let user_id: i64 = row.get(0)?;
            let created_at: i64 = row.get(1)?;
            let last_seen_at: i64 = row.get(2)?;
            let expires_at: i64 = row.get(3)?;
            let now = unix_now();
            if user_id != principal.id
                || now >= expires_at
                || now.saturating_sub(last_seen_at) > crate::auth::session::IDLE_TIMEOUT_SECS
                || now.saturating_sub(created_at) > crate::auth::session::ABSOLUTE_LIFETIME_SECS
                || claims.exp <= now
            {
                return Ok(None);
            }
            return Ok(Some(actor));
        }

        // This lookup bypasses hot JWT/token caches and validates the original
        // stored token owner UUID, lifecycle and current account incarnation.
        let Some(auth) = self.current_token_authority(&claims.sub).await? else {
            return Ok(None);
        };
        if auth.owner != principal
            || auth.scope.as_str() != claims.scope
            || auth.owner_incarnation.as_ref() != Some(incarnation)
            || auth.browser_session_id_hash.is_some()
            || claims.exp <= unix_now()
        {
            return Ok(None);
        }
        // Provenance uses the token's original grants, not today's filtered
        // memberships. Requested-action authorization separately applies live
        // IAM, so losing one grant does not invalidate unrelated read access.
        let now = unix_now();
        let Some(grants) = self
            .backend
            .query_opt(
                "SELECT t.permissions, t.expires_at, t.rotated_at FROM tokens t
             JOIN authorization_scopes a ON a.scope_key = t.scope_key
             LEFT JOIN orgs o ON o.id = a.org_id
             WHERE t.id = ?1 AND t.owner_incarnation = ?2 AND t.owner_kind = ?3
               AND t.owner_id = ?4 AND t.scope_key = ?5 AND t.revoked_at IS NULL
               AND (t.expires_at IS NULL OR t.expires_at > ?6)
               AND (t.rotated_at IS NULL OR t.rotated_at > ?7)
               AND (a.org_id IS NULL OR o.deleted_at IS NULL)
               AND ((t.owner_kind = 'user' AND EXISTS (SELECT 1 FROM users u
                     WHERE u.id = t.owner_id AND u.deleted_at IS NULL
                       AND u.principal_incarnation = t.owner_incarnation))
                 OR (t.owner_kind = 'service_account' AND EXISTS (
                     SELECT 1 FROM service_accounts s JOIN orgs owner_org ON owner_org.id = s.org_id
                     WHERE s.id = t.owner_id AND owner_org.deleted_at IS NULL
                       AND s.principal_incarnation = t.owner_incarnation)))",
                &vals![
                    claims.sub,
                    incarnation,
                    claims.owner_kind,
                    claims.owner_id,
                    claims.scope,
                    now,
                    now.saturating_sub(super::ROTATION_GRACE_SECS)
                ],
            )
            .await?
        else {
            return Ok(None);
        };
        let expiry: Option<i64> = grants.get(1)?;
        let rotation: Option<i64> = grants.get(2)?;
        let latest = unix_now();
        if expiry.is_some_and(|expiry| latest >= expiry)
            || rotation.is_some_and(|rotation| {
                latest.saturating_sub(rotation) >= super::ROTATION_GRACE_SECS
            })
        {
            return Ok(None);
        }
        let persisted: String = grants.get(0)?;
        let permissions = super::parse_permission_names(&persisted);
        if claims.perms.iter().any(|permission| {
            !permissions
                .iter()
                .any(|granted| granted.as_str() == permission)
        }) || claims.exp <= unix_now()
        {
            return Ok(None);
        }
        Ok(Some(actor))
    }

    /// Resolves a real current token authority after domain-specific signature checks.
    ///
    /// Callers must authenticate the enclosing Hub or OCI token, audience,
    /// repository grant and expiry before using its underlying token UUID. This
    /// method performs no token minting and accepts no browser pseudo-subject.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed retained account data.
    pub async fn current_token_authority(
        &self,
        token_id: &str,
    ) -> Result<Option<super::TokenAuth>> {
        self.live_token_auth_by_id(token_id, false).await
    }
}
