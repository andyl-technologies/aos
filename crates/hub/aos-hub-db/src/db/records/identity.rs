//! Identity records returned by typed Hub persistence operations.

use super::*;

/// An organization-owned non-human principal.
#[derive(Debug, Clone)]
pub struct ServiceAccountRecord {
    /// Stable database identity retained across renames.
    pub id: i64,
    /// Owning organization identity.
    pub org_id: i64,
    /// Name unique within the organization.
    pub name: String,
    /// Creation timestamp.
    pub created_at: i64,
}

/// An invitation system-of-record row.
#[derive(Debug, Clone)]
pub struct InvitationRecord {
    /// Database id.
    pub id: i64,
    /// Org the invitation grants membership in.
    pub org_id: i64,
    /// Invited email address.
    pub email: String,
    /// Scope path the resulting grant is bound to.
    pub scope: String,
    /// Role the resulting grant confers.
    pub role: String,
    /// Unix time the invitation was created.
    pub created_at: i64,
    /// Unix time the invitation was accepted, when applicable.
    pub accepted_at: Option<i64>,
    /// Unix time an administrator cancelled the invitation, when applicable.
    pub cancelled_at: Option<i64>,
    /// Unix time after which the invitation can no longer be accepted.
    pub expires_at: i64,
}

/// One organization whose current identity-provider policy applies to a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcedSsoProvider {
    /// Database identity of the organization that owns the policy.
    pub org_id: i64,
    /// Human-facing organization slug used to begin its sign-in flow.
    pub org_slug: String,
    /// Current issuer identifier accepted for the organization.
    pub issuer: String,
}

/// An in-flight OIDC authorization-code request (system-of-record row).
///
/// Created at the hub's `auth::oidc::begin_login` and consumed exactly once at
/// the callback by [`Database::take_oidc_flow`]; carries the PKCE
/// `code_verifier` and the `nonce` the returned id_token is checked against.
#[derive(Debug, Clone)]
pub struct OidcFlowRecord {
    /// The opaque CSRF `state` value echoed back by the IdP.
    pub state: String,
    /// The org whose IdP this flow targets.
    pub org_id: i64,
    /// Verifier configuration that was trusted when the flow began.
    pub verifier_id: String,
    /// The nonce bound into the authorization request; the id_token's `nonce`
    /// claim must equal it.
    pub nonce: String,
    /// The PKCE code verifier whose S256 challenge was sent at authorization.
    pub code_verifier: String,
    /// Where to send the browser after a successful login, or `None` for the
    /// instance home.
    pub redirect_after: Option<String>,
    /// Unix time the flow expires; a callback after this is rejected.
    pub expires_at: i64,
}

/// A registered passkey / WebAuthn credential (system-of-record row).
///
/// Created at the service WebAuthn registration flow and looked up by
/// [`Database::webauthn_credential_by_id`] on every assertion. The hub stores
/// only the public key (the `attestation: none` policy means no attestation
/// statement is ever persisted), so a database leak yields nothing usable for
/// impersonation.
#[derive(Debug, Clone)]
pub struct WebauthnCredentialRecord {
    /// Database id.
    pub id: i64,
    /// Owning user id.
    pub user_id: i64,
    /// The authenticator's raw credential id, base64url-encoded; the lookup key
    /// an assertion arrives with, UNIQUE across all users.
    pub credential_id: String,
    /// The credential's COSE public key, base64-encoded as the authenticator
    /// emitted it; re-decoded by the verifier on every assertion.
    pub public_key: String,
    /// The authenticator's signature counter, enforced monotonic on assertion
    /// to detect a cloned authenticator.
    pub sign_count: i64,
    /// Advisory transports the authenticator reported (JSON array), or `None`.
    pub transports: Option<String>,
    /// A human label for the passkey, or `None`.
    pub label: Option<String>,
    /// Unix time the credential was registered.
    pub created_at: i64,
    /// Unix time the credential last authenticated a login, or `None`.
    pub last_used_at: Option<i64>,
}

/// An in-flight WebAuthn ceremony challenge (system-of-record row).
///
/// Created at the start of a registration or assertion ceremony and consumed
/// exactly once at verify by [`Database::take_webauthn_challenge`]. Mirrors
/// [`OidcFlowRecord`]'s short-lived, single-use shape: the random `challenge`
/// the client signs into `clientDataJSON` must match a live, unexpired row, and
/// taking it deletes it so a challenge can never be replayed.
#[derive(Debug, Clone)]
pub struct WebauthnChallengeRecord {
    /// The random challenge value, base64url-encoded.
    pub challenge: String,
    /// The registering user for a registration ceremony, or `None` for a
    /// usernameless assertion ceremony (resolved from the presented credential).
    pub user_id: Option<i64>,
    /// The ceremony kind: `"registration"` or `"assertion"`.
    pub kind: String,
    /// Unix time the challenge expires; a verify after this is rejected.
    pub expires_at: i64,
    /// Browser-session state that authorized a registration ceremony.
    pub registration_binding: Option<WebauthnChallengeBinding>,
}

/// Browser-session state bound to a passkey registration ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebauthnChallengeBinding {
    /// Hash of the browser-session secret that began the ceremony.
    pub(in crate::db) session_id_hash: String,
    /// Monotonic session generation observed when the ceremony began.
    pub(in crate::db) reauthentication_generation: i64,
}

impl WebauthnChallengeBinding {
    /// Captures one browser session's current reauthentication generation.
    #[must_use]
    pub fn for_session(secret: &str, reauthentication_generation: i64) -> Self {
        Self {
            session_id_hash: aos_hub_model::auth::token::sha256_hex(secret),
            reauthentication_generation,
        }
    }

    /// Reports whether this binding still matches the browser session.
    #[must_use]
    pub fn matches_session(&self, secret: &str, reauthentication_generation: i64) -> bool {
        self.session_id_hash == aos_hub_model::auth::token::sha256_hex(secret)
            && self.reauthentication_generation == reauthentication_generation
    }
}

/// The outcome of [`Database::link_or_create_identity`]: the resolved user and
/// how the identity was reconciled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityLink {
    /// An existing verifier and subject identity resolved to this user id.
    Existing(i64),
    /// A verified email on a captured domain linked to an existing user.
    Linked(i64),
    /// A fresh user and identity were provisioned (JIT).
    Created(i64),
}

/// Secret-free access-token metadata exposed to authorized administrators.
#[derive(Debug, Clone)]
pub struct AccessTokenMetadata {
    /// Stable token-generation identity.
    pub token_id: String,
    /// Owning principal kind.
    pub owner_kind: String,
    /// Owning principal database identity.
    pub owner_id: i64,
    /// Exact authorization scope.
    pub scope: String,
    /// Parsed capability set.
    pub permissions: Vec<aos_hub_model::domain::Permission>,
    /// Operator-facing purpose, never secret material.
    pub comment: Option<String>,
    /// Creation timestamp.
    pub created_at: i64,
    /// Optional expiration timestamp.
    pub expires_at: Option<i64>,
    /// Most recent successful use.
    pub last_used_at: Option<i64>,
    /// Rotation timestamp when superseded.
    pub rotated_at: Option<i64>,
    /// Retirement timestamp when explicitly revoked.
    pub retired_at: Option<i64>,
    /// Exact lifecycle revision.
    pub resource_version: String,
}

/// A validated human session: the user and their current sudo level.
///
/// Produced by [`Database::validate_session`] after a cookie secret checks
/// out (hash matches and the session has not expired); validation also
/// bumps `last_seen_at`.
#[derive(Debug, Clone)]
pub struct SessionAuth {
    /// The authenticated user's id.
    pub user_id: i64,
    /// `1` when the session is sudo-capable (re-authenticated recently).
    pub auth_level: i64,
    /// Unix time the user last (re-)authenticated, for sudo freshness.
    pub last_authenticated_at: i64,
    /// Unix time the session expires.
    pub expires_at: i64,
    /// Evidence that established or most recently elevated the session.
    pub authentication: SessionAuthentication,
    /// Monotonic generation advanced by each in-place reauthentication.
    pub reauthentication_generation: i64,
}

/// Authentication evidence retained with a browser session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "method", content = "provider", rename_all = "snake_case")]
pub enum SessionAuthentication {
    /// A session created before authentication evidence was recorded.
    LegacyLocal,
    /// A local password was verified.
    Password,
    /// A single-use email link was verified.
    MagicLink,
    /// A registered passkey assertion was verified.
    Passkey,
    /// An OpenID Connect token from the named issuer was verified.
    Oidc(String),
}

impl Default for SessionAuthentication {
    fn default() -> Self {
        Self::LegacyLocal
    }
}

impl SessionAuthentication {
    /// Converts authentication evidence into its persisted columns.
    pub(in crate::db) fn database_values(&self) -> (&'static str, Option<&str>) {
        match self {
            Self::LegacyLocal => ("legacy_local", None),
            Self::Password => ("password", None),
            Self::MagicLink => ("magic_link", None),
            Self::Passkey => ("passkey", None),
            Self::Oidc(issuer) => ("oidc", Some(issuer)),
        }
    }

    /// Reconstructs authentication evidence from its persisted columns.
    pub(in crate::db) fn from_database(method: &str, provider: Option<String>) -> Result<Self> {
        match (method, provider) {
            ("legacy_local", None) => Ok(Self::LegacyLocal),
            ("password", None) => Ok(Self::Password),
            ("magic_link", None) => Ok(Self::MagicLink),
            ("passkey", None) => Ok(Self::Passkey),
            ("oidc", Some(issuer)) if !issuer.is_empty() => Ok(Self::Oidc(issuer)),
            _ => anyhow::bail!("session authentication evidence is malformed"),
        }
    }
}

/// The outcome of polling a device-authorization grant (RFC 8628).
#[derive(Debug, Clone)]
pub enum DevicePollResult {
    /// The user has neither approved nor denied yet.
    Pending,
    /// The client polled faster than the advertised interval.
    SlowDown,
    /// The user denied the request.
    Denied,
    /// The device code is unknown, expired, or was already delivered.
    Expired,
    /// The user approved and the credential pair was delivered exactly once.
    Approved(DeviceTokenGrant),
}

/// Credentials issued by one successful device-code poll.
#[derive(Debug, Clone)]
pub struct DeviceTokenGrant {
    /// Live authorization projected into the short-lived access JWT.
    pub auth: TokenAuth,
    /// Opaque rotating refresh credential returned exactly once.
    pub refresh_token: String,
    /// Remaining idle lifetime of the refresh credential, in seconds.
    pub refresh_expires_in: i64,
}

/// Outcome of rotating an OAuth refresh credential.
#[derive(Debug, Clone)]
pub enum RefreshTokenResult {
    /// The credential rotated successfully.
    Rotated(DeviceTokenGrant),
    /// The credential is unknown, expired, revoked, or has no live authority.
    Invalid,
    /// A consumed credential was reused; its complete family was revoked.
    Reused,
}

impl IdentityLink {
    /// The resolved user id, regardless of how it was reconciled.
    #[must_use]
    pub fn user_id(&self) -> i64 {
        match self {
            IdentityLink::Existing(id) | IdentityLink::Linked(id) | IdentityLink::Created(id) => {
                *id
            }
        }
    }
}

impl SessionAuth {
    /// Whether this session is currently sudo-capable at time `now`.
    ///
    /// True when the session was minted sudo (`auth_level == 1`) **and** the
    /// last re-authentication is within
    /// [`SUDO_WINDOW_SECS`](aos_hub_model::auth::session::SUDO_WINDOW_SECS) of `now`.
    /// Destructive operations gate on this so a long-lived but stale session
    /// cannot perform them without the user re-authenticating.
    #[must_use]
    pub fn is_sudo(&self, now: i64) -> bool {
        self.auth_level == 1
            && now.saturating_sub(self.last_authenticated_at)
                < aos_hub_model::auth::session::SUDO_WINDOW_SECS
    }
}
