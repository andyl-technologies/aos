//! Sessions reads in the identity capability.

use super::*;

impl RpcService {
    /// Resolves a session from its cookie secret, read-through cached in KV when
    /// a [`KvStore`](crate::kv::KvStore) is attached (RFC-0004 ch.14 Phase C).
    ///
    /// On the hot path — the session lookup runs on **every** authenticated
    /// request — this serves the resolution from KV (sub-ms, off the database session
    /// cost) for [`HOT_TTL_SECS`](crate::cache::HOT_TTL_SECS), and additionally
    /// avoids the `last_seen_at` write `validate_session` performs on a cache
    /// hit. Expiry is still enforced exactly: the cached `expires_at` is
    /// re-checked against the current clock, so an expired session is never
    /// served from cache even within the TTL window. Revocation lag is bounded
    /// to the TTL (≤60 s) plus any explicit [`RpcService::invalidate_session_cache`] on
    /// logout — the eventual-consistency contract this tier accepts.
    ///
    /// With no `kv` attached this is exactly
    /// [`resolve_session`](crate::web::session::resolve_session) against the
    /// database (the pre-Phase-C path).
    ///
    /// # Errors
    ///
    /// Returns an error on a KV read failure or a database failure while loading
    /// the session.
    pub async fn resolve_session_cached(
        &self,
        secret: &str,
    ) -> anyhow::Result<Option<crate::web::session::ResolvedSession>> {
        let Some(kv) = &self.kv else {
            return crate::web::session::resolve_session(&self.db, secret).await;
        };
        let key = session_cache_key(secret);
        let db = &self.db;
        let cached: Option<CachedSession> = crate::cache::read_through(
            kv.as_ref(),
            &key,
            Some(crate::cache::HOT_TTL_SECS),
            || async move {
                Ok(crate::web::session::resolve_session(db, secret)
                    .await?
                    .map(|rs| CachedSession::from_resolved(&rs)))
            },
        )
        .await?;
        let now = clock::now_unix_secs();
        let Some(cached) = cached else {
            return Ok(None);
        };
        if !self.db.principal_is_live("user", cached.user_id).await? {
            return Ok(None);
        }
        Ok(cached.into_resolved(secret, now))
    }
}
