//! Sessions reads in the identity capability.

use super::*;

impl RpcService {
    /// Resolves a session from its cookie secret, read-through cached in KV when
    /// a [`KvStore`](crate::kv::KvStore) is attached (RFC-0004 ch.14 Phase C).
    ///
    /// A cache hit reuses presentation and sudo metadata for
    /// [`HOT_TTL_SECS`](crate::cache::HOT_TTL_SECS) and skips the cold loader's
    /// `last_seen_at` bookkeeping write. The authenticated cookie hash, original
    /// session/account UUID pin and live idle/absolute bounds are checked in SQL
    /// on every resolution. [`invalidate_session_cache`] also removes cached
    /// presentation state on logout.
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
        let Some(resolved) = cached.into_resolved(secret, now) else {
            return Ok(None);
        };
        // Cached provenance must still match the retained session pin as well
        // as its live account. An old cache cannot revive an unpinned cookie.
        if !self.db.session_auth_is_current(&resolved.auth).await? {
            return Ok(None);
        }
        Ok(Some(resolved))
    }
}
