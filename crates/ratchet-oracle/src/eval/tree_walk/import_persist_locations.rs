//! Multi-location (L2) probing for import-time persistent parse artifacts.
//!
//! MEMO-2 (RFC-0007 doc 29 §5.4) generalizes the persist cache to an ordered
//! list of disk locations. Imports hydrate parse artifacts on the eval hot
//! path, so their probe order lives here: the primary location first, then
//! each opened `AOS_NIX_MEMO_DISK` secondary (fastest class first). A
//! secondary hit is promoted by materializing the hydrated artifact into the
//! primary location and is counted in the `memo_l2_*` stats; when no
//! secondary is configured the path is byte-identical to the historical
//! primary-only probe (one `Vec::is_empty` check).

use super::*;

use crate::cache::hashing::cache_hash_family;

impl TreeWalk {
    /// Loads an import's parse artifact from any configured persist location.
    ///
    /// Returns the first hydrated artifact in probe order. Secondary hits are
    /// promoted into the primary location (unconditionally — the artifact
    /// demonstrably exists on a slower location and belongs on the fast path)
    /// and counted; promotion failures are ignored.
    pub(super) fn load_persist_cached_import(
        &mut self,
        realpath: &Path,
        source: &[u8],
    ) -> Option<CachedParse> {
        self.open_persist_import_cache();
        let cache = self.parse_cache.as_ref()?;
        if let Some(persist_cache) = self.persist_cache.as_ref() {
            if let Some(cached) = persist_cache
                .load_parse_cache_source_from_index(cache, realpath, source)
                .ok()
                .flatten()
            {
                return Some(cached);
            }
        }
        if self.persist_secondary_caches.is_empty() {
            return None;
        }
        // The parse-artifact key is derived under the primary's content-hash
        // family. A same-family secondary is probed directly; a cross-family
        // secondary is probed by re-deriving its keys under its own recorded
        // family from the identity-carrying (realpath, source) preimage
        // (RFC-0007 §P4 Option C). Either way a hit is promoted into the primary
        // under the primary family below. The homogeneous stack takes the direct
        // path — no extra hashing.
        let probe_family = self
            .persist_cache
            .as_ref()
            .map_or_else(cache_hash_family, PersistCache::hash_family);
        let mut secondary_hit = None;
        for (_, secondary) in &self.persist_secondary_caches {
            let secondary_family = secondary.hash_family();
            let cached = if secondary_family == probe_family {
                secondary
                    .load_parse_cache_source_from_index(cache, realpath, source)
                    .ok()
                    .flatten()
            } else {
                secondary
                    .load_parse_cache_source_from_index_for_family(
                        cache,
                        realpath,
                        source,
                        secondary_family,
                    )
                    .ok()
                    .flatten()
            };
            if let Some(cached) = cached {
                secondary_hit = Some(cached);
                break;
            }
        }
        let Some(cached) = secondary_hit else {
            self.stats.memo_l2_secondary_misses =
                self.stats.memo_l2_secondary_misses.saturating_add(1);
            return None;
        };
        self.stats.memo_l2_secondary_hits = self.stats.memo_l2_secondary_hits.saturating_add(1);
        if let Some(persist_cache) = self.persist_cache.as_ref() {
            let file_key = ParseFileKey::for_source(realpath, source);
            if persist_cache
                .materialize_parse_artifact_entry_indexed(
                    &file_key,
                    cached.key,
                    &cached.entry,
                    MaterializationDecision::Materialize,
                )
                .is_ok()
            {
                self.stats.memo_l2_promotions = self.stats.memo_l2_promotions.saturating_add(1);
            }
        }
        Some(cached)
    }
}
