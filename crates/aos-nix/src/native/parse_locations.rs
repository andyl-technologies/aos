//! Multi-location (L2) probing for the entry file's persistent parse artifact.
//!
//! MEMO-2 generalizes the persist cache to an ordered list of disk locations
//! (RFC-0007 doc 29 §5.4). The native instantiate path parses its entry file
//! before any evaluator exists, so its parse-artifact probe lives here: the
//! primary `AOS_NIX_CACHE` location is consulted first, then each
//! `AOS_NIX_MEMO_DISK` secondary (fastest class first). A secondary hit is
//! promoted by materializing the hydrated artifact into the primary location,
//! so subsequent runs answer from the fast path. Import-time parse artifacts
//! take the analogous path inside the tree walk (`import_persist_locations`).

use super::*;

use crate::cache::persist::open_secondary_caches;

impl NixNative {
    /// Probes every configured persist-cache location for a parse artifact.
    ///
    /// Returns the first hydrated artifact together with whether it came from
    /// a secondary location (and therefore should be promoted). Location-level
    /// failures are treated as misses at that location.
    pub(super) fn load_native_parse_artifact_any(
        &self,
        cache: &ParseCache,
        persist_cache: &PersistCache,
        source_path: Option<&Path>,
        source: &[u8],
    ) -> Option<(CachedParse, bool)> {
        if let Some(cached) = load_parse_artifact_from(persist_cache, cache, source_path, source) {
            return Some((cached, false));
        }
        let secondaries = self.options.memo_disk_locations();
        if secondaries.is_empty() {
            return None;
        }
        for (_, secondary) in
            open_secondary_caches(secondaries, self.options.persist_cache_verify())
        {
            if let Some(cached) = load_parse_artifact_from(&secondary, cache, source_path, source) {
                return Some((cached, true));
            }
        }
        None
    }

    /// Copies a secondary-location parse artifact into the primary location.
    ///
    /// This is the L2 promotion write: unconditional (not gated on the
    /// in-memory entry's `stored` flag) because the artifact demonstrably
    /// exists on a slower location and belongs on the fast path. Failures are
    /// ignored — the artifact remains readable from its home location.
    pub(super) fn promote_native_parse_artifact(
        &self,
        persist_cache: &PersistCache,
        source: &[u8],
        source_path: Option<&Path>,
        cached: &CachedParse,
    ) {
        if let Some(source_path) = source_path {
            let file_key = ParseFileKey::for_source(source_path, source);
            let _ = persist_cache.materialize_parse_artifact_entry_indexed(
                &file_key,
                cached.key,
                &cached.entry,
                MaterializationDecision::Materialize,
            );
        } else {
            let _ = persist_cache.materialize_parse_cache_entry_indexed(
                cached.key,
                &cached.entry,
                MaterializationDecision::Materialize,
            );
        }
    }
}

/// Loads a parse artifact from one location, mapping failures to a miss.
fn load_parse_artifact_from(
    persist_cache: &PersistCache,
    cache: &ParseCache,
    source_path: Option<&Path>,
    source: &[u8],
) -> Option<CachedParse> {
    if let Some(source_path) = source_path {
        persist_cache
            .load_parse_cache_source_from_index(cache, source_path, source)
            .ok()
            .flatten()
    } else {
        persist_cache
            .load_parse_cache_bytes_from_index(cache, source)
            .ok()
            .flatten()
    }
}
