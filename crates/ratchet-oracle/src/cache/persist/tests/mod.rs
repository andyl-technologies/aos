//! Tests for the persistent eval-cache layout and stores.
//!
//! Shared fixtures live here; the test cases are grouped by concern into the
//! child modules below.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::cache::MaterializationCosts;

mod cache_artifact_tests;
mod cache_io_tests;
mod format_tests;
mod layout_tests;
mod pack_tests;
mod root_record_tests;
mod schema_tests;

static TEST_ID: AtomicUsize = AtomicUsize::new(0);

fn temp_root() -> PathBuf {
    let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aos-nix-persist-cache-{id}-{}", std::process::id()))
}

fn sentinel(path: PathBuf) -> PathBuf {
    fs::create_dir_all(path.parent().expect("sentinel parent exists"))
        .expect("sentinel parent creates");
    fs::write(&path, b"keep me").expect("sentinel writes");
    path
}

fn test_parse_key(source: &[u8]) -> ParseCacheKey {
    use crate::cache::parse::{PARSE_CACHE_SCHEMA_VERSION, ParseCacheFlags};

    ParseCacheKey::for_source(source, PARSE_CACHE_SCHEMA_VERSION, ParseCacheFlags::new())
}

fn bundle_with_meta(
    bundle: &ParseArtifactBundle,
    meta: crate::cache::parse::ParseCacheMeta,
) -> ParseArtifactBundle {
    match bundle.facts_bytes() {
        Some(facts) => ParseArtifactBundle::new_with_facts(
            bundle.resolved_bytes(),
            bundle.ir_bytes(),
            bundle.symbols_bytes(),
            meta.to_toml().into_bytes(),
            facts,
        ),
        None => ParseArtifactBundle::new(
            bundle.resolved_bytes(),
            bundle.ir_bytes(),
            bundle.symbols_bytes(),
            meta.to_toml().into_bytes(),
        ),
    }
}

fn bundle_with_resolved(
    bundle: &ParseArtifactBundle,
    resolved: impl Into<Vec<u8>>,
) -> ParseArtifactBundle {
    match bundle.facts_bytes() {
        Some(facts) => ParseArtifactBundle::new_with_facts(
            resolved,
            bundle.ir_bytes(),
            bundle.symbols_bytes(),
            bundle.meta_toml_bytes(),
            facts,
        ),
        None => ParseArtifactBundle::new(
            resolved,
            bundle.ir_bytes(),
            bundle.symbols_bytes(),
            bundle.meta_toml_bytes(),
        ),
    }
}

fn profitable_materialization_signals(
    likely_redemanded_across_runs: bool,
) -> MaterializationSignals {
    MaterializationSignals::new(
        MaterializationCosts::new(100, 10, 20, 30),
        likely_redemanded_across_runs,
    )
}
