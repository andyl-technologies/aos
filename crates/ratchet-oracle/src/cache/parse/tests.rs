//! Unit tests for the parse artifact cache: key/flag identity, round-trip
//! encode/decode of resolved and lowered artifacts, file memoization, and
//! corruption handling.

use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::compile::{lower, resolve};
use crate::syntax::parse_str;
use aos_nix_dialect::nix_lower;

static TEST_ID: AtomicUsize = AtomicUsize::new(0);

mod artifact_bundle;
mod artifact_validation;
mod chunk_e;
mod part_1;
mod part_2;
mod simplify_identity;

fn temp_root() -> PathBuf {
    let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aos-nix-parse-cache-{id}-{}", std::process::id()))
}

fn cache_temp_files(entry: &ParseCacheEntry) -> Vec<PathBuf> {
    fs::read_dir(entry.dir())
        .expect("entry dir reads")
        .map(|entry| entry.expect("dir entry reads").path())
        .filter(|path| {
            path.file_name()
                .expect("file name exists")
                .to_string_lossy()
                .contains(".tmp-")
        })
        .collect()
}

fn test_lowered_ir_fingerprint(source: &[u8]) -> LoweredIrFingerprint {
    LoweredIrFingerprint::from_durable_hash(DurableBlake3Hash::for_bytes(source))
}

fn resolved_single_symbol(symbols: SymbolTable, symbol: Symbol) -> ResolvedAst {
    ResolvedAst {
        root: NodeId::new(0),
        arena: AstArena::from_raw_parts(
            vec![Node::new(
                NodeKind::GlobalVar,
                Span::new(0, 1),
                NodeData::Symbol(symbol),
            )],
            Vec::new(),
        ),
        symbols,
        scopes: ScopeTables::from_raw_parts(
            Vec::new(),
            vec![None],
            Vec::new(),
            Vec::new(),
            vec![None],
        ),
    }
}

fn resolved_single_symbol_with_scopes(scopes: ScopeTables) -> ResolvedAst {
    let mut symbols = SymbolTable::new();
    let x = symbols.intern(b"x").expect("x symbol interns");
    ResolvedAst {
        root: NodeId::new(0),
        arena: AstArena::from_raw_parts(
            vec![Node::new(
                NodeKind::GlobalVar,
                Span::new(0, 1),
                NodeData::Symbol(x),
            )],
            Vec::new(),
        ),
        symbols,
        scopes,
    }
}

fn bundle_with_meta(bundle: &ParseArtifactBundle, meta: ParseCacheMeta) -> ParseArtifactBundle {
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

fn lowered_ir_for_source(source: &str) -> Ir {
    let resolved = resolve(parse_str(source).expect("source parses")).expect("scope resolves");
    nix_lower(file_local_resolved(&resolved).expect("symbols remap")).expect("resolved AST lowers")
}
