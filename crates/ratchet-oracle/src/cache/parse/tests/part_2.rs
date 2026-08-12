//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn lowered_ir_artifacts_roundtrip_through_entry_files() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = r#"
        let
          name = "dyn";
        in rec {
          ${name} = builtins.getEnv "HOME";
          drv = derivationStrict { name = "x"; };
          flag = true;
          kind = builtins.typeOf flag;
          broken = builtins.break (name == "dyn");
          none = null;
          picked = with { fallback = 2; }; fallback;
        }
    "#;
    let resolved = resolve(parse_str(source).expect("source parses")).expect("scope resolves");
    let expected = nix_lower(file_local_resolved(&resolved).expect("symbols remap"))
        .expect("resolved AST lowers");
    let entry = cache.entry_for_source(source.as_bytes());
    let meta = ParseCacheMeta::new(
        cache.schema_version(),
        Some("expr.nix".to_owned()),
        resolved.arena.len() as u32,
        resolved.symbols.len() as u32,
    );

    entry
        .write_resolved(&resolved, &meta)
        .expect("resolved artifact writes");
    assert!(entry.is_complete());
    assert!(
        entry
            .read_artifact_bundle()
            .expect("artifact bundle reads")
            .facts_bytes()
            .is_some()
    );

    let (loaded, _) = entry.read_ir().expect("lowered IR artifact reads");
    assert!(lowered_ir_matches(&loaded, &expected));
    let dynamic_binding = loaded
        .bindings
        .iter()
        .find(|binding| matches!(binding.key, IrAttrPathSegment::Dynamic(_)))
        .expect("dynamic binding round-trips");
    let dynamic_start = source.find("${name}").expect("dynamic binding exists") as u32;
    assert_eq!(
        dynamic_binding.position,
        Some(Span::new(
            dynamic_start,
            dynamic_start + "${name}".len() as u32
        ))
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn lowered_ir_entry_read_overlays_optional_fact_sidecar() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = "let x = 1; in x";
    let resolved = resolve(parse_str(source).expect("source parses")).expect("scope resolves");
    let entry = cache.entry_for_source(source.as_bytes());
    let meta = ParseCacheMeta::new(
        cache.schema_version(),
        Some("expr.nix".to_owned()),
        resolved.arena.len() as u32,
        resolved.symbols.len() as u32,
    );
    entry
        .write_resolved(&resolved, &meta)
        .expect("resolved artifact writes");
    let (base_ir, _) = entry.read_ir().expect("IR reads");
    let fact_id = base_ir.root;
    let mut expected = IrFacts::conservative(base_ir.arena.nodes().len());
    let root_fact = ExprFacts {
        strictness: Strictness::DemandedBeforeEffect,
        cardinality: Cardinality::Once,
        escape: Escape::NoEscape,
    };
    *expected.get_mut(fact_id).expect("root fact exists") = root_fact;
    let stored = entry.read_artifact_bundle().expect("artifact bundle reads");
    let overlaid = ParseArtifactBundle::new_with_facts(
        stored.resolved_bytes(),
        stored.ir_bytes(),
        stored.symbols_bytes(),
        stored.meta_toml_bytes(),
        encode_ir_facts(
            &expected,
            lowered_ir_fingerprint(&base_ir).expect("IR fingerprint computes"),
            crate::compile::IR_ANALYSIS_VERSION,
        )
        .expect("fact artifact encodes"),
    );
    entry
        .write_artifact_bundle(&overlaid)
        .expect("fact sidecar writes");

    let (loaded, _) = entry.read_ir().expect("lowered IR artifact reads");

    assert_eq!(loaded.facts.as_slice(), expected.as_slice());
    assert_eq!(loaded.node_facts(fact_id), Some(root_fact));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_fact_sidecar_persists_refreshed_analysis_facts() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"builtins.toJSON (let x = 1; in x)";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let mut analyzed = parsed.ir.clone();
    crate::compile::annotate_ir(&mut analyzed).expect("analysis succeeds");
    assert_ne!(
        parsed.ir.facts.as_slice(),
        analyzed.facts.as_slice(),
        "analysis should refresh at least one fact"
    );

    parsed
        .entry
        .write_fact_sidecar(&analyzed)
        .expect("refreshed fact sidecar writes");
    let (loaded, facts_current) = parsed
        .entry
        .read_ir()
        .expect("refreshed fact sidecar reads");

    assert!(lowered_ir_matches(&loaded, &analyzed));
    assert_eq!(loaded.facts.as_slice(), analyzed.facts.as_slice());
    assert!(
        facts_current,
        "refreshed sidecar records the current analysis version"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_fact_sidecar_rejects_ir_for_different_artifact() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let parsed = cache
        .load_or_parse_bytes(b"let x = 1; in x", Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let original_bundle = fs::read(parsed.entry.bundle_path()).expect("original bundle read");
    let mut other = lowered_ir_for_source("let y = 2; in y");
    crate::compile::annotate_ir(&mut other).expect("analysis succeeds");

    let error = parsed
        .entry
        .write_fact_sidecar(&other)
        .expect_err("mismatched fact sidecar is rejected");

    assert!(matches!(
        error,
        ParseCacheError::InvalidFactSidecarUpdate { path, message }
            if path == parsed.entry.bundle_path() && message.contains("fingerprint")
    ));
    assert_eq!(
        fs::read(parsed.entry.bundle_path()).expect("bundle remains readable"),
        original_bundle
    );
    assert!(
        parsed
            .ir
            .facts
            .as_slice()
            .iter()
            .all(|facts| *facts == ExprFacts::conservative()),
        "failed analysis should leave in-memory facts conservative"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_fact_sidecar_rejects_wrong_fact_table_length() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let parsed = cache
        .load_or_parse_bytes(b"let x = 1; in x", Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let original_bundle = fs::read(parsed.entry.bundle_path()).expect("original bundle read");
    let mut invalid = parsed.ir.clone();
    invalid.facts = IrFacts::conservative(invalid.arena.nodes().len() + 1);

    let error = parsed
        .entry
        .write_fact_sidecar(&invalid)
        .expect_err("invalid fact table length is rejected");

    assert!(matches!(
        error,
        ParseCacheError::InvalidFactSidecarUpdate { path, message }
            if path == parsed.entry.bundle_path() && message.contains("fact table length")
    ));
    assert_eq!(
        fs::read(parsed.entry.bundle_path()).expect("bundle remains readable"),
        original_bundle
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_fact_sidecar_reports_corrupt_stored_artifact() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let parsed = cache
        .load_or_parse_bytes(b"let x = 1; in x", Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    // Corrupt only the lowered-IR section, keeping the bundle frame decodable so
    // write_fact_sidecar surfaces a DecodeArtifact for the stored IR.
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let corrupt = ParseArtifactBundle::new(
        bundle.resolved_bytes(),
        b"not an ir artifact".to_vec(),
        bundle.symbols_bytes(),
        bundle.meta_toml_bytes(),
    );
    fs::write(
        parsed.entry.bundle_path(),
        corrupt.encode().expect("corrupt bundle encodes"),
    )
    .expect("corrupt ir writes");

    let error = parsed
        .entry
        .write_fact_sidecar(&parsed.ir)
        .expect_err("corrupt stored IR is rejected");

    assert!(matches!(
        error,
        ParseCacheError::DecodeArtifact { path, .. } if path == parsed.entry.bundle_path()
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_fact_sidecar_reports_corrupt_stored_symbols() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let parsed = cache
        .load_or_parse_bytes(b"let x = 1; in x", Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    // Corrupt only the symbol section, keeping the bundle frame decodable so
    // write_fact_sidecar surfaces a DecodeArtifact for the stored symbols.
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let corrupt = ParseArtifactBundle::new(
        bundle.resolved_bytes(),
        bundle.ir_bytes(),
        b"not a symbol artifact".to_vec(),
        bundle.meta_toml_bytes(),
    );
    fs::write(
        parsed.entry.bundle_path(),
        corrupt.encode().expect("corrupt bundle encodes"),
    )
    .expect("corrupt symbols write");

    let error = parsed
        .entry
        .write_fact_sidecar(&parsed.ir)
        .expect_err("corrupt stored symbols are rejected");

    assert!(matches!(
        error,
        ParseCacheError::DecodeArtifact { path, .. } if path == parsed.entry.bundle_path()
    ));

    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn write_fact_sidecar_reports_fact_write_failure() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let parsed = cache
        .load_or_parse_bytes(b"let x = 1; in x", Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    // The stored bundle must still read, but its atomic rewrite must fail: make
    // the entry directory read-only so the temp file cannot be created while the
    // existing bundle stays readable.
    fs::set_permissions(parsed.entry.dir(), fs::Permissions::from_mode(0o555))
        .expect("entry dir turns read-only");

    let error = parsed.entry.write_fact_sidecar(&parsed.ir);

    fs::set_permissions(parsed.entry.dir(), fs::Permissions::from_mode(0o755))
        .expect("entry dir permissions restore");
    let error = error.expect_err("fact sidecar write failure is reported");

    assert!(matches!(
        error,
        ParseCacheError::WriteArtifact { path, .. } if path == parsed.entry.bundle_path()
    ));
    assert!(
        cache_temp_files(&parsed.entry).is_empty(),
        "temporary files were not cleaned up"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cached_parse_refresh_and_store_facts_updates_memory_and_sidecar() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"builtins.toJSON (let x = 1; in x)";
    let mut parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let conservative = parsed.ir.facts.as_slice().to_vec();

    let report = parsed
        .refresh_and_store_facts()
        .expect("facts refresh and store");

    assert!(!report.dependency_footprint.is_empty());
    assert_ne!(parsed.ir.facts.as_slice(), conservative.as_slice());
    let cached = cache
        .load_cached_bytes(source)
        .expect("cache read succeeds")
        .expect("cache entry exists");
    assert_eq!(cached.ir.facts.as_slice(), parsed.ir.facts.as_slice());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cached_parse_ensure_facts_skips_reanalysis_on_version_current_sidecar() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"builtins.toJSON (let x = 1; in x)";
    let mut parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");

    // The freshly-written entry carries an unanalyzed (version 0) sidecar.
    assert!(!parsed.facts_current);
    let report = parsed
        .ensure_facts_current_and_stored()
        .expect("facts refresh and store");
    assert!(report.is_some(), "a cold entry runs the analysis");
    assert!(parsed.facts_current);

    // A warm load applies the version-current sidecar and skips re-analysis.
    let mut warm = cache
        .load_cached_bytes(source)
        .expect("cache read succeeds")
        .expect("cache entry exists");
    assert!(warm.facts_current, "warm load applies the current sidecar");
    let warm_facts = warm.ir.facts.as_slice().to_vec();
    let skipped = warm
        .ensure_facts_current_and_stored()
        .expect("warm ensure succeeds");
    assert!(skipped.is_none(), "warm ensure skips re-analysis");
    assert_eq!(warm.ir.facts.as_slice(), warm_facts.as_slice());
    assert_eq!(warm.ir.facts.as_slice(), parsed.ir.facts.as_slice());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cached_parse_ensure_facts_reanalyzes_on_stale_analysis_version() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"builtins.toJSON (let x = 1; in x)";
    let mut parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    parsed
        .ensure_facts_current_and_stored()
        .expect("cold analysis succeeds");

    // Rewrite the bundle's fact section with a stale (bumped-away-from) analysis
    // version, keeping the fingerprint valid so it decodes but is not current.
    let stored = parsed
        .entry
        .read_artifact_bundle()
        .expect("stored bundle reads");
    let stale = encode_ir_facts(
        &parsed.ir.facts,
        lowered_ir_fingerprint(&parsed.ir).expect("IR fingerprint computes"),
        IR_ANALYSIS_VERSION + 1,
    )
    .expect("stale sidecar encodes");
    let stale_bundle = ParseArtifactBundle::new_with_facts(
        stored.resolved_bytes(),
        stored.ir_bytes(),
        stored.symbols_bytes(),
        stored.meta_toml_bytes(),
        stale,
    );
    fs::write(
        parsed.entry.bundle_path(),
        stale_bundle.encode().expect("stale bundle encodes"),
    )
    .expect("stale sidecar writes");

    let mut warm = cache
        .load_cached_bytes(source)
        .expect("cache read succeeds")
        .expect("cache entry exists");
    assert!(
        !warm.facts_current,
        "a non-current analysis version is not consumed as current"
    );
    let report = warm
        .ensure_facts_current_and_stored()
        .expect("stale entry re-analyzes");
    assert!(report.is_some());
    assert!(warm.facts_current);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cached_parse_refresh_facts_updates_memory_without_sidecar_write() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"builtins.toJSON (let x = 1; in x)";
    let mut parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let original_bundle = fs::read(parsed.entry.bundle_path()).expect("original bundle read");

    parsed.refresh_facts().expect("facts refresh");

    assert!(
        parsed
            .ir
            .facts
            .as_slice()
            .iter()
            .any(|facts| *facts != ExprFacts::conservative())
    );
    assert_eq!(
        fs::read(parsed.entry.bundle_path()).expect("bundle remains readable"),
        original_bundle
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cached_parse_refresh_and_store_facts_reports_analysis_failure_without_writing() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let mut parsed = cache
        .load_or_parse_bytes(b"let x = 1; in x", Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let original_bundle = fs::read(parsed.entry.bundle_path()).expect("original bundle read");
    parsed.ir.root = IrId::new(u32::MAX);

    let error = parsed
        .refresh_and_store_facts()
        .expect_err("invalid IR root rejects analysis");

    assert!(matches!(error, ParseFactRefreshError::Analyze { .. }));
    assert_eq!(
        fs::read(parsed.entry.bundle_path()).expect("bundle remains readable"),
        original_bundle
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_or_parse_analyzed_bytes_refreshes_memory_and_sidecar() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"builtins.toJSON (let x = 1; in x)";

    let analyzed = cache
        .load_or_parse_analyzed_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses and analyzes");

    assert!(!analyzed.parsed.hit);
    assert!(analyzed.parsed.stored);
    assert!(analyzed.facts_stored);
    assert!(!analyzed.analysis.dependency_footprint.is_empty());
    assert!(
        analyzed
            .parsed
            .ir
            .facts
            .as_slice()
            .iter()
            .any(|facts| *facts != ExprFacts::conservative())
    );

    let hit = cache
        .load_cached_bytes(source)
        .expect("cached source loads")
        .expect("cache entry exists");
    assert!(hit.hit);
    assert_eq!(hit.ir.facts.as_slice(), analyzed.parsed.ir.facts.as_slice());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_or_parse_analyzed_bytes_refreshes_existing_cache_hits() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"builtins.toJSON (let x = 1; in x)";
    let miss = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    assert!(!miss.hit);
    assert!(
        miss.ir
            .facts
            .as_slice()
            .iter()
            .all(|facts| *facts == ExprFacts::conservative())
    );

    let analyzed = cache
        .load_or_parse_analyzed_bytes(source, Some("expr.nix".to_owned()))
        .expect("source loads and analyzes from cache");

    assert!(analyzed.parsed.hit);
    assert!(analyzed.facts_stored);
    assert!(
        analyzed
            .parsed
            .ir
            .facts
            .as_slice()
            .iter()
            .any(|facts| *facts != ExprFacts::conservative())
    );

    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn load_or_parse_analyzed_bytes_keeps_analysis_when_fact_storage_fails() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"builtins.toJSON (let x = 1; in x)";
    // Populate a complete entry (conservative facts in its bundle), then make the
    // entry directory read-only so the analyzed load hits the mandatory bundle
    // but cannot rewrite its fact section.
    let entry = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss")
        .entry;
    fs::set_permissions(entry.dir(), fs::Permissions::from_mode(0o555))
        .expect("entry dir turns read-only");

    let analyzed = cache
        .load_or_parse_analyzed_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses and analyzes despite fact sidecar failure");
    let cached = cache
        .load_cached_bytes(source)
        .expect("cached source loads")
        .expect("cache entry exists");

    fs::set_permissions(entry.dir(), fs::Permissions::from_mode(0o755))
        .expect("entry dir permissions restore");

    assert!(analyzed.parsed.stored);
    assert!(!analyzed.facts_stored);
    assert!(
        analyzed
            .parsed
            .ir
            .facts
            .as_slice()
            .iter()
            .any(|facts| *facts != ExprFacts::conservative())
    );
    assert!(
        cached
            .ir
            .facts
            .as_slice()
            .iter()
            .all(|facts| *facts == ExprFacts::conservative()),
        "failed sidecar storage should not make cached reads analyzed"
    );

    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn cached_parse_refresh_and_store_facts_reports_sidecar_write_failure() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let mut parsed = cache
        .load_or_parse_bytes(
            b"builtins.toJSON (let x = 1; in x)",
            Some("expr.nix".to_owned()),
        )
        .expect("source parses on miss");
    // The stored bundle must still read, but its atomic rewrite must fail: make
    // the entry directory read-only so the fact-refresh write cannot commit.
    fs::set_permissions(parsed.entry.dir(), fs::Permissions::from_mode(0o555))
        .expect("entry dir turns read-only");

    let error = parsed.refresh_and_store_facts();

    fs::set_permissions(parsed.entry.dir(), fs::Permissions::from_mode(0o755))
        .expect("entry dir permissions restore");
    let error = error.expect_err("fact sidecar write failure is reported");

    assert!(matches!(
        error,
        ParseFactRefreshError::Cache(ParseCacheError::WriteArtifact { path, .. })
            if path == parsed.entry.bundle_path()
    ));
    assert!(
        parsed
            .ir
            .facts
            .as_slice()
            .iter()
            .any(|facts| *facts != ExprFacts::conservative()),
        "in-memory facts should remain refreshed after sidecar write failure"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn lowered_ir_entry_ignores_mismatched_fact_sidecar_fingerprint() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let first = cache
        .load_or_parse_bytes(b"1", Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let other_ir = lowered_ir_for_source("2");
    // Replace the bundle's lowered-IR section but keep the original fact section:
    // the retained facts now fingerprint-mismatch the swapped IR, so read_ir must
    // ignore them and fall back to conservative facts.
    let bundle = first
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let facts = bundle
        .facts_bytes()
        .expect("freshly parsed entry carries a fact sidecar");
    let mismatched = ParseArtifactBundle::new_with_facts(
        bundle.resolved_bytes(),
        encode_lowered_ir(&other_ir).expect("other IR encodes"),
        bundle.symbols_bytes(),
        bundle.meta_toml_bytes(),
        facts,
    );
    fs::write(
        first.entry.bundle_path(),
        mismatched.encode().expect("mismatched bundle encodes"),
    )
    .expect("replacement IR writes");

    let (loaded, facts_current) = first
        .entry
        .read_ir()
        .expect("stale fact sidecar is ignored");

    assert!(!facts_current, "a stale fact sidecar cannot be current");
    assert!(lowered_ir_matches(&loaded, &other_ir));
    assert!(
        loaded
            .facts
            .as_slice()
            .iter()
            .all(|facts| *facts == ExprFacts::conservative())
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn lowered_ir_roundtrip_preserves_captured_search_path_literal() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = "let __nixPath = []; in <a.nix>";
    let resolved = resolve(parse_str(source).expect("source parses")).expect("scope resolves");
    let expected = nix_lower(file_local_resolved(&resolved).expect("symbols remap"))
        .expect("resolved AST lowers");
    let entry = cache.entry_for_source(source.as_bytes());
    let meta = ParseCacheMeta::new(
        cache.schema_version(),
        Some("expr.nix".to_owned()),
        resolved.arena.len() as u32,
        resolved.symbols.len() as u32,
    );

    entry
        .write_resolved(&resolved, &meta)
        .expect("resolved artifact writes");
    assert!(entry.is_complete());

    let (loaded, _) = entry.read_ir().expect("lowered IR artifact reads");
    assert!(lowered_ir_matches(&loaded, &expected));
    let search_path = loaded
        .arena
        .nodes()
        .iter()
        .find_map(|node| match node.data {
            IrData::SearchPath {
                literal,
                search_path: Some(search_path),
            } => Some((literal, search_path)),
            _ => None,
        })
        .expect("captured search-path payload round-trips");
    assert_eq!(
        loaded.symbols.resolve(search_path.0),
        Some(b"<a.nix>".as_slice())
    );
    assert_eq!(
        loaded.arena.nodes()[search_path.1.index()].kind,
        IrKind::LocalVar
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn content_hash_key_matches_source_key_and_addresses_the_same_entry() {
    use crate::cache::ParseFileContentHash;

    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let content_hash = ParseFileContentHash::for_source(source);

    // The source-bytes and content-hash key derivations must agree.
    assert_eq!(
        cache.key_for_source(source),
        cache.key_for_content_hash(content_hash)
    );

    // Storing through the content-hash path is a hit through the source path and
    // vice versa: both derivations address the same on-disk entry.
    let stored = cache
        .load_or_parse_bytes_with_content_hash(source, content_hash, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    assert!(!stored.hit);
    assert!(stored.stored);

    let via_source = cache
        .load_cached_bytes(source)
        .expect("cached load succeeds")
        .expect("entry is present");
    assert!(via_source.hit);
    assert_eq!(via_source.key, stored.key);

    let reparse = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("second load succeeds");
    assert!(reparse.hit);
    assert_eq!(reparse.key, stored.key);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn distinct_sources_produce_distinct_content_hash_keys() {
    use crate::cache::ParseFileContentHash;

    let cache = ParseCache::new(PathBuf::from("/nonexistent/parse"));
    let first = cache.key_for_content_hash(ParseFileContentHash::for_source(b"let a = 1; in a"));
    let second = cache.key_for_content_hash(ParseFileContentHash::for_source(b"let b = 2; in b"));

    assert_ne!(first, second);
}
