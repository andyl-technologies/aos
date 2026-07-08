//! Parse artifact bundle hydration and validation tests.

use super::*;

#[test]
fn artifact_bundle_round_trips_complete_entry_payloads() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");

    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let encoded = bundle.encode().expect("artifact bundle encodes");
    let decoded = ParseArtifactBundle::decode(&encoded).expect("artifact bundle decodes");

    assert_eq!(decoded, bundle);
    assert_eq!(decoded.facts_bytes(), bundle.facts_bytes());
    assert!(decoded.facts_bytes().is_some());
    assert!(String::from_utf8_lossy(decoded.meta_toml_bytes()).contains("schema_version = 10"));
    let meta = decoded.decode_meta().expect("bundle metadata decodes");
    assert_eq!(meta.schema_version, cache.schema_version());
    assert_eq!(meta.source_hint.as_deref(), Some("expr.nix"));

    let resolved_symbols =
        decode_symbols(decoded.symbols_bytes()).expect("resolved symbols decode");
    let resolved = decode_resolved_ir(decoded.resolved_bytes(), resolved_symbols)
        .expect("resolved artifact decodes");
    assert_eq!(resolved.arena.nodes(), parsed.resolved.arena.nodes());

    let ir_symbols = decode_symbols(decoded.symbols_bytes()).expect("IR symbols decode");
    let ir = decode_lowered_ir(decoded.ir_bytes(), ir_symbols).expect("IR artifact decodes");
    assert!(lowered_ir_matches(&ir, &parsed.ir));

    let factless_bundle = ParseArtifactBundle::new(
        bundle.resolved_bytes(),
        bundle.ir_bytes(),
        bundle.symbols_bytes(),
        bundle.meta_toml_bytes(),
    );
    let factless_encoded = factless_bundle
        .encode()
        .expect("factless artifact bundle encodes");
    let factless_decoded =
        ParseArtifactBundle::decode(&factless_encoded).expect("factless bundle decodes");
    assert_eq!(factless_decoded, factless_bundle);
    assert!(factless_decoded.facts_bytes().is_none());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_bundle_hydrates_entry_files() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let hydrated = ParseCacheEntry::new(root.join("hydrated-entry"));

    hydrated
        .write_artifact_bundle(&bundle)
        .expect("artifact bundle hydrates");

    assert!(hydrated.is_complete());
    assert!(hydrated.facts_path().is_file());
    assert_eq!(
        hydrated
            .read_artifact_bundle()
            .expect("hydrated bundle reads"),
        bundle
    );
    let resolved = hydrated
        .read_resolved()
        .expect("hydrated resolved artifact reads");
    assert_eq!(resolved.arena.nodes(), parsed.resolved.arena.nodes());
    let (ir, _) = hydrated.read_ir().expect("hydrated IR artifact reads");
    assert!(lowered_ir_matches(&ir, &parsed.ir));
    assert_eq!(ir.facts.as_slice(), parsed.ir.facts.as_slice());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_bundle_hydration_replaces_stale_fact_sidecar() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let hydrated = ParseCacheEntry::new(root.join("hydrated-entry"));
    hydrated
        .write_resolved(
            &parsed.resolved,
            &ParseCacheMeta::new(cache.schema_version(), Some("stale.nix".to_owned()), 0, 0),
        )
        .expect("initial artifact writes");
    let (stale_ir, _) = hydrated.read_ir().expect("initial IR reads");
    let mut stale_facts = IrFacts::conservative(stale_ir.arena.nodes().len());
    let stale_fact = ExprFacts {
        strictness: Strictness::DemandedBeforeEffect,
        cardinality: Cardinality::Once,
        escape: Escape::NoEscape,
    };
    *stale_facts
        .get_mut(stale_ir.root)
        .expect("stale root fact exists") = stale_fact;
    fs::write(
        hydrated.facts_path(),
        encode_ir_facts(
            &stale_facts,
            lowered_ir_fingerprint(&stale_ir).expect("stale IR fingerprint computes"),
            crate::compile::IR_ANALYSIS_VERSION,
        )
        .expect("stale facts encode"),
    )
    .expect("stale facts write");

    assert!(hydrated.facts_path().is_file());

    hydrated
        .write_artifact_bundle(&bundle)
        .expect("artifact bundle hydrates");

    assert!(hydrated.is_complete());
    assert!(hydrated.facts_path().is_file());
    let (ir, _) = hydrated.read_ir().expect("hydrated IR reads");
    assert_eq!(ir.facts.as_slice(), parsed.ir.facts.as_slice());
    assert_ne!(ir.node_facts(ir.root), Some(stale_fact));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_bundle_hydration_removes_stale_fact_sidecar_for_factless_bundles() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let factless_bundle = ParseArtifactBundle::new(
        bundle.resolved_bytes(),
        bundle.ir_bytes(),
        bundle.symbols_bytes(),
        bundle.meta_toml_bytes(),
    );
    let hydrated = ParseCacheEntry::new(root.join("hydrated-entry"));
    hydrated
        .write_resolved(
            &parsed.resolved,
            &ParseCacheMeta::new(cache.schema_version(), Some("stale.nix".to_owned()), 0, 0),
        )
        .expect("initial artifact writes");

    assert!(hydrated.facts_path().is_file());

    hydrated
        .write_artifact_bundle(&factless_bundle)
        .expect("factless artifact bundle hydrates");

    assert!(hydrated.is_complete());
    assert!(!hydrated.facts_path().exists());
    let (ir, _) = hydrated.read_ir().expect("hydrated IR reads");
    assert!(
        ir.facts
            .as_slice()
            .iter()
            .all(|facts| *facts == ExprFacts::conservative())
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_bundle_hydration_ignores_invalid_fact_payloads() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let malformed_fact_bundle = ParseArtifactBundle::new_with_facts(
        bundle.resolved_bytes(),
        bundle.ir_bytes(),
        bundle.symbols_bytes(),
        bundle.meta_toml_bytes(),
        b"not a facts artifact",
    );
    let hydrated = ParseCacheEntry::new(root.join("hydrated-entry"));

    hydrated
        .write_artifact_bundle(&malformed_fact_bundle)
        .expect("artifact bundle hydrates");

    assert!(hydrated.is_complete());
    assert!(!hydrated.facts_path().exists());
    let (ir, _) = hydrated.read_ir().expect("hydrated IR reads");
    assert!(
        ir.facts
            .as_slice()
            .iter()
            .all(|facts| *facts == ExprFacts::conservative())
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_bundle_validated_write_checks_metadata_before_hydration() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let hydrated = ParseCacheEntry::new(root.join("validated-entry"));

    let meta = hydrated
        .write_artifact_bundle_validated(&bundle, cache.schema_version())
        .expect("validated artifact bundle hydrates");

    assert_eq!(meta.schema_version, cache.schema_version());
    assert_eq!(meta.source_hint.as_deref(), Some("expr.nix"));
    assert!(hydrated.is_complete());
    assert_eq!(
        hydrated
            .read_artifact_bundle()
            .expect("hydrated bundle reads"),
        bundle
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_bundle_validated_write_rejects_schema_mismatch_before_writing() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let meta = bundle.decode_meta().expect("bundle metadata decodes");
    let wrong_meta = ParseCacheMeta::new(
        cache.schema_version() + 1,
        meta.source_hint,
        meta.node_count,
        meta.symbol_count,
    );
    let wrong_schema_bundle = bundle_with_meta(&bundle, wrong_meta);
    let hydrated = ParseCacheEntry::new(root.join("validated-entry"));

    let error = hydrated
        .write_artifact_bundle_validated(&wrong_schema_bundle, cache.schema_version())
        .expect_err("schema mismatch errors");

    assert!(matches!(
        error,
        ParseCacheError::DecodeMeta { message } if message.contains("schema_version")
    ));
    assert!(!hydrated.dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_bundle_validated_write_rejects_symbol_count_mismatch_before_writing() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let meta = bundle.decode_meta().expect("bundle metadata decodes");
    let wrong_meta = ParseCacheMeta::new(
        meta.schema_version,
        meta.source_hint,
        meta.node_count,
        meta.symbol_count + 1,
    );
    let wrong_count_bundle = bundle_with_meta(&bundle, wrong_meta);
    let hydrated = ParseCacheEntry::new(root.join("validated-entry"));

    let error = hydrated
        .write_artifact_bundle_validated(&wrong_count_bundle, cache.schema_version())
        .expect_err("symbol-count mismatch errors");

    assert!(matches!(
        error,
        ParseCacheError::DecodeMeta { message } if message.contains("symbol_count")
    ));
    assert!(!hydrated.dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_bundle_validated_write_rejects_node_count_mismatch_before_writing() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let meta = bundle.decode_meta().expect("bundle metadata decodes");
    let wrong_meta = ParseCacheMeta::new(
        meta.schema_version,
        meta.source_hint,
        meta.node_count + 1,
        meta.symbol_count,
    );
    let wrong_count_bundle = bundle_with_meta(&bundle, wrong_meta);
    let hydrated = ParseCacheEntry::new(root.join("validated-entry"));

    let error = hydrated
        .write_artifact_bundle_validated(&wrong_count_bundle, cache.schema_version())
        .expect_err("node-count mismatch errors");

    assert!(matches!(
        error,
        ParseCacheError::DecodeMeta { message } if message.contains("node_count")
    ));
    assert!(!hydrated.dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_bundle_validated_write_rejects_malformed_resolved_before_writing() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let malformed_bundle = bundle_with_resolved(&bundle, b"not a resolved artifact".to_vec());
    let hydrated = ParseCacheEntry::new(root.join("validated-entry"));

    let error = hydrated
        .write_artifact_bundle_validated(&malformed_bundle, cache.schema_version())
        .expect_err("malformed resolved artifact errors");

    assert!(matches!(
        error,
        ParseCacheError::DecodeArtifactBundle { message }
            if message.contains("resolved.bin")
    ));
    assert!(!hydrated.dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_bundle_validated_write_preserves_existing_entry_after_malformed_resolved() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let malformed_bundle = bundle_with_resolved(&bundle, b"not a resolved artifact".to_vec());
    let hydrated = ParseCacheEntry::new(root.join("validated-entry"));
    hydrated
        .write_artifact_bundle_validated(&bundle, cache.schema_version())
        .expect("valid bundle hydrates");

    let error = hydrated
        .write_artifact_bundle_validated(&malformed_bundle, cache.schema_version())
        .expect_err("malformed resolved artifact errors");

    assert!(matches!(
        error,
        ParseCacheError::DecodeArtifactBundle { message }
            if message.contains("resolved.bin")
    ));
    assert!(hydrated.is_complete());
    assert_eq!(
        hydrated
            .read_artifact_bundle()
            .expect("existing bundle remains readable"),
        bundle
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_bundle_rejects_invalid_payloads() {
    let short = ParseArtifactBundle::decode(b"bad").expect_err("short bundle errors");
    assert!(matches!(
        short,
        ParseCacheError::DecodeArtifactBundle { message } if message.contains("unexpected end")
    ));

    let mut unsupported_version = Vec::new();
    unsupported_version.extend_from_slice(BUNDLE_MAGIC);
    write_u32(&mut unsupported_version, ARTIFACT_VERSION + 1);
    let version_error =
        ParseArtifactBundle::decode(&unsupported_version).expect_err("bad version errors");
    assert!(matches!(
        version_error,
        ParseCacheError::DecodeArtifactBundle { message }
            if message.contains("unsupported parse artifact bundle version")
    ));

    let mut truncated_section = Vec::new();
    truncated_section.extend_from_slice(BUNDLE_MAGIC);
    write_u32(&mut truncated_section, ARTIFACT_VERSION);
    write_u32(&mut truncated_section, 4);
    truncated_section.extend_from_slice(b"ir");
    let section_error =
        ParseArtifactBundle::decode(&truncated_section).expect_err("short section errors");
    assert!(matches!(
        section_error,
        ParseCacheError::DecodeArtifactBundle { message } if message.contains("unexpected end")
    ));
}
