//! Split-out tests (part_1). See parent module.

use super::*;


#[test]
fn keys_depend_on_source_schema_and_flags() {
    let flags = ParseCacheFlags::new();
    assert_eq!(flags, ParseCacheFlags::default());
    let key = ParseCacheKey::for_source(b"let x = 1; in x", 7, flags);
    assert_eq!(key, ParseCacheKey::for_source(b"let x = 1; in x", 7, flags));
    assert_ne!(key, ParseCacheKey::for_source(b"let x = 2; in x", 7, flags));
    assert_ne!(key, ParseCacheKey::for_source(b"let x = 1; in x", 8, flags));
    assert_ne!(
        key,
        ParseCacheKey::for_source(
            b"let x = 1; in x",
            7,
            ParseCacheFlags {
                retain_trivia: false,
                ..flags
            },
        )
    );
    // A simplify-on process must key its entries apart from simplify-off ones:
    // the flag-gated simplifier persists simplified ir.bin, and a shared entry
    // would let a simplify-off reader load it.
    assert_ne!(
        key,
        ParseCacheKey::for_source(
            b"let x = 1; in x",
            7,
            ParseCacheFlags {
                simplify: !flags.simplify,
                ..flags
            },
        )
    );
    assert_eq!(key.cache_dir_name().len(), 64);
}

#[test]
fn lowered_ir_fingerprint_is_stable_for_same_artifact() {
    let ir = lowered_ir_for_source("{ a = 1 + 2; }");

    assert_eq!(
        lowered_ir_fingerprint(&ir).expect("fingerprint computes"),
        lowered_ir_fingerprint(&ir).expect("fingerprint computes again")
    );
}

#[test]
fn lowered_ir_matcher_ignores_non_serialized_fact_table() {
    let left = lowered_ir_for_source("let x = 1; in x");
    let mut right = left.clone();
    right
        .facts
        .get_mut(right.root)
        .expect("root fact exists")
        .strictness = crate::compile::Strictness::DemandedBeforeEffect;

    assert!(
        lowered_ir_matches(&left, &right),
        "ir.bin equality ignores analysis facts because facts live in facts.bin"
    );

    let encoded = encode_lowered_ir(&right).expect("IR artifact encodes");
    let decoded = decode_lowered_ir(&encoded, right.symbols.clone()).expect("IR artifact decodes");
    assert_eq!(
        decoded.node_facts(decoded.root),
        Some(crate::compile::ExprFacts::conservative())
    );
}

#[test]
fn lowered_ir_fact_artifacts_roundtrip() {
    let mut facts = IrFacts::conservative(2);
    let fingerprint = test_lowered_ir_fingerprint(b"fact-artifact-test");
    let expected = ExprFacts {
        strictness: Strictness::DemandedBeforeEffect,
        cardinality: Cardinality::Once,
        escape: Escape::NoEscape,
    };
    *facts.get_mut(IrId::new(1)).expect("fact slot exists") = expected;

    let encoded = encode_ir_facts(&facts, fingerprint, crate::compile::IR_ANALYSIS_VERSION).expect("fact artifact encodes");
    let (decoded, analysis_version) =
        decode_ir_facts(&encoded, 2, fingerprint).expect("fact artifact decodes");
    assert_eq!(analysis_version, crate::compile::IR_ANALYSIS_VERSION);

    assert_eq!(decoded.as_slice(), facts.as_slice());
    assert_eq!(decoded.get(IrId::new(1)), Some(expected));
}

#[test]
fn lowered_ir_fact_artifacts_roundtrip_boolean_fact_bits() {
    let mut facts = IrFacts::conservative(3);
    let fingerprint = test_lowered_ir_fingerprint(b"fact-flag-test");
    facts.set_try_eval_barrier(IrId::new(0), true);
    facts.set_assembly_eager(IrId::new(1), true);
    facts.set_try_eval_barrier(IrId::new(2), true);
    facts.set_assembly_eager(IrId::new(2), true);

    let encoded = encode_ir_facts(&facts, fingerprint, crate::compile::IR_ANALYSIS_VERSION)
        .expect("fact artifact encodes");
    let (decoded, _) = decode_ir_facts(&encoded, 3, fingerprint).expect("fact artifact decodes");

    assert_eq!(decoded, facts);
    assert!(decoded.try_eval_barrier(IrId::new(0)));
    assert!(!decoded.assembly_eager(IrId::new(0)));
    assert!(!decoded.try_eval_barrier(IrId::new(1)));
    assert!(decoded.assembly_eager(IrId::new(1)));
    assert!(decoded.try_eval_barrier(IrId::new(2)));
    assert!(decoded.assembly_eager(IrId::new(2)));
}

#[test]
fn lowered_ir_fact_artifacts_roundtrip_capture_plans() {
    let mut facts = IrFacts::conservative(4);
    let fingerprint = test_lowered_ir_fingerprint(b"fact-capture-plan-test");
    facts.set_capture_plan(
        IrId::new(1),
        Some(CapturePlan::Flat(Box::new([
            Upvalue { depth: 0, slot: 2 },
            Upvalue { depth: 3, slot: 1 },
        ]))),
    );
    facts.set_capture_plan(
        IrId::new(2),
        Some(CapturePlan::SharedChain(SharedChainReason::DynamicScope)),
    );
    facts.set_capture_plan(IrId::new(3), Some(CapturePlan::Flat(Box::new([]))));
    facts.set_flat_capture_access(
        IrId::new(0),
        Some(FlatCaptureAccess {
            site: IrId::new(1),
            index: 1,
        }),
    );

    let encoded = encode_ir_facts(&facts, fingerprint, crate::compile::IR_ANALYSIS_VERSION)
        .expect("fact artifact encodes");
    let (decoded, analysis_version) =
        decode_ir_facts(&encoded, 4, fingerprint).expect("fact artifact decodes");

    assert_eq!(analysis_version, crate::compile::IR_ANALYSIS_VERSION);
    assert_eq!(decoded, facts);
    assert!(decoded.capture_plan(IrId::new(0)).is_none());
    assert_eq!(
        decoded.capture_plan(IrId::new(2)),
        Some(&CapturePlan::SharedChain(SharedChainReason::DynamicScope))
    );
}

#[test]
fn version_four_fact_artifacts_decode_without_flat_capture_accesses() {
    let mut facts = IrFacts::conservative(2);
    facts.set_capture_plan(
        IrId::new(1),
        Some(CapturePlan::Flat(Box::new([Upvalue { depth: 0, slot: 0 }]))),
    );
    facts.set_flat_capture_access(
        IrId::new(0),
        Some(FlatCaptureAccess {
            site: IrId::new(1),
            index: 0,
        }),
    );
    let fingerprint = test_lowered_ir_fingerprint(b"fact-capture-access-version-test");

    let encoded = encode_ir_facts(&facts, fingerprint, 4).expect("version 4 facts encode");
    let (decoded, version) =
        decode_ir_facts(&encoded, 2, fingerprint).expect("version 4 facts decode");

    assert_eq!(version, 4);
    assert!(decoded.capture_plan(IrId::new(1)).is_some());
    assert!(decoded.flat_capture_accesses().iter().all(Option::is_none));
}

#[test]
fn lowered_ir_fact_artifacts_without_capture_section_decode_for_old_versions() {
    // A version-3 sidecar (or a version-0 placeholder) ends after the
    // per-node records; decoding hydrates the facts with no capture plans.
    let mut facts = IrFacts::conservative(2);
    facts.set_capture_plan(
        IrId::new(0),
        Some(CapturePlan::SharedChain(SharedChainReason::TooManyFreeVars)),
    );
    let fingerprint = test_lowered_ir_fingerprint(b"fact-capture-version-test");

    for version in [0u32, 2, 3] {
        let encoded =
            encode_ir_facts(&facts, fingerprint, version).expect("fact artifact encodes");
        let (decoded, analysis_version) =
            decode_ir_facts(&encoded, 2, fingerprint).expect("fact artifact decodes");
        assert_eq!(analysis_version, version);
        assert!(
            decoded.capture_plans().iter().all(Option::is_none),
            "pre-4 sidecars must decode with no capture plans"
        );
    }
}

#[test]
fn lowered_ir_fact_artifacts_reject_invalid_capture_plan_tags() {
    let mut facts = IrFacts::conservative(1);
    facts.set_capture_plan(IrId::new(0), Some(CapturePlan::Flat(Box::new([]))));
    let fingerprint = test_lowered_ir_fingerprint(b"fact-capture-tag-test");
    let mut encoded = encode_ir_facts(&facts, fingerprint, crate::compile::IR_ANALYSIS_VERSION)
        .expect("fact artifact encodes");
    // magic + artifact version + analysis version + fingerprint + count +
    // one per-node record (3 tags + flag byte) + plan count + node id puts
    // the plan tag next.
    let plan_tag_offset = FACTS_MAGIC.len() + 4 + 4 + 32 + 4 + 4 + 4 + 4;
    encoded[plan_tag_offset] = 9;

    let error = decode_ir_facts(&encoded, 1, fingerprint).expect_err("invalid plan tag errors");

    assert!(error.contains("invalid capture plan tag"), "{error}");
}

#[test]
fn lowered_ir_fact_artifacts_reject_invalid_flag_bytes() {
    let facts = IrFacts::conservative(1);
    let fingerprint = test_lowered_ir_fingerprint(b"fact-flag-test");
    let mut encoded = encode_ir_facts(&facts, fingerprint, crate::compile::IR_ANALYSIS_VERSION)
        .expect("fact artifact encodes");
    // magic + artifact version + analysis version + fingerprint + count +
    // the three per-node fact tags put the flag byte last in the record.
    encoded[FACTS_MAGIC.len() + 4 + 4 + 32 + 4 + 3] = 0b1000;

    let error = decode_ir_facts(&encoded, 1, fingerprint).expect_err("invalid flag byte errors");

    assert!(error.contains("invalid node fact flag byte"), "{error}");
}

#[test]
fn lowered_ir_fact_artifacts_reject_count_mismatch() {
    let facts = IrFacts::conservative(1);
    let fingerprint = test_lowered_ir_fingerprint(b"fact-artifact-test");
    let encoded = encode_ir_facts(&facts, fingerprint, crate::compile::IR_ANALYSIS_VERSION).expect("fact artifact encodes");
    let error = decode_ir_facts(&encoded, 2, fingerprint).expect_err("mismatched count errors");

    assert!(error.contains("does not match node count"), "{error}");
}

#[test]
fn lowered_ir_fact_artifacts_reject_invalid_tags() {
    let facts = IrFacts::conservative(1);
    let fingerprint = test_lowered_ir_fingerprint(b"fact-artifact-test");
    let mut encoded = encode_ir_facts(&facts, fingerprint, crate::compile::IR_ANALYSIS_VERSION).expect("fact artifact encodes");
    // magic + artifact version + analysis version + fingerprint + count.
    encoded[FACTS_MAGIC.len() + 4 + 4 + 32 + 4] = 99;

    let error = decode_ir_facts(&encoded, 1, fingerprint).expect_err("invalid fact tag errors");

    assert!(error.contains("invalid strictness fact tag"), "{error}");
}

#[test]
fn lowered_ir_fact_artifacts_reject_fingerprint_mismatch() {
    let facts = IrFacts::conservative(1);
    let encoded = encode_ir_facts(&facts, test_lowered_ir_fingerprint(b"old-ir"), crate::compile::IR_ANALYSIS_VERSION)
        .expect("fact artifact encodes");

    let error = decode_ir_facts(&encoded, 1, test_lowered_ir_fingerprint(b"new-ir"))
        .expect_err("mismatched fingerprint errors");

    assert!(error.contains("fingerprint"), "{error}");
}

#[test]
fn lowered_ir_fingerprint_depends_on_symbol_artifact() {
    let first = lowered_ir_for_source(r#"{ a = "x"; }"#);
    let second = lowered_ir_for_source(r#"{ a = "y"; }"#);
    assert_eq!(
        encode_lowered_ir(&first).expect("first IR encodes"),
        encode_lowered_ir(&second).expect("second IR encodes"),
        "the IR artifact alone should not distinguish equal-shaped string symbols"
    );

    assert_ne!(
        lowered_ir_fingerprint(&first).expect("first fingerprint computes"),
        lowered_ir_fingerprint(&second).expect("second fingerprint computes")
    );
}

#[test]
fn lowered_ir_fingerprint_depends_on_ir_artifact() {
    let first = lowered_ir_for_source("{ a = 1; }");
    let second = lowered_ir_for_source("{ a = 1 + 2; }");

    assert_ne!(
        lowered_ir_fingerprint(&first).expect("first fingerprint computes"),
        lowered_ir_fingerprint(&second).expect("second fingerprint computes")
    );
}

#[test]
fn entry_paths_follow_rfc_layout() {
    let cache = ParseCache::new("/cache/parse");
    let entry = cache.entry_for_source(b"true");
    assert_eq!(entry.ir_path().file_name().expect("file name"), "ir.bin");
    assert_eq!(
        entry.resolved_path().file_name().expect("file name"),
        "resolved.bin"
    );
    assert_eq!(
        entry.symbols_path().file_name().expect("file name"),
        "symbols.bin"
    );
    assert_eq!(
        entry.facts_path().file_name().expect("file name"),
        "facts.bin"
    );
    assert_eq!(
        entry.meta_path().file_name().expect("file name"),
        "meta.toml"
    );
    assert_eq!(
        entry.dir().parent().expect("parent"),
        Path::new("/cache/parse")
    );
}

#[test]
fn metadata_is_diagnostic_and_escaped_toml() {
    let meta = ParseCacheMeta::new(7, Some("pkgs/foo\"bar\n\u{7}baz.nix".to_owned()), 12, 3);
    assert_eq!(
        meta.to_toml(),
        "schema_version = 7\nsource_hint = \"pkgs/foo\\\"bar\\n\\u0007baz.nix\"\nnode_count = 12\nsymbol_count = 3\n"
    );
    assert_eq!(
        ParseCacheMeta::from_toml(&meta.to_toml()).expect("metadata decodes"),
        meta
    );
    assert_eq!(
        ParseCacheMeta::from_toml("schema_version = 7\nnode_count = 12\nsymbol_count = 3\n")
            .expect("metadata without source hint decodes"),
        ParseCacheMeta::new(7, None, 12, 3)
    );
}

#[test]
fn metadata_rejects_invalid_toml_schema() {
    let malformed =
        ParseCacheMeta::from_toml("schema_version =").expect_err("malformed metadata errors");
    assert!(matches!(
        malformed,
        ParseCacheError::DecodeMeta { message } if !message.is_empty()
    ));

    let missing = ParseCacheMeta::from_toml("schema_version = 7\nsymbol_count = 3\n")
        .expect_err("missing metadata field errors");
    assert!(matches!(
        missing,
        ParseCacheError::DecodeMeta { message } if message.contains("node_count")
    ));

    let wrong_type = ParseCacheMeta::from_toml(
        "schema_version = 7\nsource_hint = 1\nnode_count = 12\nsymbol_count = 3\n",
    )
    .expect_err("wrong source hint type errors");
    assert!(matches!(
        wrong_type,
        ParseCacheError::DecodeMeta { message } if message.contains("source_hint")
    ));

    let out_of_range =
        ParseCacheMeta::from_toml("schema_version = -1\nnode_count = 12\nsymbol_count = 3\n")
            .expect_err("negative metadata integer errors");
    assert!(matches!(
        out_of_range,
        ParseCacheError::DecodeMeta { message } if message.contains("schema_version")
    ));
}

#[test]
fn write_meta_creates_entry_directory() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let entry = cache.entry_for_source(b"builtins");
    let meta = ParseCacheMeta::new(cache.schema_version(), Some("expr".to_owned()), 1, 1);

    entry.write_meta(&meta).expect("metadata writes");
    let text = fs::read_to_string(entry.meta_path()).expect("metadata is readable");
    assert!(text.contains(&format!("schema_version = {PARSE_CACHE_SCHEMA_VERSION}")));
    assert!(!entry.is_complete());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_resolved_cleans_temporary_files_after_artifact_commit_failure() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = "let x = 1; in x";
    let resolved = resolve(parse_str(source).expect("source parses")).expect("source resolves");
    let entry = cache.entry_for_source(source.as_bytes());
    let meta = ParseCacheMeta::new(
        cache.schema_version(),
        Some("expr.nix".to_owned()),
        resolved.arena.len() as u32,
        resolved.symbols.len() as u32,
    );
    entry.ensure_dir().expect("entry dir creates");
    // Block the atomic bundle rename target with a directory so the single-file
    // commit fails after its temp file is written.
    fs::create_dir(entry.bundle_path()).expect("blocking bundle directory creates");

    let error = entry
        .write_resolved(&resolved, &meta)
        .expect_err("artifact commit fails");
    match error {
        ParseCacheError::WriteArtifact { path, .. } => assert_eq!(path, entry.bundle_path()),
        other => panic!("unexpected write error: {other:?}"),
    }

    assert!(!entry.is_complete());
    assert!(entry.bundle_path().is_dir());
    assert!(
        cache_temp_files(&entry).is_empty(),
        "temporary files were not cleaned up"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_resolved_commits_mandatory_artifacts_when_fact_sidecar_write_fails() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = "let x = 1; in x";
    let resolved = resolve(parse_str(source).expect("source parses")).expect("source resolves");
    let entry = cache.entry_for_source(source.as_bytes());
    let meta = ParseCacheMeta::new(
        cache.schema_version(),
        Some("expr.nix".to_owned()),
        resolved.arena.len() as u32,
        resolved.symbols.len() as u32,
    );
    entry.ensure_dir().expect("entry dir creates");
    fs::create_dir(entry.facts_path()).expect("blocking fact sidecar directory creates");

    entry
        .write_resolved(&resolved, &meta)
        .expect("mandatory artifacts still write");

    assert!(entry.is_complete());
    assert!(entry.facts_path().is_dir());
    let (loaded, _) = entry.read_ir().expect("IR reads without fact sidecar");
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
fn load_or_parse_writes_then_hits_by_source_content() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";

    let miss = cache
        .load_or_parse_bytes(source, Some("first.nix".to_owned()))
        .expect("source parses on miss");
    assert!(!miss.hit);
    assert!(miss.stored);
    assert!(miss.entry.is_complete());
    assert!(
        miss.entry
            .read_artifact_bundle()
            .expect("artifact bundle reads")
            .facts_bytes()
            .is_some()
    );

    let hit = cache
        .load_or_parse_bytes(source, Some("second-name-is-not-identity.nix".to_owned()))
        .expect("source loads on hit");
    assert!(hit.hit);
    assert!(hit.stored);
    assert_eq!(hit.key, miss.key);
    assert_eq!(hit.resolved.arena.nodes(), miss.resolved.arena.nodes());
    assert!(lowered_ir_matches(&hit.ir, &miss.ir));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_cached_bytes_misses_incomplete_entries() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";

    let cached = cache
        .load_cached_bytes(source)
        .expect("load-only cache miss succeeds");

    assert!(cached.is_none());
    assert!(!cache.entry_for_source(source).dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_cached_bytes_misses_partially_populated_entries() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let entry = cache.entry_for_source(source);
    entry.ensure_dir().expect("entry dir creates");
    fs::write(entry.resolved_path(), b"not enough artifacts").expect("partial artifact writes");

    let cached = cache
        .load_cached_bytes(source)
        .expect("load-only partial cache miss succeeds");

    assert!(cached.is_none());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_cached_bytes_returns_complete_entry() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");

    let cached = cache
        .load_cached_bytes(source)
        .expect("load-only cache hit succeeds")
        .expect("cached entry exists");

    assert!(cached.hit);
    assert!(cached.stored);
    assert_eq!(cached.key, parsed.key);
    assert_eq!(cached.entry, parsed.entry);
    assert_eq!(cached.resolved.arena.nodes(), parsed.resolved.arena.nodes());
    assert!(lowered_ir_matches(&cached.ir, &parsed.ir));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_cached_bytes_reports_corrupt_complete_entries() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    // Corrupt only the lowered-IR section of the bundle, leaving the frame and
    // the other sections decodable, so the read still surfaces DecodeArtifact.
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
    .expect("corrupt bundle writes");

    let error = cache
        .load_cached_bytes(source)
        .expect_err("load-only cache hit reports corrupt artifact");

    assert!(matches!(
        error,
        ParseCacheError::DecodeArtifact { path, .. } if path == parsed.entry.bundle_path()
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_cached_bytes_ignores_corrupt_fact_sidecars() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    fs::write(parsed.entry.facts_path(), b"not a fact artifact").expect("corrupt facts write");

    let cached = cache
        .load_cached_bytes(source)
        .expect("load-only cache hit ignores corrupt fact artifact")
        .expect("cached entry remains usable");

    assert!(cached.hit);
    assert!(
        cached
            .ir
            .facts
            .as_slice()
            .iter()
            .all(|facts| *facts == ExprFacts::conservative())
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_or_parse_recovers_from_corrupt_artifact() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let first = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    fs::write(first.entry.bundle_path(), b"not a bundle artifact").expect("corrupt bundle writes");

    let recovered = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source reparses after corrupt cache");
    assert!(!recovered.hit);
    assert!(recovered.stored);
    assert!(recovered.entry.is_complete());
    assert_eq!(
        recovered.resolved.arena.nodes(),
        first.resolved.arena.nodes()
    );
    assert!(lowered_ir_matches(&recovered.ir, &first.ir));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_or_parse_consumes_valid_lowered_ir_artifact() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"1";
    let first = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    let other_resolved =
        resolve(parse_str("2").expect("other source parses")).expect("other source resolves");
    let other_ir = lower(file_local_resolved(&other_resolved).expect("other symbols remap"))
        .expect("other source lowers");
    // Swap the stored bundle's lowered-IR section for a valid-but-mismatched
    // artifact: the entry stays complete and the cache trusts the stored IR.
    let bundle = first
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let swapped = ParseArtifactBundle::new(
        bundle.resolved_bytes(),
        encode_lowered_ir(&other_ir).expect("other IR encodes"),
        bundle.symbols_bytes(),
        bundle.meta_toml_bytes(),
    );
    fs::write(
        first.entry.bundle_path(),
        swapped.encode().expect("swapped bundle encodes"),
    )
    .expect("mismatched IR writes");

    let recovered = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source loads valid lowered IR artifact");
    assert!(recovered.hit);
    assert!(recovered.stored);
    assert!(recovered.entry.is_complete());
    assert_eq!(
        recovered.resolved.arena.nodes(),
        first.resolved.arena.nodes()
    );
    assert!(lowered_ir_matches(&recovered.ir, &other_ir));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_or_parse_treats_write_failures_as_cache_misses() {
    let root = temp_root();
    fs::write(&root, b"not a directory").expect("file cache root writes");
    let cache = ParseCache::new(root.join("parse"));

    let parsed = cache
        .load_or_parse_bytes(b"let x = 1; in x", Some("expr.nix".to_owned()))
        .expect("parse succeeds despite cache write failure");
    assert!(!parsed.hit);
    assert!(!parsed.stored);

    let _ = fs::remove_file(root);
}

#[cfg(unix)]
#[test]
fn file_memo_shares_artifacts_across_symlinked_paths() {
    use std::os::unix::fs::symlink;

    let root = temp_root();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("source dir creates");
    let source_path = src_dir.join("expr.nix");
    let link_path = src_dir.join("linked-expr.nix");
    fs::write(&source_path, b"let x = 1; in x").expect("source writes");
    symlink(&source_path, &link_path).expect("symlink creates");
    let mut memo = FileParseMemo::with_cache_root(root.join("parse"));

    let first = memo
        .load_or_parse_file(&source_path)
        .expect("source parses through real path");
    assert!(!first.memo_hit);
    assert!(!first.parsed.hit);
    assert!(first.parsed.stored);
    assert_eq!(
        first.file_key.realpath(),
        fs::canonicalize(&source_path)
            .expect("source canonicalizes")
            .as_path()
    );

    let second = memo
        .load_or_parse_file(&link_path)
        .expect("source parses through symlink path");
    assert!(second.memo_hit);
    assert_eq!(second.file_key, first.file_key);
    assert_eq!(second.parsed.key, first.parsed.key);
    assert_eq!(memo.len(), 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn file_memo_rekeys_when_file_content_changes() {
    let root = temp_root();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("source dir creates");
    let source_path = src_dir.join("expr.nix");
    fs::write(&source_path, b"let x = 1; in x").expect("source writes");
    let mut memo = FileParseMemo::with_cache_root(root.join("parse"));

    let first = memo
        .load_or_parse_file(&source_path)
        .expect("initial source parses");
    assert!(!first.memo_hit);
    assert_eq!(memo.len(), 1);

    fs::write(&source_path, b"let x = 2; in x").expect("changed source writes");
    let changed = memo
        .load_or_parse_file(&source_path)
        .expect("changed source parses");
    assert!(!changed.memo_hit);
    assert_eq!(first.file_key.realpath(), changed.file_key.realpath());
    assert_ne!(
        first.file_key.content_hash(),
        changed.file_key.content_hash()
    );
    assert_ne!(first.parsed.key, changed.parsed.key);
    assert_eq!(memo.len(), 2);

    let repeated = memo
        .load_or_parse_file(&source_path)
        .expect("changed source memoizes");
    assert!(repeated.memo_hit);
    assert_eq!(repeated.file_key, changed.file_key);
    assert_eq!(memo.len(), 2);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn resolved_artifacts_roundtrip_through_entry_files() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = "let outer = {}; x = 1; in with outer; rec { inherit x; y = x; }";
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
    assert!(entry.is_complete());

    let loaded = entry.read_resolved().expect("resolved artifact reads");
    assert_eq!(loaded.root, resolved.root);
    assert_eq!(loaded.arena.nodes(), resolved.arena.nodes());
    assert_eq!(loaded.arena.child_pool(), resolved.arena.child_pool());
    assert_eq!(loaded.symbols.symbols(), resolved.symbols.symbols());
    assert_eq!(loaded.scopes.frames(), resolved.scopes.frames());
    assert_eq!(loaded.scopes.node_frames(), resolved.scopes.node_frames());
    assert_eq!(loaded.scopes.with_chains(), resolved.scopes.with_chains());
    assert_eq!(
        loaded.scopes.inherit_resolutions(),
        resolved.scopes.inherit_resolutions()
    );
    assert_eq!(
        loaded.scopes.node_inherits(),
        resolved.scopes.node_inherits()
    );

    let _ = fs::remove_dir_all(root);
}
