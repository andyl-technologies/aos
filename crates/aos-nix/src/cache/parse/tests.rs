//! Unit tests for the parse artifact cache: key/flag identity, round-trip
//! encode/decode of resolved and lowered artifacts, file memoization, and
//! corruption handling.

use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::compile::resolve;
use crate::syntax::parse_str;

static TEST_ID: AtomicUsize = AtomicUsize::new(0);

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
            },
        )
    );
    assert_eq!(key.to_hex().len(), 64);
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
}

#[test]
fn write_meta_creates_entry_directory() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let entry = cache.entry_for_source(b"builtins");
    let meta = ParseCacheMeta::new(cache.schema_version(), Some("expr".to_owned()), 1, 1);

    entry.write_meta(&meta).expect("metadata writes");
    let text = fs::read_to_string(entry.meta_path()).expect("metadata is readable");
    assert!(text.contains("schema_version = 6"));
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
    entry.write_meta(&meta).expect("stale metadata writes");
    fs::create_dir(entry.ir_path()).expect("blocking artifact directory creates");

    let error = entry
        .write_resolved(&resolved, &meta)
        .expect_err("artifact commit fails");
    match error {
        ParseCacheError::WriteArtifact { path, .. } => assert_eq!(path, entry.ir_path()),
        other => panic!("unexpected write error: {other:?}"),
    }

    assert!(!entry.is_complete());
    assert!(!entry.meta_path().exists());
    assert!(entry.resolved_path().is_file());
    assert!(entry.ir_path().is_dir());
    assert!(
        cache_temp_files(&entry).is_empty(),
        "temporary files were not cleaned up"
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
    assert!(String::from_utf8_lossy(decoded.meta_toml_bytes()).contains("schema_version = 6"));

    let resolved_symbols =
        decode_symbols(decoded.symbols_bytes()).expect("resolved symbols decode");
    let resolved = decode_resolved_ir(decoded.resolved_bytes(), resolved_symbols)
        .expect("resolved artifact decodes");
    assert_eq!(resolved.arena.nodes(), parsed.resolved.arena.nodes());

    let ir_symbols = decode_symbols(decoded.symbols_bytes()).expect("IR symbols decode");
    let ir = decode_lowered_ir(decoded.ir_bytes(), ir_symbols).expect("IR artifact decodes");
    assert!(lowered_ir_matches(&ir, &parsed.ir));

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

#[test]
fn load_or_parse_recovers_from_corrupt_artifact() {
    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let first = cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses on miss");
    fs::write(first.entry.ir_path(), b"not an ir artifact").expect("corrupt ir writes");

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
    fs::write(
        first.entry.ir_path(),
        encode_lowered_ir(&other_ir).expect("other IR encodes"),
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
fn serialization_remaps_symbols_to_file_local_ids() {
    let mut shifted_symbols = SymbolTable::new();
    shifted_symbols
        .intern(b"unused")
        .expect("unused symbol interns");
    let shifted_x = shifted_symbols.intern(b"x").expect("x symbol interns");
    let shifted = resolved_single_symbol(shifted_symbols, shifted_x);

    let mut local_symbols = SymbolTable::new();
    let local_x = local_symbols.intern(b"x").expect("local x interns");
    let local = resolved_single_symbol(local_symbols, local_x);

    let root = temp_root();
    let cache = ParseCache::new(root.join("parse"));
    let entry = cache.entry_for_source(b"symbol-remap");
    let meta = ParseCacheMeta::for_resolved(
        cache.schema_version(),
        Some("expr.nix".to_owned()),
        &shifted,
    )
    .expect("metadata counts file-local symbols");
    assert_eq!(meta.symbol_count, 1);

    entry
        .write_resolved(&shifted, &meta)
        .expect("shifted artifact writes");
    let loaded = entry.read_resolved().expect("shifted artifact reads");
    assert_eq!(loaded.symbols.symbols(), &[b"x".to_vec()]);
    assert_eq!(loaded.arena.nodes(), local.arena.nodes());
    assert_eq!(
        loaded.scopes.inherit_resolutions(),
        local.scopes.inherit_resolutions()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn duplicate_serialized_symbols_are_rejected() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SYMBOL_MAGIC);
    write_u32(&mut bytes, ARTIFACT_VERSION);
    write_u32(&mut bytes, 2);
    write_u32(&mut bytes, 1);
    bytes.push(b'a');
    write_u32(&mut bytes, 1);
    bytes.push(b'a');

    let error = decode_symbols(&bytes).expect_err("duplicate symbol is invalid");
    assert!(error.contains("duplicate symbol"));
}

#[test]
fn lowered_ir_rejects_inconsistent_node_payload_and_effect() {
    let invalid_payload = Ir {
        root: IrId::new(0),
        arena: IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Null,
                Span::new(0, 4),
                EffectClass::Pure,
                IrData::Bool(true),
            )],
            Vec::new(),
        ),
        symbols: SymbolTable::new(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&invalid_payload).expect("invalid payload encodes");
    let error = decode_lowered_ir(&bytes, SymbolTable::new())
        .expect_err("invalid kind/data pair is rejected");
    assert!(error.contains("invalid IR data"));

    let invalid_effect = Ir {
        root: IrId::new(0),
        arena: IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::DerivationStrict,
                Span::new(0, 16),
                EffectClass::Pure,
                IrData::Node(IrId::new(0)),
            )],
            Vec::new(),
        ),
        symbols: SymbolTable::new(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&invalid_effect).expect("invalid effect encodes");
    let error =
        decode_lowered_ir(&bytes, SymbolTable::new()).expect_err("invalid node effect is rejected");
    assert!(error.contains("invalid IR effect"));

    let mut symbols = SymbolTable::new();
    let type_of = symbols.intern(b"typeOf").expect("typeOf interns");
    let invalid_primop_effect = Ir {
        root: IrId::new(1),
        arena: IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Bool,
                    Span::new(16, 20),
                    EffectClass::Pure,
                    IrData::Bool(true),
                ),
                IrNode::new(
                    IrKind::PrimOp,
                    Span::new(0, 20),
                    EffectClass::Effectful,
                    IrData::PrimOp {
                        symbol: type_of,
                        args: IrChildSlice::new(0, 1),
                    },
                ),
            ],
            vec![IrId::new(0)],
        ),
        symbols: symbols.clone(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&invalid_primop_effect).expect("invalid primop effect encodes");
    let error = decode_lowered_ir(&bytes, symbols).expect_err("pure primop effect is rejected");
    assert!(error.contains("invalid IR effect"));

    let mut symbols = SymbolTable::new();
    let derivation_strict = symbols
        .intern(b"derivationStrict")
        .expect("derivationStrict interns");
    let derivation_as_primop = Ir {
        root: IrId::new(1),
        arena: IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Bool,
                    Span::new(20, 24),
                    EffectClass::Pure,
                    IrData::Bool(false),
                ),
                IrNode::new(
                    IrKind::PrimOp,
                    Span::new(0, 24),
                    EffectClass::Effectful,
                    IrData::PrimOp {
                        symbol: derivation_strict,
                        args: IrChildSlice::new(0, 1),
                    },
                ),
            ],
            vec![IrId::new(0)],
        ),
        symbols: symbols.clone(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&derivation_as_primop).expect("derivation primop encodes");
    let error =
        decode_lowered_ir(&bytes, symbols).expect_err("derivationStrict is not a normal primop");
    assert!(error.contains("unknown IR primop symbol"));

    let mut symbols = SymbolTable::new();
    let future = symbols.intern(b"futurePrimop").expect("future interns");
    let unknown_primop = Ir {
        root: IrId::new(1),
        arena: IrArena::from_raw_parts(
            vec![
                IrNode::new(
                    IrKind::Bool,
                    Span::new(20, 24),
                    EffectClass::Pure,
                    IrData::Bool(false),
                ),
                IrNode::new(
                    IrKind::PrimOp,
                    Span::new(0, 24),
                    EffectClass::Pure,
                    IrData::PrimOp {
                        symbol: future,
                        args: IrChildSlice::new(0, 1),
                    },
                ),
            ],
            vec![IrId::new(0)],
        ),
        symbols: symbols.clone(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: Vec::new().into_boxed_slice(),
        shapes: Vec::new().into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&unknown_primop).expect("unknown primop encodes");
    let error = decode_lowered_ir(&bytes, symbols).expect_err("unknown primop is rejected");
    assert!(error.contains("unknown IR primop symbol"));
}

#[test]
fn lowered_ir_rejects_inconsistent_attrset_shapes() {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a interns");
    let b = symbols.intern(b"b").expect("b interns");
    let static_binding = IrBinding {
        key: IrAttrPathSegment::Static(a),
        position: None,
        value: IrId::new(0),
    };
    let invalid_shape = Ir {
        root: IrId::new(0),
        arena: IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::AttrSet,
                Span::new(0, 9),
                EffectClass::Pure,
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: false,
                    frame: None,
                },
            )],
            Vec::new(),
        ),
        symbols: symbols.clone(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: vec![static_binding].into_boxed_slice(),
        shapes: vec![IrShape::new(vec![b].into_boxed_slice())].into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&invalid_shape).expect("invalid shape encodes");
    let error =
        decode_lowered_ir(&bytes, symbols.clone()).expect_err("invalid attrset shape is rejected");
    assert!(error.contains("shape does not match"));

    let invalid_dynamic_flag = Ir {
        root: IrId::new(0),
        arena: IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::AttrSet,
                Span::new(0, 9),
                EffectClass::Pure,
                IrData::AttrSet {
                    shape: IrShapeId::new(0),
                    bindings: IrBindingSlice::new(0, 1),
                    recursive: false,
                    has_dynamic: true,
                    frame: None,
                },
            )],
            Vec::new(),
        ),
        symbols: symbols.clone(),
        frames: Vec::new().into_boxed_slice(),
        with_chains: Vec::new().into_boxed_slice(),
        attr_paths: Vec::new().into_boxed_slice(),
        bindings: vec![static_binding].into_boxed_slice(),
        shapes: vec![IrShape::new(vec![a].into_boxed_slice())].into_boxed_slice(),
    };
    let bytes = encode_lowered_ir(&invalid_dynamic_flag).expect("invalid flag encodes");
    let error =
        decode_lowered_ir(&bytes, symbols).expect_err("invalid attrset dynamic flag is rejected");
    assert!(error.contains("dynamic flag"));
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
    let expected =
        lower(file_local_resolved(&resolved).expect("symbols remap")).expect("resolved AST lowers");
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

    let loaded = entry.read_ir().expect("lowered IR artifact reads");
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
