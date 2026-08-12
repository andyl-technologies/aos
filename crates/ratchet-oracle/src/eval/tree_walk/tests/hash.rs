//! Tree-walk evaluator tests: hash.

use super::*;
use crate::cache::{
    DurableBlake3Hash, PARSE_CACHE_SCHEMA_VERSION, ParseCache, ParseCacheFlags, ParseCacheKey,
    ParseFileKey, PersistCache, PersistFileArtifactKey,
};
use crate::string::NixString;

#[test]
fn hash_string_primop_hashes_bytes() {
    assert_eq!(
        eval_string_bytes("builtins.hashString \"md5\" \"abc\""),
        b"900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        eval_string_bytes("builtins.hashString \"sha1\" \"abc\""),
        b"a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        eval_string_bytes("builtins.hashString \"sha256\" \"abc\""),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
            eval_string_bytes("builtins.hashString \"sha512\" \"abc\""),
            b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { hashString = type: value: \"local\"; }; in builtins.hashString \"sha256\" \"abc\""
        ),
        b"local"
    );
}

#[test]
fn configured_import_cache_preserves_hash_builtin_surface() {
    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn push_durable_blake3_canaries(
        canaries: &mut Vec<(String, Vec<u8>)>,
        name: &str,
        hash: &DurableBlake3Hash,
    ) {
        canaries.push((format!("{name} BLAKE3 hex"), hash.to_hex().into_bytes()));
        canaries.push((format!("{name} BLAKE3 raw bytes"), hash.as_bytes().to_vec()));
        canaries.push((
            format!("{name} BLAKE3 Nix base32"),
            nix_compat::nixbase32::encode(&hash.as_bytes()).into_bytes(),
        ));
    }

    fn push_parse_key_canaries(
        canaries: &mut Vec<(String, Vec<u8>)>,
        name: &str,
        key: ParseCacheKey,
    ) {
        let hash = key.as_durable_hash();
        canaries.push((format!("{name} BLAKE3 hex"), hash.to_hex().into_bytes()));
        canaries.push((format!("{name} BLAKE3 raw bytes"), hash.as_bytes().to_vec()));
        canaries.push((
            format!("{name} BLAKE3 Nix base32"),
            nix_compat::nixbase32::encode(&hash.as_bytes()).into_bytes(),
        ));
    }

    fn push_hot_string_canaries(canaries: &mut Vec<(String, Vec<u8>)>, name: &str, value: &[u8]) {
        let hot_canary = NixString::from_bytes(value.to_vec())
            .structural_hash_xxh3()
            .raw_for_tests();
        canaries.push((
            format!("{name} hot xxh3 decimal"),
            hot_canary.to_string().into_bytes(),
        ));
        canaries.push((
            format!("{name} hot xxh3 hex"),
            format!("{hot_canary:016x}").into_bytes(),
        ));
        canaries.push((
            format!("{name} hot xxh3 little-endian bytes"),
            hot_canary.to_le_bytes().to_vec(),
        ));
        canaries.push((
            format!("{name} hot xxh3 big-endian bytes"),
            hot_canary.to_be_bytes().to_vec(),
        ));
    }

    fn evaluate_hash_surface(source: &str, options: TreeWalkOptions) -> (Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let value = evaluator.eval_root().expect("hash expression evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let output = evaluator
            .heap()
            .get_string(value)
            .expect("hash result is a string")
            .bytes()
            .to_vec();
        (output, import_stats)
    }

    let root = fs::canonicalize(unique_temp_dir("import-cache-hash-surface-parity"))
        .expect("temp directory canonicalizes");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let third_parse_root = root.join("third-parse-cache");
    let fourth_parse_root = root.join("fourth-parse-cache");
    let persist_root = root.join("persist-cache");
    let import_path = root.join("imported.nix");
    let imported_value = b"hash-surface-value";
    let changed_imported_value = b"changed-hash-surface-value";
    let imported_source = br#""hash-surface-value""#;
    let changed_imported_source = br#""changed-hash-surface-value""#;
    fs::write(&import_path, imported_source).expect("import source writes");
    let import_realpath = fs::canonicalize(&import_path).expect("import path canonicalizes");
    let source = format!(
        r#"let imported = import {}; in builtins.hashString "sha256" imported"#,
        import_path.display()
    );

    let mut uncached_options = TreeWalkOptions::new();
    uncached_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (uncached_output, uncached_stats) = evaluate_hash_surface(&source, uncached_options);
    assert_eq!(uncached_stats, (0, 0));

    let mut miss_options = TreeWalkOptions::new();
    miss_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_output, miss_stats) = evaluate_hash_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 1));
    assert_eq!(miss_output, uncached_output);

    let mut hit_options = TreeWalkOptions::new();
    hit_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_output, hit_stats) = evaluate_hash_surface(&source, hit_options);
    assert_eq!(hit_stats, (1, 0));
    assert_eq!(hit_output, uncached_output);
    assert!(
        ParseCache::new(&second_parse_root)
            .entry_for_source(imported_source)
            .is_complete(),
        "persistent hit should hydrate the runtime parse-cache entry"
    );

    fs::write(&import_path, changed_imported_source).expect("changed import source writes");

    let mut changed_uncached_options = TreeWalkOptions::new();
    changed_uncached_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (changed_uncached_output, changed_uncached_stats) =
        evaluate_hash_surface(&source, changed_uncached_options);
    assert_eq!(changed_uncached_stats, (0, 0));
    assert_ne!(changed_uncached_output, uncached_output);

    let mut changed_miss_options = TreeWalkOptions::new();
    changed_miss_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    changed_miss_options.set_parse_cache_root(&third_parse_root);
    changed_miss_options.set_persist_cache_root(&persist_root);
    let (changed_miss_output, changed_miss_stats) =
        evaluate_hash_surface(&source, changed_miss_options);
    assert_eq!(changed_miss_stats, (0, 1));
    assert_eq!(changed_miss_output, changed_uncached_output);

    let mut changed_hit_options = TreeWalkOptions::new();
    changed_hit_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    changed_hit_options.set_parse_cache_root(&fourth_parse_root);
    changed_hit_options.set_persist_cache_root(&persist_root);
    let (changed_hit_output, changed_hit_stats) =
        evaluate_hash_surface(&source, changed_hit_options);
    assert_eq!(changed_hit_stats, (1, 0));
    assert_eq!(changed_hit_output, changed_uncached_output);
    assert!(
        ParseCache::new(&fourth_parse_root)
            .entry_for_source(changed_imported_source)
            .is_complete(),
        "changed persistent hit should hydrate the runtime parse-cache entry"
    );

    let root_parse_key = ParseCacheKey::for_source(
        source.as_bytes(),
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let imported_parse_key = ParseCacheKey::for_source(
        imported_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let changed_imported_parse_key = ParseCacheKey::for_source(
        changed_imported_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let file_key = ParseFileKey::for_source(&import_realpath, imported_source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, imported_parse_key);
    let changed_file_key = ParseFileKey::for_source(&import_realpath, changed_imported_source);
    let changed_artifact_key =
        PersistFileArtifactKey::from_parse_file_key(&changed_file_key, changed_imported_parse_key);
    let persist_cache = PersistCache::open(&persist_root).expect("persistent cache opens");
    assert!(
        persist_cache
            .lookup_file_artifact(artifact_key)
            .expect("persistent file-artifact lookup succeeds")
            .is_some(),
        "hash canary import should materialize a persistent file-artifact mapping"
    );
    assert!(
        persist_cache
            .lookup_file_artifact(changed_artifact_key)
            .expect("changed persistent file-artifact lookup succeeds")
            .is_some(),
        "changed hash canary import should materialize a persistent file-artifact mapping"
    );

    let mut canaries = Vec::new();
    push_parse_key_canaries(&mut canaries, "root parse-cache", root_parse_key);
    push_parse_key_canaries(
        &mut canaries,
        "original import parse-cache",
        imported_parse_key,
    );
    push_parse_key_canaries(
        &mut canaries,
        "changed import parse-cache",
        changed_imported_parse_key,
    );
    let file_content_hash = file_key.content_hash().as_durable_hash();
    push_durable_blake3_canaries(&mut canaries, "original file-content", &file_content_hash);
    let changed_file_content_hash = changed_file_key.content_hash().as_durable_hash();
    push_durable_blake3_canaries(
        &mut canaries,
        "changed file-content",
        &changed_file_content_hash,
    );
    push_hot_string_canaries(&mut canaries, "original imported string", imported_value);
    push_hot_string_canaries(
        &mut canaries,
        "changed imported string",
        changed_imported_value,
    );

    let outputs = [
        ("original cache-disabled", &uncached_output),
        ("original persistent miss", &miss_output),
        ("original persistent hit", &hit_output),
        ("changed cache-disabled", &changed_uncached_output),
        ("changed persistent miss", &changed_miss_output),
        ("changed persistent hit", &changed_hit_output),
    ];
    for (output_name, output) in outputs {
        for (canary_name, canary) in &canaries {
            assert!(
                !contains_bytes(output, canary),
                "{canary_name} leaked into {output_name} hash builtin output: {output:?}"
            );
        }
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn first_class_binary_builtin_selects_are_curried() {
    assert_eq!(
        eval_string_bytes("let h = builtins.hashString \"sha256\"; in h \"abc\""),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(eval("let add = builtins.add 1; in add 2").as_int(), Ok(3));
    assert_eq!(
        eval("let less = builtins.lessThan 1; in less 2").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let cmp = builtins.compareVersions \"1.2\"; in cmp \"1.10\"").as_int(),
        Ok(-1)
    );
    assert_eq!(
        eval_string_bytes("let get = builtins.getAttr \"a\"; in get { a = \"x\"; }"),
        b"x"
    );
    assert_eq!(
        eval("let has = builtins.hasAttr \"a\"; in has { a = 1; }").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval(
            "let remove = builtins.removeAttrs { a = 1; b = 2; }; in remove [ \"a\" ] == { b = 2; }"
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
            eval("let intersect = builtins.intersectAttrs { a = 0; c = 0; }; in intersect { a = 1; b = 2; } == { a = 1; }").as_bool(),
            Ok(true)
        );
    assert_eq!(
        eval_list_ints(
            "let cat = builtins.catAttrs \"a\"; in cat [ { a = 1; } { b = 2; } { a = 3; } ]"
        ),
        vec![1, 3]
    );
    assert_eq!(
        eval_list_ints(
            "let cat = builtins.catAttrs \"a\"; in cat [
               (builtins.foldl' (acc: _x: acc) { a = 1; } [])
             ]"
        ),
        vec![1]
    );
    assert_eq!(
        eval_list_ints(
            "builtins.catAttrs \"a\" [
               (builtins.foldl' (acc: _x: acc) { a = 1; } [])
             ]"
        ),
        vec![1]
    );
    assert_eq!(
        eval_string_bytes("let join = builtins.concatStringsSep \",\"; in join [ \"a\" \"b\" ]"),
        b"a,b"
    );
    assert_eq!(
        eval("let s = builtins.seq (1 / 0); in builtins.isFunction s").as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval("let s = builtins.seq 1; in builtins.length (s [ 1 (1 / 0) ])").as_int(),
        Ok(2)
    );
}

#[test]
fn first_class_binary_builtin_type_checks_left_before_right() {
    for (source, expected, actual) in [
        (
            "let cmp = builtins.compareVersions 1; in cmp (1 / 0)",
            "string",
            ValueTag::Int,
        ),
        (
            "let and = builtins.bitAnd true; in and (1 / 0)",
            "int",
            ValueTag::Bool,
        ),
    ] {
        let error = eval_whnf_owned(&lower(source)).expect_err("left argument is rejected");

        let TreeWalkErrorKind::Type {
            expected: found_expected,
            actual: found_actual,
            ..
        } = error.kind()
        else {
            panic!("expected a type error for {source}, got {error:?}");
        };
        assert_eq!(found_expected, expected, "{source}");
        assert_eq!(found_actual, actual, "{source}");
    }
}

#[test]
fn first_class_ternary_builtin_selects_are_curried() {
    assert_eq!(
        eval("let fold = builtins.foldl' builtins.add; sum = fold 0; in sum [ 1 2 3 ]").as_int(),
        Ok(6)
    );
    assert_eq!(
        eval_string_bytes("let slice = builtins.substring 1; take2 = slice 2; in take2 \"abcd\""),
        b"bc"
    );
    assert_eq!(
        eval_string_bytes(
            "let replace = builtins.replaceStrings [ \"a\" ]; swap = replace [ \"b\" ]; in swap \"a\""
        ),
        b"b"
    );
}

#[test]
fn hash_string_primop_hashes_context_bearing_string_bytes() {
    let ir = lower("builtins.hashString \"sha256\" \"abc\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let string = args[1];
    let string_span = ir.arena.node(string).expect("string argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"abc".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_hash_string_primop_with_string_value(
            ir.root,
            root.span,
            algorithm,
            string,
            string_span,
            value,
        )
        .expect("hashString evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result is a string");

    assert_eq!(
        string.bytes(),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(!string.has_context());
}

#[test]
fn hash_string_primop_rejects_context_bearing_algorithm() {
    let ir = lower("builtins.hashString \"sha256\" (1 / 0)");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let source = ContextElement::opaque_path(b"/nix/store/source".to_vec())
        .expect("source context is valid");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(
            b"sha256".to_vec(),
            StringContext::singleton(source).expect("source context allocates"),
        ))
        .expect("context-bearing algorithm allocates");

    let error = evaluator
        .eval_hash_algorithm(algorithm, algorithm_span, value, "hashString")
        .expect_err("hashString rejects algorithm string context");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            id: algorithm,
            op: "hashString",
        }
    );
    assert_eq!(error.span(), algorithm_span);
}

#[test]
fn hash_string_primop_checks_algorithm_before_string() {
    let ir = lower("builtins.hashString \"bad\" (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

    let error = eval_whnf_owned(&ir).expect_err("unknown algorithm is rejected first");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm {
            id: algorithm,
            algorithm: b"bad".to_vec(),
        }
    );
    assert_eq!(error.span(), algorithm_span);

    let ir = lower("builtins.hashString \"SHA256\" \"abc\"");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];

    let error = eval_whnf_owned(&ir).expect_err("algorithm names are case-sensitive");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm {
            id: algorithm,
            algorithm: b"SHA256".to_vec(),
        }
    );
}

#[test]
fn hash_string_primop_type_checks_arguments() {
    let ir = lower("builtins.hashString 1 (1 / 0)");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let algorithm = args[0];
    let algorithm_span = ir.arena.node(algorithm).expect("algorithm exists").span;

    let error = eval_whnf_owned(&ir).expect_err("algorithm must be a string");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: algorithm,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), algorithm_span);

    let ir = lower("builtins.hashString \"sha256\" { outPath = \"abc\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let string = args[1];
    let string_span = ir.arena.node(string).expect("string exists").span;

    let error = eval_whnf_owned(&ir).expect_err("string argument is not coerced");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: string,
            expected: "string",
            actual: ValueTag::Attrs,
        }
    );
    assert_eq!(error.span(), string_span);
}

#[test]
fn placeholder_primop_matches_cpp_nix_hash_scheme() {
    assert_eq!(
        eval_string_bytes(r#"builtins.placeholder "out""#),
        b"/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9"
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.placeholder "dev""#),
        b"/02qcpld1y6xhs5gz9bchpxaw0xdhmsp5dv88lh25r2ss44kh8dxz"
    );
    assert_eq!(
        eval("builtins.stringLength (builtins.placeholder \"out\")").as_int(),
        Ok(53)
    );
    assert_eq!(
        eval_string_bytes(r#"let p = builtins.placeholder; in p "out""#),
        b"/1rz4g4znpzjwh1xymhjpm42vipw92pr73vdgl6xs1hycac8kf2n9"
    );
    assert_eq!(
        eval_string_bytes(
            r#"let builtins = { placeholder = output: "local"; }; in builtins.placeholder "out""#
        ),
        b"local"
    );
}
