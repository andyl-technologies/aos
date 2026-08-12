//! Tree-walk evaluator tests for convertHash behavior.

use super::*;
use crate::cache::{
    DurableBlake3Hash, PARSE_CACHE_SCHEMA_VERSION, ParseCache, ParseCacheFlags, ParseCacheKey,
    ParseFileKey, PersistCache, PersistFileArtifactKey,
};
use crate::string::NixString;

#[test]
fn configured_import_cache_preserves_convert_hash_surface() {
    fn evaluate_convert_hash_surface(
        source: &str,
        options: TreeWalkOptions,
    ) -> (Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let value = evaluator
            .eval_root()
            .expect("convertHash expression evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let output = evaluator
            .heap()
            .get_string(value)
            .expect("convertHash result is a string")
            .bytes()
            .to_vec();
        (output, import_stats)
    }

    fn configured_options(root: &Path) -> TreeWalkOptions {
        let mut options = TreeWalkOptions::new();
        options
            .set_path_literal_base(path_bytes(root))
            .expect("path base configures");
        options
    }

    fn hot_string_surface_canaries(label: &str, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let hot_canary = NixString::from_bytes(bytes.to_vec())
            .structural_hash_xxh3()
            .raw_for_tests();
        vec![
            (
                format!("{label} hot xxh3 decimal"),
                hot_canary.to_string().into_bytes(),
            ),
            (
                format!("{label} hot xxh3 hex"),
                format!("{hot_canary:016x}").into_bytes(),
            ),
            (
                format!("{label} hot xxh3 little-endian bytes"),
                hot_canary.to_le_bytes().to_vec(),
            ),
            (
                format!("{label} hot xxh3 big-endian bytes"),
                hot_canary.to_be_bytes().to_vec(),
            ),
        ]
    }

    let root = fs::canonicalize(unique_temp_dir("import-cache-convert-hash-surface-parity"))
        .expect("temp directory canonicalizes");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let persist_root = root.join("persist-cache");
    let import_path = root.join("convert-hash-args.nix");
    let imported_hash = b"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";
    let imported_format = b"nix32";
    let decoded_digest = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let imported_source =
        br#"{ hash = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="; toHashFormat = "nix32"; }"#;
    fs::write(&import_path, imported_source).expect("convertHash args import writes");
    let import_realpath = fs::canonicalize(&import_path).expect("import path canonicalizes");
    let source = format!(
        "builtins.convertHash (import {})",
        path_source(&import_path)
    );
    let expected_output = b"1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s";

    let (uncached_output, uncached_stats) =
        evaluate_convert_hash_surface(&source, configured_options(&root));
    assert_eq!(uncached_stats, (0, 0));
    assert_eq!(uncached_output, expected_output);

    let mut miss_options = configured_options(&root);
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_output, miss_stats) = evaluate_convert_hash_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 1));
    assert_eq!(miss_output, uncached_output);

    let mut hit_options = configured_options(&root);
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_output, hit_stats) = evaluate_convert_hash_surface(&source, hit_options);
    assert_eq!(hit_stats, (1, 0));
    assert_eq!(hit_output, uncached_output);
    assert!(
        ParseCache::new(&second_parse_root)
            .entry_for_source(imported_source)
            .is_complete(),
        "persistent hit should hydrate the runtime parse-cache entry"
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
    let file_key = ParseFileKey::for_source(&import_realpath, imported_source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, imported_parse_key);
    assert!(
        PersistCache::open(&persist_root)
            .expect("persistent cache opens")
            .lookup_file_artifact(artifact_key)
            .expect("persistent file-artifact lookup succeeds")
            .is_some(),
        "convertHash canary import should materialize a persistent file-artifact mapping"
    );

    let mut canaries =
        durable_hash_surface_canaries("root parse-cache BLAKE3", root_parse_key.as_durable_hash());
    canaries.extend(durable_hash_surface_canaries(
        "import parse-cache BLAKE3",
        imported_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "import file-content BLAKE3",
        file_key.content_hash().as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "imported hash BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(imported_hash),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "decoded hash digest BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(&decoded_digest),
    ));
    canaries.extend(hot_string_surface_canaries(
        "convertHash input hash",
        imported_hash,
    ));
    canaries.extend(hot_string_surface_canaries(
        "convertHash output format",
        imported_format,
    ));

    for (surface_name, output) in [
        ("cache-disabled convertHash surface", &uncached_output),
        ("persistent miss convertHash surface", &miss_output),
        ("persistent hit convertHash surface", &hit_output),
    ] {
        assert_surface_canaries_absent(surface_name, "hash output", output, &canaries);
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn convert_hash_primop_converts_formats() {
    let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"base64\"; }}"
        )),
        b"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"nix32\"; }}"
        )),
        b"1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"base32\"; }}"
        )),
        b"1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"{sha256}\"; hashAlgo = \"sha256\"; toHashFormat = \"sri\"; }}"
        )),
        b"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = \"sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s\"; toHashFormat = \"base16\"; }"
        ),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash {{ hash = \"sha256:{sha256}\"; toHashFormat = \"base16\"; }}"
        )),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.convertHash (builtins.foldl' (acc: _x: acc) {{ hash = \"sha256:{sha256}\"; toHashFormat = \"base16\"; }} [])"
        )),
        sha256.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = builtins.hashString \"md5\" \"abc\"; hashAlgo = \"md5\"; toHashFormat = \"nix32\"; }"
        ),
        b"3jgzhjhz9zjvbb0kyj7jc500ch"
    );
    assert_eq!(
        eval_string_bytes(
            "builtins.convertHash { hash = builtins.hashString \"sha1\" \"abc\"; hashAlgo = \"sha1\"; toHashFormat = \"base64\"; }"
        ),
        b"qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
    );
    assert_eq!(
            eval_string_bytes(
                "builtins.convertHash { hash = builtins.hashString \"sha512\" \"abc\"; hashAlgo = \"sha512\"; toHashFormat = \"nix32\"; }"
            ),
            b"2gs8k559z4rlahfx0y688s49m2vvszylcikrfinm30ly9rak69236nkam5ydvly1ai7xac99vxfc4ii84hawjbk876blyk1jfhkbbyx"
        );
    assert_eq!(
        eval_string_bytes(
            "let builtins = { convertHash = args: \"local\"; }; in builtins.convertHash { hash = 1 / 0; }"
        ),
        b"local"
    );
}

#[test]
fn convert_hash_primop_can_be_selected_as_a_function() {
    assert_eq!(
        eval_string_bytes(
            "let convert = builtins.convertHash; in convert { hash = \"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }"
        ),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn convert_hash_primop_checks_arguments_in_nix_order() {
    let ir = lower("builtins.convertHash 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("argument must be an attrset");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "attrs",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = 1 / 0; hashAlgo = 1 / 0; toHashFormat = 1 / 0; }",
    ))
    .expect_err("hash is forced first");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = 1 / 0; toHashFormat = 1 / 0; }",
    ))
    .expect_err("hashAlgo is forced second");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = 1 / 0; }",
    ))
    .expect_err("toHashFormat is forced third");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::DivisionByZero { .. }
    ));
}

#[test]
fn convert_hash_primop_reports_missing_attributes() {
    let ir = lower("builtins.convertHash { hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let mut evaluator = TreeWalk::new(&ir);

    let error = evaluator
        .eval_root()
        .expect_err("convertHash requires hash");

    let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
        panic!("expected missing hash attribute");
    };
    assert_eq!(id, argument);
    assert_eq!(evaluator.symbols.resolve(symbol), Some(b"hash".as_slice()));

    let ir = lower(
        "builtins.convertHash { hash = builtins.hashString \"sha256\" \"abc\"; hashAlgo = \"sha256\"; }",
    );
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let mut evaluator = TreeWalk::new(&ir);

    let error = evaluator
        .eval_root()
        .expect_err("convertHash requires toHashFormat");

    let TreeWalkErrorKind::MissingAttribute { id, symbol } = error.kind() else {
        panic!("expected missing toHashFormat attribute");
    };
    assert_eq!(id, argument);
    assert_eq!(
        evaluator.symbols.resolve(symbol),
        Some(b"toHashFormat".as_slice())
    );
}

#[test]
fn convert_hash_primop_requires_direct_strings() {
    let ir = lower(
        "builtins.convertHash { hash = { outPath = \"abc\"; }; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
    );
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("convertHash argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("hash is not coerced");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Attrs,
        }
    );
    assert_eq!(error.span(), argument_span);

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = null; toHashFormat = \"base16\"; }",
    ))
    .expect_err("hashAlgo must be a string when present");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = { outPath = \"base16\"; }; }",
        ))
        .expect_err("toHashFormat is not coerced");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Attrs,
            ..
        }
    ));
}

#[test]
fn convert_hash_primop_rejects_invalid_hashes() {
    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"bad\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("unknown algorithm is rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashAlgorithm { algorithm, .. }
            if algorithm.as_slice() == b"bad"
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = \"bad\"; }",
    ))
    .expect_err("unknown format is rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnknownHashFormat { format, .. }
            if format.as_slice() == b"bad"
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"abc\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("untyped hashes require hashAlgo");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashAlgorithmRequired { hash, .. }
            if hash.as_slice() == b"abc"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=\"; hashAlgo = \"md5\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("typed hashes must agree with hashAlgo");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashAlgorithmMismatch { expected, .. }
            if expected.as_slice() == b"md5"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"abc\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("short hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::HashWrongLength { hash, algorithm, .. }
            if hash.as_slice() == b"abc" && algorithm.as_slice() == b"sha256"
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("invalid hex hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidBase16Hash { .. }
    ));

    let error = eval_whnf_owned(&lower(
            "builtins.convertHash { hash = \"????????????????????????????????????????????\"; hashAlgo = \"sha256\"; toHashFormat = \"base16\"; }",
        ))
        .expect_err("invalid base64 hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidBase64Hash { .. }
    ));

    let error = eval_whnf_owned(&lower(
        "builtins.convertHash { hash = \"sha256-invalid\"; toHashFormat = \"base16\"; }",
    ))
    .expect_err("invalid SRI hashes are rejected");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::InvalidSriHash { .. }
    ));
}
