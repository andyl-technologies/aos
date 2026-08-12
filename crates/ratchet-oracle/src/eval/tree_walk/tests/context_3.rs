//! Tree-walk evaluator tests: context 3.

use super::*;
use crate::cache::{
    DurableBlake3Hash, PARSE_CACHE_SCHEMA_VERSION, ParseCache, ParseCacheFlags, ParseCacheKey,
    ParseFileKey, PersistCache, PersistFileArtifactKey,
};
use crate::string::NixString;

mod output_dependency;

#[test]
fn store_path_primop_returns_context_bearing_store_strings() {
    let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src";
    let child = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src/sub";
    let context_json =
        br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true}}"#.to_vec();

    assert_eq!(
        eval_string_bytes(&format!("builtins.storePath {root}")),
        root.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(r#"builtins.storePath "{root}/.""#)),
        root.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(r#"builtins.storePath "{child}""#)),
        child.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!(r#"builtins.storePath {{ outPath = "{root}"; }}"#)),
        root.as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.typeOf (builtins.storePath {root})")),
        b"string"
    );
    assert_eq!(
        eval_json_bytes(&format!("builtins.getContext (builtins.storePath {root})")),
        context_json
    );
    assert_eq!(
        eval_json_bytes(&format!(
            r#"builtins.getContext (builtins.storePath "{child}")"#
        )),
        br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true}}"#.to_vec()
    );
}

#[test]
fn store_path_primop_unions_existing_string_context() {
    let source = r#"builtins.getContext (
            builtins.storePath (
                builtins.appendContext
                  "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src"
                  {
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other" = {
                      path = true;
                    };
                  }
            )
        )"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true},"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other":{"path":true}}"#.to_vec()
        );
}

#[test]
fn store_path_context_is_observed_by_derivation_strict_as_input_src() {
    let source = r#"let
             src = builtins.storePath "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src";
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               inherit src;
             };
           in {
             drvPath = d.drvPath;
             out = d.out;
             src = src;
             srcContext = builtins.getContext src;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/vkbcsd0wpf20mil1mngbk8dzrh9z3sdv-x.drv","out":"/nix/store/y1q9h2irnds1pphaf2cpyxdv54y87w6d-x","src":"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src","srcContext":{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true}}}"#.to_vec()
        );
}

#[test]
fn store_path_primop_uses_configured_store_dir() {
    let root = "/custom/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src";
    let options =
        TreeWalkOptions::with_store_dir(b"/custom/store".to_vec()).expect("store dir configures");

    assert_eq!(
        eval_string_bytes_with_options(&format!("builtins.storePath {root}"), options.clone()),
        root.as_bytes()
    );
    assert_eq!(
        eval_json_bytes_with_options(
            &format!(r#"builtins.getContext (builtins.storePath "{root}/sub")"#),
            options,
        ),
        br#"{"/custom/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src":{"path":true}}"#.to_vec()
    );
}

#[test]
fn store_path_primop_rejects_non_store_paths() {
    let error = eval_whnf_owned(&lower(r#"builtins.storePath "/tmp/not-store""#))
        .expect_err("storePath rejects paths outside the store");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StorePathNotInStore {
            path,
            ..
        } if path.as_slice() == b"/tmp/not-store"
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.storePath "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src/..""#,
    ))
    .expect_err("storePath rejects normalized store dir");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StorePathNotInStore {
            path,
            ..
        } if path.as_slice() == b"/nix/store"
    ));

    let error = eval_whnf_owned(&lower("builtins.storePath 1"))
        .expect_err("storePath coerces its argument to a string");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));
}

#[test]
fn store_path_primop_is_gated_by_filesystem_policy() {
    let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src";
    let source = format!(r#"builtins.storePath "{root}""#);
    let ir = lower(&source);

    let error = eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Pure))
        .expect_err("pure mode rejects storePath calls");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StorePathPureEval { id: ir.root }
    );

    assert_eq!(
        eval_with_options(
            "builtins ? storePath",
            TreeWalkOptions::with_eval_mode(EvalMode::Pure)
        )
        .as_bool(),
        Ok(true)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.typeOf builtins.storePath",
            TreeWalkOptions::with_eval_mode(EvalMode::Pure)
        ),
        b"lambda"
    );
    let fallback_ir = lower("builtins.storePath or 42");
    assert_eq!(
        eval_whnf_owned_with_options(
            &fallback_ir,
            TreeWalkOptions::with_eval_mode(EvalMode::Pure)
        )
        .expect("storePath is visible to select-or in pure mode")
        .value()
        .tag(),
        ValueTag::Primop
    );

    let invalid_ir = lower("builtins.storePath 1");
    let (argument, argument_span) = primop_argument(&invalid_ir, 0);
    let error =
        eval_whnf_owned_with_options(&invalid_ir, TreeWalkOptions::with_eval_mode(EvalMode::Pure))
            .expect_err("pure storePath still validates its argument before mode rejection");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let mut allowed_pure_options = TreeWalkOptions::with_eval_mode(EvalMode::Pure);
    allowed_pure_options
        .add_allowed_path(b"/nix/store".to_vec())
        .expect("store root configures as allowed");
    let error = eval_whnf_owned_with_options(&ir, allowed_pure_options)
        .expect_err("pure mode rejects storePath even when path policy would allow it");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StorePathPureEval { id: ir.root }
    );

    let selected_call = lower(&format!(r#"let f = builtins.storePath; in f "{root}""#));
    let error = eval_whnf_owned_with_options(
        &selected_call,
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure mode rejects selected first-class storePath calls");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StorePathPureEval { .. }
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(b"/nix/store".to_vec())
        .expect("store root configures as allowed");
    assert_eq!(
        eval_string_bytes_with_options(&source, options),
        root.as_bytes()
    );
}

#[test]
fn to_file_primop_builds_text_store_paths_and_context() {
    let source = r#"let
            p = builtins.toFile "foo" "bar";
            nested = builtins.toFile "baz" p;
            dot = builtins.toFile ".x" "x";
        in {
            path = p;
            ctx = builtins.getContext p;
            nested = nested;
            nestedCtx = builtins.getContext nested;
            dot = dot;
            firstClass = (builtins.toFile "hello") "abc";
        }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"ctx":{"/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo":{"path":true}},"dot":"/nix/store/1x49d9g8znzikskxdsx7k6kk2qzcdrps-.x","firstClass":"/nix/store/4falznnjmyg7iqca3qlskx9l79bh6hwd-hello","nested":"/nix/store/5xd714cbfnkz02h2vbsj4fm03x3f15nf-baz","nestedCtx":{"/nix/store/5xd714cbfnkz02h2vbsj4fm03x3f15nf-baz":{"path":true}},"path":"/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo"}"#.to_vec()
        );
}

#[test]
fn configured_import_cache_preserves_to_file_store_path_surface() {
    fn evaluate_to_file_surface(
        source: &str,
        options: TreeWalkOptions,
    ) -> (Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let value = evaluator.eval_root().expect("toFile expression evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let output = evaluator
            .heap()
            .get_string(value)
            .expect("toFile result is a string")
            .bytes()
            .to_vec();
        (output, import_stats)
    }

    fn configured_options(root: &Path, store_dir: &Path) -> TreeWalkOptions {
        let mut options = TreeWalkOptions::with_store_dir(path_bytes(store_dir))
            .expect("store directory configures");
        options
            .set_path_literal_base(path_bytes(root))
            .expect("path base configures");
        options
    }

    fn checked_store_path(output: &[u8], store_dir: &Path) -> PathBuf {
        let path = PathBuf::from(std::str::from_utf8(output).expect("store path is UTF-8"));
        assert!(
            path.starts_with(store_dir),
            "toFile store path {path:?} should stay under configured store dir {store_dir:?}"
        );
        path
    }

    fn assert_persistent_artifact(
        persist_root: &Path,
        realpath: &Path,
        source: &[u8],
        parse_key: ParseCacheKey,
    ) {
        let file_key = ParseFileKey::for_source(realpath, source);
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        assert!(
            PersistCache::open(persist_root)
                .expect("persistent cache opens")
                .lookup_file_artifact(artifact_key)
                .expect("persistent file-artifact lookup succeeds")
                .is_some(),
            "toFile canary import should materialize a persistent file-artifact mapping"
        );
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

    let root = fs::canonicalize(unique_temp_dir("import-cache-to-file-surface-parity"))
        .expect("temp directory canonicalizes");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let persist_root = root.join("persist-cache");
    let store_dir = root.join("store");
    fs::create_dir(&store_dir).expect("store directory creates");
    let name_path = root.join("to-file-name.nix");
    let contents_path = root.join("to-file-contents.nix");
    let name = b"cache-surface-to-file";
    let contents = b"toFile cache surface payload";
    let name_source = format!(
        "{}\n",
        nix_string_literal(std::str::from_utf8(name).expect("name is UTF-8"))
    )
    .into_bytes();
    let contents_source = format!(
        "{}\n",
        nix_string_literal(std::str::from_utf8(contents).expect("contents are UTF-8"))
    )
    .into_bytes();
    fs::write(&name_path, &name_source).expect("toFile name import writes");
    fs::write(&contents_path, &contents_source).expect("toFile contents import writes");
    let name_realpath = fs::canonicalize(&name_path).expect("name path canonicalizes");
    let contents_realpath = fs::canonicalize(&contents_path).expect("contents path canonicalizes");
    let source = format!(
        "builtins.toFile (import {}) (import {})",
        path_source(&name_path),
        path_source(&contents_path)
    );

    let uncached_options = configured_options(&root, &store_dir);
    let (uncached_output, uncached_stats) = evaluate_to_file_surface(&source, uncached_options);
    assert_eq!(uncached_stats, (0, 0));
    assert!(
        uncached_output.ends_with(b"-cache-surface-to-file"),
        "toFile surface should expose the requested name: {uncached_output:?}"
    );
    checked_store_path(&uncached_output, &store_dir);

    let mut miss_options = configured_options(&root, &store_dir);
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_output, miss_stats) = evaluate_to_file_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 2));
    assert_eq!(miss_output, uncached_output);

    let mut hit_options = configured_options(&root, &store_dir);
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_output, hit_stats) = evaluate_to_file_surface(&source, hit_options);
    assert_eq!(hit_stats, (2, 0));
    assert_eq!(hit_output, uncached_output);

    let second_parse = ParseCache::new(&second_parse_root);
    assert!(
        second_parse.entry_for_source(&name_source).is_complete(),
        "persistent hit should hydrate the imported name parse-cache entry"
    );
    assert!(
        second_parse
            .entry_for_source(&contents_source)
            .is_complete(),
        "persistent hit should hydrate the imported contents parse-cache entry"
    );

    let root_parse_key = ParseCacheKey::for_source(
        source.as_bytes(),
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let name_parse_key = ParseCacheKey::for_source(
        &name_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let contents_parse_key = ParseCacheKey::for_source(
        &contents_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    assert_persistent_artifact(&persist_root, &name_realpath, &name_source, name_parse_key);
    assert_persistent_artifact(
        &persist_root,
        &contents_realpath,
        &contents_source,
        contents_parse_key,
    );

    let mut canaries =
        durable_hash_surface_canaries("root parse-cache BLAKE3", root_parse_key.as_durable_hash());
    canaries.extend(durable_hash_surface_canaries(
        "name import parse-cache BLAKE3",
        name_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "contents import parse-cache BLAKE3",
        contents_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "name import file-content BLAKE3",
        ParseFileKey::for_source(&name_realpath, &name_source)
            .content_hash()
            .as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "contents import file-content BLAKE3",
        ParseFileKey::for_source(&contents_realpath, &contents_source)
            .content_hash()
            .as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "toFile contents BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(contents),
    ));
    canaries.extend(hot_string_surface_canaries("toFile name", name));
    canaries.extend(hot_string_surface_canaries("toFile contents", contents));

    for (surface_name, output) in [
        ("cache-disabled toFile surface", &uncached_output),
        ("persistent miss toFile surface", &miss_output),
        ("persistent hit toFile surface", &hit_output),
    ] {
        assert_surface_canaries_absent(surface_name, "store path", output, &canaries);
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn to_file_primop_validates_name_before_forcing_contents() {
    let error = eval_whnf_owned(&lower(r#"builtins.toFile 1 (builtins.throw "contents")"#))
        .expect_err("toFile validates the name type before forcing contents");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.toFile
                (builtins.storePath "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src")
                (builtins.throw "contents")"#,
    ))
    .expect_err("toFile validates name context before forcing contents");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed { op: "toFile", .. }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.toFile "bad/name" (builtins.throw "contents")"#,
    ))
    .expect_err("toFile forces contents before constructing the store path");
    assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));
}

#[test]
fn to_file_text_store_is_visible_to_filesystem_builtins_and_import() {
    let source = r#"let
            p = builtins.toFile "x.nix" "1 + 2";
            scoped = builtins.toFile "scoped.nix" "y + 1";
        in {
            exists = builtins.pathExists p;
            type = builtins.readFileType p;
            read = builtins.readFile p;
            imported = import p;
            scoped = builtins.scopedImport { y = 4; } scoped;
        }"#;

    assert_eq!(
        eval_json_bytes(source),
        br#"{"exists":true,"imported":3,"read":"1 + 2","scoped":5,"type":"regular"}"#.to_vec()
    );
}

#[test]
fn to_file_text_store_read_file_preserves_references() {
    let source = r#"let
            p = builtins.toFile "foo" "bar";
            q = builtins.toFile "baz" p;
            read = builtins.readFile q;
        in {
            ctx = builtins.getContext read;
            sameAgain = builtins.toFile "again" read == builtins.toFile "again" p;
        }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"ctx":{"/nix/store/vxjiwkjkn7x4079qvh1jkl5pn05j2aw0-foo":{"path":true}},"sameAgain":true}"#.to_vec()
        );
}

#[test]
fn to_file_text_store_import_uses_import_cache() {
    let outcome = eval_owned(
        r#"let
                p = builtins.toFile "cached.nix" "builtins.trace \"cached\" 1";
                values = [ (import p) (import p) ];
            in builtins.deepSeq values values"#,
    );

    assert_eq!(outcome.trace_output().len(), 1);
    assert_trace_output(
        outcome.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        b"cached",
    );
}

#[test]
fn to_file_text_store_import_records_complete_empty_trace() {
    let outcome = eval_whnf_owned(&lower(
        r#"let p = builtins.toFile "generated.nix" "1"; in import p"#,
    ))
    .expect("text-store import evaluates");

    assert_eq!(outcome.value().as_int(), Ok(1));
    assert!(outcome.impure_input_trace().is_empty());
    assert!(outcome.impure_input_trace_complete());
}

#[test]
fn to_file_text_store_import_with_current_time_records_uncacheable_trace() {
    let current_time = 1_700_000_000;
    let options = TreeWalkOptions::with_current_time(current_time).expect("currentTime is valid");
    let outcome = eval_whnf_owned_with_options(
        &lower(r#"let p = builtins.toFile "generated.nix" "builtins.currentTime"; in import p"#),
        options,
    )
    .expect("text-store import evaluates");

    assert_eq!(outcome.value().as_int(), Ok(current_time));
    assert_eq!(
        outcome.impure_input_trace(),
        &[ImpureInputFingerprint::current_time()]
    );
    assert!(outcome.impure_input_trace_complete());
}

#[test]
fn first_class_text_store_import_does_not_replay_without_text_store_effects() {
    fn imported_text_store_path(ir: &Ir, persist_root: &Path) -> Vec<u8> {
        let mut options = TreeWalkOptions::with_eval_cache_enabled(true);
        options.set_persist_cache_root(persist_root);
        let mut evaluator = TreeWalk::with_options_and_eval_cache(
            ir,
            options,
            Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
        );
        let value = evaluator.eval_root().expect("text-store import evaluates");
        let path = evaluator
            .heap()
            .get_string(value)
            .expect("import result is a string")
            .bytes()
            .to_vec();
        assert!(
            evaluator.text_store.contains_key(&path),
            "imported toFile side effect should populate the returned text-store path"
        );
        assert!(evaluator.impure_input_trace().is_empty());
        assert!(evaluator.impure_input_trace_complete());
        evaluator.advance_persist_eval_cache_run_boundary();
        path
    }

    let persist_root = unique_temp_dir("force-cache-first-class-text-store-import-no-replay");
    let ir = lower(
        r#"let
             b = builtins;
             payload = b.toFile
               "outer-generated.nix"
               "builtins.toFile \"inner-generated.nix\" \"\\\"inner payload\\\"\"";
           in b.seq payload (b.import payload)"#,
    );

    let first = imported_text_store_path(&ir, &persist_root);
    let second = imported_text_store_path(&ir, &persist_root);
    let third = imported_text_store_path(&ir, &persist_root);
    assert_eq!(second, first);
    assert_eq!(third, first);

    fs::remove_dir_all(persist_root).expect("persistent temp directory removes");
}

#[test]
fn to_file_text_store_read_file_rejects_nul_bytes() {
    let error = eval_whnf_owned(&lower(
        r#"builtins.readFile (builtins.toFile "nul" (builtins.fromJSON "\"a\\u0000b\""))"#,
    ))
    .expect_err("readFile rejects NUL bytes from text store files");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FileReadContainsNul { .. }
    ));
}

#[test]
fn to_file_primop_rejects_invalid_name_and_types() {
    for name in ["bad/name", "", ".", "..", ".-x", "..-x"] {
        let source = format!(r#"builtins.toFile "{name}" "x""#);
        let error =
            eval_whnf_owned(&lower(&source)).expect_err("invalid store path names are rejected");
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::ToFilePath { .. }),
            "{name:?} rejected as ToFilePath, got {error:?}"
        );
    }

    let error = eval_whnf_owned(&lower(r#"builtins.toFile 1 "x""#))
        .expect_err("toFile name must be a string");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(r#"builtins.toFile "x" 1"#))
        .expect_err("toFile contents must be a string");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));
}

#[test]
fn to_file_primop_rejects_contextual_names_and_derivation_contents() {
    let error = eval_whnf_owned(&lower(
        r#"builtins.toFile
                (builtins.storePath "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src")
                "x""#,
    ))
    .expect_err("toFile names cannot carry context");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed { op: "toFile", .. }
    ));

    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ ];
             };
           in builtins.toFile "bad" d.out"#;
    let error = eval_whnf_owned(&lower(source))
        .expect_err("toFile contents cannot reference derivation outputs");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::ToFileDerivationReference {
            kind: ContextKind::SingleOutput,
            ..
        }
    ));

    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = [ ];
             };
           in builtins.toFile "ok" (builtins.unsafeDiscardOutputDependency d.drvPath)"#;
    eval_whnf_owned(&lower(source))
        .expect("toFile allows derivation contexts downgraded to opaque paths");
}

#[test]
fn add_drv_output_dependencies_primop_upgrades_derivation_context() {
    assert_eq!(
        eval_string_bytes(
            "let builtins = { addDrvOutputDependencies = value: \"shadow\"; }; in builtins.addDrvOutputDependencies \"x\""
        ),
        b"shadow"
    );

    let ir = lower("builtins.addDrvOutputDependencies \"x\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("addDrvOutputDependencies argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let drv_path = b"/nix/store/derivation.drv";
    let context = StringContext::singleton(
        ContextElement::opaque_path(drv_path.to_vec()).expect("drv context is valid"),
    )
    .expect("context allocates");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(drv_path.to_vec(), context))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_add_drv_output_dependencies_primop(ir.root, root.span, argument, argument_span, value)
        .expect("addDrvOutputDependencies evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result string exists");

    assert_eq!(string.bytes(), drv_path);
    assert_eq!(string.context().len(), 1);
    let element = string
        .context()
        .elements()
        .first()
        .expect("result context element exists");
    assert_eq!(element.kind(), ContextKind::DeepDerivation);
    assert_eq!(element.path(), drv_path);
}

#[test]
fn add_drv_output_dependencies_primop_is_idempotent_for_deep_context() {
    let ir = lower("builtins.addDrvOutputDependencies \"x\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("addDrvOutputDependencies argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;
    let mut evaluator = TreeWalk::new(&ir);
    let drv_path = b"/nix/store/deep.drv";
    let context = StringContext::singleton(
        ContextElement::deep_derivation(drv_path.to_vec()).expect("deep context is valid"),
    )
    .expect("context allocates");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(drv_path.to_vec(), context))
        .expect("context-bearing string allocates");

    let result = evaluator
        .eval_add_drv_output_dependencies_primop(ir.root, root.span, argument, argument_span, value)
        .expect("addDrvOutputDependencies evaluates");
    let string = evaluator
        .heap
        .get_string(result)
        .expect("result string exists");

    assert_eq!(string.bytes(), drv_path);
    assert_eq!(string.context().len(), 1);
    let element = string
        .context()
        .elements()
        .first()
        .expect("result context element exists");
    assert_eq!(element.kind(), ContextKind::DeepDerivation);
    assert_eq!(element.path(), drv_path);
}

#[test]
fn add_drv_output_dependencies_primop_rejects_invalid_context_shapes() {
    let ir = lower("builtins.addDrvOutputDependencies \"x\"");
    let root = *ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let argument = ir
        .arena
        .child_slice(args)
        .expect("primop args exist")
        .first()
        .copied()
        .expect("addDrvOutputDependencies argument exists");
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("empty context is rejected");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextElementCount {
            id: argument,
            len: 0,
        }
    );
    assert_eq!(error.span(), argument_span);

    let mut evaluator = TreeWalk::new(&ir);
    let context = StringContext::new(vec![
        ContextElement::opaque_path(b"/nix/store/a.drv".to_vec()).expect("first context is valid"),
        ContextElement::opaque_path(b"/nix/store/b.drv".to_vec()).expect("second context is valid"),
    ]);
    let value = evaluator
        .heap
        .alloc_string(NixString::new(b"x".to_vec(), context))
        .expect("context-bearing string allocates");
    let error = evaluator
        .eval_add_drv_output_dependencies_primop(ir.root, root.span, argument, argument_span, value)
        .expect_err("multiple context elements are rejected");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextElementCount {
            id: argument,
            len: 2,
        }
    );

    let mut evaluator = TreeWalk::new(&ir);
    let source_path = b"/nix/store/source";
    let context = StringContext::singleton(
        ContextElement::opaque_path(source_path.to_vec()).expect("source context is valid"),
    )
    .expect("context allocates");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(source_path.to_vec(), context))
        .expect("context-bearing string allocates");
    let error = evaluator
        .eval_add_drv_output_dependencies_primop(ir.root, root.span, argument, argument_span, value)
        .expect_err("non-derivation context paths are rejected");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextPathNotDerivation {
            id: argument,
            path: source_path.to_vec(),
        }
    );

    let mut evaluator = TreeWalk::new(&ir);
    let drv_path = b"/nix/store/output.drv";
    let context = StringContext::singleton(
        ContextElement::single_output(drv_path.to_vec(), b"out".to_vec())
            .expect("output context is valid"),
    )
    .expect("context allocates");
    let value = evaluator
        .heap
        .alloc_string(NixString::new(drv_path.to_vec(), context))
        .expect("context-bearing string allocates");
    let error = evaluator
        .eval_add_drv_output_dependencies_primop(ir.root, root.span, argument, argument_span, value)
        .expect_err("output context is rejected");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextDerivationOutput {
            id: argument,
            output: b"out".to_vec(),
        }
    );
}

#[test]
fn add_drv_output_dependencies_primop_coerces_argument() {
    let ir = lower("builtins.addDrvOutputDependencies 1");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("integer coercion is rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: argument,
            expected: "string",
            actual: ValueTag::Int,
        }
    );
    assert_eq!(error.span(), argument_span);

    let ir = lower("builtins.addDrvOutputDependencies { outPath = \"x\"; }");
    let root = ir.arena.node(ir.root).expect("root exists");
    let IrData::PrimOp { args, .. } = root.data else {
        panic!("root is a primop");
    };
    let args = ir.arena.child_slice(args).expect("primop args exist");
    let argument = args[0];
    let argument_span = ir.arena.node(argument).expect("argument exists").span;

    let error = eval_whnf_owned(&ir).expect_err("coerced context-free string is rejected");

    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::StringContextElementCount {
            id: argument,
            len: 0,
        }
    );
    assert_eq!(error.span(), argument_span);
}
