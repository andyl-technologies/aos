//! Split-out tests (part_1). See parent module.

use super::*;

#[test]
fn scoped_import_ifd_error_reports_scoped_import_op() {
    let root = fs::canonicalize(unique_temp_dir("ifd-scoped")).expect("temp dir canonicalizes");
    let store = root.join("store");
    fs::create_dir(&store).expect("store dir creates");
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let import_path = output_path.join("imported.nix");
    let source = format!(
        "builtins.scopedImport {{ }} (builtins.appendContext {file} {{ {drv} = {{ outputs = [ \"out\" ]; }}; }})",
        file = nix_string_literal(&path_source(&import_path)),
        drv = nix_string_literal(&path_source(&drv_path)),
    );
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())
        .expect("store dir configures");

    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("scopedImport IFD requires a realizer");
    let TreeWalkErrorKind::UnsupportedImportFromDerivation { op, detail, .. } = error.kind() else {
        panic!("unexpected error kind: {error:?}");
    };
    assert_eq!(op, "scopedImport");
    assert_eq!(detail.path(), import_path.as_os_str().as_bytes());
    assert_eq!(detail.drv_path(), drv_path.as_os_str().as_bytes());
    assert_eq!(detail.output_name(), Some(b"out".as_slice()));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn import_evaluates_files_directories_and_escaping_values_in_one_heap() {
    let root =
        fs::canonicalize(unique_temp_dir("import-basic")).expect("temp directory canonicalizes");
    let subdir = root.join("sub");
    let dir_import = root.join("dir");
    let empty_dir = root.join("empty-dir");
    fs::create_dir(&subdir).expect("sub directory creates");
    fs::create_dir(&dir_import).expect("import directory creates");
    fs::create_dir(&empty_dir).expect("empty import directory creates");
    fs::write(subdir.join("dep.nix"), b"2").expect("dep writes");
    fs::write(subdir.join("inc.nix"), b"3").expect("inc writes");
    fs::write(subdir.join("data.txt"), b"data").expect("data writes");
    fs::write(subdir.join("rec.nix"), b"rec { x = 4; y = x; }").expect("rec writes");
    fs::write(
        subdir.join("child.nix"),
        br#"{
              a = 1;
              nested = import ./dep.nix;
              f = x: x + import ./inc.nix;
              formal = { a ? 1, b }: a + b;
              rel = ./data.txt;
            }"#,
    )
    .expect("child writes");
    fs::write(dir_import.join("default.nix"), b"5").expect("default writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");

    assert_eq!(
        eval_with_options("(import ./sub/child.nix).a", options.clone())
            .as_int()
            .expect("imported attr is int"),
        1
    );
    assert_eq!(
        eval_with_options("(import ./sub/child.nix).nested", options.clone())
            .as_int()
            .expect("imported nested value is int"),
        2
    );
    assert_eq!(
        eval_with_options("(import ./sub/child.nix).f 4", options.clone())
            .as_int()
            .expect("imported function result is int"),
        7
    );
    assert_eq!(
        eval_string_bytes_with_options(
            "builtins.baseNameOf ((import ./sub/child.nix).rel)",
            options.clone(),
        ),
        b"data.txt"
    );
    assert_eq!(
        eval_with_options("(import ./sub/rec.nix).y == 4", options.clone())
            .as_bool()
            .expect("imported recursive attr equality is bool"),
        true
    );
    assert_eq!(
        eval_with_options(
            r#"let args = builtins.functionArgs (import ./sub/child.nix).formal;
                   in args.a && !(args.b)"#,
            options.clone(),
        )
        .as_bool()
        .expect("imported functionArgs result is bool"),
        true
    );
    let xml = eval_string_bytes_with_options(
        "builtins.toXML (import ./sub/child.nix).formal",
        options.clone(),
    );
    assert!(
        xml.windows(b"attrspat".len())
            .any(|window| window == b"attrspat"),
        "imported formal-set lambda XML includes attrspat"
    );
    let traced_path = eval_whnf_owned_with_options(
        &lower("builtins.trace (import ./sub/child.nix).rel 0"),
        options.clone(),
    )
    .expect("imported path trace evaluates");
    let expected_path = subdir.join("data.txt").as_os_str().as_bytes().to_vec();
    assert_eq!(traced_path.trace_output().len(), 1);
    assert_trace_output(
        traced_path
            .trace_output()
            .first()
            .expect("path trace output exists"),
        EvalTraceKind::Trace,
        &expected_path,
    );
    assert_eq!(
        eval_with_options("import ./dir", options.clone())
            .as_int()
            .expect("directory import is int"),
        5
    );
    let missing_default =
        eval_whnf_owned_with_options(&lower("import ./empty-dir"), options.clone())
            .expect_err("directory import without default.nix rejects");
    assert!(matches!(
        missing_default.kind(),
        TreeWalkErrorKind::FileRead { .. }
    ));
    let first_class =
        eval_whnf_owned_with_options(&lower("let f = import; in f ./sub/child.nix"), options)
            .expect("first-class import evaluates");
    assert_eq!(first_class.value().tag(), ValueTag::Attrs);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn import_via_symlinked_directory_keeps_requested_relative_base() {
    let root = fs::canonicalize(unique_temp_dir("import-symlink-base"))
        .expect("temp directory canonicalizes");
    let fixture = root.join("symlink-resolution");
    let foo = fixture.join("foo");
    let overlays = fixture.join("overlays");
    fs::create_dir(&fixture).expect("fixture dir creates");
    fs::create_dir(&foo).expect("foo dir creates");
    fs::create_dir_all(foo.join("lib")).expect("lib dir creates");
    fs::create_dir(&overlays).expect("overlays dir creates");
    std::os::unix::fs::symlink("../overlays", foo.join("overlays"))
        .expect("overlays symlink creates");
    fs::write(foo.join("lib/default.nix"), br#""test""#).expect("lib default writes");
    fs::write(overlays.join("overlay.nix"), b"import ../lib").expect("overlay writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");

    assert_eq!(
        eval_string_bytes_with_options(
            "import ./symlink-resolution/foo/overlays/overlay.nix",
            options,
        ),
        b"test"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn import_uses_fresh_scope_and_shared_result_cache() {
    let root = fs::canonicalize(unique_temp_dir("import-scope-cache"))
        .expect("temp directory canonicalizes");
    fs::write(root.join("fresh.nix"), b"secret").expect("fresh writes");
    fs::write(root.join("traced.nix"), br#"builtins.trace "once" 9"#).expect("traced writes");
    std::os::unix::fs::symlink(root.join("traced.nix"), root.join("traced-link.nix"))
        .expect("trace symlink creates");
    let traced_dir = root.join("traced-dir");
    fs::create_dir(&traced_dir).expect("traced dir creates");
    fs::write(
        traced_dir.join("default.nix"),
        br#"builtins.trace "dir-once" 8"#,
    )
    .expect("traced default writes");
    fs::write(root.join("self.nix"), b"import ./self.nix").expect("self writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");

    let fresh_error = eval_whnf_owned_with_options(
        &lower("with { secret = 42; }; import ./fresh.nix"),
        options.clone(),
    )
    .expect_err("imported file does not inherit caller with-scope");
    assert!(matches!(
        fresh_error.kind(),
        TreeWalkErrorKind::ImportScope { .. } | TreeWalkErrorKind::UnresolvedWithVar { .. }
    ));
    let fresh_let_error = eval_whnf_owned_with_options(
        &lower("let secret = 42; in import ./fresh.nix"),
        options.clone(),
    )
    .expect_err("imported file does not inherit caller let-scope");
    assert!(matches!(
        fresh_let_error.kind(),
        TreeWalkErrorKind::ImportScope { .. } | TreeWalkErrorKind::UnresolvedWithVar { .. }
    ));

    let traced = eval_whnf_owned_with_options(
        &lower("builtins.deepSeq [ (import ./traced.nix) (import ./traced.nix) ] 0"),
        options.clone(),
    )
    .expect("cached imports evaluate");
    assert_eq!(traced.value().as_int().expect("trace result is int"), 0);
    assert_eq!(traced.trace_output().len(), 1);
    assert_trace_output(
        traced.trace_output().first().expect("trace output exists"),
        EvalTraceKind::Trace,
        b"once",
    );

    let symlinked = eval_whnf_owned_with_options(
        &lower("builtins.deepSeq [ (import ./traced.nix) (import ./traced-link.nix) ] 0"),
        options.clone(),
    )
    .expect("canonicalized imports share cache");
    assert_eq!(symlinked.value().as_int().expect("trace result is int"), 0);
    assert_eq!(symlinked.trace_output().len(), 1);
    assert_trace_output(
        symlinked
            .trace_output()
            .first()
            .expect("trace output exists"),
        EvalTraceKind::Trace,
        b"once",
    );

    let default_nix = eval_whnf_owned_with_options(
        &lower("builtins.deepSeq [ (import ./traced-dir) (import ./traced-dir/default.nix) ] 0"),
        options.clone(),
    )
    .expect("directory and default.nix imports share cache");
    assert_eq!(
        default_nix.value().as_int().expect("trace result is int"),
        0
    );
    assert_eq!(default_nix.trace_output().len(), 1);
    assert_trace_output(
        default_nix
            .trace_output()
            .first()
            .expect("trace output exists"),
        EvalTraceKind::Trace,
        b"dir-once",
    );

    let cycle = eval_whnf_owned_with_options(&lower("import ./self.nix"), options)
        .expect_err("recursive import is rejected");
    assert!(matches!(
        cycle.kind(),
        TreeWalkErrorKind::RecursiveImport { .. }
    ));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn uncached_filesystem_import_runs_analysis_in_process() {
    let root = fs::canonicalize(unique_temp_dir("import-uncached-analysis"))
        .expect("temp directory canonicalizes");
    fs::write(
        root.join("dep.nix"),
        b"let captured = 2; in (x: captured + x) 3",
    )
    .expect("dep writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let ir = lower("import ./dep.nix");
    let mut evaluator = TreeWalk::with_options(&ir, options);

    assert_eq!(
        evaluator
            .eval_root()
            .expect("uncached import evaluates")
            .as_int()
            .expect("uncached result is int"),
        5
    );
    assert!(
        evaluator.stats().campaign().flat_env_captures > 0,
        "uncached imported IR should consume its in-process capture plans"
    );
    assert_eq!(evaluator.import_parse_cache_stats(), (0, 0));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn ordinary_filesystem_import_uses_configured_parse_cache() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    fs::write(root.join("dep.nix"), b"{ zOnly = 41; }").expect("dep writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    let ir = lower(r#"builtins.concatStringsSep "," (builtins.attrNames (import ./dep.nix))"#);

    let mut first = TreeWalk::with_options(&ir, options.clone());
    let value = first.eval_root().expect("first import evaluates");
    let string = first
        .heap()
        .get_string(value)
        .expect("attrNames result concatenates to string");
    assert_eq!(string.bytes(), b"zOnly");
    assert_eq!(first.import_parse_cache_stats(), (0, 1));
    assert_eq!(first.stats().force_cache_hits(), 0);
    assert_eq!(first.stats().force_cache_misses(), 0);
    assert_eq!(first.stats().cache_hits(), 0);
    assert_eq!(first.stats().cache_misses(), 1);
    assert!(
        fs::read_dir(&cache_root)
            .expect("cache directory exists")
            .next()
            .is_some(),
        "first import should write a durable parse-cache entry"
    );

    let mut second = TreeWalk::with_options(&ir, options);
    let value = second.eval_root().expect("second import evaluates");
    let string = second
        .heap()
        .get_string(value)
        .expect("cached attrNames result concatenates to string");
    assert_eq!(string.bytes(), b"zOnly");
    assert_eq!(second.import_parse_cache_stats(), (1, 0));
    assert_eq!(second.stats().force_cache_hits(), 0);
    assert_eq!(second.stats().force_cache_misses(), 0);
    assert_eq!(second.stats().cache_hits(), 1);
    assert_eq!(second.stats().cache_misses(), 0);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn ordinary_filesystem_import_refreshes_parse_cache_analysis_facts() {
    use crate::cache::ParseCache;

    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-analysis"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    let source = b"(x: x + 1) (1 + 2)";
    fs::write(root.join("dep.nix"), source).expect("dep writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    let ir = lower("import ./dep.nix");

    let mut first = TreeWalk::with_options(&ir, options.clone());
    assert_eq!(
        first
            .eval_root()
            .expect("first import evaluates")
            .as_int()
            .expect("first result is int"),
        4
    );
    assert_eq!(first.import_parse_cache_stats(), (0, 1));
    assert!(
        first.stats().thunks_elided() > 0,
        "analyzed imported IR should elide a strict thunk"
    );

    let parse_cache = ParseCache::new(&cache_root);
    let cached = parse_cache
        .load_cached_bytes(source)
        .expect("cached import reads")
        .expect("cache entry exists");
    assert!(
        cached
            .ir
            .facts
            .as_slice()
            .iter()
            .any(|facts| *facts != crate::compile::ExprFacts::conservative()),
        "import analysis should persist non-conservative facts"
    );

    let mut second = TreeWalk::with_options(&ir, options);
    assert_eq!(
        second
            .eval_root()
            .expect("cached import evaluates")
            .as_int()
            .expect("cached result is int"),
        4
    );
    assert_eq!(second.import_parse_cache_stats(), (1, 0));
    assert!(
        second.stats().thunks_elided() > 0,
        "cached analyzed import should preserve lowering facts"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn ordinary_filesystem_import_persists_refreshed_analysis_facts() {
    use crate::cache::ParseCache;

    let root = fs::canonicalize(unique_temp_dir("import-persist-parse-cache-analysis"))
        .expect("temp directory canonicalizes");
    let first_parse_root = root.join("first-parse");
    let second_parse_root = root.join("second-parse");
    let persist_root = root.join("persist");
    let source = b"(x: x + 1) (1 + 2)";
    fs::write(root.join("dep.nix"), source).expect("dep writes");
    let ir = lower("import ./dep.nix");

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    first_options.set_parse_cache_root(&first_parse_root);
    first_options.set_persist_cache_root(&persist_root);

    let mut first = TreeWalk::with_options(&ir, first_options);
    assert_eq!(
        first
            .eval_root()
            .expect("first import evaluates")
            .as_int()
            .expect("first result is int"),
        4
    );
    assert_eq!(first.import_parse_cache_stats(), (0, 1));
    assert!(
        first.stats().thunks_elided() > 0,
        "first analyzed import should elide a strict thunk"
    );

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    second_options.set_parse_cache_root(&second_parse_root);
    second_options.set_persist_cache_root(&persist_root);

    let mut second = TreeWalk::with_options(&ir, second_options);
    assert_eq!(
        second
            .eval_root()
            .expect("persistent cached import evaluates")
            .as_int()
            .expect("persistent cached result is int"),
        4
    );
    assert_eq!(second.import_parse_cache_stats(), (1, 0));
    assert!(
        second.stats().thunks_elided() > 0,
        "persistent analyzed import should preserve refreshed facts"
    );

    let cached = ParseCache::new(&second_parse_root)
        .load_cached_bytes(source)
        .expect("persistent hydrated import reads")
        .expect("persistent hydrated cache entry exists");
    assert!(
        cached
            .ir
            .facts
            .as_slice()
            .iter()
            .any(|facts| *facts != crate::compile::ExprFacts::conservative()),
        "persistent hydrated import should carry non-conservative facts"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn ordinary_filesystem_import_uses_persistent_parse_cache_index() {
    use crate::cache::{MaterializationDecision, ParseCache, ParseFileKey, PersistCache};

    let root = fs::canonicalize(unique_temp_dir("import-persist-parse-cache"))
        .expect("temp directory canonicalizes");
    let seed_parse_root = root.join("seed-parse");
    let runtime_parse_root = root.join("runtime-parse");
    let persist_root = root.join("persist");
    let dep_path = root.join("dep.nix");
    let source = b"{ zOnly = 41; }";
    fs::write(&dep_path, source).expect("dep writes");
    let realpath = fs::canonicalize(&dep_path).expect("dep canonicalizes");
    let seed_parse = ParseCache::new(&seed_parse_root);
    let parsed = seed_parse
        .load_or_parse_bytes(source, Some(realpath.to_string_lossy().into_owned()))
        .expect("seed source parses");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    let file_key = ParseFileKey::for_source(&realpath, source);
    persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("seed parse artifact materializes");
    fs::remove_dir_all(&seed_parse_root).expect("seed parse cache removes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&runtime_parse_root);
    options.set_persist_cache_root(&persist_root);
    let ir = lower(r#"builtins.concatStringsSep "," (builtins.attrNames (import ./dep.nix))"#);

    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator
        .eval_root()
        .expect("persistent cached import evaluates");
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("attrNames result concatenates to string");

    assert_eq!(string.bytes(), b"zOnly");
    assert_eq!(evaluator.import_parse_cache_stats(), (1, 0));
    assert!(
        ParseCache::new(&runtime_parse_root)
            .entry_for_source(source)
            .is_complete(),
        "persistent hit should hydrate the runtime parse-cache entry"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn ordinary_filesystem_import_falls_back_after_persistent_parse_cache_miss() {
    use crate::cache::{ParseCache, PersistCache};

    let root = fs::canonicalize(unique_temp_dir("import-persist-parse-cache-miss"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    let persist_root = root.join("persist");
    let source = b"{ zOnly = 41; }";
    fs::write(root.join("dep.nix"), source).expect("dep writes");
    PersistCache::open(&persist_root).expect("empty persistent cache opens");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    options.set_persist_cache_root(&persist_root);
    let ir = lower(r#"builtins.concatStringsSep "," (builtins.attrNames (import ./dep.nix))"#);

    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator
        .eval_root()
        .expect("persistent miss falls back to parsing");
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("attrNames result concatenates to string");

    assert_eq!(string.bytes(), b"zOnly");
    assert_eq!(evaluator.import_parse_cache_stats(), (0, 1));
    assert!(
        ParseCache::new(&cache_root)
            .entry_for_source(source)
            .is_complete(),
        "persistent miss should keep the ordinary parse-cache write path"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn ordinary_filesystem_import_materializes_persistent_parse_cache_after_fallback() {
    use crate::cache::{ParseCache, PersistCache};

    let root = fs::canonicalize(unique_temp_dir("import-persist-parse-cache-writeback"))
        .expect("temp directory canonicalizes");
    let first_parse_root = root.join("first-parse");
    let second_parse_root = root.join("second-parse");
    let persist_root = root.join("persist");
    let source = b"{ zOnly = 41; }";
    fs::write(root.join("dep.nix"), source).expect("dep writes");
    PersistCache::open(&persist_root).expect("empty persistent cache opens");

    let mut first_options = TreeWalkOptions::new();
    first_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    first_options.set_parse_cache_root(&first_parse_root);
    first_options.set_persist_cache_root(&persist_root);
    let ir = lower(r#"builtins.concatStringsSep "," (builtins.attrNames (import ./dep.nix))"#);

    let mut first = TreeWalk::with_options(&ir, first_options);
    let first_value = first
        .eval_root()
        .expect("persistent miss falls back to parsing");
    let first_string = first
        .heap()
        .get_string(first_value)
        .expect("attrNames result concatenates to string");
    assert_eq!(first_string.bytes(), b"zOnly");
    assert_eq!(first.import_parse_cache_stats(), (0, 1));

    let mut second_options = TreeWalkOptions::new();
    second_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    second_options.set_parse_cache_root(&second_parse_root);
    second_options.set_persist_cache_root(&persist_root);
    let mut second = TreeWalk::with_options(&ir, second_options);
    let second_value = second
        .eval_root()
        .expect("persistent writeback feeds later import");
    let second_string = second
        .heap()
        .get_string(second_value)
        .expect("attrNames result concatenates to string");

    assert_eq!(second_string.bytes(), b"zOnly");
    assert_eq!(second.import_parse_cache_stats(), (1, 0));
    assert!(
        ParseCache::new(&second_parse_root)
            .entry_for_source(source)
            .is_complete(),
        "durable writeback should hydrate the later runtime parse-cache entry"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn ordinary_filesystem_import_ignores_persistent_parse_cache_writeback_errors() {
    use crate::cache::{ParseCache, PersistCache};

    let root = fs::canonicalize(unique_temp_dir("import-persist-parse-cache-write-error"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    let persist_root = root.join("persist");
    let source = b"{ zOnly = 41; }";
    fs::write(root.join("dep.nix"), source).expect("dep writes");
    let persist = PersistCache::open(&persist_root).expect("persistent cache opens");
    let file_index_path = persist.file_index().path().to_path_buf();

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    options.set_persist_cache_root(&persist_root);
    let ir = lower(r#"builtins.concatStringsSep "," (builtins.attrNames (import ./dep.nix))"#);

    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.persist_cache = Some(persist);
    evaluator.persist_cache_open_attempted = true;
    fs::remove_file(file_index_path.as_path()).expect("file index removes");
    fs::create_dir(file_index_path.as_path()).expect("file index path becomes directory");

    let value = evaluator
        .eval_root()
        .expect("persistent writeback failure stays advisory");
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("attrNames result concatenates to string");

    assert_eq!(string.bytes(), b"zOnly");
    assert_eq!(evaluator.import_parse_cache_stats(), (0, 1));
    assert!(
        ParseCache::new(&cache_root)
            .entry_for_source(source)
            .is_complete(),
        "ordinary parse-cache write should survive persistent writeback failure"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn ordinary_filesystem_import_falls_back_after_stale_persistent_parse_cache_hit() {
    use crate::cache::{
        PERSIST_BLOB_PACK_HEADER_LEN, ParseCache, ParseFileKey, PersistBlobLocation, PersistCache,
        PersistFileArtifactIndexEntry, PersistFileArtifactIndexValue, PersistFileArtifactKey,
        PersistFileBlobHash,
    };

    let root = fs::canonicalize(unique_temp_dir("import-persist-parse-cache-stale-hit"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    let persist_root = root.join("persist");
    let source = b"{ zOnly = 41; }";
    let dep_path = root.join("dep.nix");
    fs::write(&dep_path, source).expect("dep writes");
    let realpath = fs::canonicalize(&dep_path).expect("dep canonicalizes");
    let parse_cache = ParseCache::new(&cache_root);
    let parse_key = parse_cache.key_for_source(source);
    let file_key = ParseFileKey::for_source(&realpath, source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let stale_value = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"missing artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
    );
    PersistCache::open(&persist_root)
        .expect("persistent cache opens")
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            artifact_key,
            stale_value,
        ))
        .expect("stale mapping records");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    options.set_persist_cache_root(&persist_root);
    let ir = lower(r#"builtins.concatStringsSep "," (builtins.attrNames (import ./dep.nix))"#);

    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator
        .eval_root()
        .expect("stale persistent hit falls back to parsing");
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("attrNames result concatenates to string");

    assert_eq!(string.bytes(), b"zOnly");
    assert_eq!(evaluator.import_parse_cache_stats(), (0, 1));
    assert!(
        parse_cache.entry_for_source(source).is_complete(),
        "stale persistent hit should keep the ordinary parse-cache write path"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn ordinary_filesystem_import_does_not_open_persist_cache_without_parse_cache() {
    let root = fs::canonicalize(unique_temp_dir("import-persist-without-parse-cache"))
        .expect("temp directory canonicalizes");
    let persist_root = root.join("persist");
    fs::write(root.join("dep.nix"), b"{ zOnly = 41; }").expect("dep writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_persist_cache_root(&persist_root);
    let ir = lower(r#"builtins.concatStringsSep "," (builtins.attrNames (import ./dep.nix))"#);

    let mut evaluator = TreeWalk::with_options(&ir, options);
    assert!(
        !persist_root.exists(),
        "constructing the evaluator should not open the persistent cache"
    );
    let value = evaluator
        .eval_root()
        .expect("import without parse-cache root evaluates");
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("attrNames result concatenates to string");

    assert_eq!(string.bytes(), b"zOnly");
    assert!(!persist_root.exists());
    assert_eq!(evaluator.import_parse_cache_stats(), (0, 0));

    fs::remove_dir_all(root).expect("temp directory removes");
}

