//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn parse_cached_import_remaps_formal_and_inherit_symbols() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-symbols"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    fs::write(
        root.join("dep.nix"),
        br#"let
                 hidden = 7;
                 f = args@{ a ? hidden, ... }: a;
               in { inherit hidden f; }"#,
    )
    .expect("dep writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    let ir = lower(
        r#"let imported = import ./dep.nix;
               in (builtins.getAttr "f" imported) {} + builtins.getAttr "hidden" imported"#,
    );

    let mut first = TreeWalk::with_options(&ir, options.clone());
    assert_eq!(
        first
            .eval_root()
            .expect("first import evaluates")
            .as_int()
            .expect("first result is int"),
        14
    );
    assert_eq!(first.import_parse_cache_stats(), (0, 1));

    let mut second = TreeWalk::with_options(&ir, options);
    assert_eq!(
        second
            .eval_root()
            .expect("cached import evaluates")
            .as_int()
            .expect("cached result is int"),
        14
    );
    assert_eq!(second.import_parse_cache_stats(), (1, 0));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn parse_cached_import_remap_preserves_analysis_facts() {
    let mut imported = lower("let x = 1; in x");
    let root = imported.root;
    let expected = crate::compile::ExprFacts {
        strictness: crate::compile::Strictness::DemandedBeforeEffect,
        cardinality: crate::compile::Cardinality::Once,
        escape: crate::compile::Escape::NoEscape,
    };
    *imported.facts.get_mut(root).expect("root fact exists") = expected;

    let mut evaluator = TreeWalk::new(&lower("null"));
    let remapped = evaluator
        .remap_cached_import_ir(IrId::new(0), Span::new(0, 1), b"/dep.nix", imported)
        .expect("cached import IR remaps");

    assert_eq!(remapped.node_facts(root), Some(expected));
}

#[test]
fn parse_cached_import_remaps_search_path_literal_symbol() {
    let imported = lower("let __nixPath = []; in <nix/fetchurl.nix>");
    let mut evaluator =
        TreeWalk::new(&lower("{ getFlake = 1; currentSystem = 2; shifted = 3; }"));
    let remapped = evaluator
        .remap_cached_import_ir(IrId::new(0), Span::new(0, 1), b"/dep.nix", imported)
        .expect("cached import IR remaps");

    let literal = remapped
        .arena
        .nodes()
        .iter()
        .find_map(|node| match node.data {
            IrData::SearchPath { literal, .. } => Some(literal),
            _ => None,
        })
        .expect("cached import contains a search-path literal");
    assert_eq!(
        evaluator.symbols.resolve(literal),
        Some(b"<nix/fetchurl.nix>".as_slice())
    );
}

#[test]
fn parse_cached_import_evaluates_search_path_literal_after_symbol_shift() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-search-path"))
        .expect("temp directory canonicalizes");
    let package = root.join("package");
    fs::create_dir(&package).expect("search-path package creates");
    fs::write(package.join("target"), b"target").expect("search-path target writes");
    fs::write(root.join("dep.nix"), b"<pkg/target>").expect("dep writes");

    let mut options = search_path_options(b"pkg", &package);
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(root.join("cache"));
    let ir = lower("let getFlake = 1; in import ./dep.nix");

    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator.eval_root().expect("cached import evaluates");
    assert_eq!(
        path_value_bytes(&evaluator, value),
        package.join("target").as_os_str().as_bytes()
    );
    assert_eq!(evaluator.import_parse_cache_stats(), (0, 1));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn try_eval_caught_import_failure_keeps_symbol_table_intact() {
    // The live symbol table must survive a failed import that `builtins.tryEval`
    // catches: the imported file parses (its symbols are adopted into the live
    // table) and then throws, so evaluation continues and later attribute
    // lookups (`good.freshA`, `good.freshB`) still resolve against that table.
    let root = fs::canonicalize(unique_temp_dir("import-tryeval-symbols"))
        .expect("temp dir canonicalizes");
    // A file that parses and interns its own symbols, then throws at evaluation.
    fs::write(
        root.join("bad.nix"),
        b"let boomSym = 1; in builtins.throw \"boom\"",
    )
    .expect("bad import writes");
    // A file whose symbols are interned only after the failed import is caught.
    fs::write(root.join("good.nix"), b"{ freshA = 3; freshB = 4; }").expect("good import writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let ir = lower(concat!(
        "let caught = ! (builtins.tryEval (import ./bad.nix)).success;\n",
        "    good = import ./good.nix;\n",
        "in (if caught then 7 else 0) + good.freshA + good.freshB"
    ));

    let mut evaluator = TreeWalk::with_options(&ir, options);
    assert_eq!(
        evaluator
            .eval_root()
            .expect("evaluation continues past the caught import failure")
            .as_int()
            .expect("result is int"),
        14
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn parse_cached_import_remaps_lowered_builtin_symbols() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-builtins"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    fs::write(
        root.join("dep.nix"),
        br#"let f = builtins.length; in builtins.add (f [ 1 2 3 ]) 4"#,
    )
    .expect("dep writes");

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
        7
    );
    assert_eq!(first.import_parse_cache_stats(), (0, 1));

    let mut second = TreeWalk::with_options(&ir, options);
    assert_eq!(
        second
            .eval_root()
            .expect("cached import evaluates")
            .as_int()
            .expect("cached result is int"),
        7
    );
    assert_eq!(second.import_parse_cache_stats(), (1, 0));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn parse_cached_import_remaps_with_var_symbols() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-with-var"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    fs::write(root.join("dep.nix"), br#"with { x = 41; }; x + 1"#).expect("dep writes");

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
        42
    );
    assert_eq!(first.import_parse_cache_stats(), (0, 1));

    let mut second = TreeWalk::with_options(&ir, options);
    assert_eq!(
        second
            .eval_root()
            .expect("cached import evaluates")
            .as_int()
            .expect("cached result is int"),
        42
    );
    assert_eq!(second.import_parse_cache_stats(), (1, 0));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn parse_cached_imports_keep_module_relative_path_bases() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-bases"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    let first_dir = root.join("first");
    let second_dir = root.join("second");
    fs::create_dir(&first_dir).expect("first dir creates");
    fs::create_dir(&second_dir).expect("second dir creates");
    fs::write(first_dir.join("dep.nix"), b"./data.txt").expect("first dep writes");
    fs::write(second_dir.join("dep.nix"), b"./data.txt").expect("second dep writes");
    fs::write(first_dir.join("data.txt"), b"first").expect("first data writes");
    fs::write(second_dir.join("data.txt"), b"second").expect("second data writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);
    let ir = lower(
        r#"builtins.toString (import ./first/dep.nix)
               + "|"
               + builtins.toString (import ./second/dep.nix)"#,
    );
    let mut evaluator = TreeWalk::with_options(&ir, options);
    let value = evaluator.eval_root().expect("imports evaluate");
    let string = evaluator
        .heap()
        .get_string(value)
        .expect("result is a string");
    let expected = format!(
        "{}|{}",
        first_dir.join("data.txt").display(),
        second_dir.join("data.txt").display()
    );
    assert_eq!(string.bytes(), expected.as_bytes());
    assert_eq!(evaluator.import_parse_cache_stats(), (1, 1));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn parse_cached_imports_keep_symlinked_requested_path_bases() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-symlink-base"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
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
    options.set_parse_cache_root(&cache_root);
    let ir = lower("import ./symlink-resolution/foo/overlays/overlay.nix");

    let mut first = TreeWalk::with_options(&ir, options.clone());
    let first_value = first.eval_root().expect("first import evaluates");
    let first_string = first
        .heap()
        .get_string(first_value)
        .expect("first result is a string");
    assert_eq!(first_string.bytes(), b"test");
    assert_eq!(first.import_parse_cache_stats(), (0, 2));

    let mut second = TreeWalk::with_options(&ir, options);
    let second_value = second.eval_root().expect("cached import evaluates");
    let second_string = second
        .heap()
        .get_string(second_value)
        .expect("cached result is a string");
    assert_eq!(second_string.bytes(), b"test");
    assert_eq!(second.import_parse_cache_stats(), (2, 0));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn parse_cache_does_not_capture_scoped_or_text_store_imports() {
    let root = fs::canonicalize(unique_temp_dir("import-parse-cache-bypass"))
        .expect("temp directory canonicalizes");
    let cache_root = root.join("cache");
    fs::write(root.join("scoped.nix"), b"secret").expect("scoped import writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    options.set_parse_cache_root(&cache_root);

    let scoped_ir = lower("builtins.scopedImport { secret = 9; } ./scoped.nix");
    let mut scoped = TreeWalk::with_options(&scoped_ir, options.clone());
    assert_eq!(
        scoped
            .eval_root()
            .expect("scoped import evaluates")
            .as_int()
            .expect("scoped result is int"),
        9
    );
    assert_eq!(scoped.import_parse_cache_stats(), (0, 0));

    let text_store_ir = lower(r#"let p = builtins.toFile "generated.nix" "3"; in import p"#);
    let mut text_store = TreeWalk::with_options(&text_store_ir, options);
    assert_eq!(
        text_store
            .eval_root()
            .expect("text-store import evaluates")
            .as_int()
            .expect("text-store result is int"),
        3
    );
    assert_eq!(text_store.import_parse_cache_stats(), (0, 0));
    assert!(
        !cache_root.exists(),
        "bypassed imports should not create parse-cache artifacts"
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}
