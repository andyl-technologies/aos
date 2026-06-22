//! Tree-walk evaluator tests: search path.

use super::*;

#[test]
fn scoped_import_injects_globals_and_bypasses_result_cache() {
    let root =
        fs::canonicalize(unique_temp_dir("scoped-import")).expect("temp directory canonicalizes");
    let dir_import = root.join("dir");
    fs::create_dir(&dir_import).expect("import directory creates");
    fs::write(root.join("value.nix"), b"x").expect("value writes");
    fs::write(root.join("shadow-builtins.nix"), b"builtins.add 1 2")
        .expect("shadow builtins writes");
    fs::write(root.join("lambda.nix"), b"y: secret + y").expect("lambda writes");
    fs::write(root.join("shadow-import.nix"), b"import ./nested.nix")
        .expect("shadow import writes");
    fs::write(root.join("nested.nix"), b"secret").expect("nested writes");
    fs::write(root.join("true.nix"), b"true").expect("true writes");
    fs::write(root.join("false.nix"), b"false").expect("false writes");
    fs::write(root.join("null.nix"), b"null").expect("null writes");
    fs::write(root.join("trace.nix"), br#"builtins.trace "scoped" 1"#).expect("trace writes");
    fs::write(dir_import.join("default.nix"), b"x").expect("default writes");

    let mut options = TreeWalkOptions::new();
    options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");

    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { x = 7; } ./value.nix",
            options.clone()
        )
        .as_int()
        .expect("scoped global is int"),
        7
    );
    assert_eq!(
        eval_with_options("builtins.scopedImport { x = 8; } ./dir", options.clone())
            .as_int()
            .expect("scoped directory import is int"),
        8
    );
    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { builtins = { add = a: b: 10; }; } ./shadow-builtins.nix",
            options.clone(),
        )
        .as_int()
        .expect("scoped builtins shadow is int"),
        10
    );
    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { import = path: 42; } ./shadow-import.nix",
            options.clone(),
        )
        .as_int()
        .expect("scoped import shadow is int"),
        42
    );
    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { true = 1; false = 2; null = 3; } ./true.nix",
            options.clone(),
        )
        .as_int()
        .expect("scoped true shadow is int"),
        1
    );
    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { true = 1; false = 2; null = 3; } ./false.nix",
            options.clone(),
        )
        .as_int()
        .expect("scoped false shadow is int"),
        2
    );
    assert_eq!(
        eval_with_options(
            "builtins.scopedImport { true = 1; false = 2; null = 3; } ./null.nix",
            options.clone(),
        )
        .as_int()
        .expect("scoped null shadow is int"),
        3
    );
    assert_eq!(
        eval_with_options(
            "(builtins.scopedImport { secret = 5; } ./lambda.nix) 2",
            options.clone(),
        )
        .as_int()
        .expect("escaped lambda sees scoped globals"),
        7
    );
    assert_eq!(
        eval_with_options(
            "let f = builtins.scopedImport { x = 11; }; in f ./value.nix",
            options.clone(),
        )
        .as_int()
        .expect("partially applied scopedImport evaluates"),
        11
    );

    let traced = eval_whnf_owned_with_options(
        &lower(
            "builtins.deepSeq [
                  (builtins.scopedImport {} ./trace.nix)
                  (builtins.scopedImport {} ./trace.nix)
                ] 0",
        ),
        options.clone(),
    )
    .expect("scoped imports evaluate");
    assert_eq!(traced.value().as_int().expect("trace result is int"), 0);
    assert_eq!(traced.trace_output().len(), 2);
    for trace in traced.trace_output() {
        assert_trace_output(trace, EvalTraceKind::Trace, b"scoped");
    }

    let plain_inner = eval_whnf_owned_with_options(
        &lower("builtins.scopedImport { secret = 9; } ./shadow-import.nix"),
        options,
    )
    .expect_err("plain import inside scopedImport does not inherit scoped globals");
    assert!(matches!(
        plain_inner.kind(),
        TreeWalkErrorKind::ImportScope { .. } | TreeWalkErrorKind::UnresolvedWithVar { .. }
    ));

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn nix_path_value_reflects_configured_search_path() {
    let (root, nixpkgs, _subdir) = search_path_fixture();
    let options = search_path_options(b"nixpkgs", &nixpkgs);

    let actual = eval_string_bytes_with_options("builtins.toJSON builtins.nixPath", options);
    let expected = format!(
        r#"[{{"path":{},"prefix":"nixpkgs"}}]"#,
        nix_string_literal(&path_source(&nixpkgs))
    );
    assert_eq!(actual, expected.into_bytes());

    let options = relative_search_path_options(&root, b"nixpkgs", b"nixpkgs/./");
    let actual = eval_string_bytes_with_options("builtins.toJSON builtins.nixPath", options);
    assert_eq!(
        actual,
        br#"[{"path":"nixpkgs/./","prefix":"nixpkgs"}]"#.to_vec()
    );
}

#[test]
fn find_file_and_search_path_return_path_values() {
    let (root, nixpkgs, subdir) = search_path_fixture();
    let prefixed = search_path_options(b"nixpkgs", &nixpkgs);
    let bare = search_path_options(b"", &root);
    let expected = path_source(&subdir);

    for (source, options) in [
        (
            r#"let p = builtins.findFile builtins.nixPath "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
            prefixed.clone(),
        ),
        (
            r#"let f = builtins.findFile; g = f builtins.nixPath; p = g "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
            prefixed.clone(),
        ),
        (
            r#"let p = <nixpkgs/subdir>; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
            prefixed,
        ),
        (
            r#"let p = builtins.findFile builtins.nixPath "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
            bare,
        ),
    ] {
        let actual = eval_json_bytes_with_options(source, options);
        let expected_json = format!(r#"["path",{}]"#, nix_string_literal(&expected));
        assert_eq!(
            actual,
            expected_json.into_bytes(),
            "source diverged: {source}"
        );
    }
}

#[test]
fn find_file_accepts_missing_prefix_and_relative_entries() {
    let (root, nixpkgs, subdir) = search_path_fixture();
    let expected = path_source(&subdir);

    for (source, options) in [
            (
                format!(
                    r#"let p = builtins.findFile [ {{ path = {}; }} ] "subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#,
                    nix_string_literal(&path_source(&nixpkgs))
                ),
                TreeWalkOptions::new(),
            ),
            (
                r#"let p = builtins.findFile [ { path = "nixpkgs"; prefix = "nixpkgs"; } ] "nixpkgs/subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#.to_owned(),
                TreeWalkOptions::with_search_path_base(root.as_os_str().as_bytes().to_vec())
                    .expect("search-path base is absolute"),
            ),
            (
                r#"let p = builtins.findFile [ { path = "nixpkgs"; } ] "subdir"; in [ (builtins.typeOf p) (builtins.toString p) ]"#.to_owned(),
                TreeWalkOptions::with_search_path_base(root.as_os_str().as_bytes().to_vec())
                    .expect("search-path base is absolute"),
            ),
            (
                r#"let p = <nixpkgs/subdir>; in [ (builtins.typeOf p) (builtins.toString p) ]"#.to_owned(),
                relative_search_path_options(&root, b"nixpkgs", b"nixpkgs"),
            ),
        ] {
            let actual = eval_json_bytes_with_options(&source, options);
            let expected_json = format!(r#"["path",{}]"#, nix_string_literal(&expected));
            assert_eq!(
                actual,
                expected_json.into_bytes(),
                "source diverged: {source}"
            );
        }
}

#[test]
fn search_path_lookup_uses_configured_order_and_fallback() {
    let root = unique_temp_dir("search-path-order");
    let first = root.join("first");
    let second = root.join("second");
    let empty = root.join("empty");
    let first_subdir = first.join("subdir");
    let second_subdir = second.join("subdir");
    fs::create_dir_all(&first_subdir).expect("first search path hit creates");
    fs::create_dir_all(&second_subdir).expect("second search path hit creates");
    fs::create_dir(&empty).expect("empty search path entry creates");

    let mut ordered = TreeWalkOptions::new();
    ordered
        .add_nix_path_entry(b"nixpkgs".to_vec(), path_bytes(&first))
        .expect("first search-path entry configures");
    ordered
        .add_nix_path_entry(b"nixpkgs".to_vec(), path_bytes(&second))
        .expect("second search-path entry configures");
    assert_eq!(
        eval_string_bytes_with_options("builtins.toString <nixpkgs>", ordered.clone()),
        path_bytes(&first)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            r#"builtins.toString (builtins.findFile builtins.nixPath "nixpkgs")"#,
            ordered.clone()
        ),
        path_bytes(&first)
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.toString <nixpkgs/subdir>", ordered.clone()),
        path_bytes(&first_subdir)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            r#"builtins.toString (builtins.findFile builtins.nixPath "nixpkgs/subdir")"#,
            ordered
        ),
        path_bytes(&first_subdir)
    );

    let mut fallback = TreeWalkOptions::new();
    fallback
        .add_nix_path_entry(b"nixpkgs".to_vec(), path_bytes(&empty))
        .expect("empty search-path entry configures");
    fallback
        .add_nix_path_entry(b"nixpkgs".to_vec(), path_bytes(&second))
        .expect("fallback search-path entry configures");
    assert_eq!(
        eval_string_bytes_with_options("builtins.toString <nixpkgs>", fallback.clone()),
        path_bytes(&empty)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            r#"builtins.toString (builtins.findFile builtins.nixPath "nixpkgs")"#,
            fallback.clone()
        ),
        path_bytes(&empty)
    );
    assert_eq!(
        eval_string_bytes_with_options("builtins.toString <nixpkgs/subdir>", fallback.clone()),
        path_bytes(&second_subdir)
    );
    assert_eq!(
        eval_string_bytes_with_options(
            r#"builtins.toString (builtins.findFile builtins.nixPath "nixpkgs/subdir")"#,
            fallback
        ),
        path_bytes(&second_subdir)
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn find_file_reports_exhausted_search_path() {
    let (_root, nixpkgs, _subdir) = search_path_fixture();
    let options = search_path_options(b"nixpkgs", &nixpkgs);
    let ir = lower(r#"builtins.findFile builtins.nixPath "nixpkgs/missing""#);
    let error = eval_whnf_owned_with_options(&ir, options)
        .expect_err("missing search-path lookup is rejected");

    assert_search_path_not_found(error, b"nixpkgs/missing");
}

#[test]
fn pure_eval_hides_configured_search_path_from_nix_path_and_angle_lookup() {
    let (_root, nixpkgs, subdir) = search_path_fixture();
    let mut hidden_options = search_path_options(b"nixpkgs", &nixpkgs);
    hidden_options
        .add_allowed_path(path_bytes(&nixpkgs))
        .expect("search path configures as allowed");
    hidden_options.set_eval_mode(EvalMode::Pure);

    assert_eq!(
        eval_string_bytes_with_options("builtins.toJSON builtins.nixPath", hidden_options.clone()),
        b"[]".to_vec()
    );

    let search_path = lower(r#"<nixpkgs/subdir>"#);
    let error = eval_whnf_owned_with_options(&search_path, hidden_options)
        .expect_err("pure eval hides configured angle-bracket search paths");
    assert_search_path_not_found(error, b"nixpkgs/subdir");

    let explicit_options = TreeWalkOptions::with_eval_mode(EvalMode::Pure);
    let explicit = format!(
        r#"builtins.toString (builtins.findFile [ {{ path = {}; prefix = "nixpkgs"; }} ] "nixpkgs/subdir")"#,
        nix_string_literal(&path_source(&nixpkgs))
    );
    assert_eq!(
        eval_string_bytes_with_options(&explicit, explicit_options.clone()),
        path_bytes(&subdir)
    );

    let default_nix = nixpkgs.join("default.nix");
    let default_nix_bytes = path_bytes(&default_nix);
    let read = format!(
        r#"builtins.readFile (builtins.findFile [ {{ path = {}; prefix = "nixpkgs"; }} ] "nixpkgs/default.nix")"#,
        nix_string_literal(&path_source(&nixpkgs))
    );
    let error = eval_whnf_owned_with_options(&lower(&read), explicit_options)
        .expect_err("pure eval still denies later filesystem reads");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied { path, mode: EvalMode::Pure, .. }
            if path.as_slice() == default_nix_bytes.as_slice()
    ));
}

#[test]
fn find_file_caches_successful_lookup_results() {
    let (_root, nixpkgs, subdir) = search_path_fixture();
    let ir = lower("0");
    let mut evaluator = TreeWalk::new(&ir);
    let entries = vec![resolved_search_path_entry(b"nixpkgs", &nixpkgs)];
    let lookup = b"nixpkgs/subdir";
    let span = Span::new(0, 0);

    let first = evaluator
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect("initial search-path lookup finds existing directory");
    assert_eq!(path_value_bytes(&evaluator, first), path_bytes(&subdir));

    fs::remove_dir(&subdir).expect("fixture subdir removes");

    let cached = evaluator
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect("cached search-path hit survives filesystem mutation");
    assert_eq!(path_value_bytes(&evaluator, cached), path_bytes(&subdir));

    let mut fresh = TreeWalk::new(&ir);
    let error = fresh
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect_err("fresh evaluator observes removed directory");
    assert_search_path_not_found(error, lookup);
}

#[test]
fn find_file_caches_exhausted_lookup_results() {
    let (_root, nixpkgs, _subdir) = search_path_fixture();
    let ir = lower("0");
    let mut evaluator = TreeWalk::new(&ir);
    let entries = vec![resolved_search_path_entry(b"nixpkgs", &nixpkgs)];
    let lookup = b"nixpkgs/later";
    let later = nixpkgs.join("later");
    let span = Span::new(0, 0);

    let first = evaluator
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect_err("initial missing search-path lookup is rejected");
    assert_search_path_not_found(first, lookup);

    fs::create_dir(&later).expect("late fixture directory creates");

    let cached = evaluator
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect_err("cached search-path miss survives filesystem mutation");
    assert_search_path_not_found(cached, lookup);

    let mut fresh = TreeWalk::new(&ir);
    let found = fresh
        .find_file_in_entries(
            ir.root,
            span,
            &entries,
            lookup,
            FindFileLookupOrigin::ExplicitSearchPath,
        )
        .expect("fresh evaluator observes late directory");
    assert_eq!(path_value_bytes(&fresh, found), path_bytes(&later));
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_find_file_and_search_path_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_find_file_and_search_path_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_find_file_and_search_path_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix findFile check");
        return;
    };
    assert_cpp_nix_find_file_and_search_path_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_json_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_json_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_json_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix JSON check");
        return;
    };
    assert_cpp_nix_json_builtins_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_xml_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_xml_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_xml_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix XML check");
        return;
    };
    assert_cpp_nix_xml_builtins_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_from_toml_builtin_matches_tree_walk() {
    let oracle = cpp_nix_oracle();
    let version = cpp_nix_version(&oracle);
    assert!(
        version.contains("(Nix) 2.24."),
        "expected a C++ Nix 2.24.x oracle, got {version}"
    );
    eprintln!("C++ Nix oracle: {version}");

    for source in [
        r#"builtins.fromTOML """#,
        r#"builtins.fromTOML ''
                a = 1
                b = 1.5
                c = true
                d = "x"
                e = [1, "x", true, [2]]

                [owner]
                name = "Tom"
            ''"#,
        r#"builtins.fromTOML ''
                [[fruit]]
                name = "apple"
                [[fruit]]
                name = "banana"
            ''"#,
        r#"builtins.fromTOML ''
                positive = 9223372036854775808
                negative = -9223372036854775809
                hex = 0x8000000000000000
                octal = 0o1000000000000000000000
                binary_min = 0b1000000000000000000000000000000000000000000000000000000000000000
                binary_minus_one = 0b1111111111111111111111111111111111111111111111111111111111111111
                binary_wrapped = 0b10000000000000000000000000000000000000000000000000000000000000000
            ''"#,
        r#"builtins.fromTOML ''
                [9223372036854775808]
                value = "key"
            ''"#,
        r#"builtins.fromTOML ''
                "a.b" = 1
                a.b = 2
            ''"#,
        r#"builtins.fromTOML ''
                pos_inf = inf
                neg_inf = -inf
                nan = nan
            ''"#,
        r#"builtins.fromTOML ''
                positive = 1e999
                positive_signed = +1e999
                negative = -1e999
                fraction = 1.0e999
            ''"#,
        r#"let f = builtins.fromTOML; in f "a = 1""#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(&oracle, source);
    }

    for source in [
        r#"builtins.fromTOML "a = null""#,
        r#"builtins.fromTOML "a = 1979-05-27T07:32:00Z""#,
        r#"builtins.fromTOML "a = 1979-05-27""#,
        r#"builtins.fromTOML "a = 07:32:00""#,
        r#"builtins.fromTOML "a = 09223372036854775808""#,
        r#"builtins.fromTOML "a = -09223372036854775809""#,
        r#"builtins.fromTOML "a = 0_9223372036854775808""#,
        r#"builtins.fromTOML "a = +0x8000000000000000""#,
        r#"builtins.fromTOML "a = 01e999""#,
        r#"builtins.fromTOML "a = 1_e999""#,
        r#"builtins.fromTOML "a = +01e999""#,
        "builtins.fromTOML \"a = 1\na = 2\"",
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(&oracle, source);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_hash_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_hash_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_hash_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix hash check");
        return;
    };
    assert_cpp_nix_hash_builtins_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_flake_ref_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_flake_ref_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_flake_ref_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix flake-ref check");
        return;
    };
    assert_cpp_nix_flake_ref_builtins_match_tree_walk(&oracle);
}
