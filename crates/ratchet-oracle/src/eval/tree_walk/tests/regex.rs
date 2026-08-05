//! Tree-walk evaluator tests: regex.

use super::*;

// Some recursive conformance cases exercise the Rust tree-walk harness deeply
// before reaching the intended max-call-depth assertion.
const CPP_NIX_RECURSION_TEST_STACK_SIZE: usize = 32 * 1024 * 1024;

fn run_cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk(oracle: String) {
    let handle = std::thread::Builder::new()
        .name("cpp-nix-recursion-oracle".to_owned())
        .stack_size(CPP_NIX_RECURSION_TEST_STACK_SIZE)
        .spawn(move || assert_cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk(&oracle))
        .expect("C++ Nix recursion oracle worker spawns");

    if let Err(payload) = handle.join() {
        std::panic::resume_unwind(payload);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_number_printing_matches_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_number_printing_matches_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_number_printing_matches_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix number printing check");
        return;
    };
    assert_cpp_nix_number_printing_matches_tree_walk(&oracle);
}

#[test]
fn number_raw_renderer_formats_integer_and_float_values() {
    for (source, expected) in [
        ("1", b"1".as_slice()),
        ("(-2)", b"-2"),
        ("9223372036854775807", b"9223372036854775807"),
        ("(-9223372036854775807 - 1)", b"-9223372036854775808"),
        ("1.0", b"1"),
        ("1.25", b"1.25"),
        ("1.23456789", b"1.23457"),
        ("(-0.0)", b"0"),
        ("0.0001", b"0.0001"),
        ("0.00001", b"1e-05"),
        ("100000.0", b"100000"),
        ("1000000.0", b"1e+06"),
        ("((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))", b"nan"),
        ("(1.0e308 * 1.0e308)", b"inf"),
        ("(builtins.sub 0.0 (1.0e308 * 1.0e308))", b"-inf"),
    ] {
        assert_eq!(
            eval_number_raw_bytes(&lower(source)).as_deref(),
            Ok(expected),
            "{source}"
        );
    }

    let ir = lower(r#""x""#);
    let error = eval_number_raw_bytes(&ir).expect_err("raw number renderer rejects strings");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::Type {
            id: ir.root,
            expected: "number",
            actual: ValueTag::String,
        }
    );
}

#[test]
#[ignore = "requires AOS_NIX_ORACLE to point at pinned nix-instantiate 2.24.12"]
fn pinned_cpp_nix_builtin_surface_matches_registry() {
    let oracle = cpp_nix_oracle();
    assert_pinned_cpp_nix_builtin_surface_matches_registry(&oracle);
}

#[test]
fn configured_pinned_cpp_nix_builtin_surface_matches_registry() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix surface check");
        return;
    };
    assert_pinned_cpp_nix_builtin_surface_matches_registry(&oracle);
}

#[test]
#[ignore = "requires AOS_NIX_ORACLE to point at pinned nix-instantiate 2.24.12"]
fn pinned_present_unimplemented_builtin_stubs_match_registry() {
    let oracle = cpp_nix_oracle();
    assert_pinned_present_unimplemented_builtin_stubs_match_registry(&oracle);
}

#[test]
fn configured_pinned_present_unimplemented_builtin_stubs_match_registry() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!(
            "AOS_NIX_ORACLE not set; skipping configured C++ Nix unimplemented builtin stub check"
        );
        return;
    };
    assert_pinned_present_unimplemented_builtin_stubs_match_registry(&oracle);
}

#[test]
#[ignore = "requires AOS_NIX_ORACLE to point at pinned nix-instantiate 2.24.12"]
fn pinned_absent_experimental_builtin_attrs_match_registry() {
    let oracle = cpp_nix_oracle();
    assert_pinned_absent_experimental_builtin_attrs_match_registry(&oracle);
}

#[test]
fn configured_pinned_absent_experimental_builtin_attrs_match_registry() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!(
            "AOS_NIX_ORACLE not set; skipping configured C++ Nix absent experimental builtin check"
        );
        return;
    };
    assert_pinned_absent_experimental_builtin_attrs_match_registry(&oracle);
}

#[test]
#[ignore = "requires AOS_NIX_ORACLE to point at pinned nix-instantiate 2.24.12"]
fn cpp_nix_identity_constants_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_identity_constants_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_identity_constants_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix oracle check");
        return;
    };
    assert_cpp_nix_identity_constants_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_control_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_control_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_control_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix control check");
        return;
    };
    assert_cpp_nix_control_builtins_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_attrset_builtin_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_attrset_builtin_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_attrset_builtin_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix attrset check");
        return;
    };
    assert_cpp_nix_attrset_builtin_semantics_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_type_predicates_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    let version = cpp_nix_version(&oracle);
    assert!(
        version.contains("(Nix) 2.24."),
        "expected a C++ Nix 2.24.x oracle, got {version}"
    );
    eprintln!("C++ Nix oracle: {version}");

    for source in [
        "builtins.isAttrs { a = 1; }",
        "builtins.isAttrs [ 1 ]",
        "builtins.isList [ 1 ]",
        "builtins.isFunction (x: x)",
        "builtins.isFunction builtins.length",
        "builtins.isFunction (builtins.map (x: x))",
        "builtins.isString \"x\"",
        "builtins.isInt 1",
        "builtins.isInt 1.0",
        "builtins.isFloat 1.0",
        "builtins.isFloat 1",
        "builtins.isBool false",
        "builtins.isNull null",
        "builtins.isPath /tmp",
        "builtins.isPath \"not-path\"",
        "builtins.typeOf 1",
        "builtins.typeOf 1.0",
        "builtins.typeOf false",
        "builtins.typeOf null",
        "builtins.typeOf \"x\"",
        "builtins.typeOf /tmp",
        "builtins.typeOf [ 1 ]",
        "builtins.typeOf { a = 1; }",
        "builtins.typeOf (x: x)",
        "builtins.typeOf builtins.length",
        "builtins.typeOf (builtins.map (x: x))",
    ] {
        assert_cpp_nix_json_matches_tree_walk(&oracle, source);
    }
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_equality_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_equality_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_equality_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix equality check");
        return;
    };
    assert_cpp_nix_equality_semantics_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_comparison_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_comparison_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_comparison_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix comparison check");
        return;
    };
    assert_cpp_nix_comparison_semantics_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_function_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_function_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_function_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix function check");
        return;
    };
    assert_cpp_nix_function_semantics_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    run_cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk(oracle);
}

#[test]
fn configured_cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix recursion check");
        return;
    };
    run_cpp_nix_recursion_and_fixed_point_semantics_match_tree_walk(oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_numeric_and_ordering_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_numeric_and_ordering_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_numeric_and_ordering_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix numeric check");
        return;
    };
    assert_cpp_nix_numeric_and_ordering_builtins_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_language_operators_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_language_operators_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_language_operators_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix operator check");
        return;
    };
    assert_cpp_nix_language_operators_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_sort_and_less_than_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_sort_and_less_than_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_sort_and_less_than_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix sort check");
        return;
    };
    assert_cpp_nix_sort_and_less_than_builtins_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_laziness_and_evaluation_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_laziness_and_evaluation_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_laziness_and_evaluation_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix laziness check");
        return;
    };
    assert_cpp_nix_laziness_and_evaluation_semantics_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_let_with_scoping_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_let_with_scoping_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_let_with_scoping_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix let/with check");
        return;
    };
    assert_cpp_nix_let_with_scoping_semantics_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_control_flow_and_error_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_control_flow_and_error_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_control_flow_and_error_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix control/error check");
        return;
    };
    assert_cpp_nix_control_flow_and_error_semantics_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_error_classes_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_error_classes_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_error_classes_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix error-class check");
        return;
    };
    assert_cpp_nix_error_classes_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_import_semantics_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_import_semantics_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_import_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix import check");
        return;
    };
    assert_cpp_nix_import_semantics_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_string_context_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_string_context_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_string_context_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix string context check");
        return;
    };
    assert_cpp_nix_string_context_builtins_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_string_coercion_contexts_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_string_coercion_contexts_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_string_coercion_contexts_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix coercion check");
        return;
    };
    assert_cpp_nix_string_coercion_contexts_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_derivation_wrapper_matches_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_derivation_wrapper_matches_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_derivation_wrapper_matches_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix derivation wrapper check");
        return;
    };
    assert_cpp_nix_derivation_wrapper_matches_tree_walk(&oracle);
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_to_string_builtin_matches_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_to_string_builtin_matches_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_to_string_builtin_matches_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix toString check");
        return;
    };
    assert_cpp_nix_to_string_builtin_matches_tree_walk(&oracle);
}

#[test]
#[ignore = "requires a C++ Nix 2.24.x nix-instantiate oracle"]
fn cpp_nix_string_path_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_string_path_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_string_path_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix string/path check");
        return;
    };
    assert_cpp_nix_string_path_builtins_match_tree_walk(&oracle);
}

#[test]
#[ignore = "requires the pinned C++ Nix 2.24.12 nix-instantiate oracle"]
fn cpp_nix_filesystem_builtins_match_tree_walk() {
    let oracle = cpp_nix_oracle();
    assert_cpp_nix_filesystem_builtins_match_tree_walk(&oracle);
}

#[test]
fn configured_cpp_nix_filesystem_builtins_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix filesystem check");
        return;
    };
    assert_cpp_nix_filesystem_builtins_match_tree_walk(&oracle);
}

#[test]
fn filesystem_builtins_report_unsupported_ifd_without_realizer() {
    let root =
        fs::canonicalize(unique_temp_dir("ifd-unsupported")).expect("temp dir canonicalizes");
    let store = root.join("store");
    fs::create_dir(&store).expect("store dir creates");
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let file_path = output_path.join("data.txt");
    let source = format!(
        "builtins.readFile (builtins.appendContext {file} {{ {drv} = {{ outputs = [ \"out\" ]; }}; }})",
        file = nix_string_literal(&path_source(&file_path)),
        drv = nix_string_literal(&path_source(&drv_path)),
    );
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())
        .expect("store dir configures");

    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("IFD requires a realizer");
    let TreeWalkErrorKind::UnsupportedImportFromDerivation { op, detail, .. } = error.kind() else {
        panic!("unexpected error kind: {error:?}");
    };
    assert_eq!(op, "readFile");
    assert_eq!(detail.path(), file_path.as_os_str().as_bytes());
    assert_eq!(detail.drv_path(), drv_path.as_os_str().as_bytes());
    assert_eq!(detail.output_name(), Some(b"out".as_slice()));
    assert_eq!(detail.context_kind(), ContextKind::SingleOutput);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn filesystem_builtins_realize_ifd_context_before_reading_paths() {
    let root =
        fs::canonicalize(unique_temp_dir("ifd-realizer")).expect("temp directory canonicalizes");
    let store = root.join("store");
    fs::create_dir(&store).expect("store dir creates");
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let data_path = output_path.join("data.txt");
    let import_path = output_path.join("imported.nix");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_realizer = Arc::clone(&requests);
    let drv_path_for_realizer = drv_path.as_os_str().as_bytes().to_vec();
    let output_path_for_realizer = output_path.clone();
    let data_path_for_realizer = data_path.clone();
    let import_path_for_realizer = import_path.clone();
    let realizer = IfdRealizer::new(move |request| {
        if request.drv_path() != drv_path_for_realizer.as_slice() {
            return Err(IfdRealizationError::new("unexpected derivation path"));
        }
        if request.output_name() != Some(b"out".as_slice()) {
            return Err(IfdRealizationError::new("unexpected output name"));
        }
        requests_for_realizer
            .lock()
            .expect("request log lock")
            .push((
                request.path().to_vec(),
                request.op(),
                request.context_kind(),
                request.effect(),
            ));
        fs::create_dir_all(&output_path_for_realizer)
            .map_err(|source| IfdRealizationError::new(source.to_string()))?;
        fs::write(&data_path_for_realizer, b"hello")
            .map_err(|source| IfdRealizationError::new(source.to_string()))?;
        fs::write(&import_path_for_realizer, b"41")
            .map_err(|source| IfdRealizationError::new(source.to_string()))?;
        Ok(())
    });
    let source = format!(
        r#"let
                 ctx = {{ {drv} = {{ outputs = [ "out" ]; }}; }};
                 data = builtins.appendContext {data} ctx;
                 dir = builtins.appendContext {output} ctx;
                 imported = builtins.appendContext {imported} ctx;
                 copied = builtins.path {{ path = data; name = "ifd-copied"; recursive = false; }};
               in builtins.readFile data == "hello"
                  && builtins.elem "data.txt" (builtins.attrNames (builtins.readDir dir))
                  && builtins.pathExists data
                  && builtins.readFileType data == "regular"
                  && builtins.isString copied
                  && builtins.readFile data == "hello"
                  && import imported == 41"#,
        drv = nix_string_literal(&path_source(&drv_path)),
        data = nix_string_literal(&path_source(&data_path)),
        output = nix_string_literal(&path_source(&output_path)),
        imported = nix_string_literal(&path_source(&import_path)),
    );
    let ir = lower(&source);
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())
        .expect("store dir configures");
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.set_ifd_realizer(realizer);
    let value = evaluator
        .eval_root()
        .expect("IFD-backed filesystem reads evaluate");
    assert_eq!(value.as_bool().expect("result is bool"), true);

    let requests = requests.lock().expect("request log lock");
    assert!(requests.iter().any(|(_, op, _, _)| *op == "readFile"));
    assert!(requests.iter().any(|(_, op, _, _)| *op == "readDir"));
    assert!(requests.iter().any(|(_, op, _, _)| *op == "pathExists"));
    assert!(requests.iter().any(|(_, op, _, _)| *op == "readFileType"));
    assert!(requests.iter().any(|(_, op, _, _)| *op == "path"));
    assert!(requests.iter().any(|(_, op, _, _)| *op == "import"));
    assert_eq!(
        requests
            .iter()
            .filter(|(_, op, _, _)| *op == "readFile")
            .count(),
        2
    );
    assert!(
        requests
            .iter()
            .all(|(_, _, kind, _)| *kind == ContextKind::SingleOutput)
    );
    assert!(
        requests
            .iter()
            .all(|(_, _, _, effect)| *effect == aos_nix_dialect::NIX_EFFECT_IFD)
    );

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn denied_ifd_path_does_not_call_realizer() {
    let root = fs::canonicalize(unique_temp_dir("ifd-denied")).expect("temp dir canonicalizes");
    let store = root.join("store");
    fs::create_dir(&store).expect("store dir creates");
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let file_path = output_path.join("data.txt");
    let source = format!(
        "builtins.readFile (builtins.appendContext {file} {{ {drv} = {{ outputs = [ \"out\" ]; }}; }})",
        file = nix_string_literal(&path_source(&file_path)),
        drv = nix_string_literal(&path_source(&drv_path)),
    );
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())
        .expect("store dir configures");
    options.set_eval_mode(EvalMode::Restricted);
    let calls = Arc::new(AtomicU64::new(0));
    let calls_for_realizer = Arc::clone(&calls);
    let realizer = IfdRealizer::new(move |_| {
        calls_for_realizer.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let ir = lower(&source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.set_ifd_realizer(realizer);

    let error = evaluator
        .eval_root()
        .expect_err("restricted mode rejects before IFD realization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied { .. }
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn mixed_opaque_and_derivation_context_rejects_before_ifd_realizer() {
    let root = fs::canonicalize(unique_temp_dir("ifd-mixed")).expect("temp dir canonicalizes");
    let store = root.join("store");
    fs::create_dir(&store).expect("store dir creates");
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let opaque_path = store.join("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-source");
    let file_path = output_path.join("data.txt");
    let source = format!(
        "builtins.readFile (builtins.appendContext {file} {{ {drv} = {{ outputs = [ \"out\" ]; }}; {opaque} = {{ path = true; }}; }})",
        file = nix_string_literal(&path_source(&file_path)),
        drv = nix_string_literal(&path_source(&drv_path)),
        opaque = nix_string_literal(&path_source(&opaque_path)),
    );
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())
        .expect("store dir configures");
    let calls = Arc::new(AtomicU64::new(0));
    let calls_for_realizer = Arc::clone(&calls);
    let realizer = IfdRealizer::new(move |_| {
        calls_for_realizer.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let ir = lower(&source);
    let mut evaluator = TreeWalk::with_options(&ir, options);
    evaluator.set_ifd_realizer(realizer);

    let error = evaluator
        .eval_root()
        .expect_err("opaque context rejects before IFD realization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed { op: "readFile", .. }
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    fs::remove_dir_all(root).expect("temp directory removes");
}
