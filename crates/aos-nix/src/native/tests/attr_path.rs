//! Tests for file-backed `-A` attribute-path instantiation and selector parsing.

use super::*;

#[test]
fn native_instantiation_imports_file_attr_path() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          pkgs.hello = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let path = native.instantiate(&file, "pkgs.hello")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-base.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_imports_directory_default_file() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate-dir")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join("default.nix"),
        r#"{
          pkgs.hello = derivationStrict {
            name = "dir-default";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let path = native.instantiate(&dir, "pkgs.hello")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-dir-default.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_restricted_mode_rejects_unallowed_root_file_before_parse() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-instantiate-restricted-denied");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let file = root.join("default.nix");
    fs::write(&file, b"let { body = 1; }")?;
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_eval_mode(EvalMode::Restricted);
    let native = NixNative::with_options(0, options)?;

    let error = native
        .instantiate(&file, "")
        .expect_err("restricted mode should reject unallowed root files before parsing");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("restricted path policy should surface as a native eval error: {error:?}");
    };
    assert!(
        message.contains("Restricted evaluation forbids filesystem access"),
        "{message}"
    );
    assert!(
        message.contains(&file.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(
        !message.contains("native expression parse failure"),
        "{message}"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_restricted_mode_accepts_allowed_directory_root_file() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-instantiate-restricted-allowed");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join("default.nix"),
        r#"{
          pkgs.hello = derivationStrict {
            name = "restricted-allowed";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_eval_mode(EvalMode::Restricted);
    options.add_allowed_path(root.as_os_str().as_bytes().to_vec())?;
    let native = NixNative::with_options(0, options)?;

    let path = native.instantiate(&dir, "pkgs.hello")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-restricted-allowed.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_empty_attr_path_selects_root() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate-empty-attr")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"derivationStrict {
          name = "root";
          system = "x86_64-linux";
          builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        }"#,
    )?;

    let path = native.instantiate(&file, "")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-root.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_reports_parse_errors_with_source() -> Result<()> {
    let (native, root, _store) = native_with_temp_store("aos-nix-native-instantiate-parse-error")?;
    let file = root.join("default.nix");
    fs::write(&file, b"let { body = 1; }")?;

    let error = native
        .instantiate(&file, "")
        .expect_err("file parse errors should stay fallback-eligible");

    let Some(NativeEvalError::Unsupported { feature, .. }) =
        error.downcast_ref::<NativeEvalError>()
    else {
        panic!("parse errors should surface as unsupported fallback errors: {error:?}");
    };
    assert!(
        feature.contains("native expression parse failure"),
        "{feature}"
    );
    assert!(feature.contains("aos_nix::parse::"), "{feature}");
    assert!(
        feature.contains(&file.to_string_lossy().to_string()),
        "{feature}"
    );
    assert!(feature.contains("let { body = 1; }"), "{feature}");
    assert!(!feature.contains("import "), "{feature}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_reports_imported_parse_cache_errors_with_source() -> Result<()> {
    let root = unique_temp_dir("aos-nix-native-instantiate-imported-parse-cache-error");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_parse_cache_root(root.join("parse-cache"));
    let native = NixNative::with_options(0, options)?;
    let file = root.join("default.nix");
    let child = root.join("child.nix");
    fs::write(&file, b"{ broken = import ./child.nix; }")?;
    fs::write(&child, b"let { body = 1; }")?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("imported parse errors should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("imported parse error should surface as a native eval error: {error:?}");
    };
    assert!(
        message.contains("failed to parse imported file"),
        "{message}"
    );
    assert!(
        message.contains(&child.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(message.contains("let { body = 1; }"), "{message}");
    assert!(!message.contains("import ./child.nix"), "{message}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_reports_imported_scope_errors_with_source() -> Result<()> {
    let (native, root, _store) =
        native_with_temp_store("aos-nix-native-instantiate-imported-scope-error")?;
    let file = root.join("default.nix");
    let child = root.join("child.nix");
    fs::write(&file, b"{ broken = import ./child.nix; }")?;
    fs::write(&child, b"missingImportedName")?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("imported scope errors should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("imported scope error should surface as a native eval error: {error:?}");
    };
    assert!(
        message.contains("failed to resolve imported file"),
        "{message}"
    );
    assert!(
        message.contains(&child.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(message.contains("missingImportedName"), "{message}");
    assert!(!message.contains("import ./child.nix"), "{message}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_reports_tree_walk_errors_with_source() -> Result<()> {
    let (native, root, _store) = native_with_temp_store("aos-nix-native-instantiate-eval-error")?;
    let file = root.join("default.nix");
    fs::write(&file, b"{ broken = 1 + true; }")?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("file tree-walk errors should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("type error should surface as a native eval error: {error:?}");
    };
    assert!(message.contains("type error"), "{message}");
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(
        message.contains(&file.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(message.contains("1 + true"), "{message}");
    assert!(!message.contains("import "), "{message}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_reports_imported_tree_walk_errors_with_source() -> Result<()> {
    let (native, root, _store) =
        native_with_temp_store("aos-nix-native-instantiate-imported-eval-error")?;
    let file = root.join("default.nix");
    let child = root.join("child.nix");
    fs::write(&file, b"{ broken = import ./child.nix; }")?;
    fs::write(&child, b"1 + true")?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("imported tree-walk errors should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("imported type error should surface as a native eval error: {error:?}");
    };
    assert!(message.contains("type error"), "{message}");
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(
        message.contains(&child.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(message.contains("1 + true"), "{message}");
    assert!(!message.contains("import ./child.nix"), "{message}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_reports_imported_context_labels_with_source() -> Result<()> {
    let (native, root, _store) =
        native_with_temp_store("aos-nix-native-instantiate-imported-eval-context")?;
    let file = root.join("default.nix");
    let child = root.join("child.nix");
    fs::write(&file, b"{ broken = import ./child.nix; }")?;
    fs::write(
        &child,
        br#"builtins.addErrorContext "child context" (1 + true)"#,
    )?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("imported tree-walk errors with child contexts should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("imported type error should surface as a native eval error: {error:?}");
    };
    assert!(
        message.contains("while evaluating: child context"),
        "{message}"
    );
    assert!(message.contains("type error"), "{message}");
    assert!(
        message.contains(&child.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(message.contains("1 + true"), "{message}");
    assert!(message.contains("child context"), "{message}");
    assert!(!message.contains("import ./child.nix"), "{message}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_file_instantiation_does_not_render_non_utf8_imported_errors_against_root() -> Result<()> {
    let (native, root, _store) =
        native_with_temp_store("aos-nix-native-instantiate-imported-non-utf8-eval-error")?;
    let file = root.join("default.nix");
    let child = root.join("child.nix");
    fs::write(&file, b"{ broken = import ./child.nix; }")?;
    fs::write(&child, b"1 + true # \xff\n")?;

    let error = native
        .instantiate(&file, "broken")
        .expect_err("non-UTF8 imported tree-walk errors should not instantiate");

    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("imported type error should surface as a native eval error: {error:?}");
    };
    assert!(message.contains("type error"), "{message}");
    assert!(
        !message.contains(&file.to_string_lossy().to_string()),
        "{message}"
    );
    assert!(!message.contains("import ./child.nix"), "{message}");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_accepts_quoted_attr_path_segments() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate-quoted")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          "pkgs.with.dot".hello = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."hello\${name}" = derivationStrict {
            name = "literal-interpolation";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."hello\\\${name}" = derivationStrict {
            name = "escaped-interpolation";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."concat.with.dot" = derivationStrict {
            name = "concat";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."weird/key+ name;let" = derivationStrict {
            name = "weird";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let path = native.instantiate(&file, r#""pkgs.with.dot".hello"#)?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-base.drv"));
    let _ = assert_materialized_drv(&path)?;

    let literal_interpolation = native.instantiate(&file, r#"pkgs."hello${name}""#)?;
    assert!(
        literal_interpolation
            .to_string_lossy()
            .ends_with("-literal-interpolation.drv")
    );
    let _ = assert_materialized_drv(&literal_interpolation)?;

    let escaped_interpolation = native.instantiate(&file, r#"pkgs."hello\${name}""#)?;
    assert!(
        escaped_interpolation
            .to_string_lossy()
            .ends_with("-escaped-interpolation.drv")
    );
    let _ = assert_materialized_drv(&escaped_interpolation)?;

    let concatenated = native.instantiate(&file, r#"pkgs.concat"."with"."dot"#)?;
    assert!(concatenated.to_string_lossy().ends_with("-concat.drv"));
    let _ = assert_materialized_drv(&concatenated)?;

    let weird = native.instantiate(&file, "pkgs.weird/key+ name;let")?;
    assert!(weird.to_string_lossy().ends_with("-weird.drv"));
    let _ = assert_materialized_drv(&weird)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_auto_calls_function_files_with_default_arguments() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate-function")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{ system ? "x86_64-linux" }: {
          pkgs.hello = derivationStrict {
            name = "base";
            inherit system;
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let path = native.instantiate(&file, "pkgs.hello")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-base.drv"));
    let materialized = assert_materialized_drv(&path)?;

    let closure = native.instantiate_closure(&file, "pkgs.hello")?;
    assert_eq!(closure.root(), path);
    assert_eq!(closure.drvs().len(), 1);
    assert_eq!(
        closure
            .drvs()
            .get(closure.root())
            .expect("function-file root derivation bytes are recorded"),
        &materialized,
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_auto_calls_formal_set_functions_along_attr_path() -> Result<()> {
    let (native, root, store) =
        native_with_temp_store("aos-nix-native-instantiate-nested-function")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          pkgs = { variant ? "nested" }: {
            hello = { suffix ? variant }: derivationStrict {
              name = suffix;
              system = "x86_64-linux";
              builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
            };
          };
        }"#,
    )?;

    let path = native.instantiate(&file, "pkgs.hello")?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-nested.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_selection_path_indexes_lists() -> Result<()> {
    let (native, root, store) = native_with_temp_store("aos-nix-native-instantiate-list-index")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          pkgs = [
            {
              hello = derivationStrict {
                name = "first";
                system = "x86_64-linux";
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              };
            }
            {
              hello = derivationStrict {
                name = "second";
                system = "x86_64-linux";
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              };
            }
          ];
        }"#,
    )?;

    let first = native.instantiate(&file, "pkgs.0.hello")?;
    assert!(first.starts_with(&store), "{}", first.display());
    assert!(first.to_string_lossy().ends_with("-first.drv"));
    let _ = assert_materialized_drv(&first)?;

    let second = native.instantiate(&file, r#"pkgs."01".hello"#)?;
    assert!(second.starts_with(&store), "{}", second.display());
    assert!(second.to_string_lossy().ends_with("-second.drv"));
    let _ = assert_materialized_drv(&second)?;

    let error = native
        .instantiate(&file, "pkgs.2.hello")
        .expect_err("out-of-range selection-path list indexes should fail");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message })
                if message.contains("list index 2 out of bounds")
        ),
        "unexpected error: {error:?}"
    );

    let error = native
        .instantiate(&file, "pkgs.4294967295.hello")
        .expect_err("u32::MAX selection-path list indexes should still be indexes");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message })
                if message.contains("list index 4294967295 out of bounds")
        ),
        "unexpected error: {error:?}"
    );

    let error = native
        .instantiate(&file, "pkgs.4294967296.hello")
        .expect_err("u32::MAX + 1 selection-path segments should be attribute names");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message }) if message.contains("expected attrs")
        ),
        "unexpected error: {error:?}"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_numeric_selection_segments_require_lists() -> Result<()> {
    let (native, root, _store) = native_with_temp_store("aos-nix-native-instantiate-numeric-attr")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          pkgs."0".hello = derivationStrict {
            name = "numeric-attr";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."4294967295".hello = derivationStrict {
            name = "max-u32-attr";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs."4294967296".hello = derivationStrict {
            name = "u32-overflow-attr";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let error = native
        .instantiate(&file, "pkgs.0.hello")
        .expect_err("numeric selection-path segments should require list values");

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message }) if message.contains("expected list")
        ),
        "unexpected error: {error:?}"
    );

    let error = native
        .instantiate(&file, "pkgs.4294967295.hello")
        .expect_err("u32::MAX numeric selection-path segments should require list values");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message }) if message.contains("expected list")
        ),
        "unexpected error: {error:?}"
    );

    let path = native.instantiate(&file, "pkgs.4294967296.hello")?;
    assert!(path.to_string_lossy().ends_with("-u32-overflow-attr.drv"));
    let _ = assert_materialized_drv(&path)?;

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_does_not_auto_call_selected_drv_path_value() -> Result<()> {
    let (native, root, _store) =
        native_with_temp_store("aos-nix-native-instantiate-callable-drv-path")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"let
          real = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        in {
          pkgs.hello.drvPath = { }: real.drvPath;
        }"#,
    )?;

    let error = native
        .instantiate(&file, "pkgs.hello")
        .expect_err("native -A traversal must not auto-call the selected drvPath value");

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message })
                if message.contains("did not produce a string drvPath")
        ),
        "unexpected error: {error:?}"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_does_not_auto_call_plain_lambda_files() -> Result<()> {
    let (native, root, _store) = native_with_temp_store("aos-nix-native-instantiate-plain-lambda")?;
    let dir = root.join("src");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"x: {
          pkgs.hello = derivationStrict {
            name = "base";
            system = "x86_64-linux";
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;

    let error = native
        .instantiate(&file, "pkgs.hello")
        .expect_err("plain lambdas should not be auto-called by native -A traversal");

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { .. })
        ),
        "unexpected error: {error:?}"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_attr_path_selector_matches_selection_path_syntax() -> Result<()> {
    for attr in [
        ".pkgs",
        ".",
        "pkgs..",
        "pkgs..hello",
        r#"pkgs."".hello"#,
        r#"pkgs.""."#,
    ] {
        let error = attr_path_selector(attr).expect_err("invalid attr path should fail");
        assert!(matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { .. })
        ));
    }

    assert_eq!(attr_path_selector("")?, "");
    assert_eq!(attr_path_selector(r#""""#)?, "");
    assert_eq!(attr_path_selector("pkgs.")?, r#"."pkgs""#);
    assert_eq!(attr_path_selector(r#"pkgs."""#)?, r#"."pkgs""#);
    assert_eq!(
        attr_path_selector("or.foo-bar.x'")?,
        r#"."or"."foo-bar"."x'""#
    );
    assert_eq!(
        attr_path_selector("let.a/b+ c;hello")?,
        r#"."let"."a/b+ c;hello""#
    );
    assert_eq!(attr_path_selector(r#"a"."b"#)?, r#"."a.b""#);
    assert_eq!(attr_path_selector("\"\"a")?, r#"."a""#);
    assert_eq!(
        attr_path_selector(r#""pkgs.with.dot".hello"#)?,
        r#"."pkgs.with.dot"."hello""#
    );
    Ok(())
}

#[test]
fn native_instantiation_string_literals_escape_interpolation_openers() -> Result<()> {
    assert_eq!(nix_string_literal(b"/tmp/${name}")?, r#""/tmp/\${name}""#);
    assert_eq!(
        parse_attr_path_segments(r#""a${b}".hello"#)?,
        vec![b"a${b}".to_vec(), b"hello".to_vec()]
    );
    assert_eq!(
        parse_attr_path_segments(r#""a\${b}".hello"#)?,
        vec![b"a\\${b}".to_vec(), b"hello".to_vec()]
    );
    assert_eq!(
        parse_attr_path_segments(r#""a\n".hello"#)?,
        vec![b"a\\n".to_vec(), b"hello".to_vec()]
    );
    Ok(())
}
