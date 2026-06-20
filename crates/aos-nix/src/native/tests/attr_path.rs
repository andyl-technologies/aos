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
