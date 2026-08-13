//! Split-out `attr_path.rs` test group (split).

use super::*;

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
