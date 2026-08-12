//! Tests for source-labelled native file instantiation diagnostics.

use super::*;

const PARSE_ERROR_SOURCE: &str = "let x = ; in x";

#[test]
fn native_file_instantiation_reports_parse_errors_with_source() -> Result<()> {
    let (native, root, _store) = native_with_temp_store("aos-nix-native-instantiate-parse-error")?;
    let file = root.join("default.nix");
    fs::write(&file, PARSE_ERROR_SOURCE.as_bytes())?;

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
    assert!(feature.contains(PARSE_ERROR_SOURCE), "{feature}");
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
    fs::write(&child, PARSE_ERROR_SOURCE.as_bytes())?;

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
    assert!(message.contains(PARSE_ERROR_SOURCE), "{message}");
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
