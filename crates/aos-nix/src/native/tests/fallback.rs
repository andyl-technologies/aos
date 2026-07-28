//! Tests that CLI-sensitive instantiation inputs stay fallback-eligible.

use super::*;

#[test]
fn native_instantiation_search_path_stays_fallback_eligible() -> Result<()> {
    let native = NixNative::new(0)?;

    for (source, expected) in [
        ("<nixpkgs>", "configured Nix search path lookup"),
        ("builtins.nixPath", "builtins.nixPath"),
        ("let b = builtins; in b.nixPath", "builtins.nixPath"),
        (r#"builtins.${"nixPath"}"#, "builtins.nixPath"),
        ("with builtins; nixPath", "builtins.nixPath"),
    ] {
        let error = native
            .instantiate_expr(source)
            .expect_err("search-path-sensitive instantiation should fall back");
        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                    if feature.contains(expected)
            ),
            "unexpected error for {source:?}: {error:?}"
        );
    }

    let dir = unique_temp_dir("aos-nix-native-instantiate-search-path");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(&file, r#"{ pkgs.hello = <nixpkgs>; }"#)?;

    let error = native
        .instantiate(&file, "pkgs.hello")
        .expect_err("file-backed search-path instantiation should fall back");
    let _ = fs::remove_dir_all(&dir);

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, .. })
                if feature.contains("configured Nix search path lookup")
        ),
        "unexpected error: {error:?}"
    );

    let configured_dir = unique_temp_dir("aos-nix-native-raw-configured-search-path");
    fs::create_dir_all(configured_dir.join("source"))?;
    let mut configured_options = TreeWalkOptions::new();
    configured_options.add_nix_path_entry(
        b"pkg".to_vec(),
        configured_dir.as_os_str().as_bytes().to_vec(),
    )?;
    let configured = NixNative::with_options(0, configured_options)?;
    let error = configured
        .instantiate_expr(
            r#"derivationStrict {
              name = "raw-configured-search-path";
              system = "x86_64-linux";
              builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
              args = [ <pkg/source> ];
            }"#,
        )
        .expect_err("raw expression search-path instantiation should still fall back");
    let _ = fs::remove_dir_all(&configured_dir);

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, .. })
                if feature.contains("configured Nix search path lookup")
        ),
        "unexpected raw expression configured search-path error: {error:?}"
    );

    let error = native
        .instantiate_expr(
            r#"builtins.findFile [ { path = "/definitely-missing-aos-nix"; } ] "missing""#,
        )
        .expect_err("explicit findFile misses are semantic eval errors");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { .. })
        ),
        "unexpected explicit findFile error: {error:?}"
    );
    Ok(())
}

#[test]
fn pure_native_instantiation_catches_missing_ambient_search_path() -> Result<()> {
    let root = unique_temp_dir("aos-nix-pure-missing-search-path");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_eval_mode(ratchet_oracle::eval::EvalMode::Pure);
    let pure = NixNative::with_options(0, options)?;
    let drv = pure.instantiate_expr(
        r#"derivationStrict {
          name = "pure-missing-search-path";
          system = "x86_64-linux";
          builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          args = [
            (if (builtins.tryEval <nixpkgs-overlays>).success
             then "unexpected"
             else "missing")
          ];
        }"#,
    )?;

    assert!(
        drv.to_string_lossy()
            .ends_with("-pure-missing-search-path.drv")
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_impure_builtin_constants_stay_fallback_eligible() -> Result<()> {
    let native = NixNative::new(0)?;

    for source in [
        "builtins.currentTime",
        "builtins.currentTime or 42",
        "builtins.currentSystem",
        "builtins ? currentTime",
        "builtins ? currentSystem",
        r#"builtins.${"currentTime"}"#,
    ] {
        let error = native
            .instantiate_expr(source)
            .expect_err("CLI-sensitive impure constants should fall back");
        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                    if feature.contains("CLI-sensitive builtin evaluation")
            ),
            "unexpected error for {source:?}: {error:?}"
        );
    }

    let configured_system = NixNative::with_options(
        0,
        TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())?,
    )?;
    let error = configured_system
        .instantiate_expr("builtins.currentSystem")
        .expect_err("configured currentSystem is evaluated natively, then rejected as non-drv");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { .. })
        ),
        "unexpected configured currentSystem error: {error:?}"
    );

    let mut pure_options = TreeWalkOptions::new();
    pure_options.set_eval_mode(EvalMode::Pure);
    let pure = NixNative::with_options(0, pure_options)?;
    let error = pure
        .instantiate_expr("builtins.currentTime or 42")
        .expect_err("pure currentTime remains a native semantic result");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { .. })
        ),
        "unexpected pure currentTime error: {error:?}"
    );

    let error = native
        .instantiate_expr("builtins.length.foo or 42")
        .expect_err("unrelated static builtins paths should stay semantic");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { .. })
        ),
        "unexpected unrelated static builtins path error: {error:?}"
    );
    Ok(())
}

#[test]
fn native_instantiation_imported_impure_constants_stay_fallback_eligible() -> Result<()> {
    let dir = unique_temp_dir("native-instantiation-impure-import");
    fs::create_dir_all(&dir)?;
    let file = dir.join("default.nix");
    fs::write(
        &file,
        r#"{
          pkgs.hello = derivationStrict {
            name = "base";
            system = builtins.currentSystem;
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs.alias = let b = builtins; in derivationStrict {
            name = "alias";
            system = b.currentSystem;
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
          pkgs.dynamic = let name = "currentSystem"; in derivationStrict {
            name = "dynamic";
            system = builtins.${name};
            builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
          };
        }"#,
    )?;
    let native = NixNative::new(0)?;

    for attr in ["pkgs.hello", "pkgs.alias", "pkgs.dynamic"] {
        let error = native
            .instantiate(&file, attr)
            .expect_err("file-backed impure constants should fall back");
        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { feature, .. })
                    if feature.contains("CLI-sensitive builtin evaluation")
            ),
            "unexpected file-backed error for {attr}: {error:?}"
        );
    }

    let file_literal = nix_string_literal(file.as_os_str().as_bytes())?;
    let error = native
        .instantiate_expr(&format!("(import {file_literal}).pkgs.hello"))
        .expect_err("expression import impure constants should fall back");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                if feature.contains("CLI-sensitive builtin evaluation")
        ),
        "unexpected expression import error: {error:?}"
    );

    let error = native
        .instantiate_expr(&format!(
            "(builtins.scopedImport {{ }} {file_literal}).pkgs.hello"
        ))
        .expect_err("scoped import impure constants should fall back");
    let _ = fs::remove_dir_all(&dir);

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                if feature.contains("CLI-sensitive builtin evaluation")
        ),
        "unexpected scoped import error: {error:?}"
    );
    Ok(())
}
