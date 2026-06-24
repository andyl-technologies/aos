//! Tests for raw-expression instantiation, in-memory `.drv` closures, and
//! store materialization.

use super::*;

const PARSE_ERROR_SOURCE: &str = "let x = ; in x";

#[test]
fn native_instantiation_expr_returns_drv_path() -> Result<()> {
    let (native, root, store) = native_with_temp_store("native-instantiation-expr")?;

    let path = native.instantiate_expr(
        r#"derivationStrict {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#,
    )?;

    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-base.drv"));
    let bytes = assert_materialized_drv(&path)?;
    assert!(bytes.starts_with(b"Derive("));

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_expr_uses_configured_parse_cache() -> Result<()> {
    let root = unique_temp_dir("native-instantiation-parse-cache");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    let cache_root = root.join("parse");
    let mut options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    options.set_parse_cache_root(&cache_root);
    let native = NixNative::with_options(0, options)?;
    let expr = r#"derivationStrict {
         name = "base";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
       }"#;

    let path = native.instantiate_expr(expr)?;

    assert!(path.starts_with(&store), "{}", path.display());
    let cache = ParseCache::new(&cache_root);
    let entry = cache.entry_for_source(derivation_path_wrapper_source(expr).as_bytes());
    assert!(
        entry.is_complete(),
        "native instantiation should populate the parse-cache entry"
    );

    let cached_path = native.instantiate_expr(expr)?;
    assert_eq!(cached_path, path);

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_reified_builtins_do_not_force_nix_path() -> Result<()> {
    let (native, root, store) = native_with_temp_store("native-reified-builtins")?;

    for source in [
        r#"let b = builtins; in b.derivationStrict {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#,
        r#"let b = builtins; in b.${"derivationStrict"} {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#,
        r#"with builtins; derivationStrict {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#,
    ] {
        let closure = native.instantiate_expr_closure(source)?;
        assert!(
            closure.root().starts_with(&store),
            "{}",
            closure.root().display()
        );
        assert!(closure.root().to_string_lossy().ends_with("-base.drv"));
    }

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_expr_returns_drv_closure_bytes() -> Result<()> {
    let native = NixNative::new(0)?;

    let closure = native.instantiate_expr_closure(
        r#"derivationStrict {
             name = "base";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }"#,
    )?;

    assert_eq!(
        closure.root(),
        Path::new("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv")
    );
    let root_bytes = closure
        .drvs()
        .get(closure.root())
        .expect("root derivation bytes are recorded");
    assert!(root_bytes.starts_with(b"Derive("));
    assert!(nix_compat::derivation::Derivation::from_aterm_bytes(root_bytes).is_ok());
    Ok(())
}

#[test]
fn native_instantiation_expr_closure_includes_input_derivation_bytes() -> Result<()> {
    let native = NixNative::new(0)?;

    let closure = native.instantiate_expr_closure(
        r#"let
             base = derivationStrict {
               name = "base";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
           in derivationStrict {
             name = "consumer";
             system = "x86_64-linux";
             builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
             input = "${base.out}";
           }"#,
    )?;

    let base = Path::new("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv");
    assert!(closure.drvs().contains_key(base));
    assert_eq!(closure.drvs().len(), 2);
    let root_bytes = closure
        .drvs()
        .get(closure.root())
        .expect("root derivation bytes are recorded");
    let root_text = std::str::from_utf8(root_bytes)?;
    assert!(root_text.contains("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv"));
    Ok(())
}

#[test]
fn native_instantiation_expr_materializes_input_drv_closure() -> Result<()> {
    let (native, root, store) = native_with_temp_store("native-materialized-closure")?;
    let expr = r#"let
         base = derivationStrict {
           name = "base";
           system = "x86_64-linux";
           builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
         };
       in derivationStrict {
         name = "consumer";
         system = "x86_64-linux";
         builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
         input = "${base.out}";
       }"#;

    let expected = native.instantiate_expr_closure(expr)?;
    assert_eq!(expected.drvs().len(), 2);
    assert!(expected.drvs().keys().all(|path| !path.exists()));

    let path = native.instantiate_expr(expr)?;

    assert_eq!(path, expected.root());
    assert!(path.starts_with(&store), "{}", path.display());
    for (path, expected_bytes) in expected.drvs() {
        let actual = assert_materialized_drv(path)?;
        assert_eq!(&actual, expected_bytes, "{}", path.display());
    }

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_refuses_conflicting_existing_drv() -> Result<()> {
    let (native, root, _store) = native_with_temp_store("native-conflicting-drv")?;
    let expr = r#"derivationStrict {
         name = "base";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
       }"#;
    let closure = native.instantiate_expr_closure(expr)?;
    let parent = closure
        .root()
        .parent()
        .ok_or_else(|| anyhow::anyhow!("root derivation path has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::write(closure.root(), b"not a derivation")?;

    let error = native
        .instantiate_expr(expr)
        .expect_err("conflicting derivation file must not be overwritten");

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Internal { message })
                if message.contains("refusing to overwrite existing derivation")
        ),
        "{error:?}"
    );
    assert_eq!(fs::read(closure.root())?, b"not a derivation");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_instantiation_expr_closure_supports_floating_ca_bytes() -> Result<()> {
    let (native, root, store) = native_with_temp_store("native-floating-ca")?;
    let expr = r#"derivationStrict {
         name = "ca";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
         __contentAddressed = true;
         outputHashAlgo = "sha256";
         outputHashMode = "recursive";
       }"#;

    let path = native.instantiate_expr(expr)?;
    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-ca.drv"));
    let materialized = assert_materialized_drv(&path)?;

    let closure = native.instantiate_expr_closure(expr)?;
    assert_eq!(closure.root(), path);
    let bytes = closure
        .drvs()
        .get(closure.root())
        .expect("floating CA root derivation bytes are recorded");
    let text = std::str::from_utf8(bytes)?;
    assert!(text.contains(r#""r:sha256""#));
    assert!(text.contains(r#"("out","","r:sha256","")"#));
    assert_eq!(&materialized, bytes);

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_path_instantiation_materializes_downstream_deferred_drv_bytes() -> Result<()> {
    let (native, root, store) = native_with_temp_store("native-deferred-drv")?;
    let expr = r#"let
         base = derivationStrict {
           name = "ca";
           system = "x86_64-linux";
           builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           __contentAddressed = true;
           outputHashAlgo = "sha256";
           outputHashMode = "recursive";
         };
       in derivationStrict {
         name = "consumer";
         system = "x86_64-linux";
         builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
         input = "${base.out}";
       }"#;

    let path = native.instantiate_expr(expr)?;
    assert!(path.starts_with(&store), "{}", path.display());
    assert!(path.to_string_lossy().ends_with("-consumer.drv"));

    let closure = native.instantiate_expr_closure(expr)?;
    assert_eq!(closure.root(), path);
    assert_eq!(closure.drvs().len(), 2);
    for (path, expected_bytes) in closure.drvs() {
        let actual = assert_materialized_drv(path)?;
        assert_eq!(&actual, expected_bytes, "{}", path.display());
    }

    let root_bytes = closure
        .drvs()
        .get(closure.root())
        .expect("deferred consumer root derivation bytes are recorded");
    let root_text = std::str::from_utf8(root_bytes)?;
    assert!(root_text.contains(r#"("out","/"#));
    assert!(!root_text.contains(r#"("out","","","")"#));
    assert!(!root_text.contains(r#"("out","")"#));
    assert_eq!(root_text.matches(r#"("out","/"#).count(), 2);
    let ca_drv = closure
        .drvs()
        .keys()
        .find(|path| path.to_string_lossy().ends_with("-ca.drv"))
        .expect("CA input derivation is recorded");
    assert!(root_text.contains(&ca_drv.display().to_string()));

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn configured_cpp_nix_native_drv_closure_bytes_match_cli() -> Result<()> {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping native drv byte oracle check");
        return Ok(());
    };
    let native = NixNative::new(0)?;
    let nonce = unique_store_name("native-drv-oracle");
    let base_name = format!("base-{nonce}");
    let consumer_name = format!("consumer-{nonce}");
    let ca_name = format!("ca-{nonce}");
    let ca_consumer_name = format!("ca-consumer-{nonce}");

    for expr in [
        format!(
            r#"derivationStrict {{
             name = "{base_name}";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
           }}"#
        ),
        format!(
            r#"let
             base = derivationStrict {{
               name = "{base_name}";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             }};
           in derivationStrict {{
             name = "{consumer_name}";
             system = "x86_64-linux";
             builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
             input = "${{base.out}}";
           }}"#
        ),
        format!(
            r#"derivationStrict {{
             name = "{ca_name}";
             system = "x86_64-linux";
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             __contentAddressed = true;
             outputHashAlgo = "sha256";
             outputHashMode = "recursive";
           }}"#
        ),
        format!(
            r#"let
             base = derivationStrict {{
               name = "{ca_name}";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             }};
           in derivationStrict {{
             name = "{ca_consumer_name}";
             system = "x86_64-linux";
             builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
             input = "${{base.out}}";
           }}"#
        ),
    ] {
        let closure = native.instantiate_expr_closure(&expr)?;
        let instantiate_output = Command::new(&oracle).args(["--expr", &expr]).output()?;
        if !instantiate_output.status.success()
            && String::from_utf8_lossy(&instantiate_output.stderr)
                .contains("experimental Nix feature")
        {
            eprintln!("configured C++ Nix oracle skipped experimental expression {expr:?}");
            continue;
        }
        assert!(
            instantiate_output.status.success(),
            "C++ Nix oracle unexpectedly rejected {expr:?}: {}",
            String::from_utf8_lossy(&instantiate_output.stderr)
        );

        for path in closure.drvs().keys() {
            assert!(
                path.exists(),
                "C++ Nix oracle did not materialize {} for {expr:?}",
                path.display()
            );
        }

        let source = derivation_path_wrapper_source(&expr);
        let output = Command::new(&oracle)
            .args(["--eval", "--strict", "--expr", &source])
            .output()?;
        if !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("experimental Nix feature")
        {
            eprintln!("configured C++ Nix oracle skipped experimental expression {expr:?}");
            continue;
        }
        assert!(
            output.status.success(),
            "C++ Nix oracle unexpectedly rejected {expr:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let root: String = serde_json::from_slice(&output.stdout)?;
        assert_eq!(closure.root(), Path::new(&root), "{expr}");

        for (path, bytes) in closure.drvs() {
            let expected = fs::read(path)?;
            assert_eq!(bytes, &expected, "{}", path.display());
        }
    }

    Ok(())
}

#[test]
fn native_instantiation_rejects_non_derivations() -> Result<()> {
    let native = NixNative::new(0)?;

    let error = native
        .instantiate_expr("1")
        .expect_err("non-derivations should not instantiate");

    assert!(matches!(
        error.downcast_ref::<NativeEvalError>(),
        Some(NativeEvalError::EvalError { .. })
    ));
    Ok(())
}

#[test]
fn native_instantiation_reports_tree_walk_errors_with_source() -> Result<()> {
    let native = NixNative::new(0)?;

    let materialized_error = native
        .instantiate_expr("1 + true")
        .expect_err("tree-walk semantic errors should not instantiate");
    assert_tree_walk_source_report(&materialized_error);

    let closure_error = native
        .instantiate_expr_closure("1 + true")
        .expect_err("tree-walk semantic errors should not produce closures");
    assert_tree_walk_source_report(&closure_error);
    Ok(())
}

fn assert_tree_walk_source_report(error: &anyhow::Error) {
    let Some(NativeEvalError::EvalError { message }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("type error should surface as a native eval error: {error:?}");
    };
    assert!(message.contains("type error"), "{message}");
    assert!(message.contains("aos_nix::eval::type"), "{message}");
    assert!(message.contains("expr.nix"), "{message}");
    assert!(message.contains("1 + true"), "{message}");
    assert!(!message.contains(".drvPath"), "{message}");
}

#[test]
fn native_instantiation_reports_parse_errors_with_source() -> Result<()> {
    let native = NixNative::new(0)?;

    let error = native
        .instantiate_expr(PARSE_ERROR_SOURCE)
        .expect_err("parse errors should stay fallback-eligible");

    let Some(NativeEvalError::Unsupported {
        feature,
        span: Some(_),
    }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("parse errors should surface as unsupported fallback errors: {error:?}");
    };
    assert!(
        feature.contains("native expression parse failure"),
        "{feature}"
    );
    assert!(feature.contains("aos_nix::parse::"), "{feature}");
    assert!(feature.contains("expr.nix"), "{feature}");
    assert!(feature.contains(PARSE_ERROR_SOURCE), "{feature}");
    assert!(!feature.contains(".drvPath"), "{feature}");
    Ok(())
}

#[test]
fn native_instantiation_reports_scope_errors_with_source() -> Result<()> {
    let native = NixNative::new(0)?;

    let error = native
        .instantiate_expr("let ${name} = 1; in 1")
        .expect_err("scope errors should stay fallback-eligible");

    let Some(NativeEvalError::Unsupported {
        feature,
        span: Some(_),
    }) = error.downcast_ref::<NativeEvalError>()
    else {
        panic!("scope errors should surface as unsupported fallback errors: {error:?}");
    };
    assert!(
        feature.contains("native expression resolve failure"),
        "{feature}"
    );
    assert!(
        feature.contains("aos_nix::resolve::dynamic_let_binding"),
        "{feature}"
    );
    assert!(feature.contains("expr.nix"), "{feature}");
    assert!(feature.contains("let ${name} = 1; in 1"), "{feature}");
    assert!(!feature.contains(".drvPath"), "{feature}");
    Ok(())
}

#[test]
fn native_instantiation_rejects_fabricated_drv_path_attrsets() -> Result<()> {
    let native = NixNative::new(0)?;

    let error = native
        .instantiate_expr(
            r#"{ drvPath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fake.drv"; }"#,
        )
        .expect_err("fabricated drvPath attrsets do not have native drv bytes");

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::EvalError { message })
                if message.contains("not produced by derivationStrict")
        ),
        "{error:?}"
    );
    Ok(())
}

#[test]
fn native_instantiation_fetch_tree_gaps_stay_fallback_eligible() -> Result<()> {
    let native = NixNative::new(0)?;

    for (source, expected_feature) in [
        (
            r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 src = builtins.fetchTree "sourcehut:~andyl/aos/main";
               }"#,
            "forge reference resolution",
        ),
        (
            r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 src = builtins.fetchTree {
                   type = "git";
                   url = "file:///no-such-repo";
                   verifyCommit = true;
                 };
               }"#,
            "verified git fetches",
        ),
    ] {
        let error = native
            .instantiate_expr(source)
            .expect_err("native fetchTree implementation gaps should fall back");

        assert!(
            matches!(
                error.downcast_ref::<NativeEvalError>(),
                Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                    if feature.contains(expected_feature)
            ),
            "{source}: {error:?}"
        );
    }

    Ok(())
}
