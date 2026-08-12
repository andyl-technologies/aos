//! Split-out `instantiate_expr.rs` test group (split).

use super::*;

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
    let source = r#"derivationStrict {
         name = "x";
         system = "x86_64-linux";
         builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
         src = builtins.fetchTree {
           type = "git";
           url = "file:///no-such-repo";
           verifyCommit = true;
         };
       }"#;

    let error = native
        .instantiate_expr(source)
        .expect_err("native fetchTree implementation gaps should fall back");

    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, span: Some(_) })
                if feature.contains("verified git fetches")
        ),
        "{source}: {error:?}"
    );

    Ok(())
}
