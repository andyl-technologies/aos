//! Selector parsing coverage for file-backed native instantiation.

use super::*;

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
