//! Tree-walk evaluator tests: POSIX ERE bracket-expression semantics.
//!
//! `builtins.match` / `builtins.split` must reproduce the bracket-expression
//! grammar of C++ Nix's `std::regex` in `extended` mode. The parity target
//! is GNU libstdc++ (the standard library of the hermetically built
//! `pkgs.nix` oracle); expectations below marked "libstdc++" follow GCC 14's
//! `bits/regex_compiler.tcc` / `bits/regex.tcc` and diverge from LLVM
//! libc++ (which, for example, accepts reversed ranges as empty sets and a
//! dash after a completed range as a literal). Rows exercised by the
//! oracle-differential test are restricted to the constructs on which both
//! implementations agree.

use super::*;

/// The Chunk-F corpus repro: systemd unit-name matching from
/// `lib/hardening.nix` consumers. POSIX treats `\` inside a bracket
/// expression as an ordinary member, so the class must match a literal
/// backslash in the escaped unit name.
#[test]
fn match_bracket_backslash_is_a_literal_member() {
    assert_eq!(
        eval_list_string_bytes(
            r#"builtins.match "[a-zA-Z0-9@%:_.\\-]+[.](service|device)" "dev-disk-by\\x2dpartlabel-swap.device""#
        ),
        vec![b"device".to_vec()]
    );
    // `[\d]` is the member set {`\`, `d`}, not a digit class.
    assert_eq!(
        eval(r#"builtins.length (builtins.match "[\\d]" "\\")"#).as_int(),
        Ok(0)
    );
    assert_eq!(
        eval(r#"builtins.length (builtins.match "[\\d]" "d")"#).as_int(),
        Ok(0)
    );
    assert_eq!(eval(r#"builtins.match "[\\d]" "5""#).as_null(), Ok(()));
}

/// Bracket-expression constructs on which libstdc++ and libc++ agree,
/// verified against a C++ Nix 2.24 oracle. Each row is
/// `(pattern, subject, matches)` for `builtins.match pattern subject`.
const AGREED_BRACKET_MATCH_ROWS: &[(&str, &str, bool)] = &[
    // Backslash is an ordinary member and a valid range endpoint.
    (r#""[a\\-b]""#, r#""_""#, true),
    (r#""[a\\-b]""#, r#""-""#, false),
    (r#""[a\\-b]""#, r#""a""#, true),
    (r#""[a\\-b]""#, r#""\\""#, true),
    (r#""[%-\\\\]""#, r#""0""#, true),
    // `]` first (after optional `^`) is an ordinary member.
    (r#""[]]""#, r#""]""#, true),
    (r#""[]a]""#, r#""]""#, true),
    (r#""[]a]""#, r#""a""#, true),
    (r#""[^]a]""#, r#""b""#, true),
    (r#""[^]a]""#, r#""]""#, false),
    // `[` (not opening a `[. [: [=` term) and Rust set operators are
    // ordinary members.
    (r#""[a[b]""#, r#""[""#, true),
    (r#""[a&&b]""#, r#""&""#, true),
    (r#""[a~~b]""#, r#""~""#, true),
    (r#""[a^]""#, r#""^""#, true),
    // Dash placement: literal when leading/trailing, range otherwise.
    (r#""[-a]""#, r#""-""#, true),
    (r#""[a-]""#, r#""-""#, true),
    (r#""[--0]""#, r#"".""#, true),
    (r#""[+--]""#, r#"",""#, true),
    // Character classes, including case-folded and GNU short names.
    (r#""[[:alpha:]]""#, r#""x""#, true),
    (r#""[[:ALPHA:]]""#, r#""x""#, true),
    (r#""[[:alpha:]0]""#, r#""0""#, true),
    (r#""[^[:space:]]""#, r#""q""#, true),
    (r#""[[:d:]]""#, r#""5""#, true),
    (r#""[[:w:]]""#, r#""_""#, true),
    (r#""[[:s:]]""#, r#"" ""#, true),
    // Collating symbols from the portable character set.
    (r#""[[.hyphen.]]""#, r#""-""#, true),
    (r#""[[.NUL.]x]""#, r#""x""#, true),
    (r#""[[.a.]-z]""#, r#""q""#, true),
    (r#""[[.comma.]]""#, r#"",""#, true),
    // Equivalence classes resolve their collating element.
    (r#""[[=a=]]""#, r#""a""#, true),
];

#[test]
fn match_bracket_semantics_agreed_rows() {
    for &(pattern, subject, matches) in AGREED_BRACKET_MATCH_ROWS {
        let source = format!("builtins.match {pattern} {subject}");
        if matches {
            assert_eq!(
                eval(&format!("builtins.length ({source})")).as_int(),
                Ok(0),
                "{source}"
            );
        } else {
            assert_eq!(eval(&source).as_null(), Ok(()), "{source}");
        }
    }
}

/// libstdc++-specific expectations (LLVM libc++ diverges): equivalence
/// classes case-fold through `transform_primary` (GCC 14 `bits/regex.h`
/// lowercases before collation), so `[=a=]` matches both cases.
#[test]
fn match_equivalence_class_case_folds_like_libstdcxx() {
    for source in [
        r#"builtins.match "[[=a=]]" "A""#,
        r#"builtins.match "[[=A=]]" "a""#,
    ] {
        assert_eq!(
            eval(&format!("builtins.length ({source})")).as_int(),
            Ok(0),
            "{source}"
        );
    }
}

/// Pattern classes libstdc++ rejects at compile time. libc++ accepts some
/// of these (reversed ranges become empty sets, a dash after a completed
/// range is a literal); the libstdc++ behavior is authoritative because the
/// hermetic corpus oracle is built against it.
const REJECTED_BRACKET_PATTERNS: &[&str] = &[
    // error_range: reversed range endpoints (`_M_make_range`).
    r#""[z-a]""#,
    // error_range: `a--` is the range `a`..`-`, which is reversed.
    r#""[a--b]""#,
    // error_range: dash after a completed range cannot start another.
    r#""[a-z-0]""#,
    r#""[-----]""#,
    // error_range: dash after a class-like term.
    r#""[[:alpha:]-z]""#,
    r#""[[=a=]-z]""#,
    // error_range: a `[. .]` / `[: :]` term cannot end a range.
    r#""[a-[.z.]]""#,
    // error_collate: `-` alone is not a portable collating name (only
    // `[.hyphen.]` is), and collating elements are single characters.
    r#""[[.-.]]""#,
    r#""[[.ab.]]""#,
    r#""[[=5=]]""#,
    // error_ctype: unknown class names (negated classes are not POSIX).
    r#""[[:^alpha:]]""#,
    r#""[[:nope:]]""#,
    // error_brack: unterminated bracket expressions.
    r#""[a""#,
    r#""[a-""#,
    r#""[]""#,
    r#""[[:alpha:]""#,
];

#[test]
fn match_rejects_bracket_patterns_like_libstdcxx() {
    for pattern in REJECTED_BRACKET_PATTERNS {
        let source = format!(r#"builtins.match {pattern} "x""#);
        let error = eval_whnf_owned(&lower(&source)).expect_err(&source);
        assert!(
            matches!(error.kind(), TreeWalkErrorKind::RegexCompile { .. }),
            "expected RegexCompile for {source}, got {error:?}"
        );
    }
}

/// `builtins.split` shares the translated pattern path.
#[test]
fn split_uses_posix_bracket_semantics() {
    assert_eq!(
        eval(r#"builtins.length (builtins.split "[\\-]" "a-b\\c")"#).as_int(),
        Ok(5)
    );
    assert_eq!(
        eval_string_bytes(r#"builtins.elemAt (builtins.split "[\\-]" "a-b\\c") 4"#),
        b"c"
    );
}

/// Differential check of the agreed rows against a real C++ Nix oracle.
/// Runs only when `AOS_NIX_ORACLE` points at a `nix-instantiate`; both
/// libstdc++- and libc++-linked oracles agree on these constructs.
#[test]
fn configured_cpp_nix_bracket_semantics_match_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix bracket semantics check");
        return;
    };
    let mut sources = vec![
        r#"builtins.match "[a-zA-Z0-9@%:_.\\-]+[.](service|device)" "dev-disk-by\\x2dpartlabel-swap.device""#.to_owned(),
        r#"builtins.split "[\\-]" "a-b\\c""#.to_owned(),
    ];
    for &(pattern, subject, _) in AGREED_BRACKET_MATCH_ROWS {
        sources.push(format!("builtins.match {pattern} {subject}"));
    }
    for source in sources {
        let expected = cpp_nix_eval_json(&oracle, &source);
        let native = eval_string_bytes(&format!("builtins.toJSON ({source})"));
        assert_eq!(
            String::from_utf8_lossy(&native),
            String::from_utf8_lossy(&expected),
            "{source}"
        );
    }
}
