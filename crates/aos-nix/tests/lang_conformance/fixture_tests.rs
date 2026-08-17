//! Local fixture coverage for the `lang.sh` conformance runner.

use super::support::*;

fn unique_temp_lang_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time is after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "aos-nix-lang-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir(&path).expect("temp lang dir creates");
    path
}

#[test]
fn discovers_lang_sh_categories_flags_and_disabled_cases() -> Result<()> {
    let cases = discover_lang_cases(&fixture_lang_dir())?;

    assert_eq!(
        cases.iter().map(|case| case.category).collect::<Vec<_>>(),
        vec![
            LangCategory::ParseFail,
            LangCategory::ParseOkay,
            LangCategory::EvalFail,
            LangCategory::EvalFail,
            LangCategory::EvalFail,
            LangCategory::EvalFail,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
            LangCategory::EvalOkay,
        ]
    );
    assert!(
        cases
            .iter()
            .any(|case| case.name == "eval-okay-disabled" && case.disabled)
    );
    let flagged = cases
        .iter()
        .find(|case| case.name == "eval-okay-with-flags")
        .expect("fixture carries flags");
    assert_eq!(flagged.flags, ["--eval", "--strict"]);

    Ok(())
}

#[test]
fn fixture_lang_conformance_runs_all_four_categories() -> Result<()> {
    let cases = discover_lang_cases(&fixture_lang_dir())?;
    let mut outcomes = Vec::new();
    for case in &cases {
        outcomes.push((case.name.as_str(), run_lang_case(case)?));
    }

    assert_eq!(
        outcomes,
        vec![
            ("parse-fail-missing-then", CaseOutcome::Passed),
            ("parse-okay-simple", CaseOutcome::Passed),
            ("eval-fail-infinite-recursion-lambda", CaseOutcome::Passed),
            ("eval-fail-max-call-depth", CaseOutcome::Passed),
            ("eval-fail-type", CaseOutcome::Passed),
            ("eval-fail-with-flags", CaseOutcome::Passed),
            ("eval-okay-attrs", CaseOutcome::Passed),
            ("eval-okay-autoargs", CaseOutcome::Passed),
            (
                "eval-okay-disabled",
                CaseOutcome::Skipped("disabled by .exp-disabled".to_owned())
            ),
            ("eval-okay-fromTOML-timestamps", CaseOutcome::Passed),
            ("eval-okay-number", CaseOutcome::Passed),
            ("eval-okay-postprocess", CaseOutcome::Passed),
            ("eval-okay-primop-app", CaseOutcome::Passed),
            ("eval-okay-recursive", CaseOutcome::Passed),
            ("eval-okay-recursive-list", CaseOutcome::Passed),
            ("eval-okay-recursive-list-long", CaseOutcome::Passed),
            ("eval-okay-recursive-list-nested", CaseOutcome::Passed),
            ("eval-okay-recursive-list-siblings", CaseOutcome::Passed),
            ("eval-okay-search-path", CaseOutcome::Passed),
            ("eval-okay-string", CaseOutcome::Passed),
            ("eval-okay-string-interpolation", CaseOutcome::Passed),
            ("eval-okay-with-flags", CaseOutcome::Passed),
        ]
    );

    Ok(())
}

#[test]
fn eval_okay_symlink_resolution_uses_requested_import_base() -> Result<()> {
    let lang_dir = unique_temp_lang_dir("symlink-resolution");
    let fixture = lang_dir.join("symlink-resolution");
    let foo = fixture.join("foo");
    let overlays = fixture.join("overlays");
    fs::create_dir(&fixture).expect("fixture dir creates");
    fs::create_dir(&foo).expect("foo dir creates");
    fs::create_dir_all(foo.join("lib")).expect("lib dir creates");
    fs::create_dir(&overlays).expect("overlays dir creates");
    std::os::unix::fs::symlink("../overlays", foo.join("overlays"))
        .expect("overlays symlink creates");
    fs::write(foo.join("lib/default.nix"), br#""test""#).expect("lib default writes");
    fs::write(overlays.join("overlay.nix"), b"import ../lib").expect("overlay writes");

    let source_path = lang_dir.join("eval-okay-symlink-resolution.nix");
    let expected_path = lang_dir.join("eval-okay-symlink-resolution.exp");
    fs::write(
        &source_path,
        b"import symlink-resolution/foo/overlays/overlay.nix",
    )
    .expect("source writes");
    fs::write(
        &expected_path,
        br#""test"
"#,
    )
    .expect("expected output writes");

    let case = LangCase {
        name: "eval-okay-symlink-resolution".to_owned(),
        category: LangCategory::EvalOkay,
        source: source_path,
        expected: Some(expected_path),
        expected_xml: None,
        postprocess: None,
        flags: Vec::new(),
        disabled: false,
    };
    let outcome = run_lang_case(&case);
    fs::remove_dir_all(&lang_dir).expect("temp lang dir removes");
    assert_eq!(outcome?, CaseOutcome::Passed);
    Ok(())
}

#[test]
fn eval_fail_detection_allows_successful_non_numeric_values() -> Result<()> {
    let flags = Vec::new();
    let config = LangEvalConfig::from_options(TreeWalkOptions::default());
    assert!(eval_strict_case(b"x: x", TreeWalkOptions::default()).is_ok());
    assert_eq!(
        eval_raw_case(
            b"x: x",
            b"/pwd/lang/eval-okay-lambda.nix",
            &fixture_lang_dir(),
            &config,
            &flags,
        )?,
        b"<LAMBDA>\n"
    );

    Ok(())
}
