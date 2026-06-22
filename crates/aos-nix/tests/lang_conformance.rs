use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use aos_nix::compile::{lower, resolve};
use aos_nix::eval::{eval_number_raw_bytes, eval_whnf_owned};
use aos_nix::syntax::parse_bytes;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum LangCategory {
    ParseFail,
    ParseOkay,
    EvalFail,
    EvalOkay,
}

#[derive(Debug)]
struct LangCase {
    name: String,
    category: LangCategory,
    source: PathBuf,
    expected: Option<PathBuf>,
    flags: Vec<String>,
    disabled: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum CaseOutcome {
    Passed,
    Skipped(String),
}

fn discover_lang_cases(lang_dir: &Path) -> Result<Vec<LangCase>> {
    let mut cases = Vec::new();
    for entry in fs::read_dir(lang_dir)
        .with_context(|| format!("reading lang corpus directory {}", lang_dir.display()))?
    {
        let entry = entry
            .with_context(|| format!("reading lang corpus entry in {}", lang_dir.display()))?;
        let path = entry.path();
        if path.extension() != Some(OsStr::new("nix")) {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(OsStr::to_str) else {
            continue;
        };
        let Some(category) = category_for_case_name(stem) else {
            continue;
        };
        let stem = stem.to_owned();
        cases.push(LangCase {
            name: stem.clone(),
            category,
            source: path,
            expected: expected_path(lang_dir, &stem, category),
            flags: read_flags(lang_dir, &stem)?,
            disabled: lang_dir.join(format!("{stem}.exp-disabled")).exists(),
        });
    }
    cases.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(cases)
}

fn category_for_case_name(name: &str) -> Option<LangCategory> {
    if name.starts_with("parse-fail-") {
        Some(LangCategory::ParseFail)
    } else if name.starts_with("parse-okay-") {
        Some(LangCategory::ParseOkay)
    } else if name.starts_with("eval-fail-") {
        Some(LangCategory::EvalFail)
    } else if name.starts_with("eval-okay-") {
        Some(LangCategory::EvalOkay)
    } else {
        None
    }
}

fn expected_path(lang_dir: &Path, stem: &str, category: LangCategory) -> Option<PathBuf> {
    match category {
        LangCategory::ParseFail | LangCategory::EvalFail => {
            Some(lang_dir.join(format!("{stem}.err.exp")))
        }
        LangCategory::ParseOkay | LangCategory::EvalOkay => {
            Some(lang_dir.join(format!("{stem}.exp")))
        }
    }
}

fn read_flags(lang_dir: &Path, stem: &str) -> Result<Vec<String>> {
    let path = lang_dir.join(format!("{stem}.flags"));
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(text
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .flat_map(str::split_whitespace)
        .map(str::to_owned)
        .collect())
}

fn run_lang_case(case: &LangCase) -> Result<CaseOutcome> {
    if case.disabled {
        return Ok(CaseOutcome::Skipped("disabled by .exp-disabled".to_owned()));
    }
    if !case.flags.is_empty() {
        return Ok(CaseOutcome::Skipped(format!(
            "case carries unsupported flags: {}",
            case.flags.join(" ")
        )));
    }

    let source =
        fs::read(&case.source).with_context(|| format!("reading {}", case.source.display()))?;
    match case.category {
        LangCategory::ParseFail => {
            if parse_bytes(&source).is_ok() {
                bail!("{} parsed but should fail", case.name);
            }
            Ok(CaseOutcome::Passed)
        }
        LangCategory::ParseOkay => {
            parse_bytes(&source).with_context(|| format!("{} should parse", case.name))?;
            Ok(CaseOutcome::Passed)
        }
        LangCategory::EvalFail => {
            if eval_case(&source).is_ok() {
                bail!("{} evaluated but should fail", case.name);
            }
            Ok(CaseOutcome::Passed)
        }
        LangCategory::EvalOkay => {
            let expected_path = case
                .expected
                .as_ref()
                .ok_or_else(|| anyhow!("{} has no expected output path", case.name))?;
            let expected = fs::read(expected_path)
                .with_context(|| format!("reading {}", expected_path.display()))?;
            let actual = eval_numeric_case(&source)
                .with_context(|| format!("{} should evaluate as a raw number", case.name))?;
            if actual != expected {
                bail!(
                    "{} output diverged:\nexpected: {}\nactual: {}",
                    case.name,
                    String::from_utf8_lossy(&expected),
                    String::from_utf8_lossy(&actual),
                );
            }
            Ok(CaseOutcome::Passed)
        }
    }
}

fn eval_case(source: &[u8]) -> Result<()> {
    let parsed = parse_bytes(source).context("parsing expression")?;
    let resolved = resolve(parsed).context("resolving expression")?;
    let ir = lower(resolved).context("lowering expression")?;
    eval_whnf_owned(&ir).context("evaluating expression")?;
    Ok(())
}

fn eval_numeric_case(source: &[u8]) -> Result<Vec<u8>> {
    let parsed = parse_bytes(source).context("parsing expression")?;
    let resolved = resolve(parsed).context("resolving expression")?;
    let ir = lower(resolved).context("lowering expression")?;
    let mut bytes = eval_number_raw_bytes(&ir).context("evaluating raw number")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn fixture_lang_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("lang")
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
            ("eval-fail-type", CaseOutcome::Passed),
            (
                "eval-okay-disabled",
                CaseOutcome::Skipped("disabled by .exp-disabled".to_owned())
            ),
            ("eval-okay-number", CaseOutcome::Passed),
            (
                "eval-okay-with-flags",
                CaseOutcome::Skipped("case carries unsupported flags: --eval --strict".to_owned())
            ),
        ]
    );

    Ok(())
}

#[test]
fn eval_fail_detection_rejects_successful_non_numeric_values() -> Result<()> {
    assert!(eval_case(b"x: x").is_ok());
    assert!(eval_numeric_case(b"x: x").is_err());

    Ok(())
}

#[test]
fn configured_upstream_lang_corpus_discovery_sees_all_categories() -> Result<()> {
    let Some(root) = std::env::var_os("AOS_NIX_LANG_TESTS") else {
        eprintln!("AOS_NIX_LANG_TESTS not set; skipping upstream lang corpus discovery check");
        return Ok(());
    };
    let cases = discover_lang_cases(Path::new(&root))?;

    for category in [
        LangCategory::ParseFail,
        LangCategory::ParseOkay,
        LangCategory::EvalFail,
        LangCategory::EvalOkay,
    ] {
        assert!(
            cases.iter().any(|case| case.category == category),
            "configured upstream corpus should include {category:?}"
        );
    }

    Ok(())
}
