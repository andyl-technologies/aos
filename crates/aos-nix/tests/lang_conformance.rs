use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use aos_nix::compile::{lower, resolve};
use aos_nix::eval::{TreeWalkOptions, eval_raw_bytes_with_options, eval_whnf_owned_with_options};
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
    let lang_dir = case
        .source
        .parent()
        .ok_or_else(|| anyhow!("{} has no lang corpus parent directory", case.name))?;
    let options = match lang_case_options(case.category, &case.flags, lang_dir) {
        Ok(options) => options,
        Err(reason) => return Ok(CaseOutcome::Skipped(reason)),
    };

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
            if eval_case(&source, options).is_ok() {
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
            let actual = eval_raw_case(&source, options)
                .with_context(|| format!("{} should evaluate as a raw value", case.name))?;
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

fn lang_case_options(
    category: LangCategory,
    flags: &[String],
    lang_dir: &Path,
) -> std::result::Result<TreeWalkOptions, String> {
    if flags.is_empty() {
        let mut options = base_eval_options(lang_dir)?;
        if category == LangCategory::EvalOkay {
            add_eval_okay_default_nix_path(&mut options, flags)?;
        }
        return Ok(options);
    }

    if matches!(category, LangCategory::ParseFail | LangCategory::ParseOkay) {
        return Err(unsupported_flags_message(flags));
    }

    match category {
        LangCategory::EvalOkay => eval_okay_options(flags, lang_dir),
        LangCategory::EvalFail => eval_fail_options(flags, lang_dir),
        LangCategory::ParseFail | LangCategory::ParseOkay => unreachable!(),
    }
}

fn eval_okay_options(
    flags: &[String],
    lang_dir: &Path,
) -> std::result::Result<TreeWalkOptions, String> {
    let mut options = base_eval_options(lang_dir)?;

    let mut index = 0;
    while let Some(flag) = flags.get(index) {
        match flag.as_str() {
            "--eval" | "--strict" => {}
            "-I" => {
                index += 1;
                let Some(entry) = flags.get(index) else {
                    return Err(unsupported_flags_message(flags));
                };
                add_search_path_entry(&mut options, entry, flags)?;
            }
            "--extra-experimental-features" => {
                index += 1;
                let Some(feature) = flags.get(index) else {
                    return Err(unsupported_flags_message(flags));
                };
                match feature.as_str() {
                    "parse-toml-timestamps" => options.set_parse_toml_timestamps(true),
                    _ => return Err(unsupported_flags_message(flags)),
                }
            }
            _ => return Err(unsupported_flags_message(flags)),
        }
        index += 1;
    }

    add_eval_okay_default_nix_path(&mut options, flags)?;
    Ok(options)
}

fn eval_fail_options(
    flags: &[String],
    lang_dir: &Path,
) -> std::result::Result<TreeWalkOptions, String> {
    if flags.len() == 2 && flags[0] == "--max-call-depth" {
        let max_call_depth = parse_max_call_depth_flag(&flags[1], flags)?;
        let mut options = base_eval_options(lang_dir)?;
        options.set_max_call_depth(max_call_depth);
        return Ok(options);
    }

    let mut saw_eval = false;
    let mut saw_strict = false;
    for flag in flags {
        match flag.as_str() {
            "--eval" => saw_eval = true,
            "--strict" => saw_strict = true,
            "--show-trace" | "--no-show-trace" => {}
            _ => return Err(unsupported_flags_message(flags)),
        }
    }

    if saw_eval && saw_strict {
        base_eval_options(lang_dir)
    } else {
        Err(unsupported_flags_message(flags))
    }
}

fn base_eval_options(lang_dir: &Path) -> std::result::Result<TreeWalkOptions, String> {
    let mut options = TreeWalkOptions::default();
    options
        .set_path_literal_base(path_bytes(lang_dir))
        .map_err(|error| error.to_string())?;
    if let Some(parent) = lang_dir.parent() {
        options
            .set_search_path_base(path_bytes(parent))
            .map_err(|error| error.to_string())?;
    }
    Ok(options)
}

fn add_eval_okay_default_nix_path(
    options: &mut TreeWalkOptions,
    flags: &[String],
) -> std::result::Result<(), String> {
    add_search_path_entry(options, "lang/dir3", flags)?;
    add_search_path_entry(options, "lang/dir4", flags)?;
    Ok(())
}

fn add_search_path_entry(
    options: &mut TreeWalkOptions,
    entry: &str,
    flags: &[String],
) -> std::result::Result<(), String> {
    let (prefix, path) = split_search_path_entry(entry);
    options
        .add_nix_path_entry(prefix.to_vec(), path.to_vec())
        .map_err(|_| unsupported_flags_message(flags))
}

fn split_search_path_entry(entry: &str) -> (&[u8], &[u8]) {
    let bytes = entry.as_bytes();
    if let Some(index) = bytes.iter().position(|byte| *byte == b'=') {
        (&bytes[..index], &bytes[index + 1..])
    } else {
        (b"", bytes)
    }
}

fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

fn parse_max_call_depth_flag(value: &str, flags: &[String]) -> std::result::Result<usize, String> {
    value.parse().map_err(|_| unsupported_flags_message(flags))
}

fn unsupported_flags_message(flags: &[String]) -> String {
    format!("case carries unsupported flags: {}", flags.join(" "))
}

fn eval_case(source: &[u8], options: TreeWalkOptions) -> Result<()> {
    let parsed = parse_bytes(source).context("parsing expression")?;
    let resolved = resolve(parsed).context("resolving expression")?;
    let ir = lower(resolved).context("lowering expression")?;
    eval_whnf_owned_with_options(&ir, options).context("evaluating expression")?;
    Ok(())
}

fn eval_raw_case(source: &[u8], options: TreeWalkOptions) -> Result<Vec<u8>> {
    let parsed = parse_bytes(source).context("parsing expression")?;
    let resolved = resolve(parsed).context("resolving expression")?;
    let ir = lower(resolved).context("lowering expression")?;
    let mut bytes = eval_raw_bytes_with_options(&ir, options).context("evaluating raw value")?;
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
            ("eval-fail-max-call-depth", CaseOutcome::Passed),
            ("eval-fail-type", CaseOutcome::Passed),
            ("eval-fail-with-flags", CaseOutcome::Passed),
            ("eval-okay-attrs", CaseOutcome::Passed),
            (
                "eval-okay-disabled",
                CaseOutcome::Skipped("disabled by .exp-disabled".to_owned())
            ),
            ("eval-okay-fromTOML-timestamps", CaseOutcome::Passed),
            ("eval-okay-number", CaseOutcome::Passed),
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
fn eval_fail_detection_allows_successful_non_numeric_values() -> Result<()> {
    assert!(eval_case(b"x: x", TreeWalkOptions::default()).is_ok());
    assert_eq!(
        eval_raw_case(b"x: x", TreeWalkOptions::default())?,
        b"<LAMBDA>\n"
    );

    Ok(())
}

#[test]
fn lang_sh_noop_eval_flags_are_supported() {
    let lang_dir = fixture_lang_dir();
    let strict_eval_flags = ["--eval", "--strict"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let eval_fail_no_trace_flags = ["--eval", "--strict", "--no-show-trace"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let trace_only_flags = ["--no-show-trace"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    assert!(lang_case_options(LangCategory::EvalOkay, &strict_eval_flags, &lang_dir).is_ok());
    assert!(
        lang_case_options(LangCategory::EvalFail, &eval_fail_no_trace_flags, &lang_dir).is_ok()
    );
    assert_eq!(
        lang_case_options(LangCategory::EvalFail, &trace_only_flags, &lang_dir),
        Err("case carries unsupported flags: --no-show-trace".to_owned())
    );
    assert_eq!(
        lang_case_options(LangCategory::ParseOkay, &strict_eval_flags, &lang_dir),
        Err("case carries unsupported flags: --eval --strict".to_owned())
    );
}

#[test]
fn lang_sh_max_call_depth_flag_configures_eval() {
    let lang_dir = fixture_lang_dir();
    let max_call_depth_flags = ["--max-call-depth", "3"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let max_call_depth_with_trace_flags = ["--max-call-depth", "3", "--no-show-trace"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let max_call_depth_with_eval_flags = ["--max-call-depth", "3", "--eval", "--strict"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let options = lang_case_options(LangCategory::EvalFail, &max_call_depth_flags, &lang_dir)
        .expect("max-call-depth flag should be supported");
    assert_eq!(options.max_call_depth(), 3);
    assert_eq!(
        lang_case_options(
            LangCategory::EvalFail,
            &max_call_depth_with_trace_flags,
            &lang_dir
        ),
        Err("case carries unsupported flags: --max-call-depth 3 --no-show-trace".to_owned())
    );
    assert_eq!(
        lang_case_options(
            LangCategory::EvalFail,
            &max_call_depth_with_eval_flags,
            &lang_dir
        ),
        Err("case carries unsupported flags: --max-call-depth 3 --eval --strict".to_owned())
    );
}

#[test]
fn lang_sh_search_path_flags_configure_eval_okay() {
    let lang_dir = fixture_lang_dir();
    let search_path_flags = ["-I", "lang/dir1", "-I", "lang/dir2", "-I", "dir5=lang/dir3"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let options = lang_case_options(LangCategory::EvalOkay, &search_path_flags, &lang_dir)
        .expect("search-path flags should be supported");
    assert_eq!(
        options.search_path_base(),
        path_bytes(&lang_dir.parent().unwrap())
    );
    assert_eq!(options.nix_path().len(), 5);
}

#[test]
fn lang_sh_experimental_feature_flags_configure_eval_okay() {
    let lang_dir = fixture_lang_dir();
    let timestamp_flags = ["--extra-experimental-features", "parse-toml-timestamps"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let unsupported_feature_flags = ["--extra-experimental-features", "flakes"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let missing_feature_flags = ["--extra-experimental-features"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let options = lang_case_options(LangCategory::EvalOkay, &timestamp_flags, &lang_dir)
        .expect("parse-toml-timestamps should be supported");
    assert!(options.parse_toml_timestamps());
    assert_eq!(options.nix_path().len(), 2);
    assert_eq!(
        lang_case_options(
            LangCategory::EvalOkay,
            &unsupported_feature_flags,
            &lang_dir
        ),
        Err("case carries unsupported flags: --extra-experimental-features flakes".to_owned())
    );
    assert_eq!(
        lang_case_options(LangCategory::EvalOkay, &missing_feature_flags, &lang_dir),
        Err("case carries unsupported flags: --extra-experimental-features".to_owned())
    );
    assert_eq!(
        lang_case_options(LangCategory::ParseOkay, &timestamp_flags, &lang_dir),
        Err(
            "case carries unsupported flags: --extra-experimental-features parse-toml-timestamps"
                .to_owned()
        )
    );
}

#[test]
fn lang_sh_capability_flags_remain_skipped() {
    let lang_dir = fixture_lang_dir();
    let autoarg_flags = [
        "--arg",
        "lib",
        "import(lang/lib.nix)",
        "--argstr",
        "xyzzy",
        "xyzzy!",
        "-A",
        "result",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();

    assert_eq!(
        lang_case_options(LangCategory::EvalOkay, &autoarg_flags, &lang_dir),
        Err(
            "case carries unsupported flags: --arg lib import(lang/lib.nix) --argstr xyzzy xyzzy! -A result"
                .to_owned()
        )
    );
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
