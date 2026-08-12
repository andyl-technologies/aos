//! Shared helpers for the Nix `lang.sh` conformance integration tests.

pub(super) use std::ffi::OsStr;
pub(super) use std::fs;
pub(super) use std::os::unix::ffi::OsStrExt;
pub(super) use std::path::{Path, PathBuf};

pub(super) use anyhow::{Context, Result, anyhow, bail};
pub(super) use aos_nix::compile::resolve;
pub(super) use aos_nix::eval::{
    TreeWalkOptions, eval_raw_bytes_with_options, eval_raw_bytes_with_options_source,
    eval_whnf_owned_with_options,
};
pub(super) use aos_nix::syntax::parse_bytes;
pub(super) use aos_nix::{NativeEvalError, NixNative};
pub(super) use aos_nix_dialect::nix_lower as lower;

pub(super) use super::{fixture_corepkgs_dir, fixture_lang_dir};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum LangCategory {
    ParseFail,
    ParseOkay,
    EvalFail,
    EvalOkay,
}

#[derive(Clone, Debug)]
pub(super) struct LangCase {
    pub(super) name: String,
    pub(super) category: LangCategory,
    pub(super) source: PathBuf,
    pub(super) expected: Option<PathBuf>,
    pub(super) expected_xml: Option<PathBuf>,
    pub(super) postprocess: Option<PathBuf>,
    pub(super) flags: Vec<String>,
    pub(super) disabled: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum CaseOutcome {
    Passed,
    Skipped(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LangEvalConfig {
    pub(super) options: TreeWalkOptions,
    pub(super) auto_args: Vec<LangAutoArg>,
    pub(super) attr_path: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum LangAutoArg {
    Expr { name: String, expr: String },
    Str { name: String, value: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LangPostprocess {
    pub(super) target: LangOutput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LangOutput {
    Out,
    Err,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct LangVersion {
    pub(super) major: u16,
    pub(super) minor: u16,
    pub(super) patch: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LangVersionRange {
    pub(super) min_inclusive: Option<LangVersion>,
    pub(super) max_exclusive: Option<LangVersion>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LangVersionSkipRule {
    pub(super) name: &'static str,
    pub(super) active: LangVersionRange,
    pub(super) reason: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LangCaseExclusion {
    pub(super) name: &'static str,
    pub(super) reason: &'static str,
}

pub(super) const PINNED_LANG_CPP_NIX_VERSION: LangVersion = LangVersion::new(2, 24, 12);
pub(super) const LANG_VERSION_SKIP_RULES: &[LangVersionSkipRule] = &[];
pub(super) const LANG_CASE_EXCLUSIONS: &[LangCaseExclusion] = &[];
pub(super) const PINNED_LANG_2_24_12_PASS_COUNT: usize = 208;
pub(super) const PINNED_LANG_2_24_12_SKIP_COUNT: usize = 1;
pub(super) const LANG_CURRENT_SYSTEM: &[u8] = b"x86_64-linux";
pub(super) const LANG_CASE_STACK_SIZE: usize = 32 * 1024 * 1024;
pub(super) const PINNED_LANG_2_24_12_SPECIAL_CASE_NAMES: &[&str] = &["non-eval-fail-bad-drvPath"];

impl LangVersion {
    pub(super) const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub(super) fn parse(input: &str) -> Option<Self> {
        let mut parts = input.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for LangVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl LangVersionRange {
    pub(super) const fn before(max_exclusive: LangVersion) -> Self {
        Self {
            min_inclusive: None,
            max_exclusive: Some(max_exclusive),
        }
    }

    pub(super) const fn since(min_inclusive: LangVersion) -> Self {
        Self {
            min_inclusive: Some(min_inclusive),
            max_exclusive: None,
        }
    }

    fn contains(self, version: LangVersion) -> bool {
        self.min_inclusive.is_none_or(|min| version >= min)
            && self.max_exclusive.is_none_or(|max| version < max)
    }
}

pub(super) fn discover_lang_cases(lang_dir: &Path) -> Result<Vec<LangCase>> {
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
            expected_xml: expected_xml_path(lang_dir, &stem, category),
            postprocess: postprocess_path(lang_dir, &stem),
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

pub(super) fn category_for_case_name(name: &str) -> Option<LangCategory> {
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

pub(super) fn expected_path(
    lang_dir: &Path,
    stem: &str,
    category: LangCategory,
) -> Option<PathBuf> {
    match category {
        LangCategory::ParseFail | LangCategory::EvalFail => {
            Some(lang_dir.join(format!("{stem}.err.exp")))
        }
        LangCategory::ParseOkay | LangCategory::EvalOkay => {
            Some(lang_dir.join(format!("{stem}.exp")))
        }
    }
}

pub(super) fn expected_xml_path(
    lang_dir: &Path,
    stem: &str,
    category: LangCategory,
) -> Option<PathBuf> {
    if category != LangCategory::EvalOkay {
        return None;
    }
    let path = lang_dir.join(format!("{stem}.exp.xml"));
    path.exists().then_some(path)
}

pub(super) fn postprocess_path(lang_dir: &Path, stem: &str) -> Option<PathBuf> {
    let path = lang_dir.join(format!("{stem}.postprocess"));
    path.exists().then_some(path)
}

pub(super) fn read_flags(lang_dir: &Path, stem: &str) -> Result<Vec<String>> {
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

pub(super) fn run_lang_case(case: &LangCase) -> Result<CaseOutcome> {
    run_lang_case_on_stack(case.clone(), false)
}

pub(super) fn run_lang_case_with_exclusions(
    case: &LangCase,
    allow_documented_exclusions: bool,
) -> Result<CaseOutcome> {
    run_lang_case_on_stack(case.clone(), allow_documented_exclusions)
}

pub(super) fn run_lang_case_on_stack(
    case: LangCase,
    allow_documented_exclusions: bool,
) -> Result<CaseOutcome> {
    let name = case.name.clone();
    let handle = std::thread::Builder::new()
        .name("aos-nix-lang-case".to_owned())
        .stack_size(LANG_CASE_STACK_SIZE)
        .spawn(move || run_lang_case_inner(&case, allow_documented_exclusions))
        .with_context(|| format!("spawning lang conformance worker for {name}"))?;

    match handle.join() {
        Ok(result) => result,
        Err(_) => bail!("lang conformance worker panicked while running {name}"),
    }
}

pub(super) fn run_lang_case_inner(
    case: &LangCase,
    allow_documented_exclusions: bool,
) -> Result<CaseOutcome> {
    if case.disabled {
        return Ok(CaseOutcome::Skipped("disabled by .exp-disabled".to_owned()));
    }
    if allow_documented_exclusions {
        if let Some(reason) = documented_case_exclusion(&case.name) {
            return Ok(CaseOutcome::Skipped(reason));
        }
    }
    if let Some(reason) = version_reactive_skip(&case.name) {
        return Ok(CaseOutcome::Skipped(reason));
    }
    let lang_dir = case
        .source
        .parent()
        .ok_or_else(|| anyhow!("{} has no lang corpus parent directory", case.name))?;
    let config = match lang_case_config_for_case(case, lang_dir) {
        Ok(config) => config,
        Err(reason) => return Ok(CaseOutcome::Skipped(reason)),
    };
    let postprocess = match lang_case_postprocess(case) {
        Ok(postprocess) => postprocess,
        Err(reason) => return Ok(CaseOutcome::Skipped(reason)),
    };

    let source =
        fs::read(&case.source).with_context(|| format!("reading {}", case.source.display()))?;
    match case.category {
        LangCategory::ParseFail => {
            if parse_case(&source).is_ok() {
                bail!("{} parsed but should fail", case.name);
            }
            Ok(CaseOutcome::Passed)
        }
        LangCategory::ParseOkay => {
            parse_case(&source).with_context(|| format!("{} should parse", case.name))?;
            Ok(CaseOutcome::Passed)
        }
        LangCategory::EvalFail => match eval_strict_case(&source, config.options) {
            Ok(()) => bail!("{} evaluated but should fail", case.name),
            Err(error) => {
                let mut err = format!("{error}\n").into_bytes();
                apply_lang_postprocess(&mut err, LangOutput::Err, postprocess);
                Ok(CaseOutcome::Passed)
            }
        },
        LangCategory::EvalOkay => {
            let expected_path = case
                .expected_xml
                .as_ref()
                .or(case.expected.as_ref())
                .ok_or_else(|| anyhow!("{} has no expected output path", case.name))?;
            let expected = fs::read(expected_path)
                .with_context(|| format!("reading {}", expected_path.display()))?;
            let mut actual = if case.expected_xml.is_some() {
                eval_xml_case(&source, config.options.clone())
                    .with_context(|| format!("{} should evaluate as XML", case.name))?
            } else {
                eval_raw_case(
                    &source,
                    case.source.as_os_str().as_bytes(),
                    lang_dir,
                    &config,
                    &case.flags,
                )
                .with_context(|| format!("{} should evaluate as a raw value", case.name))?
            };
            normalize_lang_pwd_paths(&mut actual, lang_dir);
            apply_lang_postprocess(&mut actual, LangOutput::Out, postprocess);
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

pub(super) fn documented_case_exclusion(name: &str) -> Option<String> {
    LANG_CASE_EXCLUSIONS
        .iter()
        .find(|exclusion| exclusion.name == name)
        .map(|exclusion| format!("documented exclusion: {}", exclusion.reason))
}

pub(super) fn configured_skip_is_allowed(case: &LangCase, reason: &str) -> bool {
    (case.disabled && reason == "disabled by .exp-disabled")
        || documented_case_exclusion(&case.name).as_deref() == Some(reason)
        || version_reactive_skip(&case.name).as_deref() == Some(reason)
}

pub(super) fn version_reactive_skip(name: &str) -> Option<String> {
    version_reactive_skip_with_rules(name, PINNED_LANG_CPP_NIX_VERSION, LANG_VERSION_SKIP_RULES)
}

pub(super) fn version_reactive_skip_with_rules(
    name: &str,
    version: LangVersion,
    rules: &[LangVersionSkipRule],
) -> Option<String> {
    rules
        .iter()
        .find(|rule| rule.name == name && rule.active.contains(version))
        .map(|rule| format!("{} (C++ Nix {version})", rule.reason))
}

pub(super) fn lang_case_postprocess(
    case: &LangCase,
) -> std::result::Result<Option<LangPostprocess>, String> {
    let Some(path) = &case.postprocess else {
        return Ok(None);
    };
    let script = fs::read_to_string(path)
        .map_err(|_| unsupported_postprocess_message(case.name.as_str()))?;
    parse_lang_postprocess(&script).map(Some).map_err(|_| {
        unsupported_postprocess_message(
            path.file_name()
                .and_then(OsStr::to_str)
                .unwrap_or(case.name.as_str()),
        )
    })
}

pub(super) fn parse_lang_postprocess(script: &str) -> std::result::Result<LangPostprocess, ()> {
    let normalized = script.replace("\r\n", "\n");
    let lines = normalized.lines().collect::<Vec<_>>();
    for (target, suffix) in [(LangOutput::Out, "out"), (LangOutput::Err, "err")] {
        if digit_normalizer_postprocess_lines(suffix) == lines {
            return Ok(LangPostprocess { target });
        }
    }
    Err(())
}

pub(super) fn digit_normalizer_postprocess_lines(suffix: &str) -> Vec<String> {
    vec![
        "# shellcheck shell=bash".to_owned(),
        "set -euo pipefail".to_owned(),
        "testcaseBasename=$1".to_owned(),
        String::new(),
        "# Line numbers change when derivation.nix docs are updated.".to_owned(),
        format!("sed -i \"$testcaseBasename.{suffix}\" \\"),
        "  -e 's/[0-9 ][0-9 ][0-9 ][0-9 ][0-9 ][0-9 ][0-9 ][0-9]\\([^0-9]\\)/<number>\\1/g' \\"
            .to_owned(),
        "  -e 's/[0-9][0-9]*/<number>/g' \\".to_owned(),
        "  ;".to_owned(),
    ]
}

pub(super) fn apply_lang_postprocess(
    output: &mut Vec<u8>,
    output_kind: LangOutput,
    postprocess: Option<LangPostprocess>,
) {
    if postprocess.is_some_and(|postprocess| postprocess.target == output_kind) {
        *output = normalize_decimal_runs(output);
    }
}

pub(super) fn normalize_decimal_runs(bytes: &[u8]) -> Vec<u8> {
    let first_pass = normalize_padded_decimal_fields(bytes);
    normalize_decimal_sequences(&first_pass)
}

pub(super) fn normalize_padded_decimal_fields(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes.get(index..index + 8).is_some_and(|field| {
            field
                .iter()
                .all(|byte| byte.is_ascii_digit() || *byte == b' ')
        }) && bytes
            .get(index + 8)
            .is_some_and(|byte| !byte.is_ascii_digit())
        {
            out.extend_from_slice(b"<number>");
            out.push(bytes[index + 8]);
            index += 9;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

pub(super) fn normalize_decimal_sequences(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            out.extend_from_slice(b"<number>");
            index += 1;
            while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

pub(super) fn normalize_lang_pwd_paths(output: &mut Vec<u8>, lang_dir: &Path) {
    let Some(pwd) = lang_dir.parent() else {
        return;
    };
    let pwd = path_bytes(pwd);
    if !pwd.is_empty() {
        *output = replace_byte_sequence(output, &pwd, b"/pwd");
    }
}

pub(super) fn replace_byte_sequence(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return bytes.to_vec();
    }

    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes
            .get(index..index + needle.len())
            .is_some_and(|candidate| candidate == needle)
        {
            out.extend_from_slice(replacement);
            index += needle.len();
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

pub(super) fn lang_case_options(
    category: LangCategory,
    flags: &[String],
    lang_dir: &Path,
) -> std::result::Result<TreeWalkOptions, String> {
    Ok(lang_case_config(category, flags, lang_dir)?.options)
}

pub(super) fn lang_case_config(
    category: LangCategory,
    flags: &[String],
    lang_dir: &Path,
) -> std::result::Result<LangEvalConfig, String> {
    if flags.is_empty() {
        let mut options = base_eval_options(lang_dir)?;
        if category == LangCategory::EvalOkay {
            add_eval_okay_default_nix_path(&mut options, flags)?;
        }
        return Ok(LangEvalConfig::from_options(options));
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

pub(super) fn lang_case_config_for_case(
    case: &LangCase,
    lang_dir: &Path,
) -> std::result::Result<LangEvalConfig, String> {
    lang_case_config(case.category, &case.flags, lang_dir)
}

pub(super) fn eval_okay_options(
    flags: &[String],
    lang_dir: &Path,
) -> std::result::Result<LangEvalConfig, String> {
    let mut options = base_eval_options(lang_dir)?;
    let mut auto_args = Vec::new();
    let mut attr_path = Vec::new();

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
            "--arg" => {
                index += 1;
                let Some(name) = flags.get(index) else {
                    return Err(unsupported_flags_message(flags));
                };
                index += 1;
                let Some(expr) = flags.get(index) else {
                    return Err(unsupported_flags_message(flags));
                };
                validate_auto_arg_name(name, flags)?;
                render_auto_arg_expr(expr, lang_dir, flags)?;
                auto_args.push(LangAutoArg::Expr {
                    name: name.clone(),
                    expr: expr.clone(),
                });
            }
            "--argstr" => {
                index += 1;
                let Some(name) = flags.get(index) else {
                    return Err(unsupported_flags_message(flags));
                };
                index += 1;
                let Some(value) = flags.get(index) else {
                    return Err(unsupported_flags_message(flags));
                };
                validate_auto_arg_name(name, flags)?;
                auto_args.push(LangAutoArg::Str {
                    name: name.clone(),
                    value: value.clone(),
                });
            }
            "-A" => {
                if !attr_path.is_empty() {
                    return Err(unsupported_flags_message(flags));
                }
                index += 1;
                let Some(attr) = flags.get(index) else {
                    return Err(unsupported_flags_message(flags));
                };
                attr_path = parse_lang_attr_path(attr, flags)?;
            }
            _ => return Err(unsupported_flags_message(flags)),
        }
        index += 1;
    }

    add_eval_okay_default_nix_path(&mut options, flags)?;
    Ok(LangEvalConfig {
        options,
        auto_args,
        attr_path,
    })
}

pub(super) fn eval_fail_options(
    flags: &[String],
    lang_dir: &Path,
) -> std::result::Result<LangEvalConfig, String> {
    if flags.len() == 2 && flags[0] == "--max-call-depth" {
        let max_call_depth = parse_max_call_depth_flag(&flags[1], flags)?;
        let mut options = base_eval_options(lang_dir)?;
        options.set_max_call_depth(max_call_depth);
        return Ok(LangEvalConfig::from_options(options));
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
        base_eval_options(lang_dir).map(LangEvalConfig::from_options)
    } else {
        Err(unsupported_flags_message(flags))
    }
}

impl LangEvalConfig {
    pub(super) fn from_options(options: TreeWalkOptions) -> Self {
        Self {
            options,
            auto_args: Vec::new(),
            attr_path: Vec::new(),
        }
    }
}

pub(super) fn base_eval_options(lang_dir: &Path) -> std::result::Result<TreeWalkOptions, String> {
    let mut options = TreeWalkOptions::default();
    options
        .set_path_literal_base(path_bytes(lang_dir))
        .map_err(|error| error.to_string())?;
    options
        .set_home_dir(b"/fake-home".to_vec())
        .map_err(|error| error.to_string())?;
    options
        .set_current_system(LANG_CURRENT_SYSTEM.to_vec())
        .map_err(|error| error.to_string())?;
    options.set_env_var(b"TEST_VAR".to_vec(), b"foo".to_vec());
    if let Some(parent) = lang_dir.parent() {
        options
            .set_search_path_base(path_bytes(parent))
            .map_err(|error| error.to_string())?;
    }
    options
        .set_corepkgs_path(path_bytes(&fixture_corepkgs_dir()))
        .map_err(|error| error.to_string())?;
    Ok(options)
}

pub(super) fn add_eval_okay_default_nix_path(
    options: &mut TreeWalkOptions,
    flags: &[String],
) -> std::result::Result<(), String> {
    add_search_path_entry(options, "lang/dir3", flags)?;
    add_search_path_entry(options, "lang/dir4", flags)?;
    Ok(())
}

pub(super) fn add_search_path_entry(
    options: &mut TreeWalkOptions,
    entry: &str,
    flags: &[String],
) -> std::result::Result<(), String> {
    let (prefix, path) = split_search_path_entry(entry);
    options
        .add_nix_path_entry(prefix.to_vec(), path.to_vec())
        .map_err(|_| unsupported_flags_message(flags))
}

pub(super) fn split_search_path_entry(entry: &str) -> (&[u8], &[u8]) {
    let bytes = entry.as_bytes();
    if let Some(index) = bytes.iter().position(|byte| *byte == b'=') {
        (&bytes[..index], &bytes[index + 1..])
    } else {
        (b"", bytes)
    }
}

pub(super) fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

pub(super) fn parse_max_call_depth_flag(
    value: &str,
    flags: &[String],
) -> std::result::Result<usize, String> {
    value.parse().map_err(|_| unsupported_flags_message(flags))
}

pub(super) fn validate_auto_arg_name(
    name: &str,
    flags: &[String],
) -> std::result::Result<(), String> {
    validate_simple_identifier(name.as_bytes(), flags)
}

pub(super) fn parse_lang_attr_path(
    attr: &str,
    flags: &[String],
) -> std::result::Result<Vec<Vec<u8>>, String> {
    let mut segments = Vec::new();
    for segment in attr.split('.') {
        validate_simple_identifier(segment.as_bytes(), flags)?;
        segments.push(segment.as_bytes().to_vec());
    }
    Ok(segments)
}

pub(super) fn validate_simple_identifier(
    bytes: &[u8],
    flags: &[String],
) -> std::result::Result<(), String> {
    let Some((first, rest)) = bytes.split_first() else {
        return Err(unsupported_flags_message(flags));
    };
    if !matches!(first, b'_' | b'a'..=b'z' | b'A'..=b'Z')
        || !rest
            .iter()
            .all(|byte| matches!(byte, b'_' | b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'))
    {
        return Err(unsupported_flags_message(flags));
    }
    Ok(())
}

pub(super) fn unsupported_flags_message(flags: &[String]) -> String {
    format!("case carries unsupported flags: {}", flags.join(" "))
}

pub(super) fn unsupported_postprocess_message(name: &str) -> String {
    format!("case carries unsupported postprocess: {name}")
}

pub(super) fn parse_case(source: &[u8]) -> Result<()> {
    let parsed = parse_bytes(source).context("parsing expression")?;
    resolve(parsed).context("resolving expression")?;
    Ok(())
}

pub(super) fn eval_strict_case(source: &[u8], options: TreeWalkOptions) -> Result<()> {
    let parsed = parse_bytes(source).context("parsing expression")?;
    let resolved = resolve(parsed).context("resolving expression")?;
    let ir = lower(resolved).context("lowering expression")?;
    eval_raw_bytes_with_options(&ir, options).context("evaluating strict expression")?;
    Ok(())
}

pub(super) fn run_non_eval_fail_bad_drv_path(lang_dir: &Path) -> Result<CaseOutcome> {
    let path = lang_dir.join("non-eval-fail-bad-drvPath.nix");
    let mut options = TreeWalkOptions::new();
    options
        .set_current_system(LANG_CURRENT_SYSTEM.to_vec())
        .context("configuring currentSystem for non-eval lang case")?;
    let native = NixNative::with_options(0, options).context("constructing native evaluator")?;
    let error = native
        .instantiate_closure(&path, "")
        .expect_err("special non-eval case should reject the root drvPath");
    match error.downcast_ref::<NativeEvalError>() {
        Some(NativeEvalError::EvalError { message }) if message.contains("non-derivation path") => {
            Ok(CaseOutcome::Passed)
        }
        _ => bail!("special non-eval case failed with unexpected error: {error:#}"),
    }
}

pub(super) fn eval_raw_case(
    source: &[u8],
    source_name: &[u8],
    lang_dir: &Path,
    config: &LangEvalConfig,
    flags: &[String],
) -> Result<Vec<u8>> {
    let source = if config.auto_args.is_empty() && config.attr_path.is_empty() {
        source.to_vec()
    } else {
        wrap_eval_okay_source(source, lang_dir, config, flags)
            .map(String::into_bytes)
            .map_err(anyhow::Error::msg)?
    };
    let parsed = parse_bytes(&source).context("parsing expression")?;
    let resolved = resolve(parsed).context("resolving expression")?;
    let ir = lower(resolved).context("lowering expression")?;
    let mut bytes = eval_raw_bytes_with_options_source(
        &ir,
        config.options.clone(),
        source_name.to_vec(),
        source.clone(),
    )
    .context("evaluating raw value")?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(super) fn eval_xml_case(source: &[u8], options: TreeWalkOptions) -> Result<Vec<u8>> {
    let source = std::str::from_utf8(source).context("source is not UTF-8")?;
    let wrapped = format!("builtins.toXML ({source})");
    let parsed = parse_bytes(wrapped.as_bytes()).context("parsing expression")?;
    let resolved = resolve(parsed).context("resolving expression")?;
    let ir = lower(resolved).context("lowering expression")?;
    let outcome = eval_whnf_owned_with_options(&ir, options).context("evaluating XML value")?;
    let string = outcome
        .heap()
        .get_string(outcome.value())
        .context("XML value should be a string")?;
    Ok(string.bytes().to_vec())
}

pub(super) fn wrap_eval_okay_source(
    source: &[u8],
    lang_dir: &Path,
    config: &LangEvalConfig,
    flags: &[String],
) -> std::result::Result<String, String> {
    let source = std::str::from_utf8(source).map_err(|_| unsupported_flags_message(flags))?;
    let mut wrapped = String::new();
    wrapped.push_str("((");
    wrapped.push_str(source);
    wrapped.push(')');
    if !config.auto_args.is_empty() {
        wrapped.push_str(" { ");
        for auto_arg in &config.auto_args {
            match auto_arg {
                LangAutoArg::Expr { name, expr } => {
                    wrapped.push_str(name);
                    wrapped.push_str(" = ");
                    wrapped.push_str(&render_auto_arg_expr(expr, lang_dir, flags)?);
                    wrapped.push_str("; ");
                }
                LangAutoArg::Str { name, value } => {
                    wrapped.push_str(name);
                    wrapped.push_str(" = ");
                    wrapped.push_str(&nix_string_literal(value.as_bytes(), flags)?);
                    wrapped.push_str("; ");
                }
            }
        }
        wrapped.push('}');
    }
    wrapped.push(')');
    for segment in &config.attr_path {
        wrapped.push('.');
        wrapped.push_str(&nix_string_literal(segment, flags)?);
    }
    Ok(wrapped)
}

pub(super) fn render_auto_arg_expr(
    expr: &str,
    lang_dir: &Path,
    flags: &[String],
) -> std::result::Result<String, String> {
    let Some(path) = expr
        .strip_prefix("import(")
        .and_then(|expr| expr.strip_suffix(')'))
    else {
        return Err(unsupported_flags_message(flags));
    };
    if path.contains("${") {
        return Err(unsupported_flags_message(flags));
    }
    let path = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        lang_dir
            .parent()
            .ok_or_else(|| unsupported_flags_message(flags))?
            .join(path)
    };
    if !path.exists() {
        return Err(unsupported_flags_message(flags));
    }
    Ok(format!(
        "import {}",
        nix_path_literal(path.as_os_str().as_bytes(), flags)?
    ))
}

pub(super) fn nix_path_literal(
    path: &[u8],
    flags: &[String],
) -> std::result::Result<String, String> {
    if !path.iter().all(
        |byte| matches!(byte, b'/' | b'.' | b'_' | b'-' | b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'),
    ) {
        return Err(unsupported_flags_message(flags));
    }
    String::from_utf8(path.to_vec()).map_err(|_| unsupported_flags_message(flags))
}

pub(super) fn nix_string_literal(
    bytes: &[u8],
    flags: &[String],
) -> std::result::Result<String, String> {
    let mut out = String::new();
    out.push('"');
    let mut cursor = 0;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b'$' if bytes.get(cursor + 1) == Some(&b'{') => {
                out.push_str("\\${");
                cursor += 1;
            }
            b' '..=b'~' => out.push(bytes[cursor] as char),
            _ => return Err(unsupported_flags_message(flags)),
        }
        cursor += 1;
    }
    out.push('"');
    Ok(out)
}
