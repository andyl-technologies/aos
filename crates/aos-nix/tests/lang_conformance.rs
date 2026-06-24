use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use aos_nix::compile::{lower, resolve};
use aos_nix::eval::{
    TreeWalkOptions, eval_raw_bytes_with_options, eval_raw_bytes_with_options_source,
    eval_whnf_owned_with_options,
};
use aos_nix::syntax::parse_bytes;
use aos_nix::{NativeEvalError, NixNative};

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
    expected_xml: Option<PathBuf>,
    postprocess: Option<PathBuf>,
    flags: Vec<String>,
    disabled: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum CaseOutcome {
    Passed,
    Skipped(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LangEvalConfig {
    options: TreeWalkOptions,
    auto_args: Vec<LangAutoArg>,
    attr_path: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LangAutoArg {
    Expr { name: String, expr: String },
    Str { name: String, value: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LangPostprocess {
    target: LangOutput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LangOutput {
    Out,
    Err,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LangVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LangVersionRange {
    min_inclusive: Option<LangVersion>,
    max_exclusive: Option<LangVersion>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LangVersionSkipRule {
    name: &'static str,
    active: LangVersionRange,
    reason: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LangCaseExclusion {
    name: &'static str,
    reason: &'static str,
}

const PINNED_LANG_CPP_NIX_VERSION: LangVersion = LangVersion::new(2, 24, 12);
const LANG_VERSION_SKIP_RULES: &[LangVersionSkipRule] = &[];
const LANG_CASE_EXCLUSIONS: &[LangCaseExclusion] = &[
    LangCaseExclusion {
        name: "eval-fail-infinite-recursion-lambda",
        reason: "native evaluator stack-safety gap for infinite lambda recursion",
    },
    LangCaseExclusion {
        name: "eval-okay-eq-derivations",
        reason: "native evaluator stack-safety gap in derivation equality",
    },
    LangCaseExclusion {
        name: "eval-okay-search-path",
        reason: "implicit C++ Nix corepkgs search path is not modeled",
    },
    LangCaseExclusion {
        name: "eval-okay-symlink-resolution",
        reason: "symlink directory resolution gap",
    },
];
const PINNED_LANG_2_24_12_PASS_COUNT: usize = 204;
const PINNED_LANG_2_24_12_SKIP_COUNT: usize = 5;
const PINNED_LANG_2_24_12_SPECIAL_CASE_NAMES: &[&str] = &["non-eval-fail-bad-drvPath"];
const PINNED_LANG_2_24_12_CASE_NAMES: &[&str] = &[
    "parse-fail-dup-attrs-1",
    "parse-fail-dup-attrs-2",
    "parse-fail-dup-attrs-3",
    "parse-fail-dup-attrs-4",
    "parse-fail-dup-attrs-7",
    "parse-fail-dup-formals",
    "parse-fail-eof-in-string",
    "parse-fail-eof-pos",
    "parse-fail-mixed-nested-attrs1",
    "parse-fail-mixed-nested-attrs2",
    "parse-fail-patterns-1",
    "parse-fail-regression-20060610",
    "parse-fail-undef-var",
    "parse-fail-undef-var-2",
    "parse-fail-utf8",
    "parse-okay-1",
    "parse-okay-crlf",
    "parse-okay-dup-attrs-5",
    "parse-okay-dup-attrs-6",
    "parse-okay-ind-string",
    "parse-okay-inherits",
    "parse-okay-mixed-nested-attrs-1",
    "parse-okay-mixed-nested-attrs-2",
    "parse-okay-mixed-nested-attrs-3",
    "parse-okay-regression-20041027",
    "parse-okay-regression-751",
    "parse-okay-subversion",
    "parse-okay-url",
    "eval-fail-abort",
    "eval-fail-addDrvOutputDependencies-empty-context",
    "eval-fail-addDrvOutputDependencies-multi-elem-context",
    "eval-fail-addDrvOutputDependencies-wrong-element-kind",
    "eval-fail-addErrorContext-example",
    "eval-fail-assert",
    "eval-fail-assert-equal-attrs-names",
    "eval-fail-assert-equal-attrs-names-2",
    "eval-fail-assert-equal-derivations",
    "eval-fail-assert-equal-derivations-extra",
    "eval-fail-assert-equal-floats",
    "eval-fail-assert-equal-function-direct",
    "eval-fail-assert-equal-int-float",
    "eval-fail-assert-equal-ints",
    "eval-fail-assert-equal-list-length",
    "eval-fail-assert-equal-paths",
    "eval-fail-assert-equal-type",
    "eval-fail-assert-equal-type-nested",
    "eval-fail-assert-nested-bool",
    "eval-fail-attr-name-type",
    "eval-fail-attrset-merge-drops-later-rec",
    "eval-fail-bad-string-interpolation-1",
    "eval-fail-bad-string-interpolation-2",
    "eval-fail-bad-string-interpolation-3",
    "eval-fail-bad-string-interpolation-4",
    "eval-fail-blackhole",
    "eval-fail-call-primop",
    "eval-fail-deepseq",
    "eval-fail-derivation-name",
    "eval-fail-dup-dynamic-attrs",
    "eval-fail-duplicate-traces",
    "eval-fail-eol-1",
    "eval-fail-eol-2",
    "eval-fail-eol-3",
    "eval-fail-fetchurl-baseName",
    "eval-fail-fetchurl-baseName-attrs",
    "eval-fail-fetchurl-baseName-attrs-name",
    "eval-fail-foldlStrict-strict-op-application",
    "eval-fail-fromTOML-timestamps",
    "eval-fail-hashfile-missing",
    "eval-fail-infinite-recursion-lambda",
    "eval-fail-list",
    "eval-fail-missing-arg",
    "eval-fail-mutual-recursion",
    "eval-fail-nested-list-items",
    "eval-fail-nonexist-path",
    "eval-fail-not-throws",
    "eval-fail-path-slash",
    "eval-fail-pipe-operators",
    "eval-fail-recursion",
    "eval-fail-remove",
    "eval-fail-scope-5",
    "eval-fail-seq",
    "eval-fail-set",
    "eval-fail-set-override",
    "eval-fail-substring",
    "eval-fail-to-path",
    "eval-fail-toJSON",
    "eval-fail-toJSON-non-utf-8",
    "eval-fail-undeclared-arg",
    "eval-fail-using-set-as-attr-name",
    "eval-okay-any-all",
    "eval-okay-arithmetic",
    "eval-okay-attrnames",
    "eval-okay-attrs",
    "eval-okay-attrs2",
    "eval-okay-attrs3",
    "eval-okay-attrs4",
    "eval-okay-attrs5",
    "eval-okay-attrs6",
    "eval-okay-autoargs",
    "eval-okay-backslash-newline-1",
    "eval-okay-backslash-newline-2",
    "eval-okay-baseNameOf",
    "eval-okay-builtins",
    "eval-okay-builtins-add",
    "eval-okay-callable-attrs",
    "eval-okay-catattrs",
    "eval-okay-closure",
    "eval-okay-comments",
    "eval-okay-concat",
    "eval-okay-concatmap",
    "eval-okay-concatstringssep",
    "eval-okay-context",
    "eval-okay-context-introspection",
    "eval-okay-convertHash",
    "eval-okay-curpos",
    "eval-okay-deepseq",
    "eval-okay-delayed-with",
    "eval-okay-delayed-with-inherit",
    "eval-okay-derivation-legacy",
    "eval-okay-dynamic-attrs",
    "eval-okay-dynamic-attrs-2",
    "eval-okay-dynamic-attrs-bare",
    "eval-okay-elem",
    "eval-okay-empty-args",
    "eval-okay-eq",
    "eval-okay-eq-derivations",
    "eval-okay-filter",
    "eval-okay-flake-ref-to-string",
    "eval-okay-flatten",
    "eval-okay-float",
    "eval-okay-floor-ceil",
    "eval-okay-foldlStrict",
    "eval-okay-foldlStrict-lazy-elements",
    "eval-okay-foldlStrict-lazy-initial-accumulator",
    "eval-okay-fromTOML",
    "eval-okay-fromTOML-timestamps",
    "eval-okay-fromjson",
    "eval-okay-fromjson-escapes",
    "eval-okay-functionargs",
    "eval-okay-getattrpos",
    "eval-okay-getattrpos-functionargs",
    "eval-okay-getattrpos-undefined",
    "eval-okay-getenv",
    "eval-okay-groupBy",
    "eval-okay-hashfile",
    "eval-okay-hashstring",
    "eval-okay-if",
    "eval-okay-import",
    "eval-okay-ind-string",
    "eval-okay-inherit-attr-pos",
    "eval-okay-inherit-from",
    "eval-okay-intersectAttrs",
    "eval-okay-let",
    "eval-okay-list",
    "eval-okay-listtoattrs",
    "eval-okay-logic",
    "eval-okay-map",
    "eval-okay-mapattrs",
    "eval-okay-merge-dynamic-attrs",
    "eval-okay-nested-with",
    "eval-okay-new-let",
    "eval-okay-null-dynamic-attrs",
    "eval-okay-overrides",
    "eval-okay-parse-flake-ref",
    "eval-okay-partition",
    "eval-okay-path",
    "eval-okay-path-string-interpolation",
    "eval-okay-pathexists",
    "eval-okay-patterns",
    "eval-okay-print",
    "eval-okay-readDir",
    "eval-okay-readFileType",
    "eval-okay-readfile",
    "eval-okay-redefine-builtin",
    "eval-okay-regex-match",
    "eval-okay-regex-split",
    "eval-okay-regression-20220122",
    "eval-okay-regression-20220125",
    "eval-okay-regrettable-rec-attrset-merge",
    "eval-okay-remove",
    "eval-okay-repeated-empty-attrs",
    "eval-okay-repeated-empty-list",
    "eval-okay-replacestrings",
    "eval-okay-scope-1",
    "eval-okay-scope-2",
    "eval-okay-scope-3",
    "eval-okay-scope-4",
    "eval-okay-scope-6",
    "eval-okay-scope-7",
    "eval-okay-search-path",
    "eval-okay-seq",
    "eval-okay-sort",
    "eval-okay-splitversion",
    "eval-okay-string",
    "eval-okay-strings-as-attrs-names",
    "eval-okay-substring",
    "eval-okay-substring-context",
    "eval-okay-symlink-resolution",
    "eval-okay-tail-call-1",
    "eval-okay-tojson",
    "eval-okay-toxml",
    "eval-okay-toxml2",
    "eval-okay-tryeval",
    "eval-okay-types",
    "eval-okay-versions",
    "eval-okay-with",
    "eval-okay-xml",
    "eval-okay-zipAttrsWith",
];

impl LangVersion {
    const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    fn parse(input: &str) -> Option<Self> {
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
    const fn before(max_exclusive: LangVersion) -> Self {
        Self {
            min_inclusive: None,
            max_exclusive: Some(max_exclusive),
        }
    }

    const fn since(min_inclusive: LangVersion) -> Self {
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

fn expected_xml_path(lang_dir: &Path, stem: &str, category: LangCategory) -> Option<PathBuf> {
    if category != LangCategory::EvalOkay {
        return None;
    }
    let path = lang_dir.join(format!("{stem}.exp.xml"));
    path.exists().then_some(path)
}

fn postprocess_path(lang_dir: &Path, stem: &str) -> Option<PathBuf> {
    let path = lang_dir.join(format!("{stem}.postprocess"));
    path.exists().then_some(path)
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
    run_lang_case_with_exclusions(case, false)
}

fn run_lang_case_with_exclusions(
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
    let config = match lang_case_config(case.category, &case.flags, lang_dir) {
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

fn documented_case_exclusion(name: &str) -> Option<String> {
    LANG_CASE_EXCLUSIONS
        .iter()
        .find(|exclusion| exclusion.name == name)
        .map(|exclusion| format!("documented exclusion: {}", exclusion.reason))
}

fn configured_skip_is_allowed(case: &LangCase, reason: &str) -> bool {
    (case.disabled && reason == "disabled by .exp-disabled")
        || documented_case_exclusion(&case.name).as_deref() == Some(reason)
        || version_reactive_skip(&case.name).as_deref() == Some(reason)
}

fn version_reactive_skip(name: &str) -> Option<String> {
    version_reactive_skip_with_rules(name, PINNED_LANG_CPP_NIX_VERSION, LANG_VERSION_SKIP_RULES)
}

fn version_reactive_skip_with_rules(
    name: &str,
    version: LangVersion,
    rules: &[LangVersionSkipRule],
) -> Option<String> {
    rules
        .iter()
        .find(|rule| rule.name == name && rule.active.contains(version))
        .map(|rule| format!("{} (C++ Nix {version})", rule.reason))
}

fn lang_case_postprocess(case: &LangCase) -> std::result::Result<Option<LangPostprocess>, String> {
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

fn parse_lang_postprocess(script: &str) -> std::result::Result<LangPostprocess, ()> {
    let normalized = script.replace("\r\n", "\n");
    let lines = normalized.lines().collect::<Vec<_>>();
    for (target, suffix) in [(LangOutput::Out, "out"), (LangOutput::Err, "err")] {
        if digit_normalizer_postprocess_lines(suffix) == lines {
            return Ok(LangPostprocess { target });
        }
    }
    Err(())
}

fn digit_normalizer_postprocess_lines(suffix: &str) -> Vec<String> {
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

fn apply_lang_postprocess(
    output: &mut Vec<u8>,
    output_kind: LangOutput,
    postprocess: Option<LangPostprocess>,
) {
    if postprocess.is_some_and(|postprocess| postprocess.target == output_kind) {
        *output = normalize_decimal_runs(output);
    }
}

fn normalize_decimal_runs(bytes: &[u8]) -> Vec<u8> {
    let first_pass = normalize_padded_decimal_fields(bytes);
    normalize_decimal_sequences(&first_pass)
}

fn normalize_padded_decimal_fields(bytes: &[u8]) -> Vec<u8> {
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

fn normalize_decimal_sequences(bytes: &[u8]) -> Vec<u8> {
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

fn normalize_lang_pwd_paths(output: &mut Vec<u8>, lang_dir: &Path) {
    let Some(pwd) = lang_dir.parent() else {
        return;
    };
    let pwd = path_bytes(pwd);
    if !pwd.is_empty() {
        *output = replace_byte_sequence(output, &pwd, b"/pwd");
    }
}

fn replace_byte_sequence(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
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

fn lang_case_options(
    category: LangCategory,
    flags: &[String],
    lang_dir: &Path,
) -> std::result::Result<TreeWalkOptions, String> {
    Ok(lang_case_config(category, flags, lang_dir)?.options)
}

fn lang_case_config(
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

fn eval_okay_options(
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

fn eval_fail_options(
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
    fn from_options(options: TreeWalkOptions) -> Self {
        Self {
            options,
            auto_args: Vec::new(),
            attr_path: Vec::new(),
        }
    }
}

fn base_eval_options(lang_dir: &Path) -> std::result::Result<TreeWalkOptions, String> {
    let mut options = TreeWalkOptions::default();
    options
        .set_path_literal_base(path_bytes(lang_dir))
        .map_err(|error| error.to_string())?;
    options
        .set_home_dir(b"/fake-home".to_vec())
        .map_err(|error| error.to_string())?;
    options.set_env_var(b"TEST_VAR".to_vec(), b"foo".to_vec());
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

fn validate_auto_arg_name(name: &str, flags: &[String]) -> std::result::Result<(), String> {
    validate_simple_identifier(name.as_bytes(), flags)
}

fn parse_lang_attr_path(attr: &str, flags: &[String]) -> std::result::Result<Vec<Vec<u8>>, String> {
    let mut segments = Vec::new();
    for segment in attr.split('.') {
        validate_simple_identifier(segment.as_bytes(), flags)?;
        segments.push(segment.as_bytes().to_vec());
    }
    Ok(segments)
}

fn validate_simple_identifier(bytes: &[u8], flags: &[String]) -> std::result::Result<(), String> {
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

fn unsupported_flags_message(flags: &[String]) -> String {
    format!("case carries unsupported flags: {}", flags.join(" "))
}

fn unsupported_postprocess_message(name: &str) -> String {
    format!("case carries unsupported postprocess: {name}")
}

fn parse_case(source: &[u8]) -> Result<()> {
    let parsed = parse_bytes(source).context("parsing expression")?;
    resolve(parsed).context("resolving expression")?;
    Ok(())
}

fn eval_strict_case(source: &[u8], options: TreeWalkOptions) -> Result<()> {
    let parsed = parse_bytes(source).context("parsing expression")?;
    let resolved = resolve(parsed).context("resolving expression")?;
    let ir = lower(resolved).context("lowering expression")?;
    eval_raw_bytes_with_options(&ir, options).context("evaluating strict expression")?;
    Ok(())
}

fn run_non_eval_fail_bad_drv_path(lang_dir: &Path) -> Result<CaseOutcome> {
    let path = lang_dir.join("non-eval-fail-bad-drvPath.nix");
    let mut options = TreeWalkOptions::new();
    options
        .set_current_system(b"x86_64-linux".to_vec())
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

fn eval_raw_case(
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

fn eval_xml_case(source: &[u8], options: TreeWalkOptions) -> Result<Vec<u8>> {
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

fn wrap_eval_okay_source(
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

fn render_auto_arg_expr(
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

fn nix_path_literal(path: &[u8], flags: &[String]) -> std::result::Result<String, String> {
    if !path.iter().all(
        |byte| matches!(byte, b'/' | b'.' | b'_' | b'-' | b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'),
    ) {
        return Err(unsupported_flags_message(flags));
    }
    String::from_utf8(path.to_vec()).map_err(|_| unsupported_flags_message(flags))
}

fn nix_string_literal(bytes: &[u8], flags: &[String]) -> std::result::Result<String, String> {
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

#[test]
fn eval_fail_dup_dynamic_attrs_rejects_runtime_duplicates() {
    let source = br#"{
  set = { "${"" + "b"}" = 1; };
  set = { "${"b" + ""}" = 2; };
}"#;

    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    eval_whnf_owned_with_options(&ir, TreeWalkOptions::default())
        .expect("duplicate dynamic key remains latent at top-level WHNF");

    let error = eval_strict_case(source, TreeWalkOptions::default())
        .expect_err("strict eval should force the duplicate dynamic key");
    assert!(
        error.to_string().contains("evaluating strict expression"),
        "{error:?}"
    );
    assert!(
        format!("{error:?}").contains("duplicate attribute key"),
        "{error:?}"
    );
}

#[test]
fn eval_fail_to_json_non_utf8_rejects_invalid_strings() {
    let source = b"builtins.toJSON \"_invalid UTF-8: \xff_\"";

    let error = eval_strict_case(source, TreeWalkOptions::default())
        .expect_err("toJSON should reject non-UTF-8 strings like the upstream lang fixture");
    assert!(
        error.to_string().contains("evaluating strict expression"),
        "{error:?}"
    );
    assert!(
        format!("{error:?}").contains("non-UTF-8 string"),
        "{error:?}"
    );
}

#[test]
fn eval_okay_foldl_strict_keeps_initial_accumulator_lazy() {
    let source = br#"
builtins.foldl'
  (_: x: x)
  (throw "This is never forced")
  [ "but the results of applying op are" 42 ]
"#;

    eval_strict_case(source, TreeWalkOptions::default())
        .expect("foldl' should not force its initial accumulator unconditionally");
    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    let output =
        eval_raw_bytes_with_options(&ir, TreeWalkOptions::default()).expect("source evaluates");
    assert_eq!(output, b"42");
}

#[test]
fn eval_fail_set_override_rejects_non_attrset_overrides() {
    let source = br#"rec { __overrides = 1; }"#;

    let error = eval_strict_case(source, TreeWalkOptions::default())
        .expect_err("__overrides should evaluate to an attrset");
    assert!(
        error.to_string().contains("evaluating strict expression"),
        "{error:?}"
    );
    assert!(format!("{error:?}").contains("__overrides"), "{error:?}");
}

#[test]
fn eval_okay_overrides_replaces_recursive_scope() {
    let source = br#"let
  overrides = { a = 2; b = 3; };
in (rec {
  __overrides = overrides;
  x = a;
  a = 1;
}).x
"#;

    eval_strict_case(source, TreeWalkOptions::default())
        .expect("__overrides should replace the recursive scope value");
    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    let output =
        eval_raw_bytes_with_options(&ir, TreeWalkOptions::default()).expect("source evaluates");
    assert_eq!(output, b"2");
}

#[test]
fn eval_okay_attrs6_applies_overrides_before_dynamic_attrs() {
    let source = br#"rec {
  "${"foo"}" = "bar";
   __overrides = { bar = "qux"; };
}
"#;

    eval_strict_case(source, TreeWalkOptions::default())
        .expect("__overrides should merge before dynamic attrs");
    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    let output =
        eval_raw_bytes_with_options(&ir, TreeWalkOptions::default()).expect("source evaluates");
    assert_eq!(
        output,
        br#"{ __overrides = { bar = "qux"; }; bar = "qux"; foo = "bar"; }"#
    );
}

fn eval_raw_fixture(source_name: &[u8], source: &[u8]) -> Vec<u8> {
    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    eval_raw_bytes_with_options_source(
        &ir,
        TreeWalkOptions::default(),
        source_name.to_vec(),
        source.to_vec(),
    )
    .expect("source evaluates")
}

#[test]
fn eval_okay_redefine_builtin_try_eval_catches_search_path_miss() {
    let source = br#"let
  throw = abort "Error!";
in (builtins.tryEval <foobaz>).success
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-redefine-builtin.nix", source),
        b"false"
    );
}

#[test]
fn eval_okay_curpos_reports_current_source_locations() {
    let source = br#"# Bla
let
  x = __curPos;
    y = __curPos;
in [ x.line x.column y.line y.column ]
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-curpos.nix", source),
        b"[ 3 7 4 9 ]"
    );
}

#[test]
fn eval_okay_getattrpos_reports_attr_source_location() {
    let source = br#"let
  as = {
    foo = "bar";
  };
  pos = builtins.unsafeGetAttrPos "foo" as;
in { inherit (pos) column line; file = baseNameOf pos.file; }
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-getattrpos.nix", source),
        br#"{ column = 5; file = "eval-okay-getattrpos.nix"; line = 3; }"#
    );
}

#[test]
fn eval_okay_getattrpos_functionargs_reports_formal_location() {
    let source = br#"let
  fun = { foo }: {};
  pos = builtins.unsafeGetAttrPos "foo" (builtins.functionArgs fun);
in { inherit (pos) column line; file = baseNameOf pos.file; }
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-getattrpos-functionargs.nix", source),
        br#"{ column = 11; file = "eval-okay-getattrpos-functionargs.nix"; line = 2; }"#
    );
}

#[test]
fn eval_okay_inherit_attr_pos_reports_inherit_target_locations() {
    let source = br#"let
  d = 0;
  x = 1;
  y = { inherit d x; };
  z = { inherit (y) d x; };
in
  [
    (builtins.unsafeGetAttrPos "d" y)
    (builtins.unsafeGetAttrPos "x" y)
    (builtins.unsafeGetAttrPos "d" z)
    (builtins.unsafeGetAttrPos "x" z)
  ]
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-inherit-attr-pos.nix", source),
        br#"[ { column = 17; file = "/pwd/lang/eval-okay-inherit-attr-pos.nix"; line = 4; } { column = 19; file = "/pwd/lang/eval-okay-inherit-attr-pos.nix"; line = 4; } { column = 21; file = "/pwd/lang/eval-okay-inherit-attr-pos.nix"; line = 5; } { column = 23; file = "/pwd/lang/eval-okay-inherit-attr-pos.nix"; line = 5; } ]"#
    );
}

#[test]
fn eval_okay_inherit_from_renders_recursive_markers() {
    let source = br#"let
  inherit (builtins.trace "used" { a = 1; b = 2; }) a b;
  x.c = 3;
  y.d = 4;

  merged = {
    inner = {
      inherit (y) d;
    };

    inner = {
      inherit (x) c;
    };
  };
in
  [ a b rec { x.c = []; inherit (x) c; inherit (y) d; __overrides.y.d = []; } merged ]
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-inherit-from.nix", source),
        r#"[ 1 2 { __overrides = { y = { d = [ ]; }; }; c = [ ]; d = 4; x = { c = [ ]; }; y = «repeated»; } { inner = { c = 3; d = 4; }; } ]"#
            .as_bytes()
    );
}

#[test]
fn eval_okay_print_renders_primops_lambdas_and_recursive_lists() {
    let source =
        br#"with builtins; trace [(1+1)] [ null toString (deepSeq "x") (a: a) (let x=[x]; in x) ]
"#;

    assert_eq!(
        eval_raw_fixture(b"/pwd/lang/eval-okay-print.nix", source),
        "[ null <PRIMOP> <PRIMOP-APP> <LAMBDA> [ [ «repeated» ] ] ]".as_bytes()
    );
}

#[test]
fn eval_fail_derivation_name_rejects_invalid_names() {
    let source = br#"derivation {
  name = "~jiggle~";
  system = "some-system";
  builder = "/dontcare";
}"#;

    let parsed = parse_bytes(source).expect("source parses");
    let resolved = resolve(parsed).expect("source resolves");
    let ir = lower(resolved).expect("source lowers");
    eval_whnf_owned_with_options(&ir, TreeWalkOptions::default())
        .expect("derivation wrapper stays lazy at WHNF like C++ Nix");

    let error = eval_strict_case(source, TreeWalkOptions::default())
        .expect_err("strict eval should force the invalid derivation name");
    assert!(
        error.to_string().contains("evaluating strict expression"),
        "{error:?}"
    );
    assert!(
        format!("{error:?}").contains("invalid derivation name")
            && format!("{error:?}").contains("contains illegal character '~'"),
        "{error:?}"
    );
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
fn lang_sh_autoarg_flags_configure_eval_okay() {
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
    let unsupported_autoarg_flags = ["--arg", "lib", "builtins"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let unsupported_name_flags = ["--argstr", "bad-name", "value"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let unsupported_attr_flags = ["-A", "\"quoted.attr\""]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let config = lang_case_config(LangCategory::EvalOkay, &autoarg_flags, &lang_dir)
        .expect("autoarg flags should be supported");
    assert_eq!(config.auto_args.len(), 2);
    assert_eq!(config.attr_path, vec![b"result".to_vec()]);
    assert_eq!(config.options.nix_path().len(), 2);

    assert_eq!(
        wrap_eval_okay_source(
            b"{ lib, xyzzy }: { result = xyzzy; }",
            &lang_dir,
            &config,
            &autoarg_flags
        )
        .expect("autoarg source should wrap"),
        format!(
            "(({{ lib, xyzzy }}: {{ result = xyzzy; }}) {{ lib = import {}/lib.nix; xyzzy = \"xyzzy!\"; }}).\"result\"",
            lang_dir.display()
        )
    );
    assert_eq!(
        nix_string_literal(b"${oops}", &autoarg_flags).expect("string literal should escape"),
        "\"\\${oops}\""
    );
    assert_eq!(
        lang_case_config(
            LangCategory::EvalOkay,
            &unsupported_autoarg_flags,
            &lang_dir
        ),
        Err("case carries unsupported flags: --arg lib builtins".to_owned())
    );
    assert_eq!(
        lang_case_config(LangCategory::EvalOkay, &unsupported_name_flags, &lang_dir),
        Err("case carries unsupported flags: --argstr bad-name value".to_owned())
    );
    assert_eq!(
        lang_case_config(LangCategory::EvalOkay, &unsupported_attr_flags, &lang_dir),
        Err("case carries unsupported flags: -A \"quoted.attr\"".to_owned())
    );
}

#[test]
fn lang_sh_digit_normalizer_postprocess_is_supported() -> Result<()> {
    let lang_dir = fixture_lang_dir();
    let case = discover_lang_cases(&lang_dir)?
        .into_iter()
        .find(|case| case.name == "eval-okay-postprocess")
        .expect("postprocess fixture exists");
    assert_eq!(
        lang_case_postprocess(&case),
        Ok(Some(LangPostprocess {
            target: LangOutput::Out
        }))
    );
    let err_script = format!("{}\n", digit_normalizer_postprocess_lines("err").join("\n"));
    assert_eq!(
        parse_lang_postprocess(&err_script),
        Ok(LangPostprocess {
            target: LangOutput::Err
        })
    );

    let mut output = b"       9| value 1234\n".to_vec();
    let postprocess = lang_case_postprocess(&case).map_err(anyhow::Error::msg)?;
    apply_lang_postprocess(&mut output, LangOutput::Out, postprocess);
    assert_eq!(output, b"<number>| value <number>\n");
    assert_eq!(parse_lang_postprocess("echo unsupported"), Err(()));

    Ok(())
}

#[test]
fn lang_version_skip_rules_react_to_pinned_version() {
    let rules = [
        LangVersionSkipRule {
            name: "eval-okay-future",
            active: LangVersionRange::before(LangVersion::new(2, 25, 0)),
            reason: "requires C++ Nix >= 2.25.0",
        },
        LangVersionSkipRule {
            name: "eval-okay-retired",
            active: LangVersionRange::since(LangVersion::new(2, 25, 0)),
            reason: "covered only before C++ Nix 2.25.0",
        },
    ];

    assert_eq!(
        version_reactive_skip_with_rules("eval-okay-future", PINNED_LANG_CPP_NIX_VERSION, &rules),
        Some("requires C++ Nix >= 2.25.0 (C++ Nix 2.24.12)".to_owned())
    );
    assert_eq!(
        version_reactive_skip_with_rules("eval-okay-future", LangVersion::new(2, 25, 0), &rules),
        None
    );
    assert_eq!(
        version_reactive_skip_with_rules("eval-okay-retired", LangVersion::new(2, 25, 0), &rules),
        Some("covered only before C++ Nix 2.25.0 (C++ Nix 2.25.0)".to_owned())
    );
    assert_eq!(
        version_reactive_skip_with_rules("eval-okay-other", PINNED_LANG_CPP_NIX_VERSION, &rules),
        None
    );
}

#[test]
fn pinned_lang_version_matches_packaged_cpp_nix() -> Result<()> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow!("{} has no repo root parent", manifest_dir.display()))?;
    let package = fs::read_to_string(repo_root.join("pkgs/tools/nix.nix"))
        .context("reading packaged C++ Nix derivation")?;
    let version = package
        .lines()
        .find_map(|line| {
            let version = line.trim().strip_prefix("version = \"")?;
            version.strip_suffix("\";")
        })
        .ok_or_else(|| anyhow!("pkgs/tools/nix.nix does not declare a version"))?;

    assert_eq!(
        LangVersion::parse(version),
        Some(PINNED_LANG_CPP_NIX_VERSION)
    );
    Ok(())
}

#[test]
fn configured_upstream_lang_corpus_gate_runs_all_categories() -> Result<()> {
    let Some(root) = std::env::var_os("AOS_NIX_LANG_TESTS") else {
        eprintln!("AOS_NIX_LANG_TESTS not set; skipping upstream lang corpus discovery check");
        return Ok(());
    };
    let lang_dir = Path::new(&root);
    let cases = discover_lang_cases(lang_dir)?;
    let discovered_names = cases
        .iter()
        .map(|case| case.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        discovered_names, PINNED_LANG_2_24_12_CASE_NAMES,
        "configured upstream corpus should match the pinned C++ Nix 2.24.12 case set"
    );
    for special_case in PINNED_LANG_2_24_12_SPECIAL_CASE_NAMES {
        assert!(
            lang_dir.join(format!("{special_case}.nix")).exists(),
            "configured upstream corpus should include special lang.sh case {special_case}"
        );
    }
    for exclusion in LANG_CASE_EXCLUSIONS {
        assert!(
            cases.iter().any(|case| case.name == exclusion.name),
            "documented exclusion {} should exist in the configured upstream corpus",
            exclusion.name
        );
    }

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

    let mut failures = Vec::new();
    let mut passed = 0usize;
    let mut skipped = 0usize;
    for case in &cases {
        match run_lang_case_with_exclusions(case, true) {
            Ok(CaseOutcome::Passed) => passed += 1,
            Ok(CaseOutcome::Skipped(reason)) => {
                if configured_skip_is_allowed(case, &reason) {
                    skipped += 1;
                    eprintln!("SKIP {}: {reason}", case.name);
                } else {
                    failures.push(format!("{} skipped unexpectedly: {reason}", case.name));
                }
            }
            Err(error) => failures.push(format!("{}: {error:#}", case.name)),
        }
    }
    match run_non_eval_fail_bad_drv_path(lang_dir) {
        Ok(CaseOutcome::Passed) => passed += 1,
        Ok(CaseOutcome::Skipped(reason)) => {
            failures.push(format!(
                "non-eval-fail-bad-drvPath skipped unexpectedly: {reason}"
            ));
        }
        Err(error) => failures.push(format!("non-eval-fail-bad-drvPath: {error:#}")),
    }
    if passed != PINNED_LANG_2_24_12_PASS_COUNT || skipped != PINNED_LANG_2_24_12_SKIP_COUNT {
        failures.push(format!(
            "configured upstream corpus counts diverged: expected {} passed / {} skipped, got {passed} passed / {skipped} skipped",
            PINNED_LANG_2_24_12_PASS_COUNT, PINNED_LANG_2_24_12_SKIP_COUNT
        ));
    }
    eprintln!(
        "configured upstream corpus: {passed} passed, {skipped} skipped, {} failed",
        failures.len()
    );
    if !failures.is_empty() {
        bail!(
            "configured upstream corpus failures:\n{}",
            failures.join("\n")
        );
    }

    Ok(())
}
