//! Structure-aware fuzz harnesses for aos-nix parity checks.

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::OnceLock;

use aos_nix::compile::{Ir, lower, resolve};
use aos_nix::eval::{
    EvalGcMode, EvalMode, GcConformanceCaseError, InternalDiffError, InternalDiffTier,
    TreeWalkError, TreeWalkOptions, compare_gc_conformance_tier_a_tier_b_raw_bytes_source,
    compare_raw_with_oracle, eval_raw_bytes_with_options,
};
use aos_nix::syntax::parse_bytes;
use aos_nix::{NativeEvalError, NixNative};
use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};

const MAX_SOURCE_LEN: usize = 4096;
const PINNED_NIX_VERSION: &str = "2.24.12";
const SOURCE_SEED_PREFIX: &str = "# aos-nix-fuzz-source\n";
const SOURCE_SEED_CONFIG_PREFIX: &str = "# aos-nix-fuzz-config ";
const ASCII_STRING_BYTES: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-";
const IDENT_FIRST_BYTES: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
const IDENT_REST_BYTES: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

/// Runs one JSON parity fuzz case.
pub fn fuzz_parity_json(data: &[u8]) {
    let Some(input) = fuzz_input_from_bytes(data) else {
        return;
    };
    let source = input.source.as_str();
    if source.len() > MAX_SOURCE_LEN {
        return;
    }

    let candidate = eval_native_json(source, &input.config);
    let Some(oracle) = eval_cpp_nix_json(source, &input.config) else {
        let _ = candidate;
        return;
    };
    let candidate = match candidate {
        NativeJson::Ok(json) => Ok(json),
        NativeJson::Unsupported => return,
        NativeJson::Err(error) => Err(error),
    };

    match (candidate, oracle) {
        (Ok(candidate), Ok(reference)) => {
            assert_eq!(candidate, reference, "generated source diverged:\n{source}")
        }
        (Ok(candidate), Err(reference_error)) => panic!(
            "aos-nix succeeded but C++ Nix failed for generated source:\n{source}\n\
             aos-nix JSON: {candidate}\nC++ Nix error: {reference_error}"
        ),
        (Err(candidate_error), Ok(reference)) => panic!(
            "aos-nix failed but C++ Nix succeeded for generated source:\n{source}\n\
             aos-nix error: {candidate_error}\nC++ Nix JSON: {reference}"
        ),
        (Err(_), Err(_)) => {}
    }
}

/// Runs one internal raw-value differential fuzz case.
pub fn fuzz_internal_diff_raw(data: &[u8]) {
    let Some(input) = fuzz_input_from_bytes(data) else {
        return;
    };
    let source = input.source;
    if source.len() > MAX_SOURCE_LEN {
        return;
    }

    let Some(ir) = lower_fuzz_source(&source) else {
        return;
    };

    let Some(options) = native_options_from_source_config(&input.config) else {
        return;
    };

    match compare_raw_with_oracle(&MirrorInternalDiffTier, &ir, options) {
        Ok(_) | Err(InternalDiffError::Oracle { .. }) => {}
        Err(InternalDiffError::Candidate {
            tier,
            source: error,
        }) => panic!(
            "{tier} failed while tree-walk oracle accepted generated source:\n{error}\n\
             generated source:\n{}",
            source
        ),
        Err(InternalDiffError::Divergence {
            tier,
            oracle,
            candidate,
        }) => panic!(
            "{tier} diverged from tree-walk oracle for generated source:\n{source}\n\
             oracle raw: {}\ncandidate raw: {}",
            String::from_utf8_lossy(&oracle),
            String::from_utf8_lossy(&candidate)
        ),
    }
}

/// Runs one Tier-A/Tier-B GC raw-byte conformance fuzz case.
pub fn fuzz_gc_tier_b_raw(data: &[u8]) {
    let Some(input) = fuzz_input_from_bytes(data) else {
        return;
    };
    let source = input.source;
    if source.len() > MAX_SOURCE_LEN {
        return;
    }

    let wrapped_source = wrap_gc_tier_b_source(&source);
    match compare_gc_conformance_tier_a_tier_b_raw_bytes_source(&wrapped_source) {
        Ok(_)
        | Err(GcConformanceCaseError::Lower { .. })
        | Err(GcConformanceCaseError::TierA { .. }) => {}
        Err(error) => panic!(
            "GC Tier-B raw-byte conformance failed for generated source:\n{wrapped_source}\n\
             error: {error}"
        ),
    }
}

fn wrap_gc_tier_b_source(source: &str) -> String {
    format!("[ (\n{source}\n) ]")
}

/// Returns the Nix source represented by a fuzzer input.
pub fn source_from_fuzz_bytes(data: &[u8]) -> Option<String> {
    fuzz_input_from_bytes(data).map(|input| input.source)
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct FuzzInput {
    source: String,
    config: FuzzSourceConfig,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct FuzzSourceConfig {
    eval_mode: Option<FuzzEvalMode>,
    current_system: Option<String>,
    allowed_paths: Vec<String>,
    allowed_uris: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum FuzzEvalMode {
    Impure,
    Restricted,
    Pure,
}

fn fuzz_input_from_bytes(data: &[u8]) -> Option<FuzzInput> {
    if let Ok(source) = std::str::from_utf8(data) {
        if let Some(source) = source.strip_prefix(SOURCE_SEED_PREFIX) {
            return Some(source_seed_input(source));
        }
    }

    let mut unstructured = Unstructured::new(data);
    let expr = GeneratedExpr::arbitrary(&mut unstructured).ok()?;
    Some(FuzzInput {
        source: expr.to_nix(),
        config: FuzzSourceConfig::default(),
    })
}

fn source_seed_input(seed: &str) -> FuzzInput {
    let mut config = FuzzSourceConfig::default();
    let mut source_lines = Vec::new();
    let mut reading_config = true;
    for line in seed.lines() {
        if reading_config {
            if let Some(raw_config) = line.strip_prefix(SOURCE_SEED_CONFIG_PREFIX) {
                apply_source_seed_config_line(&mut config, raw_config);
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            reading_config = false;
        }
        source_lines.push(line);
    }

    FuzzInput {
        source: source_lines.join("\n").trim().to_owned(),
        config,
    }
}

fn apply_source_seed_config_line(config: &mut FuzzSourceConfig, line: &str) {
    let Some((key, value)) = line.split_once('=') else {
        return;
    };
    let key = key.trim();
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    match key {
        "eval-mode" => match value {
            "impure" => config.eval_mode = Some(FuzzEvalMode::Impure),
            "restricted" => config.eval_mode = Some(FuzzEvalMode::Restricted),
            "pure" => config.eval_mode = Some(FuzzEvalMode::Pure),
            _ => {}
        },
        "current-system" | "system" => config.current_system = Some(value.to_owned()),
        "allowed-path" => config.allowed_paths.push(value.to_owned()),
        "allowed-uri" => config.allowed_uris.push(value.to_owned()),
        _ => {}
    }
}

struct MirrorInternalDiffTier;

impl InternalDiffTier for MirrorInternalDiffTier {
    fn name(&self) -> &'static str {
        "tree-walk-mirror"
    }

    fn eval_raw(&self, ir: &Ir, options: TreeWalkOptions) -> Result<Vec<u8>, TreeWalkError> {
        eval_raw_bytes_with_options(ir, options)
    }
}

fn lower_fuzz_source(source: &str) -> Option<Ir> {
    let parsed = parse_bytes(source.as_bytes()).ok()?;
    let resolved = resolve(parsed).ok()?;
    lower(resolved).ok()
}

#[derive(Debug)]
enum NativeJson {
    Ok(String),
    Unsupported,
    Err(String),
}

fn eval_native_json(source: &str, config: &FuzzSourceConfig) -> NativeJson {
    let Some(options) = native_options_from_source_config(config) else {
        return NativeJson::Unsupported;
    };
    let native = match NixNative::with_options(0, options) {
        Ok(native) => native,
        Err(error) => return NativeJson::Err(error.to_string()),
    };
    match native.eval_expr(source) {
        Ok(json) => NativeJson::Ok(trim_json_text(json)),
        Err(error) if native_error_is_unsupported(&error) => NativeJson::Unsupported,
        Err(error) => NativeJson::Err(error.to_string()),
    }
}

fn native_error_is_unsupported(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<NativeEvalError>(),
        Some(NativeEvalError::Unsupported { .. })
    )
}

fn native_options_from_source_config(config: &FuzzSourceConfig) -> Option<TreeWalkOptions> {
    let mut options = TreeWalkOptions::new();
    if let Some(mode) = config.eval_mode {
        options.set_eval_mode(match mode {
            FuzzEvalMode::Impure => EvalMode::Impure,
            FuzzEvalMode::Restricted => EvalMode::Restricted,
            FuzzEvalMode::Pure => EvalMode::Pure,
        });
    }
    if let Some(current_system) = &config.current_system {
        options
            .set_current_system(current_system.as_bytes().to_vec())
            .ok()?;
    }
    for path in &config.allowed_paths {
        options.add_allowed_path(path.as_bytes().to_vec()).ok()?;
    }
    for uri in &config.allowed_uris {
        options.add_allowed_uri(uri.as_bytes().to_vec()).ok()?;
    }
    apply_native_eval_mode_env(&mut options);
    Some(options)
}

/// Applies the `AOS_NIX_JIT` / `AOS_NIX_PARALLEL` / `AOS_NIX_GC` execution-mode
/// env vars to the native fuzz evaluator's options, mirroring the `aos` CLI's
/// `NixEvalConfig`->`TreeWalkOptions` mapping (`aos-core/src/nix/eval.rs`).
///
/// Without this the fuzz matrix would silently run serial + no-JIT regardless of
/// the leg selected, which is exactly the JIT-off mismeasurement landmine: the
/// carrier-specific code (one-word stack maps, decoded-core emitters, deopt)
/// lives in the JIT path, so the JIT and parallel legs must be real. The C++
/// oracle is unaffected — these knobs only select the native execution tier, not
/// the evaluated result — so a mode change must not change parity.
fn apply_native_eval_mode_env(options: &mut TreeWalkOptions) {
    let jit = std::env::var("AOS_NIX_JIT")
        .map(|value| matches!(value.trim(), "1" | "true"))
        .unwrap_or(false);
    options.set_jit_tier1_publish_enabled(jit);
    if let Ok(value) = std::env::var("AOS_NIX_GC") {
        // Same truthiness as the CLI's `set_aos_nix_gc_env_var` (case-sensitive).
        if matches!(value.trim(), "sweep" | "1" | "true") {
            options.set_gc_mode(EvalGcMode::Sweep);
        }
    }
    if let Ok(value) = std::env::var("AOS_NIX_GC_THRESHOLD") {
        if let Ok(threshold) = value.trim().parse::<u64>() {
            options.set_gc_sweep_threshold(threshold);
        }
    }
    if let Ok(value) = std::env::var("AOS_NIX_PARALLEL") {
        if let Some(workers) = value.trim().parse::<usize>().ok().and_then(std::num::NonZeroUsize::new)
        {
            options.set_parallel_workers(Some(workers));
            // The CLI mapping forces tier-1 JIT off under parallel workers.
            options.set_jit_tier1_publish_enabled(false);
        }
    }
}

fn eval_cpp_nix_json(source: &str, config: &FuzzSourceConfig) -> Option<Result<String, String>> {
    let oracle = oracle_command()?;
    let mut command = Command::new(oracle);
    command.args(["--eval", "--strict", "--json"]);
    apply_cpp_source_config(&mut command, config);
    let output = command
        .args(["--expr", source])
        .output()
        .unwrap_or_else(|error| panic!("C++ Nix oracle runs: {error}"));
    if output.status.success() {
        Some(Ok(trim_json_text(
            String::from_utf8(output.stdout).unwrap_or_else(|error| {
                panic!("C++ Nix oracle produced non-UTF-8 stdout: {error}")
            }),
        )))
    } else {
        Some(Err(String::from_utf8_lossy(&output.stderr).into_owned()))
    }
}

fn apply_cpp_source_config(command: &mut Command, config: &FuzzSourceConfig) {
    if let Some(current_system) = &config.current_system {
        command.args(["--option", "system", current_system]);
    }
    let restricted = matches!(config.eval_mode, Some(FuzzEvalMode::Restricted));
    if let Some(mode) = config.eval_mode {
        match mode {
            FuzzEvalMode::Impure => {
                command.args(["--option", "pure-eval", "false"]);
                command.args(["--option", "restrict-eval", "false"]);
            }
            FuzzEvalMode::Restricted => {
                command.args(["--option", "pure-eval", "false"]);
                command.args(["--option", "restrict-eval", "true"]);
            }
            FuzzEvalMode::Pure => {
                command.args(["--option", "pure-eval", "true"]);
                command.args(["--option", "restrict-eval", "false"]);
            }
        }
    }
    if restricted {
        for path in &config.allowed_paths {
            command.args(["-I", path]);
        }
    }
    if restricted && !config.allowed_paths.is_empty() {
        command.args([
            "--option",
            "allowed-impure-host-deps",
            &config.allowed_paths.join(" "),
        ]);
    }
    if restricted && !config.allowed_uris.is_empty() {
        command.args(["--option", "allowed-uris", &config.allowed_uris.join(" ")]);
    }
}

fn oracle_command() -> Option<&'static str> {
    static ORACLE: OnceLock<Option<String>> = OnceLock::new();
    ORACLE
        .get_or_init(|| {
            let oracle = std::env::var("AOS_NIX_ORACLE").ok()?;
            assert_pinned_cpp_nix_oracle(&oracle);
            Some(oracle)
        })
        .as_deref()
}

fn assert_pinned_cpp_nix_oracle(oracle: &str) {
    let output = Command::new(oracle)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("C++ Nix oracle version runs: {error}"));
    assert!(
        output.status.success(),
        "C++ Nix oracle version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let version = trim_json_text(
        String::from_utf8(output.stdout)
            .unwrap_or_else(|error| panic!("C++ Nix version is non-UTF-8: {error}")),
    );
    assert!(
        version.ends_with(&format!(" {PINNED_NIX_VERSION}"))
            || version.ends_with(&format!("(Nix) {PINNED_NIX_VERSION}")),
        "expected pinned C++ Nix {PINNED_NIX_VERSION} oracle, got {version}"
    );
}

fn trim_json_text(mut text: String) -> String {
    while matches!(text.as_bytes().last(), Some(b'\n' | b'\r')) {
        let _ = text.pop();
    }
    text
}

#[derive(Debug, Clone)]
enum GeneratedExpr {
    Int(u16),
    Bool(bool),
    String(String),
    List(Vec<GeneratedExpr>),
    Attrs(BTreeMap<String, GeneratedExpr>),
    If {
        condition: bool,
        then_expr: Box<GeneratedExpr>,
        else_expr: Box<GeneratedExpr>,
    },
    Let {
        name: String,
        value: Box<GeneratedExpr>,
        body: Box<GeneratedExpr>,
    },
    Add(u16, u16),
    ListConcat(Vec<GeneratedExpr>, Vec<GeneratedExpr>),
    AttrUpdate(
        BTreeMap<String, GeneratedExpr>,
        BTreeMap<String, GeneratedExpr>,
    ),
}

impl<'a> Arbitrary<'a> for GeneratedExpr {
    fn arbitrary(unstructured: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Self::arbitrary_depth(unstructured, 4)
    }
}

impl GeneratedExpr {
    fn arbitrary_depth(unstructured: &mut Unstructured<'_>, depth: u8) -> ArbitraryResult<Self> {
        if depth == 0 {
            return Self::arbitrary_leaf(unstructured);
        }

        match unstructured.int_in_range(0..=9)? {
            0 => Self::arbitrary_leaf(unstructured),
            1 => Ok(Self::List(arbitrary_expr_vec(unstructured, depth - 1)?)),
            2 => Ok(Self::Attrs(arbitrary_attr_map(unstructured, depth - 1)?)),
            3 => Ok(Self::If {
                condition: bool::arbitrary(unstructured)?,
                then_expr: Box::new(Self::arbitrary_depth(unstructured, depth - 1)?),
                else_expr: Box::new(Self::arbitrary_depth(unstructured, depth - 1)?),
            }),
            4 => Ok(Self::Let {
                name: arbitrary_ident(unstructured)?,
                value: Box::new(Self::arbitrary_depth(unstructured, depth - 1)?),
                body: Box::new(Self::arbitrary_depth(unstructured, depth - 1)?),
            }),
            5 => Ok(Self::Add(
                unstructured.int_in_range(0..=1000)?,
                unstructured.int_in_range(0..=1000)?,
            )),
            6 => Ok(Self::ListConcat(
                arbitrary_expr_vec(unstructured, depth - 1)?,
                arbitrary_expr_vec(unstructured, depth - 1)?,
            )),
            7 => Ok(Self::AttrUpdate(
                arbitrary_attr_map(unstructured, depth - 1)?,
                arbitrary_attr_map(unstructured, depth - 1)?,
            )),
            _ => Self::arbitrary_leaf(unstructured),
        }
    }

    fn arbitrary_leaf(unstructured: &mut Unstructured<'_>) -> ArbitraryResult<Self> {
        match unstructured.int_in_range(0..=2)? {
            0 => Ok(Self::Int(unstructured.int_in_range(0..=1000)?)),
            1 => Ok(Self::Bool(bool::arbitrary(unstructured)?)),
            _ => Ok(Self::String(arbitrary_ascii_string(unstructured)?)),
        }
    }

    fn to_nix(&self) -> String {
        match self {
            Self::Int(value) => value.to_string(),
            Self::Bool(true) => "true".to_owned(),
            Self::Bool(false) => "false".to_owned(),
            Self::String(value) => nix_string_literal(value),
            Self::List(values) => {
                let body = values
                    .iter()
                    .map(Self::to_nix)
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("[ {body} ]")
            }
            Self::Attrs(attrs) => format_attrset(attrs),
            Self::If {
                condition,
                then_expr,
                else_expr,
            } => format!(
                "(if {} then {} else {})",
                if *condition { "true" } else { "false" },
                then_expr.to_nix(),
                else_expr.to_nix()
            ),
            Self::Let { name, value, body } => {
                format!("(let {name} = {}; in {})", value.to_nix(), body.to_nix())
            }
            Self::Add(left, right) => format!("({left} + {right})"),
            Self::ListConcat(left, right) => {
                let left = Self::List(left.clone()).to_nix();
                let right = Self::List(right.clone()).to_nix();
                format!("({left} ++ {right})")
            }
            Self::AttrUpdate(left, right) => {
                format!("({} // {})", format_attrset(left), format_attrset(right))
            }
        }
    }
}

fn arbitrary_expr_vec(
    unstructured: &mut Unstructured<'_>,
    depth: u8,
) -> ArbitraryResult<Vec<GeneratedExpr>> {
    let count = unstructured.int_in_range(0..=4)?;
    (0..count)
        .map(|_| GeneratedExpr::arbitrary_depth(unstructured, depth))
        .collect()
}

fn arbitrary_attr_map(
    unstructured: &mut Unstructured<'_>,
    depth: u8,
) -> ArbitraryResult<BTreeMap<String, GeneratedExpr>> {
    let count = unstructured.int_in_range(0..=4)?;
    let mut attrs = BTreeMap::new();
    for _ in 0..count {
        attrs.insert(
            arbitrary_ident(unstructured)?,
            GeneratedExpr::arbitrary_depth(unstructured, depth)?,
        );
    }
    Ok(attrs)
}

fn arbitrary_ident(unstructured: &mut Unstructured<'_>) -> ArbitraryResult<String> {
    loop {
        let len = unstructured.int_in_range(1..=6)?;
        let mut bytes = Vec::with_capacity(len);
        bytes.push(*unstructured.choose(IDENT_FIRST_BYTES)?);
        for _ in 1..len {
            bytes.push(*unstructured.choose(IDENT_REST_BYTES)?);
        }
        let ident = String::from_utf8(bytes).expect("identifier bytes are ASCII");
        if !is_nix_keyword(&ident) {
            return Ok(ident);
        }
    }
}

fn arbitrary_ascii_string(unstructured: &mut Unstructured<'_>) -> ArbitraryResult<String> {
    let len = unstructured.int_in_range(0..=12)?;
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        bytes.push(*unstructured.choose(ASCII_STRING_BYTES)?);
    }
    Ok(String::from_utf8(bytes).expect("string bytes are ASCII"))
}

fn format_attrset(attrs: &BTreeMap<String, GeneratedExpr>) -> String {
    let body = attrs
        .iter()
        .map(|(name, value)| format!("{} = {};", nix_string_literal(name), value.to_nix()))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{{ {body} }}")
}

fn nix_string_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '$' => escaped.push_str("\\$"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

fn is_nix_keyword(value: &str) -> bool {
    matches!(
        value,
        "assert" | "else" | "if" | "in" | "inherit" | "let" | "or" | "rec" | "then" | "with"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_args(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn source_seed_prefix_uses_literal_nix_source() {
        let source = source_from_fuzz_bytes(b"# aos-nix-fuzz-source\n{ b = 2; a = 1; }\n")
            .expect("source seed decodes");

        assert_eq!(source, "{ b = 2; a = 1; }");
    }

    #[test]
    fn source_seed_config_is_parsed_and_stripped_from_source() {
        let input = fuzz_input_from_bytes(
            b"# aos-nix-fuzz-source\n\
              # aos-nix-fuzz-config eval-mode=impure\n\
              # aos-nix-fuzz-config current-system=x86_64-linux\n\
              # aos-nix-fuzz-config allowed-path=/repo\n\
              # aos-nix-fuzz-config allowed-uri=https://cache.example/\n\
              builtins.currentSystem\n",
        )
        .expect("configured source seed decodes");

        assert_eq!(input.source, "builtins.currentSystem");
        assert_eq!(input.config.eval_mode, Some(FuzzEvalMode::Impure));
        assert_eq!(input.config.current_system.as_deref(), Some("x86_64-linux"));
        assert_eq!(input.config.allowed_paths, vec!["/repo"]);
        assert_eq!(input.config.allowed_uris, vec!["https://cache.example/"]);
    }

    #[test]
    fn source_seed_config_ignores_unknown_or_invalid_lines() {
        let input = fuzz_input_from_bytes(
            b"# aos-nix-fuzz-source\n\
              # aos-nix-fuzz-config eval-mode=weird\n\
              # aos-nix-fuzz-config unknown=value\n\
              # aos-nix-fuzz-config current-system=\n\
              1 + 1\n",
        )
        .expect("source seed decodes");

        assert_eq!(input.source, "1 + 1");
        assert_eq!(input.config, FuzzSourceConfig::default());
    }

    #[test]
    fn source_seed_config_maps_to_native_options() {
        let config = FuzzSourceConfig {
            eval_mode: Some(FuzzEvalMode::Restricted),
            current_system: Some("x86_64-linux".to_owned()),
            allowed_paths: vec!["/repo".to_owned()],
            allowed_uris: vec!["https://cache.example/".to_owned()],
        };

        let options = native_options_from_source_config(&config).expect("options map");

        assert_eq!(options.eval_mode(), EvalMode::Restricted);
        assert_eq!(options.current_system(), Some(b"x86_64-linux".as_slice()));
        assert_eq!(options.allowed_paths(), &[b"/repo".to_vec()]);
        assert_eq!(
            options.allowed_uris(),
            &[b"https://cache.example/".to_vec()]
        );
    }

    #[test]
    fn restricted_source_seed_config_maps_to_cpp_oracle_args() {
        let config = FuzzSourceConfig {
            eval_mode: Some(FuzzEvalMode::Restricted),
            current_system: Some("x86_64-linux".to_owned()),
            allowed_paths: vec!["/repo".to_owned()],
            allowed_uris: vec!["https://cache.example/".to_owned()],
        };
        let mut command = Command::new("nix-instantiate");

        apply_cpp_source_config(&mut command, &config);

        assert_eq!(
            command_args(&command),
            [
                "--option",
                "system",
                "x86_64-linux",
                "--option",
                "pure-eval",
                "false",
                "--option",
                "restrict-eval",
                "true",
                "-I",
                "/repo",
                "--option",
                "allowed-impure-host-deps",
                "/repo",
                "--option",
                "allowed-uris",
                "https://cache.example/"
            ]
        );
    }

    #[test]
    fn arbitrary_bytes_generate_bounded_nix_source() {
        let source = source_from_fuzz_bytes(b"abcdef0123456789").expect("generated source exists");

        assert!(source.len() <= MAX_SOURCE_LEN, "{source}");
        let native = NixNative::new(0).expect("native evaluator initializes");
        let _ = native.eval_expr(&source);
    }

    #[test]
    fn internal_diff_fuzzer_accepts_source_seed() {
        fuzz_internal_diff_raw(
            b"# aos-nix-fuzz-source\nlet x = 1 + 2; in { value = x; list = [ true \"ok\" ]; }\n",
        );
    }

    #[test]
    fn gc_tier_b_raw_fuzzer_accepts_source_seed() {
        fuzz_gc_tier_b_raw(
            b"# aos-nix-fuzz-source\nlet x = { a = 1 + 2; }; in { inherit x; y = [ x ]; }\n",
        );
    }

    #[test]
    fn gc_tier_b_raw_fuzzer_accepts_trailing_line_comment_source_seed() {
        fuzz_gc_tier_b_raw(
            b"# aos-nix-fuzz-source\nlet x = { a = 1 + 2; }; in { inherit x; } # trailing comment\n",
        );
    }
}
