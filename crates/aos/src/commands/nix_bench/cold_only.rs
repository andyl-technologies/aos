//! Cold-only instruction-attribution path for `aos nix-bench`.
//!
//! The instruction-bloat campaign (RFC-0007) needs a *clean per-op instruction
//! budget*: retired instructions for exactly one cold native evaluation, divided
//! by that evaluation's op counters. The full benchmark path cannot provide it —
//! it builds a C++ oracle (a separate process whose instructions would pollute a
//! `perf stat`), runs a warm re-instantiate, gates parity, and records history.
//!
//! Selected by `AOS_NIX_BENCH_COLD_ONLY=1`, this path instead runs **one
//! isolated native-only cold eval per `-A` attribute** and prints one greppable
//! result line, doing nothing else:
//!
//! ```text
//! aos_nix_cold_only {"attr":"pkgs.zlib","drv":"/nix/store/…-zlib.drv","wall_ns":123456789}
//! ```
//!
//! Wrap the process in `perf stat -e instructions:u` for the cold instruction
//! count (no C++ subprocess, no warm eval), and run it again with
//! `AOS_NIX_EVAL_STATS=1` to read the same deterministic eval's op counters and
//! force-shape census; the per-op instruction budget is the ratio. See
//! `docs/rfcs/0007-nix-evaluator/design-notes/instruction-bloat-perf-attribution.md`.

use std::path::Path;
use std::time::Instant;

use anyhow::Result;

use aos_core::nix::{NixEvalConfig, NixRunner};
use aos_core::output::Printer;

use super::{absolute_eval_file, corpus, fresh_isolated_candidate, native_instantiate};

/// Returns whether `AOS_NIX_BENCH_COLD_ONLY=1` selects this path.
pub(super) fn enabled() -> bool {
    std::env::var("AOS_NIX_BENCH_COLD_ONLY").is_ok_and(|value| value == "1")
}

/// Runs one isolated, native-only cold eval per requested attribute and prints a
/// greppable JSON result line, doing nothing else.
///
/// Each attribute uses a [`fresh_isolated_candidate`], so every in-process memo
/// tier starts empty of data from earlier runs while remaining enabled for reuse
/// within this evaluation. Persistent cache population is measured separately.
/// There is no C++ oracle, warm re-instantiate, parity gate, or history — see
/// the [module docs](self).
///
/// # Errors
///
/// Returns an error if no attributes were requested (`-A` is required here,
/// since attribute discovery would need the oracle this path deliberately
/// omits), if the eval file cannot be resolved, or if a cold evaluator cannot be
/// built or its instantiation fails.
pub(super) fn run(
    printer: &Printer,
    verbose: u8,
    eval_config: &NixEvalConfig,
    file: Option<&Path>,
    attrs: &[String],
) -> Result<()> {
    if attrs.is_empty() {
        anyhow::bail!(
            "AOS_NIX_BENCH_COLD_ONLY requires at least one -A/--attr (this path builds no oracle, \
             so it cannot discover attributes)"
        );
    }
    let root = NixRunner::find_root()?;
    let file = file
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join("default.nix"));
    let file = absolute_eval_file(&file)?;
    for spec in corpus::explicit_benchmark_specs(&file, attrs) {
        let (candidate, _cache_dir) = fresh_isolated_candidate(verbose, eval_config, &spec)?;
        let started = Instant::now();
        let drv = native_instantiate(candidate.as_ref(), &spec)?;
        let wall_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        printer.plain(&format!(
            "aos_nix_cold_only {{\"attr\":{},\"drv\":{},\"wall_ns\":{wall_ns}}}",
            json_string(&spec.attr),
            json_string(&drv.to_string_lossy()),
        ));
    }
    Ok(())
}

/// Serializes a string as a minimal JSON string literal (quotes plus `"` and
/// `\` escaping), enough for the attribute and store-path fields printed here.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::json_string;

    /// JSON string escaping covers the quote and backslash cases store paths and
    /// attribute names can contain; ordinary characters pass through.
    #[test]
    fn json_string_escapes_quotes_and_backslashes() {
        assert_eq!(json_string("pkgs.zlib"), "\"pkgs.zlib\"");
        assert_eq!(json_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(json_string(r"a\b"), r#""a\\b""#);
    }
}
