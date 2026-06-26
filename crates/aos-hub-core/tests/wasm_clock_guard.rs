//! Guard: no wasm-unsafe wall-clock calls outside [`aos_hub_core::clock`].
//!
//! `aos-hub-core` compiles to `wasm32-unknown-unknown` and runs in the
//! Cloudflare Worker, where `std::time::SystemTime::now()` (and a bare
//! `std::time::Instant::now()`) **panic** — the platform has no system clock.
//! All time access must go through [`aos_hub_core::clock`], which reads the host
//! `Date.now()` on the Worker and `std::time` natively.
//!
//! This has bitten production twice (most recently the org audit feed threw a
//! `1101` because `console_render::ago` called `SystemTime::now()` per row). A
//! grep at review time is easy to forget, so this scans the crate source and
//! fails the build if the forbidden call reappears anywhere but `clock.rs`.

use std::fs;
use std::path::{Path, PathBuf};

/// Source-text needles that panic on `wasm32`. `clock.rs` is the one sanctioned
/// home (it gates them behind `#[cfg(not(target_arch = "wasm32"))]`).
const FORBIDDEN: &[&str] = &["SystemTime::now()", "std::time::Instant::now()"];

#[test]
fn core_has_no_wasm_unsafe_clock_calls() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    scan(&src, &mut offenders);
    assert!(
        offenders.is_empty(),
        "wasm-unsafe clock call(s) found — route time through `crate::clock` \
         (these PANIC in the Cloudflare Worker):\n{}",
        offenders.join("\n"),
    );
}

/// Recursively scan `dir` for `.rs` files containing a [`FORBIDDEN`] needle in
/// code (line comments stripped), skipping the sanctioned `clock.rs`.
fn scan(dir: &Path, offenders: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan(&path, offenders);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("clock.rs") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for (lineno, line) in text.lines().enumerate() {
            // Strip a `//`-comment tail so the rule's own explanatory comments
            // (which name the forbidden call) do not trip it.
            let code = line.split("//").next().unwrap_or("");
            for needle in FORBIDDEN {
                if code.contains(needle) {
                    offenders.push(format!("{}:{}: {}", rel(&path), lineno + 1, line.trim()));
                }
            }
        }
    }
}

/// Render `path` relative to the crate root for a readable failure message.
fn rel(path: &Path) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.strip_prefix(&root)
        .unwrap_or(path)
        .display()
        .to_string()
}
