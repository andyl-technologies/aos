//! Manual refusal-census probe for the heap-image snapshot (RFC-0007 doc 31 §1
//! feasibility).
//!
//! Ignored by default — it is a diagnostic harness, not a gate. Drive it with a
//! Nix expression that forces the real lib+stdenv prelude through absolute-path
//! imports and print the refusal-census table plus whether capture would be
//! refused:
//!
//! ```text
//! AOS_NIX_CENSUS_EXPR='builtins.deepSeq (import /abs/andyl-os/lib) null' \
//!   cargo test --manifest-path crates/Cargo.toml -p ratchet-oracle \
//!     --features candidate_c_value census_probe -- --ignored --nocapture
//! ```
//!
//! Use an expression ending in a fully-forced leaf (`.drvPath`, `deepSeq …`) so
//! the prelude is actually materialized; a bare attrset only forces its spine.

use super::*;

#[test]
#[ignore = "manual probe; set AOS_NIX_CENSUS_EXPR to force the real prelude"]
fn census_probe() {
    let Some(expr) = std::env::var_os("AOS_NIX_CENSUS_EXPR") else {
        eprintln!("AOS_NIX_CENSUS_EXPR unset; nothing to probe");
        return;
    };
    let expr = expr.to_string_lossy().into_owned();
    let outcome = eval_owned_with_source(b"census", &expr);
    eprint!("{}", outcome.heap().refusal_census());
    match outcome.heap().capture_heap_image() {
        Ok(_) => eprintln!("capture_heap_image: ACCEPTED (no closures/records refused)"),
        Err(error) => eprintln!("capture_heap_image: REFUSED -> {error}"),
    }
}
