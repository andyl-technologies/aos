//! FV-6 arena-owned closure payload regression tests.

use super::*;

#[test]
fn native_expression_retains_only_thunk_state_sidecar_arcs() -> Result<()> {
    let native = NixNative::new(0)?;
    let (_, stats) = native.eval_expr_with_stats("let a = 1 + 1; in (x: a + x) 3")?;
    assert_eq!(
        stats.campaign().payload_arc_clones,
        0,
        "FV-6 must not clone outer thunk/lambda/primop payload Arcs"
    );
    // Pre-I1 this asserted `> 0`: every force cloned the thunk-state sidecar
    // Arc, and the clone count was the witness that only the sidecar (never a
    // payload Arc) was retained. The I1 lazy mint (cd6bdfa7a) moves the state
    // into a fresh Arc on first force — no clone at all — so the strictly
    // stronger property holds: forcing this expression clones NO Arcs. A
    // regression that reintroduces per-force state-sidecar churn fails here.
    assert_eq!(
        stats.campaign().thunk_state_arc_clones,
        0,
        "first-force must mint (move) the thunk-state sidecar, not clone it"
    );
    Ok(())
}
