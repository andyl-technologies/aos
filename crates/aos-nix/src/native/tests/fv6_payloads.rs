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
    assert!(
        stats.campaign().thunk_state_arc_clones > 0,
        "forcing must retain only the independently live thunk-state sidecar"
    );
    Ok(())
}
